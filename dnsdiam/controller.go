package dnsdiam

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/peer"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

type bindingKey struct {
	realm string
	app   uint32
}
type managedBinding struct {
	candidate Candidate
	spec      peer.Discovery
	evidence  *tlsEvidence
}
type managedHost struct {
	lease    *peer.Lease
	bindings map[bindingKey]managedBinding
	spec     peer.Discovery
}

// Controller owns the leases it acquires. Operations are serialized, including
// callbacks supplied through Policy; cancellation interrupts pending discovery
// and acquisition. It never replaces manually configured peer ownership.
// A single host can serve multiple applications in one requested realm. Sharing
// one host across different requested realms is rejected conservatively.
type Controller struct {
	discoverer *Discoverer
	manager    *peer.Manager
	policy     Policy
	gate       chan struct{}
	ctx        context.Context
	cancel     context.CancelFunc
	closeOnce  sync.Once
	done       chan struct{}
	retired    sync.WaitGroup
	closed     bool
	owned      map[string]*managedHost
	persistent map[bindingKey]bool
	watchers   map[bindingKey]int
}

// NewController binds discovery to an already configured Manager. Start the
// Manager before calling Ensure or Watch. Policy and TLS credentials are immutable
// after construction; replace the controller to change credential policy.
func NewController(discoverer *Discoverer, manager *peer.Manager, policy Policy) (*Controller, error) {
	if discoverer == nil || manager == nil || policy.Authorize == nil {
		return nil, ErrInvalid
	}
	if policy.TLSConfig == nil && !policy.AllowPlaintext {
		return nil, ErrUnauthorized
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Controller{discoverer: discoverer, manager: manager, policy: policy, gate: make(chan struct{}, 1), ctx: ctx, cancel: cancel, done: make(chan struct{}), owned: make(map[string]*managedHost), persistent: make(map[bindingKey]bool), watchers: make(map[bindingKey]int)}
	c.gate <- struct{}{}
	return c, nil
}
func (c *Controller) lock(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.ctx.Done():
		return context.Canceled
	case <-c.gate:
	}
	if c.closed || c.ctx.Err() != nil {
		c.unlock()
		return context.Canceled
	}
	return nil
}
func (c *Controller) unlock() { c.gate <- struct{}{} }
func (c *Controller) operationContext(ctx context.Context) (context.Context, func()) {
	op, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.ctx, cancel)
	return op, func() { stop(); cancel() }
}
func requestKey(request Request) (bindingKey, error) {
	realm, err := absolute(request.Realm, false)
	if err != nil {
		return bindingKey{}, err
	}
	return bindingKey{identityName(realm), request.ApplicationID}, nil
}
func (c *Controller) defaultRequest(realm string, app uint32) Request {
	r := Request{Realm: realm, ApplicationID: app, Transports: []Transport{TLS}}
	if c.policy.AllowPlaintext {
		r.Transports = append(r.Transports, TCP, SCTP)
	}
	return r
}

// Ensure uses an eligible configured route before querying DNS. Acquired leases
// remain until their deadlines or Close. Cancellation during this operation
// releases its requested binding; unrelated bindings remain owned.
func (c *Controller) Ensure(ctx context.Context, realm string, app uint32) error {
	if c == nil {
		return ErrInvalid
	}
	request := c.defaultRequest(realm, app)
	key, err := requestKey(request)
	if err != nil {
		return err
	}
	if err = c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	op, stop := c.operationContext(ctx)
	defer stop()
	err = c.ensureLocked(op, request, key, false)
	if err == nil && c.owns(key) {
		c.persistent[key] = true
	}
	if op.Err() != nil {
		c.removeBindingLocked(key)
		return op.Err()
	}
	return err
}
func (c *Controller) owns(key bindingKey) bool {
	for _, host := range c.owned {
		if _, ok := host.bindings[key]; ok {
			return true
		}
	}
	return false
}
func (c *Controller) ensureLocked(ctx context.Context, request Request, key bindingKey, force bool) error {
	if (!force || !c.owns(key)) && c.manager.HasRoute(datatype.DiameterIdentity(key.realm), key.app) {
		return nil
	}
	request.Realm = key.realm
	if len(request.Transports) > 0 {
		request.Transports = slices.DeleteFunc(slices.Clone(request.Transports), func(t Transport) bool { return t == DTLS })
		if len(request.Transports) == 0 {
			return ErrUnsupportedTransport
		}
	}
	candidates, err := c.discoverer.Discover(ctx, request)
	if err != nil {
		if onlyNoService(err) {
			c.removeBindingLocked(key)
		}
		return err
	}
	selected := make(map[string]bool)
	var protocol Transport
	failures := []error{ErrNoService}
	for rank, candidate := range candidates {
		if err = ctx.Err(); err != nil {
			c.removeBindingLocked(key)
			return err
		}
		if candidate.Transport == DTLS || protocol != "" && candidate.Transport != protocol {
			continue
		}
		host := identityName(candidate.Host)
		if candidate.TTL <= 0 || !c.discoverer.cfg.Now().Before(candidate.ExpiresAt) {
			c.removeHostBindingLocked(host, key)
			delete(selected, host)
			failures = append(failures, ErrExpired)
			continue
		}
		if selected[host] {
			continue
		}
		// Reuse the callback's evidence together with its TLS configuration.
		// A refresh still validates the current naming chain and authorization.
		var retained *tlsEvidence
		if old := c.owned[host]; old != nil {
			for _, binding := range old.bindings {
				prior := binding.candidate
				prior.ApplicationID = candidate.ApplicationID
				if sameProof(prior, candidate) {
					retained = binding.evidence
					break
				}
			}
		}
		spec, evidence, prepareErr := c.policy.prepareWithEvidence(candidate, c.discoverer.cfg.Now, retained)
		if prepareErr != nil {
			if errors.Is(prepareErr, ErrUnauthorized) {
				c.removeHostBindingLocked(host, key)
			}
			failures = append(failures, prepareErr)
			continue
		}
		// The discoverer has already applied RFC 3958 §2.2.4 and RFC 2782's
		// priority/weight ordering; Manager must preserve that resulting order.
		spec.RouteOrder = map[uint32]uint64{key.app: uint64(rank) + 1}
		if err = c.installLocked(ctx, key, candidate, spec, evidence); err != nil {
			if errors.Is(err, ErrUnauthorized) {
				c.removeHostBindingLocked(host, key)
			}
			failures = append(failures, err)
			continue
		}
		selected[host] = true
		protocol = candidate.Transport
		if len(selected) == 2 {
			break
		}
	}
	if err = ctx.Err(); err != nil {
		c.removeBindingLocked(key)
		return err
	}
	if len(selected) == 0 {
		return errors.Join(failures...)
	}
	for host, owned := range c.owned {
		if _, ok := owned.bindings[key]; ok && !selected[host] {
			c.removeHostBindingLocked(host, key)
		}
	}
	return nil
}

// Only an entirely definitive absence withdraws existing authorization. A joined
// lookup, limit, cancellation or malformed-response error leaves the old deadline.
func onlyNoService(err error) bool {
	if err == ErrNoService {
		return true
	}
	switch e := err.(type) {
	case interface{ Unwrap() []error }:
		children := e.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !onlyNoService(child) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return onlyNoService(e.Unwrap())
	default:
		return false
	}
}
func sameProof(a, b Candidate) bool {
	return a.Realm == b.Realm && a.ApplicationID == b.ApplicationID && a.Host == b.Host && a.Transport == b.Transport && a.Port == b.Port && equalAddressSets(a.Addresses, b.Addresses) && slices.Equal(a.Names, b.Names)
}

func equalAddressSets(a, b []netip.Addr) bool {
	set := func(addresses []netip.Addr) map[netip.Addr]bool {
		result := make(map[netip.Addr]bool, len(addresses))
		for _, address := range addresses {
			result[address.Unmap()] = true
		}
		return result
	}
	x, y := set(a), set(b)
	if len(x) != len(y) {
		return false
	}
	for address := range x {
		if !y[address] {
			return false
		}
	}
	return true
}

func sameEndpoint(a, b peer.PeerConfig) bool {
	if a.Host != b.Host || a.NoAutoReconnect != b.NoAutoReconnect {
		return false
	}
	type endpointKey struct {
		network, address string
		tls              bool
	}
	set := func(endpoints []peer.Endpoint) map[endpointKey]bool {
		result := make(map[endpointKey]bool, len(endpoints))
		for _, endpoint := range endpoints {
			address := endpoint.Address
			if ap, err := netip.ParseAddrPort(address); err == nil {
				address = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String()
			}
			result[endpointKey{endpoint.Network, address, endpoint.TLSConfig != nil}] = true
		}
		return result
	}
	x, y := set(a.Endpoints), set(b.Endpoints)
	if len(x) != len(y) {
		return false
	}
	for endpoint := range x {
		if !y[endpoint] {
			return false
		}
	}
	return true
}
func (c *Controller) installLocked(ctx context.Context, key bindingKey, candidate Candidate, spec peer.Discovery, evidence *tlsEvidence) error {
	hostKey := identityName(candidate.Host)
	old := c.owned[hostKey]
	bindings := make(map[bindingKey]managedBinding)
	replacement := false
	if old != nil {
		for existing, binding := range old.bindings {
			if existing.realm != key.realm {
				return fmt.Errorf("%w: host %s already serves a different requested realm", peer.ErrDiscoveryOwned, hostKey)
			}
			if c.discoverer.cfg.Now().Before(binding.spec.ExpiresAt) {
				bindings[existing] = binding
			}
		}
		prior, had := bindings[key]
		replacement = !sameEndpoint(spec.Peer, old.spec.Peer) || had && !sameProof(prior.candidate, candidate)
		if !replacement {
			// Equality concerns the address set. Retained leases keep their dial
			// attempt order and the TLS configuration coupled to its evidence.
			if evidence != nil && len(old.spec.Peer.Endpoints) > 0 && evidence.config != old.spec.Peer.Endpoints[0].TLSConfig {
				replacement = true
			} else {
				spec.Peer.Endpoints = slices.Clone(old.spec.Peer.Endpoints)
			}
		}
	}
	bindings[key] = managedBinding{candidate: candidate, spec: spec, evidence: evidence}
	if replacement && evidence != nil {
		// A replacement uses one TLS configuration for every application. Rebind
		// all validators to that configuration's selection evidence, preserving
		// each application's DNS proof, expiry and routing rank.
		for existing, binding := range bindings {
			if binding.evidence == evidence {
				continue
			}
			renewed, _, err := c.policy.prepareWithEvidence(binding.candidate, c.discoverer.cfg.Now, evidence)
			if err != nil {
				return err
			}
			renewed.RouteOrder = binding.spec.RouteOrder
			binding.spec, binding.evidence = renewed, evidence
			bindings[existing] = binding
		}
	}
	aggregate, err := aggregateBindings(bindings)
	if err != nil {
		return err
	}
	if old != nil && !replacement {
		// Every contributing authorization is checked again on the retained session.
		err = old.lease.Refresh(ctx, aggregate)
		if err == nil {
			old.bindings = bindings
			old.spec = aggregate
			return nil
		}
		if !errors.Is(err, peer.ErrLeaseExpired) && !errors.Is(err, peer.ErrDiscoveryChanged) {
			return err
		}
	}
	if old != nil {
		delete(c.owned, hostKey)
		if err = old.lease.Release(ctx); err != nil {
			c.retireLease(old.lease)
			return err
		}
	}
	lease, err := c.manager.AcquireDiscovered(ctx, aggregate)
	if err != nil {
		return err
	}
	c.owned[hostKey] = &managedHost{lease: lease, bindings: bindings, spec: aggregate}
	return nil
}
func aggregateBindings(bindings map[bindingKey]managedBinding) (peer.Discovery, error) {
	keys := make([]bindingKey, 0, len(bindings))
	for key := range bindings {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].realm != keys[j].realm {
			return keys[i].realm < keys[j].realm
		}
		return keys[i].app < keys[j].app
	})
	if len(keys) == 0 {
		return peer.Discovery{}, ErrNoService
	}
	spec := bindings[keys[0]].spec
	spec.Peer.Endpoints = slices.Clone(spec.Peer.Endpoints)
	spec.ApplicationIDs = nil
	spec.RouteOrder = make(map[uint32]uint64, len(keys))
	validators := make([]func(diam.Conn, *smpeer.Metadata) (time.Time, error), 0, len(keys))
	for _, key := range keys {
		binding := bindings[key]
		if binding.spec.Realm != spec.Realm || !sameEndpoint(binding.spec.Peer, spec.Peer) {
			return peer.Discovery{}, fmt.Errorf("%w: incompatible shared peer bindings", ErrInvalid)
		}
		spec.ExpiresAt = earlier(spec.ExpiresAt, binding.spec.ExpiresAt)
		spec.ApplicationIDs = append(spec.ApplicationIDs, key.app)
		spec.RouteOrder[key.app] = binding.spec.RouteOrder[key.app]
		validators = append(validators, binding.spec.Validate)
	}
	spec.Validate = func(conn diam.Conn, meta *smpeer.Metadata) (time.Time, error) {
		var deadline time.Time
		for _, validate := range validators {
			capAt, err := validate(conn, meta.Clone())
			if err != nil {
				return time.Time{}, err
			}
			deadline = earlier(deadline, capAt)
		}
		return deadline, nil
	}
	return spec, nil
}

// Watch refreshes owned routes before expiry with jitter. Failed refresh never
// extends a lease. Canceling the watch releases bindings not retained by Ensure
// or another watch; Close cancels all watches and releases every owned lease.
func (c *Controller) Watch(ctx context.Context, request Request) error {
	if c == nil {
		return ErrInvalid
	}
	key, err := requestKey(request)
	if err != nil {
		return err
	}
	if err = c.lock(ctx); err != nil {
		return err
	}
	c.watchers[key]++
	c.unlock()
	defer c.removeWatcher(key)
	first := true
	for {
		if err = c.lock(ctx); err != nil {
			return err
		}
		op, stop := c.operationContext(ctx)
		err = c.ensureLocked(op, request, key, true)
		canceled := op.Err()
		stop()
		delay := c.refreshDelayLocked(key, err != nil)
		c.unlock()
		if canceled != nil {
			return canceled
		}
		if err != nil && first {
			return err
		}
		first = false
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-c.ctx.Done():
			timer.Stop()
			return context.Canceled
		}
	}
}
func (c *Controller) refreshDelayLocked(key bindingKey, failed bool) time.Duration {
	var expiry time.Time
	for _, owned := range c.owned {
		if _, ok := owned.bindings[key]; ok {
			expiry = earlier(expiry, owned.lease.ExpiresAt())
		}
	}
	if expiry.IsZero() {
		return time.Second
	}
	remaining := expiry.Sub(c.discoverer.cfg.Now())
	if remaining <= 0 {
		return 100 * time.Millisecond
	}
	c.discoverer.randomMu.Lock()
	jitter := c.discoverer.cfg.RandIntn(21)
	c.discoverer.randomMu.Unlock()
	if jitter < 0 || jitter > 20 {
		jitter = 10
	}
	factor := 60 + jitter
	if failed {
		factor = 20
	}
	delay := remaining / 100 * time.Duration(factor)
	if delay < time.Millisecond {
		delay = time.Millisecond
	}
	return delay
}
func (c *Controller) removeWatcher(key bindingKey) {
	<-c.gate
	defer c.unlock()
	if c.closed {
		return
	}
	c.watchers[key]--
	if c.watchers[key] <= 0 {
		delete(c.watchers, key)
		if !c.persistent[key] {
			c.removeBindingLocked(key)
		}
	}
}
func (c *Controller) removeBindingLocked(key bindingKey) {
	for host := range c.owned {
		c.removeHostBindingLocked(host, key)
	}
}
func (c *Controller) removeHostBindingLocked(host string, key bindingKey) {
	owned := c.owned[host]
	if owned == nil {
		return
	}
	if _, ok := owned.bindings[key]; !ok {
		return
	}
	delete(owned.bindings, key)
	if len(owned.bindings) == 0 {
		delete(c.owned, host)
		c.retireLease(owned.lease)
		return
	}
	spec, err := aggregateBindings(owned.bindings)
	if err == nil {
		err = owned.lease.Refresh(c.ctx, spec)
	}
	if err != nil {
		delete(c.owned, host)
		c.retireLease(owned.lease)
		return
	}
	owned.spec = spec
}

// Revoke synchronously, then join bounded shutdown independently of a caller's
// canceled context. Close serializes admission before waiting for these workers.
func (c *Controller) retireLease(lease *peer.Lease) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = lease.Release(ctx)
	c.retired.Add(1)
	go func() { defer c.retired.Done(); _ = lease.Release(context.Background()) }()
}

// Close cancels in-flight work and joins all owned lease shutdowns. A canceled
// waiting context does not cancel cleanup; another Close can wait for completion.
func (c *Controller) Close(ctx context.Context) error {
	if c == nil {
		return nil
	}
	if ctx == nil {
		return ErrInvalid
	}
	c.closeOnce.Do(func() {
		c.cancel()
		go func() {
			<-c.gate
			c.closed = true
			for host, owned := range c.owned {
				delete(c.owned, host)
				c.retireLease(owned.lease)
			}
			c.unlock()
			c.retired.Wait()
			close(c.done)
		}()
	})
	select {
	case <-c.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
