package peer

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/sm"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

var (
	ErrManagerNotRunning  = errors.New("peer: manager is not running")
	ErrLeaseExpired       = errors.New("peer: discovery lease expired or released")
	ErrDiscoveryOwned     = errors.New("peer: host already has an owner")
	ErrDiscoveryChanged   = errors.New("peer: changed endpoint configuration requires a replacement lease")
	ErrDiscoveryAdmission = errors.New("peer: discovered peer admission failed")
)

// Discovery authorizes a peer until ExpiresAt. Validate must establish the
// discovered peer's role and naming authority (RFC 6733 §§5.2, 13.1). It runs
// before CER admission and CEA acceptance, and again on every Refresh. Metadata
// is a private copy. A nonzero returned deadline further limits authorization.
// Validate must return promptly and must not call blocking Manager/Lease methods.
type Discovery struct {
	Peer           PeerConfig
	Realm          datatype.DiameterIdentity
	ApplicationIDs []uint32
	// RouteOrder ranks this peer for each application within Realm. Lower
	// values are tried first; omitted entries are zero. Equal ranks use
	// ASCII-normalized host identity as a stable tie-break. Refresh updates
	// the ranking without replacing an unchanged admitted connection.
	RouteOrder map[uint32]uint64
	ExpiresAt  time.Time
	Validate   func(diam.Conn, *smpeer.Metadata) (time.Time, error)
	// AllowRealm optionally authorizes an actual realm differing from Realm.
	// Nil requires exact ASCII case-insensitive equality. Routes retain Realm.
	AllowRealm func(expected, actual datatype.DiameterIdentity) bool
	tlsSources []*tls.Config
}

// Lease owns one discovered peer. Its capability cannot operate on a subsequent
// acquisition of the same host. Release is idempotent.
type Lease struct{ a *actor }
type discoveryState struct {
	spec    Discovery
	expires time.Time
	revoked bool
}
type discoveryCommand struct {
	ctx    context.Context
	spec   Discovery
	result chan error
}
type discoveryReady struct {
	once sync.Once
	done chan struct{}
	err  error
}
type dynamicRoute struct {
	actor   *actor
	order   uint64
	expires time.Time
}

func (m *Manager) cloneDiscovery(spec Discovery) (Discovery, error) {
	if spec.ExpiresAt.IsZero() || !m.cfg.Now().Before(spec.ExpiresAt) {
		return Discovery{}, ErrLeaseExpired
	}
	if !asciiIdentity(spec.Peer.Host) || !asciiIdentity(spec.Realm) || len(spec.Peer.Host) == 0 || identity(spec.Peer.Host) == identity(m.cfg.Settings.OriginHost) || len(spec.Realm) == 0 || strings.ContainsAny(string(spec.Realm), "* ") || len(spec.ApplicationIDs) == 0 || spec.Validate == nil {
		return Discovery{}, fmt.Errorf("%w: ASCII host and realm, applications and validator are required", ErrDiscoveryAdmission)
	}
	spec.ApplicationIDs = append([]uint32(nil), spec.ApplicationIDs...)
	spec.RouteOrder = maps.Clone(spec.RouteOrder)
	spec.Peer.Endpoints = append([]Endpoint(nil), spec.Peer.Endpoints...)
	spec.tlsSources = make([]*tls.Config, len(spec.Peer.Endpoints))
	for i, e := range spec.Peer.Endpoints {
		spec.tlsSources[i] = e.TLSConfig
		switch e.Network {
		case "", "tcp", "tcp4", "tcp6", "sctp", "sctp4", "sctp6":
		default:
			return Discovery{}, fmt.Errorf("peer: unsupported network %q", e.Network)
		}
		if e.Address == "" {
			return Discovery{}, errors.New("peer: empty endpoint address")
		}
		if e.TLSConfig != nil {
			if strings.HasPrefix(e.Network, "sctp") {
				return Discovery{}, errors.New("peer: TLS/SCTP is unsupported")
			}
			spec.Peer.Endpoints[i].TLSConfig = e.TLSConfig.Clone()
		}
	}
	return spec, nil
}

// AcquireDiscovered waits for a validated, watchdog-eligible connection. Its
// acknowledgement is independent of the bounded observational event queue.
func (m *Manager) AcquireDiscovered(ctx context.Context, spec Discovery) (*Lease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	spec, err := m.cloneDiscovery(spec)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	if !m.started || m.closing || m.runCtx.Err() != nil {
		m.mu.Unlock()
		return nil, ErrManagerNotRunning
	}
	key := identity(spec.Peer.Host)
	if m.peers[key] != nil {
		m.mu.Unlock()
		return nil, ErrDiscoveryOwned
	}
	a := &actor{m: m, cfg: spec.Peer, events: make(chan event, m.cfg.Limits.Events), done: make(chan struct{}), state: Closed, ready: &discoveryReady{done: make(chan struct{})}, leaseStop: make(chan struct{})}
	a.discovery.Store(&discoveryState{spec: spec, expires: spec.ExpiresAt})
	a.publish(nil)
	m.peers[key] = a
	m.wg.Add(1)
	m.mu.Unlock()
	go a.run()
	a.post(event{kind: discoveryStart})
	lease := &Lease{a: a}
	select {
	case <-a.ready.done:
		if err := ctx.Err(); err != nil {
			a.revokeDiscovery()
			return nil, err
		}
		if a.ready.err != nil {
			a.revokeDiscovery()
			return nil, a.ready.err
		}
		if !a.leaseLive() {
			a.revokeDiscovery()
			return nil, ErrLeaseExpired
		}
		return lease, nil
	case <-a.done:
		a.revokeDiscovery()
		return nil, ErrLeaseExpired
	case <-ctx.Done():
		a.revokeDiscovery()
		return nil, ctx.Err()
	}
}

// ExpiresAt returns the effective deadline after policy and certificate caps.
func (l *Lease) ExpiresAt() time.Time {
	if l == nil || l.a == nil {
		return time.Time{}
	}
	return l.a.discovery.Load().expires
}

// Release immediately revokes routing and waits for bounded peer shutdown.
// Context cancellation stops waiting; revocation and shutdown continue.
func (l *Lease) Release(ctx context.Context) error {
	if l == nil || l.a == nil {
		return nil
	}
	l.a.revokeDiscovery()
	select {
	case <-l.a.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Refresh revalidates the active connection before changing authorization.
// A failed refresh preserves the previous deadline; an expired lease cannot
// be revived. Endpoint changes, including a different TLSConfig source pointer,
// return ErrDiscoveryChanged: release this lease and acquire a replacement.
// Reuse immutable TLSConfig pointers to retain an unchanged TLS connection.
func (l *Lease) Refresh(ctx context.Context, spec Discovery) error {
	if l == nil || l.a == nil {
		return ErrLeaseExpired
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	spec, err := l.a.m.cloneDiscovery(spec)
	if err != nil {
		return err
	}
	if !l.a.leaseLive() {
		return ErrLeaseExpired
	}
	cmd := &discoveryCommand{ctx: ctx, spec: spec, result: make(chan error, 1)}
	select {
	case l.a.events <- event{kind: discoveryRefresh, discovery: cmd}:
	case <-l.a.done:
		return ErrLeaseExpired
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-cmd.result:
		return err
	case <-l.a.done:
		return ErrLeaseExpired
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (a *actor) leaseLive() bool {
	d := a.discovery.Load()
	return d == nil || !d.revoked && a.m.cfg.Now().Before(d.expires)
}

// RFC 6733 §4.3.1 requires ASCII Diameter identities, including A-labels for
// internationalized names. Check original bytes before accepting lease scope.
func asciiIdentity(id datatype.DiameterIdentity) bool {
	for i := 0; i < len(id); i++ {
		if id[i] >= 0x80 {
			return false
		}
	}
	return true
}
func (a *actor) discoveryMessageIdentities(msg *diam.Message) bool {
	if a == nil {
		return false
	}
	if a.discovery.Load() == nil {
		return true
	}
	for _, field := range msg.AVP {
		if field == nil || field.VendorID != 0 || field.Code != avp.DestinationRealm && field.Code != avp.DestinationHost {
			continue
		}
		id, ok := field.Data.(datatype.DiameterIdentity)
		if !ok || !asciiIdentity(id) {
			return false
		}
	}
	return true
}

// Realm delegation authorizes the peer's advertised identity; it does not widen
// the requested destination realm authorized by this lease.
func (a *actor) discoveryRealm(realm string) bool {
	if a == nil {
		return false
	}
	d := a.discovery.Load()
	return d == nil || asciiIdentity(datatype.DiameterIdentity(realm)) && (realm == "" || identity(d.spec.Realm) == identity(datatype.DiameterIdentity(realm)))
}
func (a *actor) discoveryAllows(app uint32) bool {
	d := a.discovery.Load()
	if d == nil {
		return true
	}
	for _, id := range d.spec.ApplicationIDs {
		if id == app {
			return true
		}
	}
	return false
}
func (a *actor) signalReady(err error) {
	if a.ready != nil {
		a.ready.once.Do(func() { a.ready.err = err; close(a.ready.done) })
	}
}

// revokeDiscovery removes only this ownership generation. The actor remains
// tracked until shutdown has joined all its dial and session workers.
func (a *actor) revokeDiscovery() {
	m := a.m
	m.mu.Lock()
	d := a.discovery.Load()
	if d == nil || d.revoked {
		m.mu.Unlock()
		return
	}
	next := *d
	next.revoked = true
	a.discovery.Store(&next)
	if m.peers[identity(a.cfg.Host)] == a {
		delete(m.peers, identity(a.cfg.Host))
		m.retiredActors = append(m.retiredActors, a)
	}
	m.removeDiscoveryRoutes(a)
	m.mu.Unlock()
	if a.leaseStop != nil {
		close(a.leaseStop)
	}
}

// removeDiscoveryRoutes requires m.mu and leaves other ownership generations
// and their relative order intact.
func (m *Manager) removeDiscoveryRoutes(a *actor) {
	for key, routes := range m.dynamicRoutes {
		routes = slices.DeleteFunc(routes, func(r dynamicRoute) bool { return r.actor == a })
		if len(routes) == 0 {
			delete(m.dynamicRoutes, key)
		} else {
			m.dynamicRoutes[key] = routes
		}
	}
}

func (a *actor) armDiscovery() {
	if a.leaseTimer != nil {
		a.leaseTimer.Stop()
	}
	d := a.discovery.Load()
	a.leaseTimer = a.m.cfg.Clock.AfterFunc(d.expires.Sub(a.m.cfg.Now()), func() { a.post(event{kind: discoveryExpire, leaseState: d}) })
}
func (a *actor) publishDiscoveryRoutes() {
	d := a.discovery.Load()
	if d == nil {
		return
	}
	a.m.mu.Lock()
	defer a.m.mu.Unlock()
	if a.m.peers[identity(a.cfg.Host)] != a || !a.leaseLive() {
		return
	}
	a.m.removeDiscoveryRoutes(a)
	for _, app := range d.spec.ApplicationIDs {
		key := routeKey{identity(d.spec.Realm), app}
		routes := a.m.dynamicRoutes[key]
		if slices.ContainsFunc(routes, func(r dynamicRoute) bool { return r.actor == a }) {
			continue
		}
		// Preserve the discovery selection order (RFC 2782 Priority/Weight;
		// RFC 3958 §2.2.4, verified Errata 8532) through route publication.
		routes = append(routes, dynamicRoute{actor: a, order: d.spec.RouteOrder[app], expires: d.expires})
		slices.SortFunc(routes, func(a, b dynamicRoute) int {
			if order := cmp.Compare(a.order, b.order); order != 0 {
				return order
			}
			return cmp.Compare(identity(a.actor.cfg.Host), identity(b.actor.cfg.Host))
		})
		a.m.dynamicRoutes[key] = routes
	}
}
func (a *actor) validateDiscovery(spec Discovery, c diam.Conn, meta *smpeer.Metadata) (time.Time, error) {
	if !a.m.cfg.Now().Before(spec.ExpiresAt) {
		return time.Time{}, ErrLeaseExpired
	}
	if meta == nil || !asciiIdentity(meta.OriginHost) || !asciiIdentity(meta.OriginRealm) || compareIdentity(meta.OriginHost, spec.Peer.Host) != 0 {
		return time.Time{}, fmt.Errorf("%w: unexpected Origin-Host", ErrDiscoveryAdmission)
	}
	if compareIdentity(meta.OriginRealm, spec.Realm) != 0 && (spec.AllowRealm == nil || !spec.AllowRealm(spec.Realm, meta.OriginRealm)) {
		return time.Time{}, fmt.Errorf("%w: unexpected Origin-Host or Origin-Realm", ErrDiscoveryAdmission)
	}
	for _, app := range spec.ApplicationIDs {
		found := false
		for _, remote := range meta.Applications {
			if remote == app || remote == 0xffffffff {
				found = true
				break
			}
		}
		if !found || !a.m.supportsApplication(app) {
			return time.Time{}, fmt.Errorf("%w: application %d", ErrDiscoveryAdmission, app)
		}
	}
	expires := spec.ExpiresAt
	capAt, err := spec.Validate(c, meta.Clone())
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %w", ErrDiscoveryAdmission, err)
	}
	if !capAt.IsZero() && capAt.Before(expires) {
		expires = capAt
	}
	if state := c.TLS(); state != nil {
		if len(state.VerifiedChains) == 0 {
			return time.Time{}, fmt.Errorf("%w: TLS chain is unverified", ErrDiscoveryAdmission)
		}
		for _, chain := range state.VerifiedChains {
			for _, cert := range chain {
				if cert.NotAfter.Before(expires) {
					expires = cert.NotAfter
				}
			}
		}
	}
	if !a.m.cfg.Now().Before(expires) {
		return time.Time{}, ErrLeaseExpired
	}
	return expires, nil
}
func (a *actor) admitDiscovery(s *session, meta *smpeer.Metadata) error {
	d := a.discovery.Load()
	if d == nil {
		return nil
	}
	if !a.leaseLive() {
		return ErrLeaseExpired
	}
	expires, err := a.validateDiscovery(d.spec, s.c, meta)
	if err != nil {
		return err
	}
	// Handshake revalidation may shorten but never prolong an existing lease.
	if d.expires.Before(expires) {
		expires = d.expires
	}
	next := *d
	next.expires = expires
	a.m.mu.Lock()
	swapped := a.discovery.CompareAndSwap(d, &next)
	a.m.mu.Unlock()
	if !swapped {
		return ErrLeaseExpired
	}
	a.armDiscovery()
	return nil
}
func (a *actor) handleDiscovery(e event) bool {
	switch e.kind {
	case discoveryStart:
		if !a.leaseLive() {
			a.revokeDiscovery()
			return true
		}
		a.armDiscovery()
		if len(a.cfg.Endpoints) > 0 {
			a.handle(event{kind: start})
		}
		return true
	case discoveryStop:
		if a.leaseTimer != nil {
			a.leaseTimer.Stop()
		}
		a.signalReady(ErrLeaseExpired)
		a.stop(sm.DisconnectDoNotWantToTalkToYou)
		return true
	case discoveryExpire:
		if a.discovery.Load() == e.leaseState && !a.leaseLive() {
			a.revokeDiscovery()
		}
		return true
	case discoveryRefresh:
		if err := e.discovery.ctx.Err(); err != nil {
			e.discovery.result <- err
		} else {
			e.discovery.result <- a.refreshDiscovery(e.discovery.ctx, e.discovery.spec)
		}
		return true
	default:
		return false
	}
}
func (a *actor) refreshDiscovery(ctx context.Context, spec Discovery) error {
	d := a.discovery.Load()
	if !a.leaseLive() || a.ownStop || a.m.isClosing() {
		return ErrLeaseExpired
	}
	if !sameDiscoveryPeer(spec, d.spec) {
		return ErrDiscoveryChanged
	}
	s := a.active
	if s == nil || s.meta == nil || s.isRetired() {
		return fmt.Errorf("%w: no admitted connection", ErrDiscoveryAdmission)
	}
	expires, err := a.validateDiscovery(spec, s.c, s.meta)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	next := &discoveryState{spec: spec, expires: expires}
	a.m.mu.Lock()
	if !a.leaseLive() || !a.discovery.CompareAndSwap(d, next) {
		a.m.mu.Unlock()
		return ErrLeaseExpired
	}
	a.m.mu.Unlock()
	a.armDiscovery()
	a.publish(nil)
	return nil
}

// HasRoute reports current eligibility, including lease expiry independently of
// timer delivery. Static route replacement never replaces the dynamic partition.
func (m *Manager) HasRoute(realm datatype.DiameterIdentity, app uint32) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closing {
		return false
	}
	key := routeKey{identity(realm), app}
	for _, host := range m.routes.Load().entries[key] {
		if a := m.peers[host]; a.discoveryRealm(string(realm)) && m.usable(a, app) != nil {
			return true
		}
	}
	for _, r := range m.dynamicRoutes[key] {
		a := r.actor
		if a.discoveryRealm(string(realm)) && m.cfg.Now().Before(r.expires) && m.usable(a, app) != nil {
			return true
		}
	}
	return false
}

// TLS configurations are immutable once used, as required by crypto/tls.
// Retain source identity while dialing a clone, including configurations with
// function hooks that reflect.DeepEqual cannot compare.
func sameDiscoveryPeer(a, b Discovery) bool {
	if compareIdentity(a.Peer.Host, b.Peer.Host) != 0 || a.Peer.NoAutoReconnect != b.Peer.NoAutoReconnect || len(a.Peer.Endpoints) != len(b.Peer.Endpoints) {
		return false
	}
	for i, e := range a.Peer.Endpoints {
		old := b.Peer.Endpoints[i]
		if e.Network != old.Network || e.Address != old.Address || a.tlsSources[i] != b.tlsSources[i] {
			return false
		}
	}
	return true
}

func (m *Manager) forgetRetiredActor(a *actor) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, retired := range m.retiredActors {
		if retired == a {
			m.retiredActors[i] = m.retiredActors[len(m.retiredActors)-1]
			m.retiredActors[len(m.retiredActors)-1] = nil
			m.retiredActors = m.retiredActors[:len(m.retiredActors)-1]
			return
		}
	}
}

// Fence attachment before scanning: newSession checks the fence under Manager.mu,
// and bind checks it under the session binding lock. Any earlier attachment is
// visible to this scan, including sessions not yet assigned to the actor's legs.
func (a *actor) closeOwnedSessions() {
	a.retiring.Store(true)
	a.m.mu.RLock()
	sessions := make([]*session, 0, len(a.m.sessions))
	for _, s := range a.m.sessions {
		sessions = append(sessions, s)
	}
	a.m.mu.RUnlock()
	for _, s := range sessions {
		owner, _ := s.binding()
		if owner == a {
			// A committed rejection still gets its bounded opportunity to reach
			// the wire before this actor retires its unattached sessions.
			if s.terminal.Load() {
				timer := time.NewTimer(a.m.cfg.Timers.Closing)
				select {
				case <-s.closed:
				case <-timer.C:
				}
				timer.Stop()
			}
			s.close()
		}
	}
	for {
		select {
		case e := <-a.events:
			if e.s != nil {
				e.s.close()
				if e.kind == coreEvent && e.input.Kind == protocol.WriteResult {
					e.s.terminalProtocol(e.input)
				}
			}
			if e.delivery != nil {
				e.delivery.finish()
			}
			if e.discovery != nil {
				e.discovery.result <- ErrLeaseExpired
			}
		default:
			return
		}
	}
}
