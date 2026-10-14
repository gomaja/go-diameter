package dnsdiam

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/peer"
	"github.com/gomaja/go-diameter/diam/sm"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

func TestControllerRejectsMissingDependencies(t *testing.T) {
	if _, err := NewController(nil, nil, Policy{}); err == nil {
		t.Fatal("controller accepted missing discoverer, manager and authorization")
	}
}

type controllerTarget struct {
	host string
	port uint16
}
type controllerResolver struct {
	mu      sync.Mutex
	targets []controllerTarget
	ttl     uint32
	proof   string
	failure error
	absent  bool
	now     func() time.Time
	queries atomic.Int32
}

func (r *controllerResolver) Lookup(ctx context.Context, name string, typ RRType) (Answer, error) {
	if err := ctx.Err(); err != nil {
		return Answer{}, err
	}
	r.queries.Add(1)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failure != nil {
		return Answer{}, r.failure
	}
	if r.absent {
		return Answer{RCode: RCodeNameError}, nil
	}
	a := Answer{ReceivedAt: r.now()}
	switch typ {
	case TypeNAPTR:
		replacement := r.proof
		if replacement == "" {
			replacement = "_diameter._tcp." + name
		}
		a.Records = []Record{nap(name, "aaa:diameter.tcp", "s", replacement, r.ttl)}
	case TypeSRV:
		if strings.HasPrefix(name, "_diameter._tcp.") {
			for _, target := range r.targets {
				a.Records = append(a.Records, srv(name, target.host+".", target.port, 0, 1, r.ttl))
			}
		}
	case TypeA:
		a.Records = []Record{{Name: name, Type: TypeA, TTL: r.ttl, Address: netip.MustParseAddr("127.0.0.1")}}
	}
	return a, nil
}
func controllerSettings(host, realm string) sm.Settings {
	settings := fixtureSettings(host, realm)
	settings.AuthApplicationID = append(settings.AuthApplicationID, diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(1)))
	return settings
}
func controllerPeer(t *testing.T, host, realm string) controllerTarget {
	t.Helper()
	// Connection-local admission keeps this fixture independent of a remote
	// Manager's host-level Closing state during deliberate lease replacement.
	settings := controllerSettings(host, realm)
	machine, err := sm.New(&settings)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &diam.Server{Handler: machine, WriteTimeout: 50 * time.Millisecond}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); <-done })
	return controllerTarget{host, uint16(listener.Addr().(*net.TCPAddr).Port)}
}
func controllerManager(t *testing.T, now func() time.Time, configured []peer.PeerConfig, routes []peer.Route) *peer.Manager {
	t.Helper()
	m, err := peer.New(peer.Config{Settings: controllerSettings("local.example.net", "local.example"), Now: now, Timers: peer.Timers{Closing: 50 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	for _, config := range configured {
		if err = m.AddPeer(config); err != nil {
			t.Fatal(err)
		}
	}
	if err = m.SetRoutes(routes); err != nil {
		t.Fatal(err)
	}
	if err = m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := m.Close(ctx, sm.DisconnectRebooting); err != nil {
			t.Error(err)
		}
	})
	return m
}
func controllerFixture(t *testing.T, m *peer.Manager, r *controllerResolver, authorize func(Candidate, diam.Conn, *smpeer.Metadata) error) *Controller {
	t.Helper()
	if authorize == nil {
		authorize = func(Candidate, diam.Conn, *smpeer.Metadata) error { return nil }
	}
	d, err := New(Config{Resolver: r, Now: r.now, RandIntn: func(int) int { return 0 }})
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewController(d, m, Policy{AllowPlaintext: true, Authorize: authorize})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := c.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return c
}
func controllerAwait(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !predicate() {
		if time.Now().After(deadline) {
			t.Fatal("controller condition did not become true")
		}
		time.Sleep(time.Millisecond)
	}
}
func controllerRefresh(t *testing.T, c *Controller, app uint32) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	return c.ensureLocked(ctx, Request{Realm: "example.net", ApplicationID: app, Transports: []Transport{TCP}}, bindingKey{"example.net", app}, true)
}
func TestControllerStaticRoutePrecedesDNS(t *testing.T) {
	target := controllerPeer(t, "manual.example.net", "example.net")
	m := controllerManager(t, time.Now, []peer.PeerConfig{{Host: datatype.DiameterIdentity(target.host), Endpoints: []peer.Endpoint{{Network: "tcp", Address: net.JoinHostPort("127.0.0.1", strconv.Itoa(int(target.port)))}}}}, []peer.Route{{Realm: "example.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{datatype.DiameterIdentity(target.host)}}})
	controllerAwait(t, func() bool { return m.HasRoute("example.net", 4) })
	r := &controllerResolver{ttl: 60, now: time.Now, failure: errors.New("DNS must not be queried")}
	c := controllerFixture(t, m, r, nil)
	if err := c.Ensure(context.Background(), "EXAMPLE.NET.", 4); err != nil {
		t.Fatal(err)
	}
	if r.queries.Load() != 0 {
		t.Fatal("eligible configured route triggered DNS")
	}
	if len(c.owned) != 0 {
		t.Fatal("controller claimed static ownership")
	}
}
func TestControllerAcquiresTwoPeersAndPreservesConnectionOnRefresh(t *testing.T) {
	first := controllerPeer(t, "a.example.net", "example.net")
	second := controllerPeer(t, "b.example.net", "example.net")
	m := controllerManager(t, time.Now, nil, nil)
	r := &controllerResolver{targets: []controllerTarget{first, second}, ttl: 60, now: time.Now}
	c := controllerFixture(t, m, r, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.Ensure(ctx, "example.net", 4); err != nil {
		t.Fatal(err)
	}
	if len(c.owned) != 2 || len(m.Peers()) != 2 {
		t.Fatalf("owned=%d peers=%d", len(c.owned), len(m.Peers()))
	}
	old := c.owned[first.host].lease
	expiry := old.ExpiresAt()
	if err := controllerRefresh(t, c, 4); err != nil {
		t.Fatal(err)
	}
	if c.owned[first.host].lease != old || !old.ExpiresAt().After(expiry) {
		t.Fatal("unchanged peer was replaced or deadline not refreshed")
	}
	before := r.queries.Load()
	if err := c.Ensure(ctx, "example.net", 4); err != nil {
		t.Fatal(err)
	}
	if r.queries.Load() != before {
		t.Fatal("Ensure rediscovered an eligible owned route")
	}
	if err := c.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if m.HasRoute("example.net", 4) {
		t.Fatal("controller Close retained routes")
	}
}
func TestControllerGroupsApplicationsAtEarliestDeadline(t *testing.T) {
	target := controllerPeer(t, "shared.example.net", "example.net")
	now := time.Now()
	clock := func() time.Time { return now }
	m := controllerManager(t, clock, nil, nil)
	r := &controllerResolver{targets: []controllerTarget{target}, ttl: 60, now: clock}
	var mu sync.Mutex
	validations := make(map[uint32]int)
	c := controllerFixture(t, m, r, func(candidate Candidate, _ diam.Conn, _ *smpeer.Metadata) error {
		mu.Lock()
		defer mu.Unlock()
		validations[candidate.ApplicationID]++
		return nil
	})
	if err := c.Ensure(context.Background(), "example.net", 4); err != nil {
		t.Fatal(err)
	}
	old := c.owned[target.host].lease
	r.mu.Lock()
	r.ttl = 30
	r.mu.Unlock()
	if err := c.Ensure(context.Background(), "example.net", 1); err != nil {
		t.Fatal(err)
	}
	if len(c.owned) != 1 || c.owned[target.host].lease != old {
		t.Fatal("shared host was duplicated or replaced")
	}
	if !m.HasRoute("example.net", 4) || !m.HasRoute("example.net", 1) {
		t.Fatal("shared applications lack routes")
	}
	if !old.ExpiresAt().Equal(now.Add(30 * time.Second)) {
		t.Fatalf("common deadline=%v", old.ExpiresAt())
	}
	if !c.owned[target.host].spec.ExpiresAt.Equal(now.Add(30 * time.Second)) {
		t.Fatal("aggregate acquisition request exceeds a contributing binding deadline")
	}
	r.mu.Lock()
	r.ttl = 120
	r.mu.Unlock()
	if err := controllerRefresh(t, c, 1); err != nil {
		t.Fatal(err)
	}
	if !old.ExpiresAt().Equal(now.Add(time.Minute)) {
		t.Fatal("one refreshed binding prolonged another binding")
	}
	mu.Lock()
	defer mu.Unlock()
	if validations[4] < 3 || validations[1] < 2 {
		t.Fatalf("not every binding revalidated: %v", validations)
	}
}
func TestControllerFailedRefreshAndZeroTTL(t *testing.T) {
	target := controllerPeer(t, "a.example.net", "example.net")
	m := controllerManager(t, time.Now, nil, nil)
	r := &controllerResolver{targets: []controllerTarget{target}, ttl: 60, now: time.Now}
	c := controllerFixture(t, m, r, nil)
	if err := c.Ensure(context.Background(), "example.net", 4); err != nil {
		t.Fatal(err)
	}
	lease := c.owned[target.host].lease
	before := lease.ExpiresAt()
	r.mu.Lock()
	r.failure = errors.New("resolver unavailable")
	r.mu.Unlock()
	if err := controllerRefresh(t, c, 4); !errors.Is(err, ErrDNS) {
		t.Fatalf("refresh failure=%v", err)
	}
	if !lease.ExpiresAt().Equal(before) {
		t.Fatal("failed refresh extended deadline")
	}
	if !m.HasRoute("example.net", 4) {
		t.Fatal("transient DNS failure revoked live authorization")
	}

	r.mu.Lock()
	r.failure = nil
	r.ttl = 0
	r.mu.Unlock()
	if err := controllerRefresh(t, c, 4); !errors.Is(err, ErrExpired) {
		t.Fatalf("zero TTL refresh=%v", err)
	}
	if !lease.ExpiresAt().Equal(before) {
		t.Fatal("zero TTL refreshed old lease")
	}
	if m.HasRoute("example.net", 4) {
		t.Fatal("fresh zero TTL retained old managed route")
	}

	if err := c.Ensure(context.Background(), "example.net", 1); !errors.Is(err, ErrExpired) {
		t.Fatalf("zero TTL acquisition=%v", err)
	}
	if m.HasRoute("example.net", 1) {
		t.Fatal("zero TTL installed a route")
	}
}
func TestControllerChangedEndpointReplacesLease(t *testing.T) {
	first := controllerPeer(t, "same.example.net", "example.net")
	replacement := controllerPeer(t, "same.example.net", "example.net")
	m := controllerManager(t, time.Now, nil, nil)
	r := &controllerResolver{targets: []controllerTarget{first}, ttl: 60, now: time.Now}
	c := controllerFixture(t, m, r, nil)
	if err := c.Ensure(context.Background(), "example.net", 4); err != nil {
		t.Fatal(err)
	}
	old := c.owned[first.host].lease
	r.mu.Lock()
	r.targets = []controllerTarget{replacement}
	r.mu.Unlock()
	if err := controllerRefresh(t, c, 4); err != nil {
		t.Fatal(err)
	}
	if c.owned[first.host].lease == old {
		t.Fatal("changed endpoint retained old lease")
	}
	if !m.HasRoute("example.net", 4) {
		t.Fatal("replacement route unavailable")
	}
}
func TestControllerWatchCancellationReleasesBinding(t *testing.T) {
	target := controllerPeer(t, "watch.example.net", "example.net")
	m := controllerManager(t, time.Now, nil, nil)
	r := &controllerResolver{targets: []controllerTarget{target}, ttl: 60, now: time.Now}
	c := controllerFixture(t, m, r, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- c.Watch(ctx, Request{Realm: "example.net", ApplicationID: 4, Transports: []Transport{TCP}})
	}()
	controllerAwait(t, func() bool { return m.HasRoute("example.net", 4) })
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Watch cancellation=%v", err)
	}
	if m.HasRoute("example.net", 4) {
		t.Fatal("canceled watch retained binding")
	}
}
func TestControllerDoesNotStealStaticHost(t *testing.T) {
	target := controllerPeer(t, "manual.example.net", "example.net")
	m := controllerManager(t, time.Now, []peer.PeerConfig{{Host: datatype.DiameterIdentity(target.host)}}, nil)
	r := &controllerResolver{targets: []controllerTarget{target}, ttl: 60, now: time.Now}
	c := controllerFixture(t, m, r, nil)
	if err := c.Ensure(context.Background(), "example.net", 4); !errors.Is(err, peer.ErrDiscoveryOwned) {
		t.Fatalf("static ownership=%v", err)
	}
	if len(m.Peers()) != 1 || m.Peers()[0].Dynamic {
		t.Fatal("static peer was replaced")
	}
}
func TestControllerDTLSOnlyWatchRejectedWithoutDNS(t *testing.T) {
	m := controllerManager(t, time.Now, nil, nil)
	r := &controllerResolver{ttl: 60, now: time.Now}
	c := controllerFixture(t, m, r, nil)
	if err := c.Watch(context.Background(), Request{Realm: "example.net", ApplicationID: 4, Transports: []Transport{DTLS}}); !errors.Is(err, ErrUnsupportedTransport) {
		t.Fatal(err)
	}
	if r.queries.Load() != 0 {
		t.Fatal("unsupported transport queried DNS")
	}
}

func TestControllerDifferentRealmsCannotShareIdentity(t *testing.T) {
	target := controllerPeer(t, "shared.example.net", "example.net")
	m := controllerManager(t, time.Now, nil, nil)
	r := &controllerResolver{targets: []controllerTarget{target}, ttl: 60, now: time.Now}
	c := controllerFixture(t, m, r, nil)
	c.discoverer.cfg.AllowDelegation = func(string, string) bool { return true }
	c.policy.AllowRealm = func(string, string) bool { return true }
	if err := c.Ensure(context.Background(), "example.net", 4); err != nil {
		t.Fatal(err)
	}
	old := c.owned[target.host].lease
	if err := c.Ensure(context.Background(), "other.example", 4); !errors.Is(err, peer.ErrDiscoveryOwned) {
		t.Fatalf("conflicting realm=%v", err)
	}
	if c.owned[target.host].lease != old || !m.HasRoute("example.net", 4) || m.HasRoute("other.example", 4) {
		t.Fatal("conflicting realm changed existing authorization")
	}
}
func TestControllerRefreshJitterUsesClockAndRNG(t *testing.T) {
	target := controllerPeer(t, "clock.example.net", "example.net")
	var nanos atomic.Int64
	nanos.Store(time.Now().UnixNano())
	now := func() time.Time { return time.Unix(0, nanos.Load()) }
	m := controllerManager(t, now, nil, nil)
	r := &controllerResolver{targets: []controllerTarget{target}, ttl: 60, now: now}
	c := controllerFixture(t, m, r, nil)
	if err := c.Ensure(context.Background(), "example.net", 4); err != nil {
		t.Fatal(err)
	}
	calls := 0
	c.discoverer.cfg.RandIntn = func(n int) int {
		if n != 21 {
			t.Fatalf("jitter bound=%d", n)
		}
		calls++
		return 20
	}
	key := bindingKey{"example.net", 4}
	if got := c.refreshDelayLocked(key, false); got != 48*time.Second {
		t.Fatalf("refresh jitter=%v", got)
	}
	if got := c.refreshDelayLocked(key, true); got != 12*time.Second {
		t.Fatalf("failed refresh retry=%v", got)
	}
	if calls != 2 {
		t.Fatalf("jitter RNG calls=%d", calls)
	}
	nanos.Add(int64(time.Minute))
	if got := c.refreshDelayLocked(key, false); got != 100*time.Millisecond {
		t.Fatalf("expired retry=%v", got)
	}
	if m.HasRoute("example.net", 4) {
		t.Fatal("clock-expired route remains available")
	}
}

type controllerBlockingResolver struct {
	entered chan struct{}
	once    sync.Once
}

func (r *controllerBlockingResolver) Lookup(ctx context.Context, _ string, _ RRType) (Answer, error) {
	r.once.Do(func() { close(r.entered) })
	<-ctx.Done()
	return Answer{}, ctx.Err()
}
func TestControllerCloseCancelsInFlightDiscovery(t *testing.T) {
	m := controllerManager(t, time.Now, nil, nil)
	r := &controllerBlockingResolver{entered: make(chan struct{})}
	d, err := New(Config{Resolver: r})
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewController(d, m, Policy{AllowPlaintext: true, Authorize: func(Candidate, diam.Conn, *smpeer.Metadata) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Ensure(context.Background(), "example.net", 4) }()
	<-r.entered
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = c.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("in-flight discovery=%v", err)
	}
	if err = c.Ensure(ctx, "example.net", 4); !errors.Is(err, context.Canceled) {
		t.Fatalf("closed controller accepted work: %v", err)
	}
}
func TestControllerWatchRefreshesBeforeExpiry(t *testing.T) {
	target := controllerPeer(t, "renew.example.net", "example.net")
	m := controllerManager(t, time.Now, nil, nil)
	r := &controllerResolver{targets: []controllerTarget{target}, ttl: 1, now: time.Now}
	c := controllerFixture(t, m, r, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- c.Watch(ctx, Request{Realm: "example.net", ApplicationID: 4, Transports: []Transport{TCP}})
	}()
	controllerAwait(t, func() bool { return m.HasRoute("example.net", 4) })
	initial := m.Peers()[0].ExpiresAt
	for {
		peers := m.Peers()
		if len(peers) > 0 && peers[0].ExpiresAt.After(initial.Add(200*time.Millisecond)) {
			break
		}
		if time.Now().After(initial.Add(-50 * time.Millisecond)) {
			t.Fatal("watch did not refresh before its admission deadline")
		}
		time.Sleep(time.Millisecond)
	}
	if !m.HasRoute("example.net", 4) {
		t.Fatal("watch lost its route during refresh")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestControllerChangedDiscoveryProofReplacesLease(t *testing.T) {
	target := controllerPeer(t, "proof.example.net", "example.net")
	m := controllerManager(t, time.Now, nil, nil)
	r := &controllerResolver{targets: []controllerTarget{target}, ttl: 60, now: time.Now}
	c := controllerFixture(t, m, r, nil)
	if err := c.Ensure(context.Background(), "example.net", 4); err != nil {
		t.Fatal(err)
	}
	old := c.owned[target.host].lease
	r.mu.Lock()
	r.proof = "_diameter._tcp.alternate.example.net."
	r.mu.Unlock()
	if err := controllerRefresh(t, c, 4); err != nil {
		t.Fatal(err)
	}
	if c.owned[target.host].lease == old {
		t.Fatal("changed discovery-name proof retained old lease")
	}
}
func TestControllerRemovesWithdrawnCandidate(t *testing.T) {
	first := controllerPeer(t, "a.example.net", "example.net")
	second := controllerPeer(t, "b.example.net", "example.net")
	m := controllerManager(t, time.Now, nil, nil)
	r := &controllerResolver{targets: []controllerTarget{first, second}, ttl: 60, now: time.Now}
	c := controllerFixture(t, m, r, nil)
	if err := c.Ensure(context.Background(), "example.net", 4); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.targets = []controllerTarget{first}
	r.mu.Unlock()
	if err := controllerRefresh(t, c, 4); err != nil {
		t.Fatal(err)
	}
	if c.owned[second.host] != nil {
		t.Fatal("withdrawn candidate remains owned")
	}
	peers := m.Peers()
	if len(peers) != 1 || string(peers[0].Host) != first.host {
		t.Fatalf("withdrawn peer retained: %+v", peers)
	}
}
func TestControllerWatchRemovalPreservesOtherApplication(t *testing.T) {
	target := controllerPeer(t, "shared.example.net", "example.net")
	m := controllerManager(t, time.Now, nil, nil)
	r := &controllerResolver{targets: []controllerTarget{target}, ttl: 60, now: time.Now}
	c := controllerFixture(t, m, r, nil)
	if err := c.Ensure(context.Background(), "example.net", 4); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- c.Watch(ctx, Request{Realm: "example.net", ApplicationID: 1, Transports: []Transport{TCP}})
	}()
	controllerAwait(t, func() bool { return m.HasRoute("example.net", 1) })
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if !m.HasRoute("example.net", 4) || m.HasRoute("example.net", 1) {
		t.Fatal("watch removal changed unrelated application or retained canceled binding")
	}
}
func TestControllerTriesNextCandidateAfterAdmissionFailure(t *testing.T) {
	denied := controllerPeer(t, "a.example.net", "example.net")
	allowed := controllerPeer(t, "b.example.net", "example.net")
	m := controllerManager(t, time.Now, nil, nil)
	r := &controllerResolver{targets: []controllerTarget{denied, allowed}, ttl: 60, now: time.Now}
	c := controllerFixture(t, m, r, func(candidate Candidate, _ diam.Conn, _ *smpeer.Metadata) error {
		if candidate.Host == denied.host {
			return errors.New("role denied")
		}
		return nil
	})
	if err := c.Ensure(context.Background(), "example.net", 4); err != nil {
		t.Fatal(err)
	}
	if c.owned[denied.host] != nil || c.owned[allowed.host] == nil || !m.HasRoute("example.net", 4) {
		t.Fatal("ordered candidate fallback failed")
	}
}

func TestControllerDefinitiveServiceWithdrawal(t *testing.T) {
	for _, kind := range []string{"empty-srv", "unavailable-target", "negative-naptr-and-fallback"} {
		t.Run(kind, func(t *testing.T) {
			target := controllerPeer(t, "a.example.net", "example.net")
			m := controllerManager(t, time.Now, nil, nil)
			r := &controllerResolver{targets: []controllerTarget{target}, ttl: 60, now: time.Now}
			c := controllerFixture(t, m, r, nil)
			if err := c.Ensure(context.Background(), "example.net", 4); err != nil {
				t.Fatal(err)
			}
			r.mu.Lock()
			switch kind {
			case "empty-srv":
				r.targets = nil
			case "unavailable-target":
				r.targets = []controllerTarget{{host: ""}}
			default:
				r.absent = true
			}
			r.mu.Unlock()
			if err := controllerRefresh(t, c, 4); !errors.Is(err, ErrNoService) {
				t.Fatalf("withdrawal error=%v", err)
			}
			if m.HasRoute("example.net", 4) {
				t.Fatal("definitive DNS withdrawal retained eligible route")
			}
		})
	}
}

func TestControllerDefinitiveAbsenceExcludesUncertainFailures(t *testing.T) {
	if !onlyNoService(errors.Join(ErrNoService, ErrNoService)) {
		t.Fatal("joined absence rejected")
	}
	for _, uncertain := range []error{ErrDNS, ErrLimit, ErrInvalid, ErrUnauthorized, context.Canceled, context.DeadlineExceeded} {
		if onlyNoService(errors.Join(ErrNoService, uncertain)) {
			t.Errorf("uncertain failure withdrew service: %v", uncertain)
		}
	}
}

func TestControllerFreshRoleDenialRevokesAffectedBinding(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(strconv.FormatBool(shared), func(t *testing.T) {
			target := controllerPeer(t, "a.example.net", "example.net")
			m := controllerManager(t, time.Now, nil, nil)
			r := &controllerResolver{targets: []controllerTarget{target}, ttl: 60, now: time.Now}
			var deny atomic.Bool
			c := controllerFixture(t, m, r, func(candidate Candidate, _ diam.Conn, _ *smpeer.Metadata) error {
				if candidate.ApplicationID == 4 && deny.Load() {
					return ErrUnauthorized
				}
				return nil
			})
			if err := c.Ensure(context.Background(), "example.net", 4); err != nil {
				t.Fatal(err)
			}
			if shared {
				if err := c.Ensure(context.Background(), "example.net", 1); err != nil {
					t.Fatal(err)
				}
			}
			deny.Store(true)
			if err := controllerRefresh(t, c, 4); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("denial=%v", err)
			}
			if m.HasRoute("example.net", 4) {
				t.Fatal("fresh role denial retained affected route")
			}
			if shared && !m.HasRoute("example.net", 1) {
				t.Fatal("role denial removed independently authorized application")
			}
		})
	}
}

func TestControllerZeroTTLWithdrawsOnlyAffectedApplication(t *testing.T) {
	target := controllerPeer(t, "a.example.net", "example.net")
	m := controllerManager(t, time.Now, nil, nil)
	r := &controllerResolver{targets: []controllerTarget{target}, ttl: 60, now: time.Now}
	c := controllerFixture(t, m, r, nil)
	for _, app := range []uint32{4, 1} {
		if err := c.Ensure(context.Background(), "example.net", app); err != nil {
			t.Fatal(err)
		}
	}
	r.mu.Lock()
	r.ttl = 0
	r.mu.Unlock()
	if err := controllerRefresh(t, c, 4); !errors.Is(err, ErrExpired) {
		t.Fatalf("zero TTL refresh: %v", err)
	}
	if m.HasRoute("example.net", 4) {
		t.Fatal("zero TTL retained affected application")
	}
	if !m.HasRoute("example.net", 1) {
		t.Fatal("zero TTL removed independently authorized application")
	}
}
