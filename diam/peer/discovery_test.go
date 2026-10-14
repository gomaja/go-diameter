package peer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/sm"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

func TestDiscoveredSnapshotProvenance(t *testing.T) {
	typ := reflect.TypeOf(PeerSnapshot{})
	if _, ok := typ.FieldByName("Dynamic"); !ok {
		t.Fatal("discovered peer snapshots cannot identify dynamic ownership")
	}
	if _, ok := typ.FieldByName("ExpiresAt"); !ok {
		t.Fatal("discovered peer snapshots cannot expose admission deadline")
	}
}

func discoverySpec() Discovery {
	return Discovery{Peer: PeerConfig{Host: "remote.example.net"}, Realm: "example.net", ApplicationIDs: []uint32{4}, ExpiresAt: time.Now().Add(time.Minute), Validate: func(diam.Conn, *smpeer.Metadata) (time.Time, error) { return time.Time{}, nil }}
}
func TestDiscoveryRequiresRunningManager(t *testing.T) {
	m, err := New(Config{Settings: testSettings("local.example.net")})
	if err != nil {
		t.Fatal(err)
	}
	defer closeManager(t, m, nil)
	if _, err = m.AcquireDiscovered(context.Background(), discoverySpec()); !errors.Is(err, ErrManagerNotRunning) {
		t.Fatalf("acquire before Start=%v", err)
	}
}
func TestDiscoveryExpiredSnapshotAndWriter(t *testing.T) {
	m, actors, sessions := outboundTestManager(t)
	now := time.Now()
	m.cfg.Now = func() time.Time { return now }
	spec := discoverySpec()
	spec.Peer = actors[0].cfg
	spec.ExpiresAt = now.Add(time.Second)
	actors[0].discovery.Store(&discoveryState{spec: spec, expires: spec.ExpiresAt})
	actors[0].publish(nil)
	if m.usable(actors[0], 4) == nil {
		t.Fatal("live lease unavailable")
	}
	now = spec.ExpiresAt
	if m.usable(actors[0], 4) != nil {
		t.Fatal("expired peer remains usable without timer delivery")
	}
	if actors[0].snapshot().Eligible {
		t.Fatal("expired snapshot still eligible")
	}
	if err := sessions[0].send(outboundRequest("", "example.net"), false); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("expired writer admission=%v", err)
	}
}

func discoveryPair(t *testing.T, now func() time.Time, clock Clock) (*Manager, Discovery) {
	t.Helper()
	local, spec, _ := discoveryPairWithRemote(t, now, clock)
	return local, spec
}
func discoveryPairWithRemote(t *testing.T, now func() time.Time, clock Clock) (*Manager, Discovery, *Manager) {
	t.Helper()
	remoteCfg := testSettings("remote.example.net")
	remoteCfg.OriginRealm = "foreign.example"
	remote, err := New(Config{Settings: remoteCfg})
	if err != nil {
		t.Fatal(err)
	}
	if err = remote.AddPeer(PeerConfig{Host: "local.example.net"}); err != nil {
		t.Fatal(err)
	}
	listener, server := startReceiver(t, remote)
	local, err := New(Config{Settings: testSettings("local.example.net"), Now: now, Clock: clock, Timers: Timers{Closing: 100 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	if err = local.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeManager(t, local, nil); closeManager(t, remote, server) })
	spec := discoverySpec()
	spec.Realm = "foreign.example"
	spec.Peer.Endpoints = []Endpoint{{Network: "tcp", Address: listener.Addr().String()}}
	if now != nil {
		spec.ExpiresAt = now().Add(time.Minute)
	}
	return local, spec, remote
}

// Local shutdown does not acknowledge that the remote actor consumed transport
// closure after DPA. Fence that independent state before a same-host acquisition;
// a fresh CER during remote Closing is correctly rejected.
func waitDiscoveryRemoteClosed(t *testing.T, ctx context.Context, remote *Manager) {
	t.Helper()
	actors := remote.allActors()
	if len(actors) != 1 {
		t.Fatalf("remote fixture has %d actors, want one", len(actors))
	}
	// CEA can reach the local peer before the remote publishes its new
	// snapshot. Commit a no-op after that CER handler before trusting Closed.
	delivery := newProtocolDelivery()
	select {
	case actors[0].events <- event{delivery: delivery}:
	case <-ctx.Done():
		t.Fatal("remote fixture barrier admission:", ctx.Err())
	}
	select {
	case <-delivery.done:
	case <-ctx.Done():
		t.Fatal("remote fixture barrier completion:", ctx.Err())
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		peers := remote.Peers()
		if len(peers) != 1 {
			t.Fatalf("remote fixture has %d peers, want one", len(peers))
		}
		if peers[0].State == Closed {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("remote did not finish disconnect:", ctx.Err())
		case <-ticker.C:
		}
	}
}

func TestDiscoveryAcquisitionRoutesRefreshAndRelease(t *testing.T) {
	var nanos atomic.Int64
	nanos.Store(time.Now().UnixNano())
	now := func() time.Time { return time.Unix(0, nanos.Load()) }
	clock := &fakeClock{}
	m, spec, remote := discoveryPairWithRemote(t, now, clock)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var validations atomic.Int32
	spec.Validate = func(diam.Conn, *smpeer.Metadata) (time.Time, error) { validations.Add(1); return time.Time{}, nil }
	lease, err := m.AcquireDiscovered(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if validations.Load() != 1 {
		t.Fatalf("admission count=%d", validations.Load())
	}
	original := lease.a.activeSession.Load()
	oldState := lease.a.discovery.Load()
	if !m.HasRoute(spec.Realm, 4) {
		t.Fatal("foreign realm was not registered on readiness")
	}
	if err = m.SetRoutes(nil); err != nil {
		t.Fatal(err)
	}
	if !m.HasRoute(spec.Realm, 4) {
		t.Fatal("static replacement erased dynamic route")
	}
	if _, _, err = m.selectPeer(outboundRequest("", "foreign.example"), nil); err != nil {
		t.Fatalf("dynamic selection: %v", err)
	}
	if _, err = m.AcquireDiscovered(ctx, spec); !errors.Is(err, ErrDiscoveryOwned) {
		t.Fatalf("duplicate owner: %v", err)
	}
	spec.ExpiresAt = spec.ExpiresAt.Add(time.Minute)
	if err = lease.Refresh(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if validations.Load() != 2 || lease.a.activeSession.Load() != original {
		t.Fatal("refresh failed to revalidate or replaced unchanged connection")
	}
	nanos.Store(oldState.expires.UnixNano())
	lease.a.post(event{kind: discoveryExpire, leaseState: oldState})
	// A subsequent acknowledged command fences the old callback's processing.
	if err = lease.Refresh(ctx, spec); err != nil {
		t.Fatalf("old expiration revoked refreshed lease: %v", err)
	}
	m.mu.RLock()
	route := m.dynamicRoutes[routeKey{identity(spec.Realm), 4}][0]
	m.mu.RUnlock()
	if !route.expires.Equal(lease.ExpiresAt()) {
		t.Fatal("route deadline differs from peer deadline")
	}
	if !m.HasRoute(spec.Realm, 4) {
		t.Fatal("refreshed route unavailable")
	}
	nanos.Store(spec.ExpiresAt.UnixNano())
	if m.HasRoute(spec.Realm, 4) {
		t.Fatal("route survived exact deadline without timer delivery")
	}
	if _, _, err = m.selectPeer(outboundRequest(string(spec.Peer.Host), string(spec.Realm)), nil); !errors.Is(err, ErrUnableToDeliver) {
		t.Fatalf("direct host survived expiry: %v", err)
	}
	// Expiry itself must retire the actor; Manager.Close has not been called.
	lease.a.post(event{kind: discoveryExpire, leaseState: lease.a.discovery.Load()})
	select {
	case <-lease.a.done:
	case <-ctx.Done():
		t.Fatal("expired actor did not retire")
	}
	waitDiscoveryRemoteClosed(t, ctx, remote)
	spec.ExpiresAt = now().Add(time.Minute)
	replacement, err := m.AcquireDiscovered(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if err = lease.Refresh(ctx, spec); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("stale refresh: %v", err)
	}
	if err = lease.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if !m.HasRoute(spec.Realm, 4) {
		t.Fatal("stale release revoked replacement")
	}
	if err = replacement.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if m.HasRoute(spec.Realm, 4) {
		t.Fatal("released route remains usable")
	}
}
func TestDiscoveryRejectsWrongCEARealm(t *testing.T) {
	m, spec := discoveryPair(t, nil, nil)
	spec.Realm = "wrong.example"
	called := false
	spec.Validate = func(diam.Conn, *smpeer.Metadata) (time.Time, error) { called = true; return time.Time{}, nil }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := m.AcquireDiscovered(ctx, spec); !errors.Is(err, ErrDiscoveryAdmission) {
		t.Fatalf("wrong realm accepted: %v", err)
	}
	if called {
		t.Fatal("policy called before realm admission")
	}
	if m.HasRoute(spec.Realm, 4) {
		t.Fatal("rejected CEA published a route")
	}
}
func TestDiscoveryRejectsPolicyBeforeOpen(t *testing.T) {
	m, spec := discoveryPair(t, nil, nil)
	denied := errors.New("role denied")
	spec.Validate = func(diam.Conn, *smpeer.Metadata) (time.Time, error) { return time.Time{}, denied }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := m.AcquireDiscovered(ctx, spec); !errors.Is(err, denied) {
		t.Fatalf("policy denial: %v", err)
	}
	if m.HasRoute(spec.Realm, 4) {
		t.Fatal("policy denied connection published a route")
	}
}
func TestDiscoveryCancelsDialAndProtectsStaticOwnership(t *testing.T) {
	entered := make(chan struct{})
	canceled := make(chan struct{})
	m, err := New(Config{Settings: testSettings("local.example.net"), Dial: func(ctx context.Context, _ Endpoint) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		return nil, ctx.Err()
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = m.AddPeer(PeerConfig{Host: "static.example.net"}); err != nil {
		t.Fatal(err)
	}
	if err = m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer closeManager(t, m, nil)
	spec := discoverySpec()
	spec.Peer.Host = "static.example.net"
	if _, err = m.AcquireDiscovered(context.Background(), spec); !errors.Is(err, ErrDiscoveryOwned) {
		t.Fatalf("static owner replaced: %v", err)
	}
	spec.Peer.Host = "remote.example.net"
	spec.Peer.Endpoints = []Endpoint{{Address: "127.0.0.1:3868"}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := m.AcquireDiscovered(ctx, spec); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("dial not started")
	}
	cancel()
	if err = <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("acquire cancellation=%v", err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("actor dial context not canceled")
	}
}
func TestDiscoveryRejectsInvalidSpec(t *testing.T) {
	m, err := New(Config{Settings: testSettings("local.example.net")})
	if err != nil {
		t.Fatal(err)
	}
	defer closeManager(t, m, nil)
	for _, tc := range []struct {
		name   string
		change func(*Discovery)
	}{
		{"zero expiry", func(d *Discovery) { d.ExpiresAt = time.Time{} }},
		{"past expiry", func(d *Discovery) { d.ExpiresAt = time.Now().Add(-time.Second) }},
		{"empty realm", func(d *Discovery) { d.Realm = "" }},
		{"empty applications", func(d *Discovery) { d.ApplicationIDs = nil }},
		{"missing validator", func(d *Discovery) { d.Validate = nil }},
		{"local identity", func(d *Discovery) { d.Peer.Host = "local.example.net" }},
		{"invalid transport", func(d *Discovery) { d.Peer.Endpoints = []Endpoint{{Network: "udp", Address: "127.0.0.1:3868"}} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := discoverySpec()
			tc.change(&spec)
			if _, err := m.cloneDiscovery(spec); err == nil {
				t.Fatal("invalid discovery accepted")
			}
		})
	}
}

type discoveryTLSConn struct {
	*fakeConn
	state tls.ConnectionState
}

func (c *discoveryTLSConn) TLS() *tls.ConnectionState { return &c.state }
func TestDiscoveryAdmissionCertificateAndCapabilities(t *testing.T) {
	m, actors, _ := outboundTestManager(t)
	a := actors[0]
	now := time.Now()
	m.cfg.Now = func() time.Time { return now }
	spec := discoverySpec()
	spec.Peer = a.cfg
	spec.ExpiresAt = now.Add(time.Hour)
	meta := &smpeer.Metadata{OriginHost: a.cfg.Host, OriginRealm: spec.Realm, Applications: []uint32{4}}
	c := &discoveryTLSConn{fakeConn: newFakeConn()}
	defer c.Close()
	leafExpiry := now.Add(20 * time.Minute)
	intermediateExpiry := now.Add(10 * time.Minute)
	c.state.VerifiedChains = [][]*x509.Certificate{{{NotAfter: leafExpiry}, {NotAfter: intermediateExpiry}}}
	got, err := a.validateDiscovery(spec, c, meta)
	if err != nil || !got.Equal(intermediateExpiry) {
		t.Fatalf("chain expiry cap=%v %v", got, err)
	}
	policyExpiry := now.Add(time.Minute)
	spec.Validate = func(diam.Conn, *smpeer.Metadata) (time.Time, error) { return policyExpiry, nil }
	got, err = a.validateDiscovery(spec, c, meta)
	if err != nil || !got.Equal(policyExpiry) {
		t.Fatalf("policy expiry cap=%v %v", got, err)
	}
	c.state.VerifiedChains = nil
	if _, err = a.validateDiscovery(spec, c, meta); !errors.Is(err, ErrDiscoveryAdmission) {
		t.Fatalf("unverified TLS=%v", err)
	}
	plain := newFakeConn()
	defer plain.Close()
	meta.Applications = []uint32{5}
	if _, err = a.validateDiscovery(spec, plain, meta); !errors.Is(err, ErrDiscoveryAdmission) {
		t.Fatalf("application mismatch=%v", err)
	}
	meta.Applications = []uint32{0xffffffff}
	if _, err = a.validateDiscovery(spec, plain, meta); err != nil {
		t.Fatalf("relay capability: %v", err)
	}
	spec.Validate = func(diam.Conn, *smpeer.Metadata) (time.Time, error) { return now, nil }
	if _, err = a.validateDiscovery(spec, plain, meta); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("expired admission evidence=%v", err)
	}
}

func TestDiscoveryActualWriterChecksDeadline(t *testing.T) {
	var nanos atomic.Int64
	nanos.Store(time.Now().UnixNano())
	m, actors, _ := outboundTestManager(t)
	m.cfg.Now = func() time.Time { return time.Unix(0, nanos.Load()) }
	a := actors[0]
	spec := discoverySpec()
	spec.Peer = a.cfg
	spec.ExpiresAt = m.cfg.Now().Add(time.Minute)
	a.discovery.Store(&discoveryState{spec: spec, expires: spec.ExpiresAt})
	a.publish(nil)
	c := &blockedWriteConn{fakeConn: newFakeConn(), entered: make(chan struct{}), release: make(chan struct{}), written: make(chan []byte, 4)}
	s := m.newSession(c, a, 10, false)
	if s == nil {
		t.Fatal("session failed")
	}
	first := outboundRequest("", "example.net")
	if err := s.send(first, false); err != nil {
		t.Fatal(err)
	}
	<-c.entered
	if err := s.send(outboundRequest("", "example.net"), false); err != nil {
		t.Fatal(err)
	}
	nanos.Store(spec.ExpiresAt.UnixNano())
	close(c.release)
	select {
	case <-s.closed:
	case <-time.After(time.Second):
		t.Fatal("writer sent queued message after expiry")
	}
	if got := len(c.written); got != 1 {
		t.Fatalf("wrote %d messages, want only already-started write", got)
	}
}
func TestDiscoveryRefreshReleaseRace(t *testing.T) {
	m, spec, remote := discoveryPairWithRemote(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := 0; i < 10; i++ {
		lease, err := m.AcquireDiscovered(ctx, spec)
		if err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { result <- lease.Refresh(ctx, spec) }()
		if err = lease.Release(ctx); err != nil {
			t.Fatal(err)
		}
		err = <-result
		if err != nil && !errors.Is(err, ErrLeaseExpired) {
			t.Fatalf("raced refresh=%v", err)
		}
		if m.HasRoute(spec.Realm, 4) {
			t.Fatal("refresh resurrected released route")
		}
		waitDiscoveryRemoteClosed(t, ctx, remote)
	}
}
func TestDiscoveryAdmissionBeforeInboundCEA(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprint(reject), func(t *testing.T) {
			m, err := New(Config{Settings: testSettings("local.example.net"), Timers: Timers{Closing: 50 * time.Millisecond}})
			if err != nil {
				t.Fatal(err)
			}
			listener, server := startReceiver(t, m)
			if err = m.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer closeManager(t, m, server)
			spec := discoverySpec()
			spec.Realm = "example.net"
			rejected := errors.New("inbound role denied")
			var validations atomic.Int32
			spec.Validate = func(diam.Conn, *smpeer.Metadata) (time.Time, error) {
				validations.Add(1)
				if reject {
					return time.Time{}, rejected
				}
				return time.Time{}, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			acquired := make(chan *Lease, 1)
			result := make(chan error, 1)
			go func() { l, err := m.AcquireDiscovered(ctx, spec); acquired <- l; result <- err }()
			for len(m.Peers()) == 0 {
				select {
				case <-ctx.Done():
					t.Fatal("peer not installed")
				default:
					time.Sleep(time.Millisecond)
				}
			}
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			cer, err := base.BuildCER(dict.Default, testBase("remote.example.net"))
			if err != nil {
				t.Fatal(err)
			}
			write(t, conn, cer)
			answer := read(t, conn)
			if reject {
				if code(t, answer) == diam.Success {
					t.Fatal("policy rejected CER received successful CEA")
				}
				if err = <-result; !errors.Is(err, rejected) {
					t.Fatalf("acquire rejection=%v", err)
				}
				<-acquired
			} else {
				if code(t, answer) != diam.Success {
					t.Fatal("valid CER rejected")
				}
				if err = <-result; err != nil {
					t.Fatal(err)
				}
				lease := <-acquired
				if !m.HasRoute(spec.Realm, 4) {
					t.Fatal("inbound validated peer has no dynamic route")
				}
				_ = conn.Close()
				if err = lease.Release(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if validations.Load() != 1 {
				t.Fatalf("inbound validations=%d", validations.Load())
			}
		})
	}
}

func TestDiscoveryReadyDoesNotDependOnObserverQueue(t *testing.T) {
	m, spec := discoveryPair(t, nil, nil)
	entered, unblock := make(chan struct{}), make(chan struct{})
	var once sync.Once
	m.cfg.OnPeerEvent = func(PeerEvent) { once.Do(func() { close(entered) }); <-unblock }
	m.notify(PeerEvent{})
	<-entered
	defer close(unblock)
	for i := 0; i < cap(m.callbackQ); i++ {
		m.callbackQ <- PeerEvent{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lease, err := m.AcquireDiscovered(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if !m.HasRoute(spec.Realm, 4) {
		t.Fatal("acquisition returned before route admission")
	}
	if err = lease.Release(ctx); err != nil {
		t.Fatal(err)
	}
}
func TestDiscoveryTLSConfigWithHookRefreshComparison(t *testing.T) {
	m, _, _ := outboundTestManager(t)
	spec := discoverySpec()
	spec.Peer.Endpoints = []Endpoint{{Network: "tcp", Address: "127.0.0.1:5868", TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, VerifyConnection: func(tls.ConnectionState) error { return nil }}}}
	first, err := m.cloneDiscovery(spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.cloneDiscovery(spec)
	if err != nil {
		t.Fatal(err)
	}
	if !sameDiscoveryPeer(first, second) {
		t.Fatal("unchanged TLS config with hook requires replacement")
	}
	spec.Peer.Endpoints[0].TLSConfig = spec.Peer.Endpoints[0].TLSConfig.Clone()
	changed, err := m.cloneDiscovery(spec)
	if err != nil {
		t.Fatal(err)
	}
	if sameDiscoveryPeer(first, changed) {
		t.Fatal("new TLS policy reused old transport")
	}
}

func TestDiscoveryAcceptedRenewalRevalidates(t *testing.T) {
	m, err := New(Config{Settings: testSettings("local.example.net"), Timers: Timers{Closing: 50 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &diam.Server{RenewAcceptedCER: true, Dict: m.cfg.Settings.Dict}
	if err = m.BindServer(server); err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	defer closeManager(t, m, server)
	if err = m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	spec := discoverySpec()
	var validations atomic.Int32
	var deny atomic.Bool
	spec.Validate = func(diam.Conn, *smpeer.Metadata) (time.Time, error) {
		validations.Add(1)
		if deny.Load() {
			return time.Time{}, errors.New("renewal authorization revoked")
		}
		return time.Time{}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	acquired := make(chan *Lease, 1)
	result := make(chan error, 1)
	go func() { l, err := m.AcquireDiscovered(ctx, spec); acquired <- l; result <- err }()
	for len(m.Peers()) == 0 {
		select {
		case <-ctx.Done():
			t.Fatal("peer not installed")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	cer, err := base.BuildCER(dict.Default, testBase("remote.example.net"))
	if err != nil {
		t.Fatal(err)
	}
	write(t, conn, cer)
	if code(t, read(t, conn)) != diam.Success {
		t.Fatal("initial CER rejected")
	}
	if err = <-result; err != nil {
		t.Fatal(err)
	}
	lease := <-acquired
	generation := lease.a.snapshot().Generation
	// Discard unsolicited watchdog requests while waiting for each CEA.
	readCEA := func() *diam.Message {
		for {
			msg := read(t, conn)
			if msg.Header.CommandCode == diam.CapabilitiesExchange {
				return msg
			}
		}
	}
	write(t, conn, cer)
	if code(t, readCEA()) != diam.Success {
		t.Fatal("renewed CER rejected")
	}
	lease.a.commit(event{}, newProtocolDelivery())
	if validations.Load() != 2 {
		t.Fatalf("renewal validations=%d", validations.Load())
	}
	if lease.a.snapshot().Generation == generation {
		t.Fatal("accepted CER did not renew session generation")
	}
	deny.Store(true)
	write(t, conn, cer)
	if code(t, readCEA()) == diam.Success {
		t.Fatal("renewal bypassed changed authorization")
	}
	if validations.Load() != 3 {
		t.Fatalf("denied renewal validations=%d", validations.Load())
	}
	if m.HasRoute(spec.Realm, 4) {
		t.Fatal("denied renewal remains routable")
	}
	if err = lease.Release(ctx); err != nil {
		t.Fatal(err)
	}
}
func TestDiscoveryExpiredWatchdogAndReconnect(t *testing.T) {
	a, s, clock := newWatchdogTestActor(t, WatchdogOkay)
	spec := discoverySpec()
	spec.Peer = a.cfg
	spec.ExpiresAt = time.Now().Add(-time.Second)
	a.discovery.Store(&discoveryState{spec: spec, expires: spec.ExpiresAt})
	a.publish(nil)
	a.watchdogTick()
	if len(s.writes) != 0 {
		t.Fatal("expired watchdog queued a request")
	}
	if a.snapshot().Eligible {
		t.Fatal("expired watchdog republished eligibility")
	}
	a.cfg.Endpoints = []Endpoint{{Network: "tcp", Address: "127.0.0.1:3868"}}
	a.m.started = true
	a.m.runCtx = context.Background()
	a.state = Closed
	before := clock.timerCount()
	a.scheduleReconnect()
	a.reconnectTick()
	a.handle(event{kind: start})
	if clock.timerCount() != before || a.state != Closed || a.dialing {
		t.Fatal("expired peer scheduled or started reconnection")
	}
}
func TestDiscoveryCloseJoinsRetiredDialWorker(t *testing.T) {
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	raw, other := net.Pipe()
	defer func() { _ = raw.Close(); _ = other.Close() }()
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	m, err := New(Config{Settings: testSettings("local.example.net"), Dial: func(ctx context.Context, _ Endpoint) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release
		return raw, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	spec := discoverySpec()
	spec.Peer.Endpoints = []Endpoint{{Network: "tcp", Address: "127.0.0.1:3868"}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := m.AcquireDiscovered(ctx, spec); result <- err }()
	<-entered
	m.mu.RLock()
	a := m.peers[identity(spec.Peer.Host)]
	m.mu.RUnlock()
	cancel()
	if err = <-result; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	<-canceled
	select {
	case <-a.done:
	case <-time.After(time.Second):
		t.Fatal("revoked actor did not exit independently")
	}
	if len(m.Peers()) != 0 {
		t.Fatal("retired peer remained visible")
	}
	closed := make(chan error, 1)
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer closeCancel()
	go func() { closed <- m.Close(closeCtx, sm.DisconnectRebooting) }()
	select {
	case err = <-closed:
		t.Fatalf("Close returned while retired dial worker was live: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err = other.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	unblock()
	if err = <-closed; err != nil {
		t.Fatal(err)
	}
	if len(m.Peers()) != 0 {
		t.Fatal("late dial resurrected released peer")
	}
	var b [1]byte
	if _, err = other.Read(b[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("late raw connection not closed: %v", err)
	}
}
func TestDiscoveryExpiredQueuedWatchdog(t *testing.T) {
	var nanos atomic.Int64
	nanos.Store(time.Now().UnixNano())
	m, actors, _ := outboundTestManager(t)
	m.cfg.Now = func() time.Time { return time.Unix(0, nanos.Load()) }
	a := actors[0]
	spec := discoverySpec()
	spec.Peer = a.cfg
	spec.ExpiresAt = m.cfg.Now().Add(time.Minute)
	a.discovery.Store(&discoveryState{spec: spec, expires: spec.ExpiresAt})
	a.publish(nil)
	c := &blockedWriteConn{fakeConn: newFakeConn(), entered: make(chan struct{}), release: make(chan struct{}), written: make(chan []byte, 4)}
	s := m.newSession(c, a, 10, false)
	if s == nil {
		t.Fatal("session failed")
	}
	dwr, err := base.BuildDWR(dict.Default, testBase("local.example.net"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.send(dwr, false); err != nil {
		t.Fatal(err)
	}
	<-c.entered
	if err = s.send(dwr, false); err != nil {
		t.Fatal(err)
	}
	nanos.Store(spec.ExpiresAt.UnixNano())
	close(c.release)
	select {
	case <-s.closed:
	case <-time.After(time.Second):
		t.Fatal("queued watchdog survived expiration")
	}
	if len(c.written) != 1 {
		t.Fatal("expired watchdog written to transport")
	}
}

func FuzzDiscoveryAdmission(f *testing.F) {
	f.Add("remote.example.net", "example.net", uint32(4), int64(time.Second))
	f.Add("REMOTE.example.NET", "EXAMPLE.NET", uint32(0xffffffff), int64(1))
	f.Add("remote.example.net", "wrong.example", uint32(4), int64(time.Minute))
	f.Add("other.example.net", "example.net", uint32(4), int64(time.Second))
	f.Add("remote.example.net", "example.net", uint32(5), int64(time.Second))
	f.Add("remote.example.net", "example.net", uint32(4), int64(0))
	f.Fuzz(func(t *testing.T, host, realm string, app uint32, remaining int64) {
		now := time.Unix(1000, 0)
		m := &Manager{cfg: Config{Now: func() time.Time { return now }}, localApps: map[uint32]struct{}{4: {}}}
		a := &actor{m: m}
		spec := discoverySpec()
		spec.ExpiresAt = now.Add(time.Duration(remaining))
		meta := &smpeer.Metadata{OriginHost: datatype.DiameterIdentity(host), OriginRealm: datatype.DiameterIdentity(realm), Applications: []uint32{app}}
		deadline, err := a.validateDiscovery(spec, &fakeConn{}, meta)
		want := remaining > 0 && identity(meta.OriginHost) == identity(spec.Peer.Host) && identity(meta.OriginRealm) == identity(spec.Realm) && (app == 4 || app == 0xffffffff)
		if (err == nil) != want {
			t.Fatalf("admission=%v for %q/%q app=%d remaining=%d", err, host, realm, app, remaining)
		}
		if err == nil && !deadline.Equal(spec.ExpiresAt) {
			t.Fatal("uncapped admission changed discovery deadline")
		}
	})
}

func TestDiscoveryDelegatedRealmRequiresExplicitPolicy(t *testing.T) {
	m, actors, _ := outboundTestManager(t)
	a := actors[0]
	spec := discoverySpec()
	spec.Peer = a.cfg
	conn := newFakeConn()
	defer conn.Close()
	meta := &smpeer.Metadata{OriginHost: a.cfg.Host, OriginRealm: "delegated.example", Applications: []uint32{4}}
	if _, err := a.validateDiscovery(spec, conn, meta); !errors.Is(err, ErrDiscoveryAdmission) {
		t.Fatalf("default accepted delegated realm: %v", err)
	}
	spec.AllowRealm = func(expected, actual datatype.DiameterIdentity) bool {
		return expected == "example.net" && actual == "delegated.example"
	}
	if _, err := a.validateDiscovery(spec, conn, meta); err != nil {
		t.Fatalf("explicit delegation rejected: %v", err)
	}
	meta.OriginRealm = "other.example"
	if _, err := a.validateDiscovery(spec, conn, meta); !errors.Is(err, ErrDiscoveryAdmission) {
		t.Fatalf("unapproved delegated realm accepted: %v", err)
	}
	_ = m
}

func TestDiscoveryRetirementClosesQueuedAttachments(t *testing.T) {
	for _, kind := range []psmEvent{dialDone, rConnCER} {
		t.Run(string(kind), func(t *testing.T) {
			m, err := New(Config{Settings: testSettings("local.example.net")})
			if err != nil {
				t.Fatal(err)
			}
			defer closeManager(t, m, nil)
			spec := discoverySpec()
			a := &actor{m: m, cfg: spec.Peer, state: WaitConnAck, events: make(chan event, 8), done: make(chan struct{})}
			a.discovery.Store(&discoveryState{spec: spec, expires: spec.ExpiresAt})
			a.publish(nil)
			m.mu.Lock()
			m.peers[identity(spec.Peer.Host)] = a
			m.wg.Add(1)
			m.mu.Unlock()
			conn := newFakeConn()
			s := m.newSession(conn, a, 1, kind == rConnCER)
			if s == nil {
				t.Fatal("attachment session not created")
			}
			// FIFO stop wins before the already-created session can become i/r.
			a.events <- event{kind: stop, cause: sm.DisconnectRebooting}
			a.events <- event{kind: kind, s: s, gen: 1, meta: &smpeer.Metadata{OriginHost: spec.Peer.Host, OriginRealm: spec.Realm, Applications: []uint32{4}}}
			go a.run()
			select {
			case <-a.done:
			case <-time.After(time.Second):
				t.Fatal("actor did not retire")
			}
			select {
			case <-s.closed:
			default:
				t.Fatal("retired actor abandoned queued connection attachment")
			}
			if !conn.Closed() {
				t.Fatal("queued transport survived actor retirement")
			}
			late := newFakeConn()
			if m.newSession(late, a, 2, false) != nil || !late.Closed() {
				t.Fatal("retired actor accepted late dial attachment")
			}
			inbound := newFakeConn()
			unbound := m.newSession(inbound, nil, 0, true)
			if unbound == nil {
				t.Fatal("unbound inbound session unavailable")
			}
			if unbound.bind(a, 3) || !inbound.Closed() {
				t.Fatal("retired actor accepted late inbound binding")
			}

		})
	}
}

func TestDiscoveryRequestedRealmScopesAllRoutes(t *testing.T) {
	m, actors, sessions := outboundTestManager(t)
	a := actors[0]
	spec := discoverySpec()
	spec.Peer = a.cfg
	spec.AllowRealm = func(_, _ datatype.DiameterIdentity) bool { return true }
	a.discovery.Store(&discoveryState{spec: spec, expires: spec.ExpiresAt})
	a.publish(nil)
	if err := m.SetRoutes([]Route{{Realm: "foreign.example", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{a.cfg.Host}}}); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{string(a.cfg.Host), ""} {
		if _, _, err := m.selectPeer(outboundRequest(host, "foreign.example"), nil); !errors.Is(err, ErrUnableToDeliver) {
			t.Errorf("foreign realm host %q accepted: %v", host, err)
		}
	}
	if m.HasRoute("foreign.example", 4) {
		t.Error("foreign static mapping widened discovery authorization")
	}
	if _, _, err := m.selectPeer(outboundRequest(string(a.cfg.Host), "EXAMPLE.NET"), nil); err != nil {
		t.Errorf("authorized realm rejected: %v", err)
	}
	if _, _, err := m.selectPeer(outboundRequest(string(actors[1].cfg.Host), "foreign.example"), nil); err != nil {
		t.Errorf("static direct host behavior changed: %v", err)
	}
	if err := sessions[0].send(outboundRequest("", "foreign.example"), false); !errors.Is(err, ErrLeaseExpired) {
		t.Errorf("writer admitted foreign realm: %v", err)
	}
	if !sessions[0].leaseAllowsWrite(writeRequest{msg: outboundRequest("", "example.net")}) {
		t.Error("writer rejected authorized realm")
	}
}

func TestDiscoveryHandshakeEOFAcknowledgesFailure(t *testing.T) {
	remoteDone := make(chan struct{})
	m, err := New(Config{Settings: testSettings("local.example.net"), Dial: func(context.Context, Endpoint) (net.Conn, error) {
		local, remote := net.Pipe()
		go func() {
			defer close(remoteDone)
			defer func() { _ = remote.Close() }()
			_, _ = diam.ReadMessage(remote, dict.Default)
		}()
		return local, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer closeManager(t, m, nil)
	if err = m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	spec := discoverySpec()
	spec.Peer.Endpoints = []Endpoint{{Network: "tcp", Address: "peer.example:3868"}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = m.AcquireDiscovered(ctx, spec)
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("handshake EOF did not acknowledge acquisition failure: %v", err)
	}
	<-remoteDone
	if m.HasRoute(spec.Realm, 4) {
		t.Fatal("failed handshake created route")
	}
}

func TestDiscoveryRejectsNonASCIIIdentityScope(t *testing.T) {
	m, actors, sessions := outboundTestManager(t)
	a := actors[0]
	spec := discoverySpec()
	spec.Peer = a.cfg
	spec.Realm = "bank.example.net"
	a.discovery.Store(&discoveryState{spec: spec, expires: spec.ExpiresAt})
	a.publish(nil)
	for _, mapped := range []bool{false, true} {
		if mapped {
			if err := m.SetRoutes([]Route{{Realm: spec.Realm, ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{a.cfg.Host}}}); err != nil {
				t.Fatal(err)
			}
		}
		for _, host := range []string{"", string(a.cfg.Host)} {
			if _, _, err := m.selectPeer(outboundRequest(host, "banK.example.net"), nil); err == nil {
				t.Errorf("non-ASCII destination accepted: mapped=%v host=%q", mapped, host)
			}
		}
		if m.HasRoute("banK.example.net", 4) {
			t.Errorf("non-ASCII route query accepted: mapped=%v", mapped)
		}
	}
	if !m.HasRoute("BANK.example.net", 4) {
		t.Error("ASCII case-insensitive route rejected")
	}
	if err := sessions[0].send(outboundRequest("", "banK.example.net"), false); !errors.Is(err, ErrLeaseExpired) {
		t.Errorf("non-ASCII writer admitted: %v", err)
	}
	if _, _, err := m.selectPeer(outboundRequest(string(actors[1].cfg.Host), "banK.example.net"), nil); err != nil {
		t.Errorf("static selection changed: %v", err)
	}
	if err := sessions[1].send(outboundRequest("", "banK.example.net"), false); err != nil {
		t.Errorf("static writer changed: %v", err)
	}
	for _, field := range []string{"host", "realm"} {
		invalid := spec
		if field == "host" {
			invalid.Peer.Host = "banK.example.net"
		} else {
			invalid.Realm = "banK.example.net"
		}
		if _, err := m.cloneDiscovery(invalid); !errors.Is(err, ErrDiscoveryAdmission) {
			t.Errorf("non-ASCII discovery %s accepted: %v", field, err)
		}
	}
}

func TestDiscoveryRawIdentityGuardsRemainIndependent(t *testing.T) {
	m, actors, sessions := outboundTestManager(t)
	a := actors[0]
	spec := discoverySpec()
	spec.Peer = a.cfg
	// Install an invalid internal state to exercise each boundary independently
	// of the public Discovery input check.
	spec.Realm = "banK.example.net"
	a.discovery.Store(&discoveryState{spec: spec, expires: spec.ExpiresAt})
	a.publish(nil)
	if err := m.SetRoutes([]Route{{Realm: spec.Realm, ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{a.cfg.Host}}}); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"", string(a.cfg.Host)} {
		if _, _, err := m.selectPeer(outboundRequest(host, string(spec.Realm)), nil); err == nil {
			t.Errorf("raw non-ASCII realm selected via %q", host)
		}
	}
	if m.HasRoute(spec.Realm, 4) {
		t.Fatal("raw non-ASCII HasRoute accepted")
	}
	if sessions[0].leaseAllowsWrite(writeRequest{msg: outboundRequest("", string(spec.Realm))}) {
		t.Fatal("raw non-ASCII actual writer admitted")
	}
	if err := m.SetRoutes([]Route{{Realm: spec.Realm, ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{actors[1].cfg.Host}}}); err != nil {
		t.Fatal(err)
	}
	if !m.HasRoute(spec.Realm, 4) {
		t.Fatal("static HasRoute behavior changed")
	}
	spec.Realm = "example.net"
	spec.AllowRealm = func(_, _ datatype.DiameterIdentity) bool { return true }
	if _, err := a.validateDiscovery(spec, sessions[0].c, &smpeer.Metadata{OriginHost: a.cfg.Host, OriginRealm: "banK.example.net", Applications: []uint32{4}}); !errors.Is(err, ErrDiscoveryAdmission) {
		t.Fatalf("non-ASCII advertised realm delegated: %v", err)
	}
}
