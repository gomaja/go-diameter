package dnsdiam

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/peer"
	"github.com/gomaja/go-diameter/diam/sm"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

type refreshTLSConn struct {
	diam.Conn
	state tls.ConnectionState
	ctx   context.Context
}

// Shorten watchdog recovery while leaving certificate and DNS expiry timers
// intact. Connect/CER timers are explicitly configured below.
type refreshWatchdogClock struct{}

func (refreshWatchdogClock) AfterFunc(delay time.Duration, callback func()) peer.Timer {
	if delay >= 28*time.Second && delay <= 32*time.Second {
		delay = 50 * time.Millisecond
	}
	return time.AfterFunc(delay, callback)
}

func (c *refreshTLSConn) Closed() bool                   { return false }
func (c *refreshTLSConn) TLS() *tls.ConnectionState      { return &c.state }
func (c *refreshTLSConn) Context() context.Context       { return c.ctx }
func (c *refreshTLSConn) SetContext(ctx context.Context) { c.ctx = ctx }

func TestTLSRetainedSelectionEvidence(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	serverTLS, clientTLS := fixtureTLS(t, []string{"peer.example.net"})
	selected := clientTLS.Certificates[0]
	clientTLS.Certificates = nil
	clientTLS.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &selected, nil }
	policy := Policy{TLSConfig: clientTLS, Authorize: authorizeFixture}
	candidate := Candidate{Realm: "example.net", ApplicationID: 4, Transport: TLS, Host: "peer.example.net", Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, ExpiresAt: now.Add(2 * time.Hour)}
	clock := func() time.Time { return now }
	initial, evidence, err := policy.prepareWithEvidence(candidate, clock, nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf := serverTLS.Certificates[0].Leaf
	newConn := func() *refreshTLSConn {
		return &refreshTLSConn{state: tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}}
	}
	meta := &smpeer.Metadata{OriginHost: "peer.example.net", OriginRealm: "example.net", Applications: []uint32{4}}
	if _, err = initial.Validate(newConn(), meta); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("missing callback selection accepted: %v", err)
	}
	if _, err = evidence.config.GetClientCertificate(&tls.CertificateRequestInfo{}); err != nil {
		t.Fatal(err)
	}
	first := newConn()
	deadline, err := initial.Validate(first, meta)
	if err != nil {
		t.Fatal(err)
	}
	if !deadline.Equal(selected.Leaf.NotAfter) {
		t.Fatalf("initial selected credential deadline: %s, want %s", deadline, selected.Leaf.NotAfter)
	}
	if first.Context() == nil {
		t.Fatal("connection lost selected credential context")
	}
	if saved, _ := first.Context().Value(clientExpiryKey{}).(time.Time); !saved.Equal(deadline) {
		t.Fatalf("connection lost selected credential evidence: %s, want %s", saved, deadline)
	}
	refreshed, retained, err := policy.prepareWithEvidence(candidate, clock, evidence)
	if err != nil || retained != evidence || refreshed.Peer.Endpoints[0].TLSConfig != initial.Peer.Endpoints[0].TLSConfig {
		t.Fatalf("TLS callback and validator evidence separated: retained=%p old=%p err=%v", retained, evidence, err)
	}
	for i, validity := range []time.Duration{30 * time.Minute, 45 * time.Minute} {
		selected, _, _ = makeCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(int64(i + 10)), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(validity), KeyUsage: x509.KeyUsageDigitalSignature}, nil, nil)
		if _, err = initial.Peer.Endpoints[0].TLSConfig.GetClientCertificate(&tls.CertificateRequestInfo{}); err != nil {
			t.Fatal(err)
		}
		for _, conn := range []*refreshTLSConn{first, newConn()} {
			deadline, err = refreshed.Validate(conn, meta)
			if err != nil || !deadline.Equal(now.Add(30*time.Minute)) {
				t.Fatalf("rotation %d lost conservative selected credential cap: deadline=%s err=%v", i, deadline, err)
			}
		}
	}
	fresh, freshEvidence, err := policy.prepareWithEvidence(candidate, clock, nil)
	if err != nil || freshEvidence == evidence {
		t.Fatalf("independent TLS configuration shared selection evidence: %v", err)
	}
	if _, err = fresh.Validate(newConn(), meta); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("fresh connection borrowed another configuration's selection: %v", err)
	}
}

func TestTLSCallbackRefreshReconnect(t *testing.T) {
	serverTLS, clientTLS := fixtureTLS(t, []string{"example.net", "_diameters._tcp.example.net", "peer.example.net"})
	if path := os.Getenv("I100_TLS_KEYLOG"); path != "" {
		log, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := log.Close(); err != nil {
				t.Error(err)
			}
		})
		clientTLS.KeyLogWriter = log
	}
	credential := clientTLS.Certificates[0]
	clientTLS.Certificates = nil
	var selections atomic.Int32
	clientTLS.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		selections.Add(1)
		return &credential, nil
	}
	addr := fixturePeer(t, fixtureSettings("peer.example.net", "example.net"), serverTLS, nil)
	t.Logf("synthetic TLS Diameter %s", addr)
	d := liveDiscovery(t, addr, TLS)
	resolver := d.cfg.Resolver.(*fakeResolver)
	for key, answer := range resolver.answers {
		for i := range answer.Records {
			answer.Records[i].TTL = 7200
		}
		resolver.answers[key] = answer
	}
	events := make(chan peer.PeerEvent, 32)
	manager, err := peer.New(peer.Config{Settings: fixtureSettings("client.example.net", "example.net"), Clock: refreshWatchdogClock{}, Timers: peer.Timers{Tc: 20 * time.Millisecond, Connect: time.Second, CER: time.Second, Closing: 20 * time.Millisecond}, OnPeerEvent: func(event peer.PeerEvent) {
		select {
		case events <- event:
		default:
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := manager.Close(ctx, sm.DisconnectRebooting); err != nil {
			t.Error(err)
		}
	})
	admitted := make(chan diam.Conn, 16)
	controller, err := NewController(d, manager, Policy{TLSConfig: clientTLS, Authorize: func(_ Candidate, conn diam.Conn, _ *smpeer.Metadata) error {
		select {
		case admitted <- conn:
		default:
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := controller.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err = controller.Ensure(ctx, "example.net", 4); err != nil {
		t.Fatal(err)
	}
	first := <-admitted
	before := manager.Peers()[0]
	if !before.ExpiresAt.Equal(credential.Leaf.NotAfter) {
		t.Fatalf("initial client certificate cap: %s, want %s", before.ExpiresAt, credential.Leaf.NotAfter)
	}
	key := bindingKey{"example.net", 4}
	if err = controller.lock(ctx); err != nil {
		t.Fatal(err)
	}
	err = controller.ensureLocked(ctx, Request{Realm: "example.net", ApplicationID: 4}, key, true)
	controller.unlock()
	if err != nil {
		t.Fatal(err)
	}
	after := manager.Peers()[0]
	if after.Generation != before.Generation || !after.ExpiresAt.Equal(before.ExpiresAt) {
		t.Fatalf("refresh replaced session or lost client certificate cap: before=%+v after=%+v", before, after)
	}
	first.Close()
	for {
		select {
		case conn := <-admitted:
			if conn != first {
				if selections.Load() < 2 {
					t.Fatal("reconnection did not request a client certificate")
				}
				if _, err := controller.owned["peer.example.net"].spec.Validate(conn, &smpeer.Metadata{OriginHost: "peer.example.net", OriginRealm: "example.net", Applications: []uint32{4}}); err != nil {
					t.Fatalf("reconnected session rejected: %v", err)
				}
				for {
					select {
					case event := <-events:
						if event.Peer.Eligible && event.Peer.Generation != before.Generation {
							if !event.Peer.ExpiresAt.Equal(before.ExpiresAt) || !manager.HasRoute("example.net", 4) {
								t.Fatalf("reconnect lost route or selected credential cap: %+v", event.Peer)
							}
							return
						}
					case <-ctx.Done():
						t.Fatalf("validated reconnect did not become eligible: %v", ctx.Err())
					}
				}
			}
		case <-ctx.Done():
			t.Fatalf("callback TLS reconnect rejected after refresh: selections=%d: %v", selections.Load(), ctx.Err())
		}
	}
}
