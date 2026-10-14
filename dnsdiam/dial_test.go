package dnsdiam

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/peer"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

type heldClock struct {
	duration time.Duration
	stopped  atomic.Bool
}

func TestPlainDialRejectsClosedAuthorizationAndUnicodeIdentity(t *testing.T) {
	for _, host := range []string{"peek.example.net", "peeK.example.net"} {
		t.Run(host, func(t *testing.T) {
			addr := fixturePeer(t, fixtureSettings(host, "example.net"), nil, nil)
			d := liveDiscovery(t, addr, TCP)
			resolver := d.cfg.Resolver.(*fakeResolver)
			key := lookupKey{"_diameters._tcp.example.net.", TypeSRV}
			a := resolver.answers[key]
			a.Records[0].SRV.Target = "peek.example.net."
			resolver.answers[key] = a
			resolver.answers[lookupKey{"peek.example.net.", TypeA}] = Answer{ReceivedAt: time.Now(), Records: []Record{address("peek.example.net.", "127.0.0.1", 60)}}
			var admitted atomic.Bool
			settings := fixtureSettings("client.example.net", "example.net")
			settings.OnHandshake = func(diam.Conn, *smpeer.Metadata) { admitted.Store(true) }
			policy := Policy{AllowPlaintext: true, Authorize: authorizeFixture}
			if host == "peek.example.net" {
				policy.Authorize = func(_ Candidate, c diam.Conn, _ *smpeer.Metadata) error { c.Close(); return nil }
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := d.DialContext(ctx, Request{Realm: "example.net", ApplicationID: 4, Transports: []Transport{TCP}}, DialConfig{Settings: settings, Policy: policy})
			if conn != nil {
				conn.Close()
			}
			if err == nil || admitted.Load() {
				t.Fatalf("closed/Unicode peer admitted: %v", err)
			}
		})
	}
}

func (c *heldClock) AfterFunc(d time.Duration, _ func()) peer.Timer { c.duration = d; return c }
func (c *heldClock) Stop() bool                                     { return !c.stopped.Swap(true) }

func TestPlainDialExpiryIndependentOfTimer(t *testing.T) {
	serverTLS, clientTLS := fixtureTLS(t, []string{"example.net", "_diameters._tcp.example.net", "peer.example.net"})
	addr := fixturePeer(t, fixtureSettings("peer.example.net", "example.net"), serverTLS, nil)
	d := liveDiscovery(t, addr, TLS)
	var current atomic.Pointer[time.Time]
	initial := time.Now()
	current.Store(&initial)
	d.cfg.Now = func() time.Time { return *current.Load() }
	clock := &heldClock{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, Request{Realm: "example.net", ApplicationID: 4}, DialConfig{Settings: fixtureSettings("client.example.net", "example.net"), Policy: Policy{TLSConfig: clientTLS, Authorize: authorizeFixture}, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	expires := conn.(*expiryConn).expires
	current.Store(&expires)
	if n, err := conn.Write([]byte{1}); n != 0 || !errors.Is(err, ErrExpired) {
		t.Fatalf("expired write=%d,%v", n, err)
	}
	if n, err := conn.WriteStream([]byte{1}, 0); n != 0 || !errors.Is(err, ErrExpired) {
		t.Fatalf("expired stream=%d,%v", n, err)
	}
	if !clock.stopped.Load() || clock.duration <= 0 || !conn.Closed() {
		t.Fatal("expiry did not retire connection/timer")
	}
}

func TestDialPlaintextRequiresOptIn(t *testing.T) {
	addr := fixturePeer(t, fixtureSettings("peer.example.net", "example.net"), nil, nil)
	d := liveDiscovery(t, addr, TCP)
	request := Request{Realm: "example.net", ApplicationID: 4, Transports: []Transport{TCP}}
	cfg := DialConfig{Settings: fixtureSettings("client.example.net", "example.net"), Policy: Policy{Authorize: authorizeFixture}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if conn, err := d.DialContext(ctx, request, cfg); conn != nil || !errors.Is(err, ErrUnauthorized) {
		if conn != nil {
			conn.Close()
		}
		t.Fatalf("plaintext implicit=%v,%v", conn, err)
	}
	cfg.Policy.AllowPlaintext = true
	conn, err := d.DialContext(ctx, request, cfg)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestPlainDialScopeAndRemoteClosure(t *testing.T) {
	settings := fixtureSettings("peer.example.net", "example.net")
	var remote atomic.Pointer[struct{ conn diam.Conn }]
	settings.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { remote.Store(&struct{ conn diam.Conn }{c}) }
	addr := fixturePeer(t, settings, nil, nil)
	d := liveDiscovery(t, addr, TCP)
	clock := &heldClock{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, Request{Realm: "example.net", ApplicationID: 4, Transports: []Transport{TCP}}, DialConfig{Settings: fixtureSettings("client.example.net", "example.net"), Policy: Policy{AllowPlaintext: true, Authorize: authorizeFixture}, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, test := range []struct {
		app   uint32
		realm string
	}{{7, "example.net"}, {4, "other.net"}} {
		message := diam.NewRequest(272, test.app, fixtureDictionary())
		message.AddAVP(diam.NewAVP(avp.DestinationRealm, avp.Mbit, 0, datatype.DiameterIdentity(test.realm)))
		wire, err := message.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		if n, err := conn.Write(wire); n != 0 || !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("unauthorized write %d/%s=%d,%v", test.app, test.realm, n, err)
		}
		if n, err := conn.WriteStream(wire, 0); n != 0 || !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("unauthorized stream %d/%s=%d,%v", test.app, test.realm, n, err)
		}
	}
	allowed := diam.NewRequest(272, 4, fixtureDictionary())
	allowed.AddAVP(diam.NewAVP(avp.DestinationRealm, avp.Mbit, 0, datatype.DiameterIdentity("example.net")))
	first, err := allowed.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	second, err := diam.NewRequest(272, 7, fixtureDictionary()).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Write(append(first, second...)); n != 0 || !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("combined frames bypassed application scope: %d %v", n, err)
	}
	for remote.Load() == nil {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		default:
			time.Sleep(time.Millisecond)
		}
	}
	remote.Load().conn.Close()
	for !clock.stopped.Load() {
		select {
		case <-ctx.Done():
			t.Fatal("remote FIN retained expiry timer")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func TestPlainDialBaseHooksCannotBypassExpiry(t *testing.T) {
	serverSettings := fixtureSettings("peer.example.net", "example.net")
	remote := make(chan diam.Conn, 1)
	serverSettings.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { remote <- c }
	addr := fixturePeer(t, serverSettings, nil, nil)
	d := liveDiscovery(t, addr, TCP)
	var current atomic.Pointer[time.Time]
	initial := time.Now()
	current.Store(&initial)
	d.cfg.Now = func() time.Time { return *current.Load() }
	clock := &heldClock{}
	var calls atomic.Int32
	settings := fixtureSettings("client.example.net", "example.net")
	settings.OnDWR = func(diam.Conn, *diam.Message) { calls.Add(1) }
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, Request{Realm: "example.net", ApplicationID: 4, Transports: []Transport{TCP}}, DialConfig{Settings: settings, Policy: Policy{AllowPlaintext: true, Authorize: authorizeFixture}, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	expires := conn.(*expiryConn).expires
	current.Store(&expires)
	message := diam.NewRequest(diam.DeviceWatchdog, 0, fixtureDictionary())
	message.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example.net")))
	message.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example.net")))
	var other diam.Conn
	select {
	case other = <-remote:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := message.WriteTo(other); err != nil {
		t.Fatal(err)
	}
	for !clock.stopped.Load() {
		select {
		case <-ctx.Done():
			t.Fatal("expired base request did not close connection")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("expired callback received connection")
	}
}
