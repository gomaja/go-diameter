package dnsdiam

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

func TestDialAuthorizationCannotCrossDeadline(t *testing.T) {
	addr := fixturePeer(t, fixtureSettings("peer.example.net", "example.net"), nil, nil)
	d := liveDiscovery(t, addr, TCP)
	var ticks atomic.Int64
	ticks.Store(time.Now().UnixNano())
	d.cfg.Now = func() time.Time { return time.Unix(0, ticks.Load()) }
	var callbacks atomic.Int32
	settings := fixtureSettings("client.example.net", "example.net")
	settings.OnHandshake = func(diam.Conn, *smpeer.Metadata) { callbacks.Add(1) }
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, Request{Realm: "example.net", ApplicationID: 4, Transports: []Transport{TCP}}, DialConfig{Settings: settings, Policy: Policy{AllowPlaintext: true, Authorize: func(Candidate, diam.Conn, *smpeer.Metadata) error { ticks.Add(int64(2 * time.Minute)); return nil }}, Clock: &heldClock{}})
	if conn != nil {
		conn.Close()
	}
	if !errors.Is(err, ErrExpired) || callbacks.Load() != 0 {
		t.Fatalf("post-deadline admission: %v callbacks=%d", err, callbacks.Load())
	}
}

func TestDialZeroTTLTransmitsNoCER(t *testing.T) {
	var cers atomic.Int32
	settings := fixtureSettings("peer.example.net", "example.net")
	settings.OnCER = func(diam.Conn, *diam.Message) { cers.Add(1) }
	addr := fixturePeer(t, settings, nil, nil)
	d := liveDiscovery(t, addr, TCP)
	resolver := d.cfg.Resolver.(*fakeResolver)
	key := lookupKey{"example.net.", TypeNAPTR}
	answer := resolver.answers[key]
	answer.Records[0].TTL = 0
	resolver.answers[key] = answer
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, Request{Realm: "example.net", ApplicationID: 4, Transports: []Transport{TCP}}, DialConfig{Settings: fixtureSettings("client.example.net", "example.net"), Policy: Policy{AllowPlaintext: true, Authorize: authorizeFixture}})
	if conn != nil {
		conn.Close()
	}
	if !errors.Is(err, ErrExpired) || cers.Load() != 0 {
		t.Fatalf("zero TTL transmitted CER: %v count=%d", err, cers.Load())
	}
}

func TestPendingCapabilityExchangeEndsAtDNSDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	workerDone := make(chan struct{})
	accepted := make(chan struct{}, 1)
	go func() {
		defer close(workerDone)
		conn, err := listener.Accept()
		if err == nil {
			defer func() { _ = conn.Close() }()
			accepted <- struct{}{}
			<-done
		}
	}()
	defer func() { close(done); _ = listener.Close(); <-workerDone }()
	d := liveDiscovery(t, listener.Addr().String(), TCP)
	resolver := d.cfg.Resolver.(*fakeResolver)
	key := lookupKey{"example.net.", TypeNAPTR}
	answer := resolver.answers[key]
	answer.Records[0].TTL = 1
	resolver.answers[key] = answer
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		conn, err := d.DialContext(ctx, Request{Realm: "example.net", ApplicationID: 4, Transports: []Transport{TCP}}, DialConfig{Settings: fixtureSettings("client.example.net", "example.net"), Policy: Policy{AllowPlaintext: true, Authorize: authorizeFixture}, MaxRetransmits: 10, RetransmitInterval: 5 * time.Second})
		if conn != nil {
			conn.Close()
		}
		result <- err
	}()
	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("unanswered CER admitted")
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("capability wait outlived DNS TTL")
	}
}

func TestIncomingApplicationMustMatchDiscovery(t *testing.T) {
	settings := fixtureSettings("peer.example.net", "example.net")
	sent := make(chan error, 1)
	settings.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) {
		_, err := diam.NewRequest(272, 7, fixtureDictionary()).WriteTo(c)
		sent <- err
	}
	addr := fixturePeer(t, settings, nil, nil)
	d := liveDiscovery(t, addr, TCP)
	local := fixtureSettings("client.example.net", "example.net")
	local.AuthApplicationID = append(local.AuthApplicationID, diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(7)))
	admitted := make(chan diam.Conn, 1)
	local.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { admitted <- c }
	var messages atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, _ := d.DialContext(ctx, Request{Realm: "example.net", ApplicationID: 4, Transports: []Transport{TCP}}, DialConfig{Settings: local, Policy: Policy{AllowPlaintext: true, Authorize: authorizeFixture}, Handler: diam.HandlerFunc(func(diam.Conn, *diam.Message) { messages.Add(1) })})
	if conn != nil {
		defer conn.Close()
	}
	select {
	case err := <-sent:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var validated diam.Conn
	select {
	case validated = <-admitted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	notifier, ok := diam.ConnAs[diam.CloseNotifier](validated)
	if !ok {
		t.Fatal("missing close notification")
	}
	select {
	case <-notifier.CloseNotify():
	case <-ctx.Done():
		t.Fatal("unapproved application did not close connection")
	}
	if messages.Load() != 0 {
		t.Fatal("application handler received an unapproved application")
	}
}
