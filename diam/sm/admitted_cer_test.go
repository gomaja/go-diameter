package sm

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// RFC 6733 sections 5.3 and 5.6: a fresh CER after removal of trusted
// metadata performs real admission and binds the peer for subsequent traffic.
func TestContextAdmissionResumesCER(t *testing.T) {
	d := newSMTestDictionary(creditcontrol.Dictionary())
	cfg := testMessageErrorSettings(d)
	cfg.EnableWatchdog = true
	cfg.WatchdogInterval = time.Hour
	var cerHooks, ceaHooks, handshakes atomic.Int32
	cfg.OnCER = func(c diam.Conn, _ *diam.Message) {
		cerHooks.Add(1)
		// A real CER owns admission even when its pre-hook replaces connection metadata.
		c.SetContext(smpeer.NewContext(context.Background(), &smpeer.Metadata{OriginHost: "hook.example", OriginRealm: "example", CEA: &smparser.CEA{}}))
	}
	cfg.OnCEA = func(diam.Conn, *diam.Message) { ceaHooks.Add(1) }
	cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) { handshakes.Add(1) }
	events := make(chan diam.ProtocolErrorEvent, 4)
	cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
	sm := mustNewStateMachine(t, cfg, d)
	dispatched := make(chan struct{}, 2)
	sm.HandleIdx(diam.CommandIndex{Code: 0xeeff, Request: false}, diam.HandlerFunc(func(diam.Conn, *diam.Message) { dispatched <- struct{}{} }))
	opened := make(chan diam.Conn, 1)
	srv := diamtest.NewUnstartedServer(diam.HandlerFunc(sm.ServeDIAM), d)
	srv.Config.OnNewConnection = func(c diam.Conn) {
		c.SetContext(smpeer.NewContext(context.Background(), &smpeer.Metadata{OriginHost: "old.example", OriginRealm: "example", CEA: &smparser.CEA{}}))
		opened <- c
	}
	srv.Start()
	defer srv.Close()
	peer, e := net.Dial("tcp", srv.Addr)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = peer.Close() }()
	_ = peer.SetDeadline(time.Now().Add(10 * time.Second))
	var c diam.Conn
	select {
	case c = <-opened:
	case <-time.After(10 * time.Second):
		t.Fatal("connection was not opened")
	}
	barrier := func() {
		_, e := diam.NewMessage(0xeeff, 0, 0, 17, 18, d).WriteTo(peer)
		if e != nil {
			t.Fatal(e)
		}
		select {
		case <-dispatched:
		case <-time.After(10 * time.Second):
			t.Fatal("dispatch barrier missing")
		}
	}
	barrier()
	c.SetContext(context.Background())
	cer := regressionCER(t, d, 1001)
	setWireIdentity(t, cer, avp.OriginHost, "new.example")
	setWireIdentity(t, cer, avp.OriginRealm, "example")
	if _, e = cer.WriteTo(peer); e != nil {
		t.Fatal(e)
	}
	if a, e := diam.ReadMessage(peer, d); e != nil || !testResultCode(a, diam.Success) {
		t.Fatalf("fresh CEA=%v err=%v", a, e)
	}
	barrier()
	s := sm.acceptedCore(c, nil, false)
	if cerHooks.Load() != 1 || ceaHooks.Load() != 1 || handshakes.Load() != 1 {
		t.Fatalf("hooks=%d/%d/%d", cerHooks.Load(), ceaHooks.Load(), handshakes.Load())
	}
	if s == nil || s.watchdogState() == nil || s.snapshot().Timer(protocol.WatchdogTimer).Token == 0 {
		t.Fatal("fresh CER did not start accepted watchdog")
	}
	// A real admitted core owns its claims; later context changes cannot
	// replace the identity established by this successful exchange.
	c.SetContext(smpeer.NewContext(context.Background(), &smpeer.Metadata{OriginHost: "forged.example", OriginRealm: "example", CER: &smparser.CER{}}))
	bad := regressionDWR(t)
	setWireIdentity(t, bad, avp.OriginHost, "forged.example")
	setWireIdentity(t, bad, avp.OriginRealm, "example")
	_, _ = bad.WriteTo(peer)
	event := protocolEvent(t, events)
	if event.Err.Kind() != diam.ProtocolInvalidDWR {
		t.Fatalf("forged identity notice=%+v", event)
	}
	good := regressionDWR(t)
	setWireIdentity(t, good, avp.OriginHost, "new.example")
	setWireIdentity(t, good, avp.OriginRealm, "example")
	_, _ = good.WriteTo(peer)
	if a, e := diam.ReadMessage(peer, d); e != nil || !testResultCode(a, diam.Success) {
		t.Fatalf("bound DWA=%v err=%v", a, e)
	}
	if c.Closed() {
		t.Fatal("valid bound DWR closed the connection")
	}
}
