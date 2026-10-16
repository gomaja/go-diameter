package sm

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// RFC 6733 §5.6: a received DPR's Closing fence and deadline survive removal
// of externally supplied admission metadata and a subsequent CER.
func TestContextAdmissionCERPreservesClosing(t *testing.T) {
	d := newSMTestDictionary(creditcontrol.Dictionary())
	cfg := testMessageErrorSettings(d)
	cfg.EnableWatchdog, cfg.WatchdogInterval, cfg.DPRCloseTimeout = true, time.Hour, time.Hour
	var cerHooks, ceaHooks, handshakes, peerNotices atomic.Int32
	cfg.OnCER = func(diam.Conn, *diam.Message) { cerHooks.Add(1) }
	cfg.OnCEA = func(diam.Conn, *diam.Message) { ceaHooks.Add(1) }
	cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) { handshakes.Add(1) }
	cfg.OnDPR = func(diam.Conn, DisconnectCause) { peerNotices.Add(1) }
	sm := mustNewStateMachine(t, cfg, d)
	cerHandled, dprHandled, opened := make(chan struct{}, 1), make(chan struct{}, 2), make(chan diam.Conn, 1)
	handler := diam.HandlerFunc(func(c diam.Conn, m *diam.Message) {
		sm.ServeDIAM(c, m)
		if m.Header.CommandCode == diam.CapabilitiesExchange {
			cerHandled <- struct{}{}
		}
		if m.Header.CommandCode == diam.DisconnectPeer {
			dprHandled <- struct{}{}
		}
	})
	meta := &smpeer.Metadata{OriginHost: "peer.example", OriginRealm: "example", CEA: &smparser.CEA{}}
	srv := diamtest.NewUnstartedServer(handler, d)
	srv.Config.OnNewConnection = func(c diam.Conn) {
		c.SetContext(smpeer.NewContext(context.Background(), meta))
		opened <- c
	}
	srv.Start()
	defer srv.Close()
	peer, err := net.Dial("tcp", srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	_ = peer.SetDeadline(time.Now().Add(10 * time.Second))
	var c diam.Conn
	select {
	case c = <-opened:
	case <-time.After(10 * time.Second):
		t.Fatal("connection was not opened")
	}
	dpr := diam.NewMessage(diam.DisconnectPeer, diam.RequestFlag, 0, 17, 18, d)
	mustSMClientAVP(t, dpr, avp.OriginHost, avp.Mbit, 0, meta.OriginHost)
	mustSMClientAVP(t, dpr, avp.OriginRealm, avp.Mbit, 0, meta.OriginRealm)
	mustSMClientAVP(t, dpr, avp.DisconnectCause, avp.Mbit, 0, datatype.Enumerated(0))
	writeDPR := func() {
		t.Helper()
		if _, err := dpr.WriteTo(peer); err != nil {
			t.Fatal(err)
		}
		answer, err := diam.ReadMessage(peer, d)
		if err != nil || answer.Header.CommandCode != diam.DisconnectPeer || answer.Header.HopByHopID != dpr.Header.HopByHopID || !testResultCode(answer, diam.Success) {
			t.Fatalf("DPA checkpoint=%v, error=%v", answer, err)
		}
		select {
		case <-dprHandled:
		case <-time.After(10 * time.Second):
			t.Fatal("DPR dispatch did not finish")
		}
	}
	writeDPR()
	before := sm.acceptedCore(c, nil, false)
	var deadline protocol.TimerSnapshot
	if before != nil {
		deadline = before.snapshot().Timer(protocol.ClosingTimer)
	}
	c.SetContext(context.Background())
	if _, err := regressionCER(t, d, 1001).WriteTo(peer); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cerHandled:
	case <-time.After(10 * time.Second):
		t.Fatal("CER dispatch did not finish")
	}
	if cerHooks.Load() != 0 || ceaHooks.Load() != 0 || handshakes.Load() != 0 {
		t.Fatalf("CER reopened Closing: hooks=%d/%d/%d", cerHooks.Load(), ceaHooks.Load(), handshakes.Load())
	}
	after := sm.acceptedCore(c, nil, false)
	if after == nil || before != after || after.snapshot().Phase() != protocol.Closing || deadline.Token == 0 || after.snapshot().Timer(protocol.ClosingTimer) != deadline || after.snapshot().Timer(protocol.WatchdogTimer).Token != 0 {
		t.Fatal("CER replaced the Closing core, deadline or supervision")
	}
	// Restoring claims allows a repeated DPR to prove that no CEA was queued
	// and that the original Closing generation still owns protocol traffic.
	c.SetContext(smpeer.NewContext(context.Background(), meta))
	dpr.Header.HopByHopID++
	writeDPR()
	if c.Closed() || after.snapshot().Phase() != protocol.Closing || after.snapshot().Timer(protocol.ClosingTimer) != deadline || peerNotices.Load() != 1 {
		t.Fatal("repeat DPR changed the Closing obligation or callback")
	}
}
