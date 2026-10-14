package sm

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

type protocolTimeoutLog struct {
	slog.Handler
	entered chan struct{}
	release <-chan struct{}
}

func (h protocolTimeoutLog) Handle(ctx context.Context, r slog.Record) error {
	err := h.Handler.Handle(ctx, r)
	if r.Message == "sm: handshake timeout; closing connection" {
		close(h.entered)
		<-h.release
	}
	return err
}
func (h protocolTimeoutLog) WithAttrs(a []slog.Attr) slog.Handler {
	h.Handler = h.Handler.WithAttrs(a)
	return h
}
func (h protocolTimeoutLog) WithGroup(group string) slog.Handler {
	h.Handler = h.Handler.WithGroup(group)
	return h
}

func TestProtocolErrorB6CERLosesTimeoutWire(t *testing.T) {
	logs := logtest.New()
	timerEntered, releaseTimer := make(chan struct{}), make(chan struct{})
	cerEntered, releaseCER := make(chan struct{}), make(chan struct{})
	var timerOnce, cerOnce sync.Once
	unblockTimer := func() { timerOnce.Do(func() { close(releaseTimer) }) }
	unblockCER := func() { cerOnce.Do(func() { close(releaseCER) }) }
	events := make(chan diam.ProtocolErrorEvent, 2)
	cfg := testMessageErrorSettings()
	cfg.HandshakeTimeout = 30 * time.Millisecond
	cfg.OnCER = func(diam.Conn, *diam.Message) { close(cerEntered); <-releaseCER }
	cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
	sm := mustNewStateMachine(t, cfg)
	opened := make(chan diam.Conn, 1)
	srv := diamtest.NewUnstartedServer(sm, dict.Default)
	srv.Config.Logger = slog.New(protocolTimeoutLog{logs.Logger().Handler(), timerEntered, releaseTimer})
	srv.Config.OnNewConnection = func(c diam.Conn) { opened <- c }
	srv.Start()
	t.Cleanup(srv.Close)
	t.Cleanup(unblockTimer)
	t.Cleanup(unblockCER)
	peer, err := net.DialTimeout("tcp", srv.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	if err := peer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	c := <-opened
	m := regressionCER(t, dict.Default, 1001)
	wire, err := m.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	writeSMErrorWire(t, peer, wire)
	select {
	case <-cerEntered:
	case <-time.After(time.Second):
		t.Fatal("CER hook missing")
	}
	select {
	case <-timerEntered:
	case <-time.After(time.Second):
		t.Fatal("timeout decision missing")
	}
	// The timer has committed timedOut but has not yet closed. Let the real
	// CER path observe that decision before its CEA write (RFC 6733 §5.6.1).
	unblockCER()
	h, _ := diam.DecodeHeader(wire)
	assertProtocolEvent(t, protocolEvent(t, events), c, h, diam.ProtocolHandshakeState, 0, true, diam.ProtocolReplyNone, 0)
	regressionClosed(t, peer)
	unblockTimer()
	assertProtocolEvent(t, protocolEvent(t, events), c, nil, diam.ProtocolHandshakeTimeout, 0, true, diam.ProtocolReplyNone, 0)
	records := logs.Records()
	if len(records) != 2 || records[0].Level != slog.LevelWarn || records[0].Message != "sm: handshake timeout; closing connection" || records[1].Message != "sm: CER after handshake timeout; closing connection" {
		t.Fatalf("records=%v", records)
	}
}

func TestProtocolErrorB12AcceptedWatchdogTimeoutWire(t *testing.T) {
	p := newProtocolWire(t, func(c *Settings) {
		c.EnableWatchdog = true
		c.WatchdogInterval = 15 * time.Millisecond
		c.watchdogTiming = &watchdogTiming{floor: time.Millisecond}
	}, true)
	dwr, err := diam.ReadMessage(p.peer, dict.Default)
	if err != nil || dwr.Header.CommandCode != diam.DeviceWatchdog || dwr.Header.CommandFlags&diam.RequestFlag == 0 {
		t.Fatalf("DWR=%v %v", dwr, err)
	}
	// Deliberately omit DWA. No peer traffic can reset the two following
	// expiries, and the existing supervisor must reach DOWN (RFC 6733 §5.5.3).
	p.closed(t)
	assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, nil, diam.ProtocolWatchdogTimeout, 0, true, diam.ProtocolReplyNone, 0)
	if records := p.logs.Records(); len(records) != 1 || records[0].Level != slog.LevelWarn || records[0].Message != "sm: watchdog timeout; closing connection" {
		t.Fatalf("records=%v", records)
	}
}
