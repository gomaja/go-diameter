package sm

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

type completedDWRGateListener struct {
	net.Listener
	entered, release chan struct{}
}

func (l completedDWRGateListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	return &completedDWRGateConn{Conn: c, entered: l.entered, release: l.release}, nil
}

type completedDWRGateConn struct {
	net.Conn
	entered, release chan struct{}
	once             sync.Once
}

func (c *completedDWRGateConn) Write(b []byte) (int, error) {
	h, e := diam.DecodeHeader(b)
	if e == nil && h.CommandCode == 0xeeff {
		c.once.Do(func() { close(c.entered) })
		<-c.release
	}
	return c.Conn.Write(b)
}

type completedDWRConn struct {
	diam.Conn
	selected chan diam.Header
}

func (c *completedDWRConn) Unwrap() diam.Conn { return c.Conn }
func (c *completedDWRConn) WriteStream(b []byte, s uint) (int, error) {
	h, e := diam.DecodeHeader(b)
	if e == nil && h.CommandCode == diam.DeviceWatchdog && h.CommandFlags&diam.RequestFlag != 0 {
		c.selected <- *h
	}
	return c.Conn.WriteStream(b, s)
}

type completedDWRLog struct {
	slog.Handler
	mark func(string)
}

func (h completedDWRLog) Handle(c context.Context, r slog.Record) error {
	h.mark("log:" + r.Message)
	return h.Handler.Handle(c, r)
}
func (h completedDWRLog) WithAttrs(a []slog.Attr) slog.Handler {
	return completedDWRLog{h.Handler.WithAttrs(a), h.mark}
}
func (h completedDWRLog) WithGroup(g string) slog.Handler {
	return completedDWRLog{h.Handler.WithGroup(g), h.mark}
}

// RFC 3539 Appendix A and RFC 6733 section 6.2.1: completion consumes a
// selected request before a blocked native publication gate is released.
func TestAcceptedCompletedDWRNativeGate(t *testing.T) {
	cfg := newAcceptedWatchdogSettings()
	cfg.WatchdogInterval = time.Hour
	cfg.watchdogTiming = &watchdogTiming{floor: time.Millisecond}
	var orderMu sync.Mutex
	var order []string
	mark := func(v string) { orderMu.Lock(); order = append(order, v); orderMu.Unlock() }
	notices := make(chan struct{}, 1)
	events := make(chan WatchdogEvent, 8)
	cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) {
		mark(fmt.Sprintf("protocol:%s/%d", e.Err.Kind(), e.Err.ResultCode()))
		notices <- struct{}{}
	}
	cfg.OnWatchdogConnEvent = func(_ diam.Conn, e WatchdogEvent) {
		mark(fmt.Sprint("watchdog:", e))
		events <- e
	}
	logs := logtest.New()
	sm := mustNewStateMachine(t, &cfg)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	opened := make(chan *completedDWRConn, 1)
	var wrapped *completedDWRConn
	server := &diam.Server{Logger: slog.New(completedDWRLog{logs, mark}), Dict: sm.dictionary, Handler: diam.HandlerFunc(func(_ diam.Conn, m *diam.Message) { sm.ServeDIAM(wrapped, m) }), OnNewConnection: func(c diam.Conn) {
		wrapped = &completedDWRConn{Conn: c, selected: make(chan diam.Header, 2)}
		opened <- wrapped
	}}
	serving := make(chan error, 1)
	go func() { serving <- server.Serve(completedDWRGateListener{ln, entered, release}) }()
	defer func() { unblock(); _ = server.Close(); <-serving }()
	peer, e := net.Dial("tcp", ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer closeDialTest(t, peer)
	if e := peer.SetDeadline(time.Now().Add(10 * time.Second)); e != nil {
		t.Fatal(e)
	}
	var c *completedDWRConn
	select {
	case c = <-opened:
	case <-time.After(10 * time.Second):
		t.Fatal("accepted connection missing")
	}
	cer := regressionCER(t, c.Dictionary(), 1001)
	_, e = cer.WriteTo(peer)
	if e != nil {
		t.Fatal(e)
	}
	if a, e := diam.ReadMessage(peer, c.Dictionary()); e != nil || !testResultCode(a, diam.Success) {
		t.Fatalf("CEA %v %v", a, e)
	}
	state := sm.acceptedCore(c, nil, false)
	deadline := time.Now().Add(10 * time.Second)
	for {
		state.mu.Lock()
		ready := state.watchdog != nil && state.timers[protocol.WatchdogTimer] != nil && state.core.Snapshot().Ready()
		state.mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("accepted watchdog did not publish its production timer")
		}
		runtime.Gosched()
	}
	timer := state.snapshot().Timer(protocol.WatchdogTimer)
	if timer.Token == 0 {
		t.Fatal("accepted watchdog timer missing")
	}
	orderMu.Lock()
	order = nil
	orderMu.Unlock()
	application := make(chan error, 1)
	go func() { _, e := diam.NewRequest(0xeeff, 4, c.Dictionary()).WriteTo(c); application <- e }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("application gate not entered")
	}
	expired := make(chan struct{})
	go func() {
		state.apply(protocol.Input{Kind: protocol.TimerExpired, Timer: protocol.WatchdogTimer, Token: timer.Token, At: timer.Deadline})
		close(expired)
	}()
	var h diam.Header
	select {
	case h = <-c.selected:
	case <-time.After(10 * time.Second):
		t.Fatal("DWR not selected")
	}
	dwa := acceptedDWA(t, diam.NewMessage(h.CommandCode, h.CommandFlags, h.ApplicationID, h.HopByHopID, h.EndToEndID, c.Dictionary()), diam.UnableToComply)
	setWireIdentity(t, dwa, avp.OriginHost, "peer.example")
	setWireIdentity(t, dwa, avp.OriginRealm, "example")
	// Bind to the CER identity rather than relying on helper defaults.
	host, _ := cer.FindAVP(avp.OriginHost, 0)
	realm, _ := cer.FindAVP(avp.OriginRealm, 0)
	setWireIdentity(t, dwa, avp.OriginHost, string(host.Data.(datatype.DiameterIdentity)))
	setWireIdentity(t, dwa, avp.OriginRealm, string(realm.Data.(datatype.DiameterIdentity)))
	if _, e = dwa.WriteTo(peer); e != nil {
		t.Fatal(e)
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		controls := state.snapshot().Controls()
		if len(controls) == 0 || len(controls) == 1 && controls[0].Answered {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("matching rejected DWA not consumed: %+v phase=%v", controls, state.snapshot().Phase())
		}
		runtime.Gosched()
	}
	// Cancellation must wake the native writer while the unrelated application
	// still owns the physical gate. Completion also disposes the core's writer
	// pin and identifier lease before any new probe can be selected.
	select {
	case <-expired:
	case <-time.After(10 * time.Second):
		t.Fatal("completed DWR writer still waits for the application gate")
	}
	state.mu.Lock()
	writes, headers := len(state.writes), len(state.writeHeaders)
	controls := state.core.Snapshot().Controls()
	state.mu.Unlock()
	if writes != 0 || headers != 0 || len(controls) != 0 {
		t.Fatalf("completed DWR retained writer or pin: writers=%d headers=%d controls=%+v", writes, headers, controls)
	}
	select {
	case <-notices:
	case <-time.After(10 * time.Second):
		t.Fatal("rejected DWA protocol callback waits for the application gate")
	}
	wantOrder := []string{
		fmt.Sprint("watchdog:", WatchdogInvalidAnswer),
		"log:sm: rejected DWA",
		fmt.Sprintf("protocol:%s/%d", diam.ProtocolRejectedDWA, diam.UnableToComply),
	}
	orderMu.Lock()
	observed := append([]string(nil), order...)
	orderMu.Unlock()
	if !reflect.DeepEqual(observed, wantOrder) {
		t.Fatalf("rejected DWA observer order=%v; want %v", observed, wantOrder)
	}
	if len(logs.Records()) != 1 {
		t.Fatalf("warning records=%v", logs.Records())
	}

	// Receipt starts a fresh Tw. Its next expiry must select a new probe even
	// though the canceled writer never acquired publication ownership.
	next := state.snapshot().Timer(protocol.WatchdogTimer)
	if next.Token == 0 || next.Token == timer.Token {
		t.Fatalf("rejected DWA did not replace Tw: old=%+v next=%+v", timer, next)
	}
	freshDone := make(chan struct{})
	go func() {
		state.apply(protocol.Input{Kind: protocol.TimerExpired, Timer: protocol.WatchdogTimer, Token: next.Token, At: next.Deadline})
		close(freshDone)
	}()
	var fresh diam.Header
	select {
	case fresh = <-c.selected:
	case <-time.After(10 * time.Second):
		t.Fatal("next Tw did not select a fresh DWR")
	}
	if fresh.HopByHopID == h.HopByHopID || fresh.EndToEndID == h.EndToEndID {
		t.Fatalf("fresh probe reused completed identifiers: old=%+v fresh=%+v", h, fresh)
	}
	controls = state.snapshot().Controls()
	if len(controls) != 1 || !controls[0].Logical || controls[0].Writers != 1 || controls[0].Answered {
		t.Fatalf("fresh DWR has no live writer pin: %+v", controls)
	}
	unblock()
	select {
	case e := <-application:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("application writer did not finish")
	}
	if m, e := diam.ReadMessage(peer, c.Dictionary()); e != nil || m.Header.CommandCode != 0xeeff {
		t.Fatalf("application=%v err=%v", m, e)
	}
	probe, e := diam.ReadMessage(peer, c.Dictionary())
	if e != nil || probe.Header.CommandCode != diam.DeviceWatchdog || probe.Header.HopByHopID != fresh.HopByHopID || probe.Header.EndToEndID != fresh.EndToEndID {
		t.Fatalf("fresh DWR wire frame=%v err=%v; selected=%+v", probe, e, fresh)
	}
	select {
	case <-freshDone:
	case <-time.After(10 * time.Second):
		t.Fatal("fresh DWR writer did not finish")
	}
	answer := acceptedDWA(t, probe, diam.Success)
	setWireIdentity(t, answer, avp.OriginHost, string(host.Data.(datatype.DiameterIdentity)))
	setWireIdentity(t, answer, avp.OriginRealm, string(realm.Data.(datatype.DiameterIdentity)))
	if _, e := answer.WriteTo(peer); e != nil {
		t.Fatal(e)
	}
	for _, want := range []WatchdogEvent{WatchdogInvalidAnswer, WatchdogRequestSent, WatchdogAnswerReceived} {
		select {
		case got := <-events:
			if got != want {
				t.Fatalf("watchdog event=%v; want %v", got, want)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("missing watchdog event %v", want)
		}
	}
	// A later frame fences the completed writer and the fresh exchange.
	if _, e := diam.NewRequest(0xeefe, 4, c.Dictionary()).WriteTo(c); e != nil {
		t.Fatal(e)
	}
	if m, e := diam.ReadMessage(peer, c.Dictionary()); e != nil || m.Header.CommandCode != 0xeefe {
		t.Fatalf("completed DWR reached wire before application fence: message=%v err=%v", m, e)
	}
}
