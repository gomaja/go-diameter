package sm

import (
	"bytes"
	"context"
	"errors"
	"net"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/internal/watchdog"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

type acceptedAdapterNotifyConn struct {
	*handshakeConn
	closed chan struct{}
	once   sync.Once
}

func (c *acceptedAdapterNotifyConn) CloseNotify() <-chan struct{} { return c.closed }
func (c *acceptedAdapterNotifyConn) Close() {
	c.handshakeConn.Close()
	c.once.Do(func() { close(c.closed) })
}

// RFC 6733 §5.4: the accepted adapter retains Disconnect's original writer
// error while still completing the core's terminal transition.
func TestAcceptedAdapterDisconnectPreservesWriterError(t *testing.T) {
	d := newSMTestDictionary(dict.Base())
	sm := mustNewStateMachine(t, testMessageErrorSettings(d), d)
	c := &acceptedAdapterNotifyConn{handshakeConn: newHandshakeConn(), closed: make(chan struct{})}
	cleanup := sm.HandleAccept(c)
	defer cleanup()
	sm.ServeDIAM(c, regressionCER(t, d, 1001))
	<-c.writes
	failure := errors.New("synthetic DPR write failure")
	c.writeErr = failure
	if err := sm.Disconnect(c, DisconnectBusy, time.Second); !errors.Is(err, failure) {
		t.Fatalf("writer error lost: got=%v want=%v", err, failure)
	}
	if !c.Closed() {
		t.Fatal("failed DPR left the connection open")
	}
}

func TestAcceptedAdapterRetainsDialedClientRepeatedCERHooks(t *testing.T) {
	d := newSMTestDictionary(dict.Base())
	cfg := testMessageErrorSettings(d)
	var hooks, notices atomic.Int32
	cfg.OnCER = func(diam.Conn, *diam.Message) { hooks.Add(1) }
	cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) {
		if e.Err.Kind() != diam.ProtocolUnexpectedMessage {
			t.Errorf("repeated CER notice=%+v", e)
		}
		notices.Add(1)
	}
	sm := mustNewStateMachine(t, cfg, d)
	c := newHandshakeConn()
	c.SetContext(smpeer.NewContext(context.Background(), &smpeer.Metadata{CEA: &smparser.CEA{}, OriginHost: "peer.example", OriginRealm: "example"}))
	sm.ServeDIAM(c, regressionCER(t, d, 1001))
	if hooks.Load() != 1 || notices.Load() != 1 {
		t.Fatalf("legacy repeated CER hooks=%d notices=%d, want one each", hooks.Load(), notices.Load())
	}
	if len(c.writes) != 0 || c.Closed() {
		t.Fatal("ignored repeated CER changed the dialed connection")
	}
}

func TestAcceptedAdapterOpaqueHandlerReleasesCore(t *testing.T) {
	d := newSMTestDictionary(dict.Base())
	sm := mustNewStateMachine(t, testMessageErrorSettings(d), d)
	// HandlerFunc deliberately hides AcceptHandler discovery. The fallback
	// core must bind its own lifetime to the native generation's DispatchDone.
	srv := diamtest.NewUnstartedServer(diam.HandlerFunc(sm.ServeDIAM), d)
	accepted := make(chan diam.Conn, 1)
	srv.Config.OnNewConnection = func(c diam.Conn) { accepted <- c }
	srv.Start()
	defer srv.Close()
	peer, err := net.Dial("tcp", srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	if err := peer.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	c := <-accepted
	writeValidSMErrorCER(t, peer)
	if answer, err := diam.ReadMessage(peer, d); err != nil || !testResultCode(answer, diam.Success) {
		t.Fatalf("CEA: %v %v", answer, err)
	}
	_ = peer.Close()
	done := mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, c).DispatchDone()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("dispatch did not exit")
	}
	// Cleanup runs in a separate watcher after DispatchDone closes.
	deadline := time.Now().Add(time.Second)
	for {
		if _, retained := sm.cores.Load(c); !retained {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("opaque handler retained the closed generation core")
		}
		time.Sleep(time.Millisecond)
	}
}

// A Conn exposing neither DispatchDone, CloseNotify nor Unwrap never reports
// its closure, so its core lives in the Conn's context: the StateMachine keeps
// no reference to it, callbacks still queued after Closed find the same core,
// concurrent first messages share one, and it is collected with the Conn.
func TestAcceptedAdapterOpaqueConnCoreLivesWithConn(t *testing.T) {
	d := newSMTestDictionary(dict.Base())
	sm := mustNewStateMachine(t, testMessageErrorSettings(d), d)
	// The StateMachine stays reachable, so it cannot hide a reference by
	// being collected together with the core.
	defer runtime.KeepAlive(sm)
	// Every reference to the connection and its core ends with this closure.
	collected := func() chan struct{} {
		c := newHandshakeConn()
		cer := regressionCER(t, d, 1001)
		cores := make(chan *acceptedHandshake, 8)
		var wg sync.WaitGroup
		for range cap(cores) {
			wg.Go(func() { cores <- sm.acceptedCore(c, cer, true) })
		}
		wg.Wait()
		close(cores)
		state := <-cores
		for other := range cores {
			if other != state {
				t.Fatal("concurrent first messages created separate cores")
			}
		}
		sm.ServeDIAM(c, cer)
		select {
		case <-c.writes:
		case <-time.After(time.Second):
			t.Fatal("CEA not written")
		}
		if state == nil || state.snapshot().Phase() != protocol.Open {
			t.Fatal("opaque connection was not admitted")
		}
		if _, held := sm.cores.Load(c); held {
			t.Fatal("the StateMachine retains the opaque connection's core")
		}
		c.Close()
		if sm.acceptedCore(c, nil, false) != state {
			t.Fatal("a callback queued after Closed lost the connection's core")
		}
		done := make(chan struct{})
		runtime.AddCleanup(state, func(done chan struct{}) { close(done) }, done)
		return done
	}()
	for deadline := time.Now().Add(5 * time.Second); ; {
		runtime.GC()
		select {
		case <-collected:
			return
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("the core outlived its connection")
		}
	}
}

type nilDispatchDoneConn struct{ *handshakeConn }

func (nilDispatchDoneConn) DispatchDone() <-chan struct{} { return nil }

// A lifecycle method that returns no channel supplies no signal either: the
// core lives in the Conn's context rather than behind a watcher that never
// wakes.
func TestAcceptedAdapterNilLifecycleChannelUsesContext(t *testing.T) {
	d := newSMTestDictionary(dict.Base())
	sm := mustNewStateMachine(t, testMessageErrorSettings(d), d)
	c := nilDispatchDoneConn{newHandshakeConn()}
	sm.ServeDIAM(c, regressionCER(t, d, 1001))
	select {
	case <-c.writes:
	case <-time.After(time.Second):
		t.Fatal("CEA not written")
	}
	if _, held := sm.cores.Load(c); held || sm.contextCore(c) == nil {
		t.Fatal("a nil lifecycle channel was treated as a closure signal")
	}
}

// RFC 3539 §3.4.1 and Appendix A: public state observations retain the order
// of committed receive/expiry decisions even when their executors are delayed.
func TestAcceptedAdapterWatchdogObservationsFollowCoreOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := newAcceptedWatchdogSettings()
		cfg.WatchdogInterval = time.Hour
		events := acceptedWatchdogEvents(&cfg)
		sm := mustNewStateMachine(t, &cfg)
		c := newAcceptedWatchdogProbeConn()
		startAcceptedTestWatchdog(t, sm, c)
		w := acceptedWatchdogState(t, sm, c)
		defer func() { c.Close(); close(c.done); sm.stopWatchdog(c); <-w.exited }()
		expireAcceptedTestWatchdog(w)
		request, err := diam.ReadMessage(bytes.NewReader(<-c.writes), c.Dictionary())
		if err != nil {
			t.Fatal(err)
		}
		if got := <-events; got.event != WatchdogRequestSent {
			t.Fatalf("initial event=%s", got.event)
		}
		expireAcceptedTestWatchdog(w)
		if got := <-events; got.event != WatchdogSuspect {
			t.Fatalf("pending probe event=%s", got.event)
		}
		saved := w.state.prepare(protocol.Input{Kind: protocol.Receive, Message: acceptedDWA(t, request, diam.Success)})
		if w.state.snapshot().Watchdog().State != watchdog.Okay {
			t.Fatal("validated DWA did not restore core health")
		}
		later := make(chan struct{})
		go func() { expireAcceptedTestWatchdog(w); close(later) }()
		synctest.Wait()
		if len(events) != 0 || len(c.writes) != 0 {
			t.Fatal("later probe crossed the earlier receive observation")
		}
		select {
		case <-later:
			t.Fatal("later publication finished before the earlier observation")
		default:
		}
		w.state.run(saved)
		synctest.Wait()
		<-later
		<-c.writes
		expireAcceptedTestWatchdog(w)
		var got []WatchdogEvent
		for len(events) != 0 {
			got = append(got, (<-events).event)
		}
		want := []WatchdogEvent{WatchdogAnswerReceived, WatchdogRecovered, WatchdogRequestSent, WatchdogSuspect}
		if !slices.Equal(got, want) || w.state.snapshot().Watchdog().State != watchdog.Suspect {
			t.Fatalf("observations=%v want=%v core=%+v", got, want, w.state.snapshot().Watchdog())
		}
	})
}

func TestAcceptedAdapterHeldUnsupportedRetainsSource(t *testing.T) {
	cfg := newAcceptedWatchdogSettings()
	cfg.EnableWatchdog = false
	var notices []diam.ProtocolErrorEvent
	cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) { notices = append(notices, e) }
	sm := mustNewStateMachine(t, &cfg)
	logs := logtest.New()
	c := &closedWatchdogConn{Conn: newHandshakeConn(), logger: logs.Logger()}
	state := primeAcceptedTestCore(t, sm, c)
	snap := state.snapshot()
	apps := snap.Capabilities().LocalApplications
	if snap.Ready() || len(apps) == 0 {
		t.Fatalf("bad fixture snapshot=%+v", snap)
	}
	m := diam.NewMessage(0xfedc, diam.RequestFlag, apps[0], 0x100, 0x200, c.Dictionary())
	sm.ServeDIAM(c, m)
	state.apply(protocol.Input{Kind: protocol.ReleaseAdmission, Token: snap.Admission()})
	if len(notices) != 1 || notices[0].Message.Header != *m.Header || notices[0].Reply != diam.ProtocolReplyWritten {
		t.Fatalf("held request notice lost source: %+v", notices)
	}
	if records := logs.Records(); len(records) != 1 || records[0].Message != "sm: unsupported command answered" {
		t.Fatalf("held request logs=%v", records)
	}
}

func TestAcceptedAdapterMessageErrorWithoutHeader(t *testing.T) {
	d := newSMTestDictionary(dict.Base())
	sm := mustNewStateMachine(t, testMessageErrorSettings(d), d)
	c := newHandshakeConn()
	_ = sm.HandleMessageError(c, &diam.Message{}, &diam.MessageError{ResultCode: diam.InvalidAVPLength})
}

// Retirement fences effects already selected by the old generation as well as
// later inputs (RFC 6733 §§5.5.4,5.6). Custom Conns need the executor fence too.
func TestAcceptedAdapterRetiredRequiredReplyIsInert(t *testing.T) {
	cfg := testMessageErrorSettings(newSMTestDictionary(dict.Base()))
	var cea, handshake int
	cfg.OnCEA = func(diam.Conn, *diam.Message) { cea++ }
	cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) { handshake++ }
	sm := mustNewStateMachine(t, cfg)
	c := newHandshakeConn()
	cleanup := sm.HandleAccept(c)
	defer cleanup()
	state := sm.acceptedCore(c, nil, false)
	batch := state.prepare(protocol.Input{Kind: protocol.Receive, Message: regressionCER(t, sm.capabilityDictionary(c, nil), 1001)})
	for _, e := range batch.effects {
		if e.Kind == protocol.RunHook {
			batch = state.prepare(protocol.Input{Kind: protocol.Continue, Token: e.Token, Message: e.Message})
			break
		}
	}
	if err := sm.HandleRetire(c, diam.SCTPAssociationRestart); err != nil {
		t.Fatal(err)
	}
	state.run(batch)
	if cea != 0 || handshake != 0 || admittedPeer(c) {
		t.Fatalf("retired effects published callbacks/metadata: CEA=%d handshake=%d", cea, handshake)
	}
	select {
	case wire := <-c.writes:
		t.Fatalf("retired generation transmitted %d bytes", len(wire))
	default:
	}
	if state.snapshot().Phase() != protocol.Retired {
		t.Fatal("retired core changed phase")
	}
}
