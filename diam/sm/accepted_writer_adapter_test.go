package sm

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

// Pause at the Conn boundary, after the adapter has selected a real write.
// Short counts and failures must remain writer results when Closing stops
// watchdog observations (RFC 6733 §§3,5.4,5.6).
type acceptedWriterResultConn struct {
	*acceptedAdapterNotifyConn
	entered, release chan struct{}
	count            int
	err              error
}

func (c *acceptedWriterResultConn) WriteStream(b []byte, stream uint) (int, error) {
	h, err := diam.DecodeHeader(b)
	if err == nil && h.CommandCode == diam.DeviceWatchdog && h.CommandFlags&diam.RequestFlag != 0 {
		close(c.entered)
		<-c.release
		if c.count < 0 {
			return len(b) - 1, c.err
		}
		return c.count, c.err
	}
	return c.acceptedAdapterNotifyConn.WriteStream(b, stream)
}

func TestAcceptedWriterAttemptFailureCrossesClosing(t *testing.T) {
	for _, result := range []struct {
		name  string
		count int
		err   error
	}{
		{"short-count", -1, nil},
		{"transport-failure", 0, errors.New("synthetic DWR transport failure")},
		{"partial-closing-error", 1, diam.ErrConnectionClosing},
		{"partial-completed-error", 1, diam.ErrRequestCompleted},
		{"partial-retired-error", 1, diam.ErrConnectionRetired},
	} {
		for _, closing := range []string{"local", "peer"} {
			t.Run(result.name+"/"+closing, func(t *testing.T) {
				cfg := newAcceptedWatchdogSettings()
				cfg.WatchdogInterval = time.Hour
				events := acceptedWatchdogEvents(&cfg)
				var peerNotices int
				cfg.OnDPR = func(diam.Conn, DisconnectCause) { peerNotices++ }
				sm := mustNewStateMachine(t, &cfg)
				c := &acceptedWriterResultConn{
					acceptedAdapterNotifyConn: &acceptedAdapterNotifyConn{handshakeConn: newHandshakeConn(), closed: make(chan struct{})},
					entered:                   make(chan struct{}), release: make(chan struct{}), count: result.count, err: result.err,
				}
				startAcceptedTestWatchdog(t, sm, c)
				w := acceptedWatchdogState(t, sm, c)
				var once sync.Once
				unblock := func() { once.Do(func() { close(c.release) }) }
				t.Cleanup(func() { unblock(); c.Close(); w.stop(); <-w.exited })
				written := make(chan struct{})
				go func() { expireAcceptedTestWatchdog(w); close(written) }()
				<-c.entered
				if controls := w.state.snapshot().Controls(); len(controls) != 1 || controls[0].Writers != 1 {
					t.Fatalf("blocked DWR did not pin its lease: %+v", controls)
				}
				finished := make(chan error, 1)
				if closing == "local" {
					go func() { finished <- sm.Disconnect(c, DisconnectBusy, time.Hour) }()
				} else {
					dpr := acceptedDPR(t)
					go func() { sm.ServeDIAM(c, dpr); finished <- nil }()
				}
				deadline := time.Now().Add(time.Second)
				for w.state.snapshot().Phase() != protocol.Closing || !w.stopped.Load() {
					if time.Now().After(deadline) {
						t.Fatal("Closing did not stop observations while the writer was blocked")
					}
					time.Sleep(time.Millisecond)
				}
				unblock()
				<-written
				if phase := w.state.snapshot().Phase(); phase != protocol.Closed {
					t.Errorf("attempted DWR failure was skipped: phase=%v, want Closed", phase)
				}
				if !c.Closed() {
					t.Error("attempted DWR failure left the transport open")
				}
				select {
				case err := <-finished:
					if closing == "local" && !errors.Is(err, ErrDisconnectClosed) {
						t.Errorf("Disconnect result=%v, want ErrDisconnectClosed", err)
					}
				case <-time.After(100 * time.Millisecond):
					t.Error("attempted DWR failure did not release the Closing caller")
				}
				if controls := w.state.snapshot().Controls(); len(controls) != 0 {
					t.Errorf("completed DWR retained a core lease or later DPR: %+v", controls)
				}
				w.state.mu.Lock()
				selected := len(w.state.writes)
				w.state.mu.Unlock()
				if selected != 0 {
					t.Errorf("completed DWR retained %d selected native tickets", selected)
				}
				if len(events) != 0 || peerNotices != 0 || len(c.writes) != 0 {
					t.Errorf("obsolete execution escaped: watchdog=%d OnDPR=%d writes=%d", len(events), peerNotices, len(c.writes))
				}
				// Complete cleanup even on the pre-fix path with a pending DPR.
				w.state.apply(protocol.Input{Kind: protocol.Abort})
			})
		}
	}
}

func TestAcceptedWriterUnattemptedProbeStaysSkipped(t *testing.T) {
	cfg := newAcceptedWatchdogSettings()
	cfg.WatchdogInterval = time.Hour
	events := acceptedWatchdogEvents(&cfg)
	sm := mustNewStateMachine(t, &cfg)
	c := &acceptedWriterResultConn{
		acceptedAdapterNotifyConn: &acceptedAdapterNotifyConn{handshakeConn: newHandshakeConn(), closed: make(chan struct{})},
		entered:                   make(chan struct{}), release: make(chan struct{}),
	}
	close(c.release)
	startAcceptedTestWatchdog(t, sm, c)
	w := acceptedWatchdogState(t, sm, c)
	t.Cleanup(func() { c.Close(); w.stop(); <-w.exited })
	timer := w.state.snapshot().Timer(protocol.WatchdogTimer)
	reservation := w.state.prepare(protocol.Input{Kind: protocol.TimerExpired, Timer: protocol.WatchdogTimer, Token: timer.Token, At: timer.Deadline})
	var token uint64
	for _, e := range reservation.effects {
		if e.Kind == protocol.ReserveIDs {
			token = e.Token
		}
	}
	if token == 0 {
		t.Fatal("watchdog did not select an ID reservation")
	}
	selected := w.state.prepare(protocol.Input{Kind: protocol.ReserveResult, Token: token, Reservation: protocol.Reservation{Token: token, Hop: 41, End: 42}})
	if controls := w.state.snapshot().Controls(); len(controls) != 1 || controls[0].Writers != 1 {
		t.Fatalf("selected DWR did not own a writer pin: %+v", controls)
	}
	closing := w.state.prepare(protocol.Input{Kind: protocol.Disconnect, Cause: uint32(DisconnectBusy), Timeout: time.Hour})
	w.state.run(selected)
	if w.state.snapshot().Phase() != protocol.Closing || c.Closed() {
		t.Fatal("unattempted DWR changed Closing into transport failure")
	}
	select {
	case <-c.entered:
		t.Fatal("obsolete selected DWR reached the transport")
	default:
	}
	if controls := w.state.snapshot().Controls(); len(controls) != 0 || len(events) != 0 {
		t.Errorf("unattempted DWR retained leases=%+v or observations=%d", controls, len(events))
	}
	w.state.apply(protocol.Input{Kind: protocol.Abort})
	w.state.run(closing)
}

func TestAcceptedWriterGateRejectionStaysSkipped(t *testing.T) {
	for _, rejected := range []struct {
		name string
		err  error
	}{
		{"closing", diam.ErrConnectionClosing},
		{"completed", diam.ErrRequestCompleted},
		{"retired", diam.ErrConnectionRetired},
	} {
		t.Run(rejected.name, func(t *testing.T) {
			cfg := newAcceptedWatchdogSettings()
			cfg.WatchdogInterval = time.Hour
			events := acceptedWatchdogEvents(&cfg)
			sm := mustNewStateMachine(t, &cfg)
			c := &acceptedWriterResultConn{
				acceptedAdapterNotifyConn: &acceptedAdapterNotifyConn{handshakeConn: newHandshakeConn(), closed: make(chan struct{})},
				entered:                   make(chan struct{}), release: make(chan struct{}), err: rejected.err,
			}
			startAcceptedTestWatchdog(t, sm, c)
			w := acceptedWatchdogState(t, sm, c)
			var once sync.Once
			unblock := func() { once.Do(func() { close(c.release) }) }
			t.Cleanup(func() { unblock(); c.Close(); w.stop(); <-w.exited })
			written := make(chan struct{})
			go func() { expireAcceptedTestWatchdog(w); close(written) }()
			protocolGenerationAwait(t, c.entered)
			closing := w.state.prepare(protocol.Input{Kind: protocol.Disconnect, Cause: uint32(DisconnectBusy), Timeout: time.Hour})
			unblock()
			protocolGenerationAwait(t, written)
			if w.state.snapshot().Phase() != protocol.Closing || c.Closed() {
				t.Fatal("gate-rejected DWR changed Closing into transport failure")
			}
			if controls := w.state.snapshot().Controls(); len(controls) != 0 || len(events) != 0 {
				t.Errorf("gate rejection retained leases=%+v or observations=%d", controls, len(events))
			}
			w.state.apply(protocol.Input{Kind: protocol.Abort})
			w.state.run(closing)
		})
	}
}

// Native transports reserve answer ownership at gate admission. Exercise the
// actual response writer and generation teardown, not only a custom Conn.
type acceptedWriterFailureListener struct {
	net.Listener
	entered, release chan struct{}
	err              error
}

func (l acceptedWriterFailureListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &acceptedWriterFailureTCP{Conn: c, entered: l.entered, release: l.release, err: l.err}, nil
}

type acceptedWriterFailureTCP struct {
	net.Conn
	entered, release chan struct{}
	err              error
}

func (c *acceptedWriterFailureTCP) Write(b []byte) (int, error) {
	if h, err := diam.DecodeHeader(b); err == nil && h.CommandCode == diam.DeviceWatchdog && h.CommandFlags&diam.RequestFlag != 0 {
		close(c.entered)
		<-c.release
		if c.err == nil {
			return len(b) - 1, nil
		}
		return 0, c.err
	}
	return c.Conn.Write(b)
}

func TestAcceptedWriterNativeFailureCrossesClosing(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(map[bool]string{false: "transport-failure", true: "short-write"}[short], func(t *testing.T) {
			cfg := newAcceptedWatchdogSettings()
			cfg.WatchdogInterval = time.Hour
			events := acceptedWatchdogEvents(&cfg)
			sm := mustNewStateMachine(t, &cfg)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			failure := errors.New("synthetic native DWR failure")
			if short {
				failure = nil
			}
			accepted := make(chan diam.Conn, 1)
			server := &diam.Server{Handler: sm, Dict: cfg.Dict, OnNewConnection: func(c diam.Conn) { accepted <- c }}
			serving := make(chan error, 1)
			go func() { serving <- server.Serve(acceptedWriterFailureListener{listener, entered, release, failure}) }()
			t.Cleanup(func() { unblock(); _ = server.Close(); <-serving })
			peer, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = peer.Close() })
			c := protocolGenerationAwait(t, accepted)
			writeValidSMErrorCER(t, peer)
			if m, err := diam.ReadMessage(peer, c.Dictionary()); err != nil || !testResultCode(m, diam.Success) {
				t.Fatalf("CEA=%v err=%v", m, err)
			}
			state := sm.acceptedCore(c, nil, false)
			deadline := time.Now().Add(time.Second)
			for state.watchdogState() == nil || !state.snapshot().Ready() {
				if time.Now().After(deadline) {
					t.Fatal("handshake did not enable watchdog")
				}
				time.Sleep(time.Millisecond)
			}
			w := state.watchdogState()
			written := make(chan struct{})
			go func() { expireAcceptedTestWatchdog(w); close(written) }()
			protocolGenerationAwait(t, entered)
			requests := pendingRequests(c)
			if requests == nil || !requests.HasPending() {
				t.Fatal("native DWR did not acquire request ownership")
			}
			finished := make(chan error, 1)
			go func() { finished <- sm.Disconnect(c, DisconnectBusy, time.Hour) }()
			for state.snapshot().Phase() != protocol.Closing || !w.stopped.Load() {
				if time.Now().After(deadline) {
					t.Fatal("Disconnect did not cross native DWR write")
				}
				time.Sleep(time.Millisecond)
			}
			unblock()
			protocolGenerationAwait(t, written)
			select {
			case err := <-finished:
				if !errors.Is(err, ErrDisconnectClosed) {
					t.Errorf("Disconnect result=%v, want ErrDisconnectClosed", err)
				}
			case <-time.After(time.Second):
				t.Error("native attempted DWR failure did not release Disconnect")
				state.apply(protocol.Input{Kind: protocol.Abort})
				_ = protocolGenerationAwait(t, finished)
			}
			if state.snapshot().Phase() != protocol.Closed || !c.Closed() {
				t.Errorf("native DWR failure left generation nonterminal: phase=%v closed=%t", state.snapshot().Phase(), c.Closed())
			}
			protocolGenerationAwait(t, mustConnAs[diam.CloseNotifier](t, c).CloseNotify())
			protocolGenerationAwait(t, mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, c).DispatchDone())
			protocolGenerationAwait(t, w.exited)
			if controls := state.snapshot().Controls(); len(controls) != 0 {
				t.Errorf("native writer retained core leases: %+v", controls)
			}
			state.mu.Lock()
			selected := len(state.writes)
			state.mu.Unlock()
			if selected != 0 || len(events) != 0 {
				t.Errorf("native disposal retained tickets=%d or emitted obsolete observations=%d", selected, len(events))
			}
		})
	}
}
