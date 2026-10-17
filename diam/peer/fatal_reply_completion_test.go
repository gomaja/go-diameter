package peer

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

// The dispatcher and actor own the decision; the test selects its writer so
// completion, disposal and session termination can be exercised independently.
func fatalReplySession(t *testing.T) (*Manager, *session, *fakeClock, chan diam.ProtocolErrorEvent) {
	t.Helper()
	a, s, clock := newWatchdogTestActor(t, WatchdogOkay)
	a.cfg.NoAutoReconnect = true
	s.m.cfg.Timers.Closing = 50 * time.Millisecond
	s.ingress = make(chan incoming, 8)
	s.m.sessions[s.c] = s
	events := make(chan diam.ProtocolErrorEvent, 4)
	s.m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
	reportingStartActor(t, a)
	s.m.wg.Add(1)
	go s.dispatch()
	return s.m, s, clock, events
}

func TestFatalMessageErrorWaitsForReplyCompletion(t *testing.T) {
	for _, outcome := range []string{"written", "failed", "short", "skipped", "terminal", "session-ended", "closing-bound"} {
		t.Run(outcome, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				m, s, clock, events := fatalReplySession(t)
				msg := watchdogRequest(t)
				// A fatal body-error callback retains a valid decoded header.
				me := &diam.MessageError{ResultCode: diam.InvalidAVPLength, Fatal: true, Err: io.ErrUnexpectedEOF}
				returned := make(chan error, 1)
				go func() { returned <- m.HandleMessageError(s.c, msg, me) }()
				queued := orderedReplyEvent(t, events)
				if queued.Reply != diam.ProtocolReplyQueued || queued.ReplyCode != diam.InvalidAVPLength || !queued.Closing {
					t.Fatalf("fatal decision = %+v", queued)
				}
				w := requiredQueuedWrite(t, s)
				synctest.Wait()
				select {
				case err := <-returned:
					t.Fatalf("handler returned before reply completion: %v", err)
				default:
				}
				switch outcome {
				case "session-ended":
					s.closeObserved()
				case "closing-bound":
					clock.mu.Lock()
					timer := clock.timers[len(clock.timers)-1]
					clock.mu.Unlock()
					if timer.duration != m.cfg.Timers.Closing {
						t.Fatalf("reply bound = %s, want %s", timer.duration, m.cfg.Timers.Closing)
					}
					timer.f()
				case "terminal":
					s.abortProtocol()
					s.finishProtocolWriter(w, protocol.SkippedStage, 0, diam.ErrConnectionRetired)
				case "skipped":
					s.c.Close()
					s.writeProtocol(w)
				default:
					c := &queuedReplyWriteConn{fakeConn: s.c.(*fakeConn), short: outcome == "short"}
					if outcome == "failed" {
						c.err = io.ErrClosedPipe
					}
					s.c = c
					s.writeProtocol(w)
				}
				if err := <-returned; err != nil {
					t.Fatal(err)
				}
				if outcome == "closing-bound" || outcome == "session-ended" {
					s.abortProtocol()
					s.finishProtocolWriter(w, protocol.SkippedStage, 0, diam.ErrConnectionRetired)
				}
				synctest.Wait()
				if outcome == "failed" || outcome == "short" || outcome == "skipped" {
					failed := orderedReplyEvent(t, events)
					if !errors.Is(failed.Err, diam.ProtocolReplyFailure) || failed.Reply != diam.ProtocolReplyFailed {
						t.Fatalf("failed reply = %+v", failed)
					}
				}
				if len(events) != 0 {
					t.Fatalf("unexpected additional reply events: %d", len(events))
				}
			})
		})
	}
}

func TestMessageErrorWithoutFatalReplyDoesNotWait(t *testing.T) {
	for _, answer := range []bool{false, true} {
		t.Run(map[bool]string{false: "fatal-answer", true: "nonfatal-request"}[answer], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				m, s, _, _ := fatalReplySession(t)
				msg := watchdogRequest(t)
				me := &diam.MessageError{ResultCode: diam.InvalidAVPLength, Fatal: !answer}
				if !answer {
					msg.Header.CommandFlags = 0
				}
				if err := m.HandleMessageError(s.c, msg, me); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

// This transport retains a write until closure even after its native deadline.
// It separates the decision's bound from the write deadline at publication.
type fatalReplyBlockedConn struct {
	net.Conn
	entered chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (c *fatalReplyBlockedConn) Write([]byte) (int, error) {
	close(c.entered)
	<-c.closed
	return 0, io.ErrClosedPipe
}
func (c *fatalReplyBlockedConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

type fatalReplyHandler struct {
	*Manager
	returned chan struct{}
}

func (h *fatalReplyHandler) HandleMessageError(c diam.Conn, msg *diam.Message, me *diam.MessageError) error {
	err := h.Manager.HandleMessageError(c, msg, me)
	close(h.returned)
	return err
}
func (h *fatalReplyHandler) Unwrap() diam.Handler { return h.Manager }

func TestFatalMessageReplyBlockedWriteEndsAtClosingBound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		settings := testSettings("local.example.net")
		events := make(chan diam.ProtocolErrorEvent, 4)
		settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
		const bound = 50 * time.Millisecond
		m, err := New(Config{Settings: settings, Timers: Timers{Closing: bound, CER: time.Hour}})
		if err != nil {
			t.Fatal(err)
		}
		raw, remote := net.Pipe()
		defer func() { _ = remote.Close() }()
		c := &fatalReplyBlockedConn{Conn: raw, entered: make(chan struct{}), closed: make(chan struct{})}
		l := &restartScriptListener{conn: c, closed: make(chan struct{})}
		handler := &fatalReplyHandler{Manager: m, returned: make(chan struct{})}
		srv := &diam.Server{Dict: settings.Dict}
		if err := m.BindServer(srv); err != nil {
			t.Fatal(err)
		}
		srv.Handler = handler
		served := make(chan error, 1)
		go func() { served <- srv.Serve(l) }()
		defer func() {
			_ = srv.Close()
			if err := <-served; err != nil && !errors.Is(err, diam.ErrServerClosed) {
				t.Error(err)
			}
			closeManager(t, m, nil)
		}()
		header := &diam.Header{Version: 2, MessageLength: 20, CommandCode: diam.CapabilitiesExchange, CommandFlags: diam.RequestFlag, HopByHopID: 7, EndToEndID: 8}
		start := time.Now()
		if _, err := remote.Write(header.Serialize()); err != nil {
			t.Fatal(err)
		}
		queued := orderedReplyEvent(t, events)
		if queued.Reply != diam.ProtocolReplyQueued {
			t.Fatalf("decision = %+v", queued)
		}
		<-c.entered
		synctest.Wait()
		select {
		case <-handler.returned:
			t.Fatal("reader returned before write completion or Closing bound")
		default:
		}
		select {
		case <-handler.returned:
		case <-time.After(bound + time.Millisecond):
			t.Fatal("blocked write held reader beyond Closing bound")
		}
		if elapsed := time.Since(start); elapsed != bound {
			t.Fatalf("reader waited %s, want %s", elapsed, bound)
		}
		var b [1]byte
		if n, err := remote.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("after bound read = %d,%v", n, err)
		}
		failed := orderedReplyEvent(t, events)
		if failed.Reply != diam.ProtocolReplyFailed || !errors.Is(failed.Err, diam.ProtocolReplyFailure) {
			t.Fatalf("failure = %+v", failed)
		}
		synctest.Wait()
		if len(events) != 0 {
			t.Fatalf("duplicate failure: %d", len(events))
		}
	})
}

func TestFatalReplyFailurePreservesBlockedQueuedObserver(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m, s, _, events := fatalReplySession(t)
		entered, release := make(chan struct{}), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		defer unblock()
		m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) {
			if e.Reply == diam.ProtocolReplyQueued {
				close(entered)
				<-release
			}
			events <- e
		}
		returned := make(chan error, 1)
		go func() {
			returned <- m.HandleMessageError(s.c, watchdogRequest(t), &diam.MessageError{ResultCode: diam.InvalidAVPLength, Fatal: true})
		}()
		<-entered
		w := requiredQueuedWrite(t, s)
		s.c = &queuedReplyWriteConn{fakeConn: s.c.(*fakeConn), err: io.ErrClosedPipe}
		s.writeProtocol(w)
		synctest.Wait()
		if len(events) != 0 {
			t.Fatal("failure overtook Queued observer")
		}
		select {
		case <-returned:
			t.Fatal("handler bypassed Queued observer")
		default:
		}
		unblock()
		if err := <-returned; err != nil {
			t.Fatal(err)
		}
		for i, status := range []diam.ProtocolReplyStatus{diam.ProtocolReplyQueued, diam.ProtocolReplyFailed} {
			e := orderedReplyEvent(t, events)
			if e.Reply != status {
				t.Fatalf("event %d = %+v, want %v", i, e, status)
			}
		}
		synctest.Wait()
		if len(events) != 0 {
			t.Fatal("duplicate failed answer event")
		}
	})
}
