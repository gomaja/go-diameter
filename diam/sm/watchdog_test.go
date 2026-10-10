package sm

import (
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

const loopWatchdogTw = 50 * time.Millisecond

type loopWatchdogProbe struct {
	conn    *watchdogProbeConn
	signals *watchdogSignals
	events  chan WatchdogEvent
	stop    chan struct{}
	exited  chan struct{}
}

func startLoopWatchdog(t *testing.T) *loopWatchdogProbe {
	t.Helper()
	signals := newWatchdogSignals()
	p := &loopWatchdogProbe{
		conn:    newWatchdogProbeConn(),
		signals: &signals,
		events:  make(chan WatchdogEvent, 16),
		stop:    make(chan struct{}),
		exited:  make(chan struct{}),
	}
	w := connWatchdog{
		conn:     p.conn,
		done:     p.conn.closed,
		stop:     p.stop,
		signals:  p.signals,
		dwac:     p.signals.dwac,
		interval: func() time.Duration { return loopWatchdogTw },
		send: func() bool {
			_, _ = p.conn.Write(nil)
			p.events <- WatchdogRequestSent
			return true
		},
		observe: func(event WatchdogEvent) { p.events <- event },
	}
	go func() { w.run(); close(p.exited) }()
	synctest.Wait()
	t.Cleanup(func() { p.conn.Close(); <-p.exited })
	return p
}

func (p *loopWatchdogProbe) wantEvent(t *testing.T, want WatchdogEvent) {
	t.Helper()
	select {
	case got := <-p.events:
		if got != want {
			t.Fatalf("watchdog event = %q, want %q", got, want)
		}
	default:
		t.Fatalf("missing watchdog event %q", want)
	}
}

func (p *loopWatchdogProbe) wantNoEvent(t *testing.T) {
	t.Helper()
	select {
	case got := <-p.events:
		t.Fatalf("unexpected watchdog event %q", got)
	default:
	}
}

func (p *loopWatchdogProbe) wantWrites(t *testing.T, want int) {
	t.Helper()
	if got := len(p.conn.writes); got != want {
		t.Fatalf("DWR writes = %d, want %d", got, want)
	}
}

func TestConnWatchdogStateOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := startLoopWatchdog(t)
		time.Sleep(loopWatchdogTw - time.Nanosecond)
		synctest.Wait()
		p.wantNoEvent(t)
		p.wantWrites(t, 0)

		time.Sleep(time.Nanosecond)
		synctest.Wait()
		p.wantEvent(t, WatchdogRequestSent)
		p.wantWrites(t, 1)

		time.Sleep(loopWatchdogTw)
		synctest.Wait()
		p.wantEvent(t, WatchdogSuspect)
		p.wantWrites(t, 1) // RFC 3539 §3.4.1 [2], Appendix A: one Pending request.
		if p.conn.Closed() {
			t.Fatal("SUSPECT closed the transport before DOWN")
		}

		time.Sleep(loopWatchdogTw)
		synctest.Wait()
		p.wantEvent(t, WatchdogTimedOut)
		p.wantWrites(t, 1)
		if !p.conn.Closed() {
			t.Fatal("DOWN did not close the transport")
		}
	})
}

func TestConnWatchdogTrafficRecoversButKeepsPending(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := startLoopWatchdog(t)
		time.Sleep(2 * loopWatchdogTw)
		synctest.Wait()
		p.wantEvent(t, WatchdogRequestSent)
		p.wantEvent(t, WatchdogSuspect)
		p.signals.received()
		synctest.Wait()
		p.wantEvent(t, WatchdogRecovered)
		time.Sleep(loopWatchdogTw)
		synctest.Wait()
		p.wantEvent(t, WatchdogSuspect)
		p.wantWrites(t, 1) // RFC 3539 Appendix A: traffic recovers, but only DWA clears Pending.
		if p.conn.Closed() {
			t.Fatal("SUSPECT closed the transport")
		}
	})
}

func TestConnWatchdogDWAClearsPending(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := startLoopWatchdog(t)
		time.Sleep(loopWatchdogTw)
		synctest.Wait()
		p.wantEvent(t, WatchdogRequestSent)
		p.signals.dwac <- struct{}{}
		synctest.Wait()
		time.Sleep(loopWatchdogTw)
		synctest.Wait()
		p.wantEvent(t, WatchdogRequestSent)
		p.wantWrites(t, 2) // RFC 3539 §3.4.1 [2]: DWA permits the next DWR.
	})
}

func TestConnWatchdogTrafficResetsTw(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := startLoopWatchdog(t)
		time.Sleep(40 * time.Millisecond)
		p.signals.received()
		synctest.Wait()
		time.Sleep(49 * time.Millisecond)
		synctest.Wait()
		p.wantNoEvent(t)
		p.wantWrites(t, 0)
		time.Sleep(time.Millisecond)
		synctest.Wait()
		p.wantEvent(t, WatchdogRequestSent) // RFC 3539 §3.4.1 [2]: received traffic resets Tw.
	})
}

func TestConnWatchdogBoundaryTrafficWins(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// The reader can record activity at the expiry timestamp before the
		// watchdog goroutine receives from timer.C. Preloading that timestamp
		// makes this tie deterministic instead of racing two timer callbacks.
		signals := newWatchdogSignals()
		signals.last.Store(time.Now().Add(loopWatchdogTw).UnixNano())
		p := &loopWatchdogProbe{
			conn: newWatchdogProbeConn(), signals: &signals,
			events: make(chan WatchdogEvent, 4), stop: make(chan struct{}), exited: make(chan struct{}),
		}
		w := connWatchdog{
			conn: p.conn, done: p.conn.closed, stop: p.stop, signals: &signals, dwac: signals.dwac,
			interval: func() time.Duration { return loopWatchdogTw },
			send: func() bool {
				_, _ = p.conn.Write(nil)
				p.events <- WatchdogRequestSent
				return true
			},
			observe: func(event WatchdogEvent) { p.events <- event },
		}
		go func() { w.run(); close(p.exited) }()
		synctest.Wait()
		defer func() { p.conn.Close(); <-p.exited }()
		time.Sleep(loopWatchdogTw)
		synctest.Wait()
		p.wantNoEvent(t)
		p.wantWrites(t, 0)
		time.Sleep(loopWatchdogTw)
		synctest.Wait()
		p.wantEvent(t, WatchdogRequestSent)
	})
}

func TestConnWatchdogStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := startLoopWatchdog(t)
		close(p.stop)
		synctest.Wait()
		select {
		case <-p.exited:
		default:
			t.Fatal("watchdog did not exit on stop")
		}
		time.Sleep(3 * loopWatchdogTw)
		synctest.Wait()
		p.wantNoEvent(t)
		p.wantWrites(t, 0)
		if p.conn.Closed() {
			t.Fatal("stop closed the transport")
		}
	})
}

func TestConnWatchdogDone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := startLoopWatchdog(t)
		p.conn.Close()
		synctest.Wait()
		select {
		case <-p.exited:
		default:
			t.Fatal("watchdog remained running after connection done")
		}
		p.wantNoEvent(t)
		p.wantWrites(t, 0)
	})
}

func TestJitteredTwBounds(t *testing.T) {
	const twinit, jitter = 30 * time.Second, 2 * time.Second
	var seenLow, seenHigh bool
	for range 1000 {
		got := jitteredTw(twinit, jitter)
		if got < twinit-jitter || got > twinit+jitter {
			t.Fatalf("jittered Tw = %s, want [%s,%s] (RFC 3539 §3.4.1 [1])", got, twinit-jitter, twinit+jitter)
		}
		seenLow = seenLow || got < twinit
		seenHigh = seenHigh || got > twinit
	}
	if !seenLow || !seenHigh {
		t.Fatal("Tw jitter did not vary on both sides of Twinit")
	}
	if got := jitteredTw(twinit, 0); got != twinit {
		t.Fatalf("zero-jitter Tw = %s, want %s", got, twinit)
	}
}

func TestPublishDWRStoppedBeforeWrite(t *testing.T) {
	c := newWatchdogProbeConn()
	var stopped atomic.Bool
	stopped.Store(true)
	mu := new(sync.Mutex)
	events := make(chan WatchdogEvent, 1)
	if publishDWR(c, regressionDWR(t), 3, mu, &stopped, func(event WatchdogEvent) { events <- event }, nil) {
		t.Fatal("stopped watchdog published a DWR")
	}
	if got := len(c.writes); got != 0 {
		t.Fatalf("DWR writes after stop = %d, want zero", got)
	}
	select {
	case got := <-events:
		t.Fatalf("event after stop = %q", got)
	default:
	}
}

type watchdogDispatchConn struct {
	*watchdogProbeConn
	dispatched <-chan struct{}
}

func (c watchdogDispatchConn) DispatchDone() <-chan struct{} { return c.dispatched }

type watchdogOuterCloseNotifier struct {
	diam.Conn
	closed <-chan struct{}
}

func (c watchdogOuterCloseNotifier) CloseNotify() <-chan struct{} { return c.closed }
func (c watchdogOuterCloseNotifier) Unwrap() diam.Conn            { return c.Conn }

func TestConnectionDoneWrapperPrecedence(t *testing.T) {
	inner := watchdogDispatchConn{newWatchdogProbeConn(), make(chan struct{})}
	outerClose := make(chan struct{})
	for _, tc := range []struct {
		name string
		conn diam.Conn
		want <-chan struct{}
	}{
		{"direct", inner, inner.dispatched},
		{"unwrapped", unwrapTestConn{inner}, inner.dispatched},
		{"outer close notifier", watchdogOuterCloseNotifier{inner, outerClose}, outerClose},
		{"close notifier fallback", inner.watchdogProbeConn, inner.closed},
		{"opaque wrapper", struct{ diam.Conn }{inner}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := connectionDone(tc.conn); got != tc.want {
				t.Fatalf("connectionDone(%T) = %v, want %v", tc.conn, got, tc.want)
			}
		})
	}
}

func TestAcceptedWatchdogWarnsWithoutLifecycleNotifier(t *testing.T) {
	cfg := *serverSettings
	cfg.EnableWatchdog = true
	logs := logtest.New()
	inner := newWatchdogProbeConn()
	// Embedding diam.Conn hides the optional lifecycle methods on inner.
	c := loggedWatchdogConn{Conn: struct{ diam.Conn }{inner}, logger: slog.New(logs)}
	sm := mustNewStateMachine(t, &cfg)
	sm.startWatchdog(c)
	if records := logs.Records(); len(records) != 1 || records[0].Level != slog.LevelWarn ||
		records[0].Message != "sm: watchdog disabled: connection exposes neither DispatchDone nor CloseNotifier" {
		t.Fatalf("watchdog warning records = %v", records)
	}
	if _, ok := sm.watchdogs.Load(c); ok {
		t.Fatal("watchdog registered without a lifecycle notifier")
	}
}

type blockingPublishWatchdogConn struct {
	*watchdogProbeConn
	entered chan struct{}
	release chan struct{}
}

func (c *blockingPublishWatchdogConn) WriteStream(b []byte, stream uint) (int, error) {
	close(c.entered)
	<-c.release
	return c.watchdogProbeConn.WriteStream(b, stream)
}

func TestPublishDWRHoldsEventLockThroughWriteAndEvent(t *testing.T) {
	c := &blockingPublishWatchdogConn{
		watchdogProbeConn: newWatchdogProbeConn(),
		entered:           make(chan struct{}),
		release:           make(chan struct{}),
	}
	mu := new(sync.Mutex)
	events := make(chan WatchdogEvent, 1)
	lockHeldAtEvent := make(chan bool, 1)
	result := make(chan bool, 1)
	request := regressionDWR(t)
	go func() {
		result <- publishDWR(c, request, 3, mu, nil, func(event WatchdogEvent) {
			if mu.TryLock() {
				mu.Unlock()
				lockHeldAtEvent <- false
			} else {
				lockHeldAtEvent <- true
			}
			events <- event
		}, nil)
	}()
	<-c.entered
	// RFC 6733 §5.6 R-Open: answer publication cannot overtake the
	// request while WriteToStream is blocked or while the event is emitted.
	if mu.TryLock() {
		mu.Unlock()
		t.Fatal("DWA observer lock was available during blocked DWR write")
	}
	close(c.release)
	if ok := <-result; !ok {
		t.Fatal("DWR publication failed")
	}
	if !<-lockHeldAtEvent {
		t.Fatal("DWA observer lock was available during request event")
	}
	if got := <-events; got != WatchdogRequestSent {
		t.Fatalf("event = %q, want request_sent", got)
	}
	if got := len(c.writes); got != 1 {
		t.Fatalf("DWR writes = %d, want one", got)
	}
}

var _ diam.Conn = (*watchdogProbeConn)(nil)

type failedPublishWatchdogConn struct {
	*watchdogProbeConn
	mu              *sync.Mutex
	unlockedAtClose bool
}

func (*failedPublishWatchdogConn) WriteStream([]byte, uint) (int, error) {
	return 0, errors.New("watchdog write failed")
}

func (c *failedPublishWatchdogConn) Close() {
	if c.mu.TryLock() {
		c.unlockedAtClose = true
		c.mu.Unlock()
	}
	c.watchdogProbeConn.Close()
}

func TestPublishDWRReleasesEventLockBeforeClose(t *testing.T) {
	mu := new(sync.Mutex)
	c := &failedPublishWatchdogConn{watchdogProbeConn: newWatchdogProbeConn(), mu: mu}
	var event WatchdogEvent
	if publishDWR(c, regressionDWR(t), 0, mu, nil, func(e WatchdogEvent) { event = e }, nil) {
		t.Fatal("failed write reported success")
	}
	if event != WatchdogWriteFailed || !c.Closed() {
		t.Fatalf("event = %s, closed = %v", event, c.Closed())
	}
	if !c.unlockedAtClose {
		t.Fatal("write failure held event lock during Close; a waiting DWA observer can deadlock")
	}
}
