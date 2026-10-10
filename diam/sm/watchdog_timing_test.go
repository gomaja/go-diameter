package sm

import (
	"log/slog"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

// RFC 3539 §3.4.1 [1] and Appendix A SetWatchdog: every re-arm draws a new
// Tw, including a reset for ordinary traffic and a successful DWA.
func TestConnWatchdogRedrawsIntervalAfterTrafficAndDWA(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newWatchdogProbeConn()
		signals := newWatchdogSignals()
		events := make(chan WatchdogEvent, 4)
		exited := make(chan struct{})
		var draws atomic.Int32
		intervals := [...]time.Duration{50 * time.Millisecond, 80 * time.Millisecond, 100 * time.Millisecond, 30 * time.Millisecond}
		w := connWatchdog{
			conn: c, done: c.closed, signals: &signals, dwac: signals.dwac,
			interval: func() time.Duration {
				n := draws.Add(1)
				if n <= int32(len(intervals)) {
					return intervals[n-1]
				}
				return time.Hour
			},
			send: func() bool {
				_, _ = c.Write(nil)
				events <- WatchdogRequestSent
				return true
			},
		}
		go func() { w.run(); close(exited) }()
		defer func() { c.Close(); <-exited }()
		wantRequest := func(stage string, writes int) {
			t.Helper()
			select {
			case got := <-events:
				if got != WatchdogRequestSent || len(c.writes) != writes {
					t.Fatalf("%s: event=%s writes=%d, want request_sent/%d", stage, got, len(c.writes), writes)
				}
			default:
				t.Fatalf("%s: missing DWR event", stage)
			}
		}
		synctest.Wait()
		if got := draws.Load(); got != 1 {
			t.Fatalf("initial Tw draws = %d, want 1", got)
		}

		time.Sleep(20 * time.Millisecond)
		signals.received()
		synctest.Wait()
		if got := draws.Load(); got != 2 {
			t.Fatalf("Tw draws after received traffic = %d, want 2", got)
		}
		time.Sleep(80*time.Millisecond - time.Nanosecond)
		synctest.Wait()
		if got := len(c.writes); got != 0 {
			t.Fatalf("DWR writes before redrawn Tw = %d, want 0", got)
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		wantRequest("first redrawn Tw", 1)
		if got := draws.Load(); got != 3 {
			t.Fatalf("Tw draws after DWR re-arm = %d, want 3", got)
		}

		signals.dwac <- struct{}{}
		synctest.Wait()
		if got := draws.Load(); got != 4 {
			t.Fatalf("Tw draws after DWA = %d, want 4", got)
		}
		time.Sleep(30*time.Millisecond - time.Nanosecond)
		synctest.Wait()
		if got := len(c.writes); got != 1 {
			t.Fatalf("DWR writes before DWA-redrawn Tw = %d, want 1", got)
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		wantRequest("DWA-redrawn Tw", 2)
	})
}

// The timer and DWA can be ready together. RFC 3539 Appendix A Rcv-DWA
// clears Pending before the expiry branch may enter SUSPECT.
func TestConnWatchdogExpiryDrainsQueuedDWA(t *testing.T) {
	for _, suspect := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "suspect"}[suspect], func(t *testing.T) {
			signals := newWatchdogSignals()
			signals.dwac <- struct{}{}
			var events []WatchdogEvent
			w := connWatchdog{
				conn: newWatchdogProbeConn(), signals: &signals, dwac: signals.dwac,
				observe: func(event WatchdogEvent) { events = append(events, event) },
			}
			state := watchdogState{pending: true, suspect: suspect}
			if !w.expire(time.Now(), &state) {
				t.Fatal("queued DWA ended watchdog")
			}
			if state.pending || state.suspect {
				t.Fatalf("state after queued DWA = %+v, want OKAY without Pending", state)
			}
			if suspect {
				if len(events) != 1 || events[0] != WatchdogRecovered {
					t.Fatalf("SUSPECT recovery events = %v", events)
				}
			} else if len(events) != 0 {
				t.Fatalf("queued DWA events = %v, want none", events)
			}
			select {
			case <-signals.dwac:
				t.Fatal("queued DWA was not drained")
			default:
			}
		})
	}
}

// RFC 3539 Appendix A INITIAL requires Connection up. A closed accepted
// connection must not acquire a watchdog even if DispatchDone is still open.
func TestAcceptedWatchdogDoesNotStartOnClosedConnection(t *testing.T) {
	t.Run("no done interface", func(t *testing.T) {
		cfg := newAcceptedWatchdogSettings()
		sm := mustNewStateMachine(t, &cfg)
		logs := logtest.New()
		inner := newAcceptedWatchdogProbeConn()
		inner.Close()
		c := &closedWatchdogConn{Conn: inner, logger: logs.Logger()}
		sm.startWatchdog(c)
		if got := logs.Records(); len(got) != 0 {
			t.Fatalf("closed connection produced watchdog diagnostics: %v", got)
		}
	})
	synctest.Test(t, func(t *testing.T) {
		cfg := newAcceptedWatchdogSettings()
		sm := mustNewStateMachine(t, &cfg)
		c := newAcceptedWatchdogProbeConn()
		defer close(c.done)
		c.Close()
		sm.startWatchdog(c)
		synctest.Wait()
		if _, ok := sm.watchdogs.Load(c); ok {
			t.Fatal("closed connection acquired watchdog")
		}
		time.Sleep(4 * cfg.WatchdogInterval)
		synctest.Wait()
		select {
		case <-c.writes:
			t.Fatal("DWR written on closed connection")
		default:
		}
	})
}

// Deliberately expose neither DispatchDone nor CloseNotify through this wrapper.
type closedWatchdogConn struct {
	diam.Conn
	logger *slog.Logger
}

func (c *closedWatchdogConn) Logger() *slog.Logger { return c.logger }

// RFC 3539 §3.4.1 [1], Appendix A SetWatchdog: the accepted-connection
// policy must pass its jitter through to each Tw draw.
func TestAcceptedWatchdogPolicyUsesJitter(t *testing.T) {
	cfg := newAcceptedWatchdogSettings()
	cfg.watchdogTiming = &watchdogTiming{floor: time.Millisecond, jitter: 20 * time.Millisecond}
	sm := mustNewStateMachine(t, &cfg)
	c := newAcceptedWatchdogProbeConn()
	sm.startWatchdog(c)
	w := acceptedWatchdogState(t, sm, c)
	t.Cleanup(func() { close(c.done); <-w.exited })
	seen := make(map[time.Duration]bool)
	for range 1000 {
		got := w.interval()
		if got < cfg.WatchdogInterval-20*time.Millisecond || got > cfg.WatchdogInterval+20*time.Millisecond {
			t.Fatalf("accepted Tw = %s, want [%s,%s]", got, cfg.WatchdogInterval-20*time.Millisecond, cfg.WatchdogInterval+20*time.Millisecond)
		}
		seen[got] = true
	}
	if len(seen) < 2 {
		t.Fatalf("accepted Tw used %d distinct values; jitter was bypassed", len(seen))
	}
}
