package sm

import (
	"log/slog"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

// RFC 3539 §3.4.1 [1] and Appendix A SetWatchdog: every re-arm draws a new
// Tw, including a reset for ordinary traffic and a successful DWA.
func TestAcceptedWatchdogDoesNotStartOnClosedConnection(t *testing.T) {
	t.Run("no done interface", func(t *testing.T) {
		cfg := newAcceptedWatchdogSettings()
		sm := mustNewStateMachine(t, &cfg)
		logs := logtest.New()
		inner := newAcceptedWatchdogProbeConn()
		inner.Close()
		c := &closedWatchdogConn{Conn: inner, logger: logs.Logger()}
		startAcceptedTestWatchdog(t, sm, c)
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
		startAcceptedTestWatchdog(t, sm, c)
		synctest.Wait()
		if _, ok := acceptedTestSupervisor(sm, c); ok {
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
	startAcceptedTestWatchdog(t, sm, c)
	w := acceptedWatchdogState(t, sm, c)
	t.Cleanup(func() { close(c.done); <-w.exited })
	seen := make(map[time.Duration]bool)
	for range 1000 {
		got := jitteredTw(w.policy.twinit, w.policy.jitter)
		if got < cfg.WatchdogInterval-20*time.Millisecond || got > cfg.WatchdogInterval+20*time.Millisecond {
			t.Fatalf("accepted Tw = %s, want [%s,%s]", got, cfg.WatchdogInterval-20*time.Millisecond, cfg.WatchdogInterval+20*time.Millisecond)
		}
		seen[got] = true
	}
	if len(seen) < 2 {
		t.Fatalf("accepted Tw used %d distinct values; jitter was bypassed", len(seen))
	}
}
