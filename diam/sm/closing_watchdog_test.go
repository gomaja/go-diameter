package sm

import (
	"log/slog"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

type closingWatchdogConn struct {
	*acceptedWatchdogProbeConn
	logger *slog.Logger
}

func (c *closingWatchdogConn) Logger() *slog.Logger { return c.logger }

// RFC 6733 §5.6: Closing has no DWR/DWA events, including a DWA dispatched
// through a supervisor pointer loaded before stopWatchdog returned.
func TestAcceptedWatchdogClosingDWA(t *testing.T) {
	for _, name := range []string{"success", "rejected", "malformed"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := newAcceptedWatchdogSettings()
				events := acceptedWatchdogEvents(&cfg)
				sm := mustNewStateMachine(t, &cfg)
				logs := logtest.New()
				c := &closingWatchdogConn{newAcceptedWatchdogProbeConn(), logs.Logger()}
				defer close(c.done)
				sm.startWatchdog(c)
				w := acceptedWatchdogState(t, sm, c)
				sm.stopWatchdog(c)
				<-w.exited

				answer := acceptedDWA(t, regressionDWR(t), diam.Success)
				switch name {
				case "rejected":
					answer = acceptedDWA(t, regressionDWR(t), diam.TooBusy)
				case "malformed":
					answer.AVP = nil
					mustSMClientAVP(t, answer, avp.ResultCode, avp.Mbit, 0, localhostAddress)
				}
				w.dwa.ServeDIAM(c, answer)
				select {
				case got := <-events:
					t.Errorf("watchdog event after stopWatchdog returned: %s", got.event)
				default:
				}
				if len(w.signals.dwac) != 0 {
					t.Error("DWA after stopWatchdog returned credited Pending")
				}
				for _, record := range logs.Records() {
					if record.Level > slog.LevelDebug {
						t.Errorf("DWA after stopWatchdog returned logged %s: %s", record.Level, record.Message)
					}
				}
			})
		})
	}
}

func TestAcceptedWatchdogClosingActivity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := newAcceptedWatchdogSettings()
		sm := mustNewStateMachine(t, &cfg)
		c := newAcceptedWatchdogProbeConn()
		defer close(c.done)
		sm.ServeDIAM(c, regressionCER(t, dict.Default, 1001))
		w := acceptedWatchdogState(t, sm, c)
		sm.stopWatchdog(c)
		<-w.exited
		// Retain the stopped entry to exercise ServeDIAM's activity hook
		// without racing the loop's asynchronous map deletion.
		sm.watchdogs.Store(c, w)
		defer sm.watchdogs.Delete(c)
		routed := false
		sm.Handle("ALL", diam.HandlerFunc(func(diam.Conn, *diam.Message) { routed = true }))
		last := w.signals.last.Load()
		answer := diam.NewRequest(999, 42, dict.Default).Answer(diam.Success)
		sm.ServeDIAM(c, answer)
		if !routed {
			t.Fatal("application answer did not reach its handler")
		}
		// RFC 6733 §5.6: Closing cannot reset the stopped watchdog's Tw.
		if w.signals.last.Load() != last || len(w.signals.signal) != 0 {
			t.Fatal("received activity touched watchdog after stopWatchdog returned")
		}
	})
}

func TestConnWatchdogClosingTimer(t *testing.T) {
	for _, tc := range []struct {
		name     string
		state    watchdogState
		activity bool
		answer   bool
	}{
		{name: "idle"},
		{name: "pending", state: watchdogState{pending: true}},
		{name: "suspect", state: watchdogState{pending: true, suspect: true}},
		{name: "activity", state: watchdogState{pending: true, suspect: true}, activity: true},
		{name: "answer", state: watchdogState{pending: true, suspect: true}, answer: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := newWatchdogProbeConn()
				signals := newWatchdogSignals()
				stop := make(chan struct{})
				w := connWatchdog{
					conn: c, stop: stop, signals: &signals, dwac: signals.dwac,
					send: func() bool { t.Error("timer sent DWR after stop"); return true },
					observe: func(event WatchdogEvent) {
						t.Errorf("timer emitted %s after stop", event)
					},
				}
				armedAt := time.Now()
				timer := time.NewTimer(loopWatchdogTw)
				defer timer.Stop()
				time.Sleep(loopWatchdogTw)
				close(stop)
				if tc.activity {
					signals.received()
				}
				if tc.answer {
					signals.dwac <- struct{}{}
				}
				// Timer and stop are ready at the same virtual instant. Force
				// the timer branch rather than depend on select's random choice.
				<-timer.C
				state := tc.state
				if w.expire(armedAt, &state) {
					t.Error("timer rearmed after stop")
				}
				// RFC 6733 §5.6: stop wins even over pending recovery or DOWN.
				if state != tc.state {
					t.Errorf("timer changed state after stop: %+v, want %+v", state, tc.state)
				}
				if c.Closed() {
					t.Error("timer closed transport after stop")
				}
				if tc.answer && len(signals.dwac) != 1 {
					t.Error("timer consumed queued DWA after stop")
				}
			})
		})
	}
}

func TestAcceptedWatchdogClosingEvents(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := newAcceptedWatchdogSettings()
		events := acceptedWatchdogEvents(&cfg)
		sm := mustNewStateMachine(t, &cfg)
		c := newAcceptedWatchdogProbeConn()
		defer close(c.done)
		sm.startWatchdog(c)
		w := acceptedWatchdogState(t, sm, c)
		sm.stopWatchdog(c)
		<-w.exited

		// A timer or message handler may reach the observer after stop.
		// RFC 6733 §5.6 excludes every watchdog event in Closing.
		for _, event := range []WatchdogEvent{
			WatchdogRequestSent, WatchdogAnswerReceived, WatchdogInvalidAnswer,
			WatchdogWriteFailed, WatchdogSuspect, WatchdogRecovered, WatchdogTimedOut,
		} {
			w.observe(c, event)
			select {
			case got := <-events:
				t.Errorf("watchdog event after stopWatchdog returned: %s", got.event)
			default:
			}
		}
	})
}

func TestAcceptedWatchdogEventsHoldStopLock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := newAcceptedWatchdogSettings()
		var w *acceptedWatchdog
		var events []WatchdogEvent
		cfg.OnWatchdogConnEvent = func(_ diam.Conn, event WatchdogEvent) {
			// RFC 6733 §5.6: checking stopped and invoking the callback
			// must be atomic with stopWatchdog, not just ordered by chance.
			if w.mu.TryLock() {
				w.mu.Unlock()
				t.Errorf("watchdog event %s did not hold stop mutex", event)
			}
			events = append(events, event)
		}
		sm := mustNewStateMachine(t, &cfg)
		c := newAcceptedWatchdogProbeConn()
		defer close(c.done)
		sm.startWatchdog(c)
		w = acceptedWatchdogState(t, sm, c)
		if !w.send() {
			t.Fatal("DWR publication failed")
		}
		w.dwa.ServeDIAM(c, acceptedDWA(t, regressionDWR(t), diam.Success))
		w.dwa.ServeDIAM(c, acceptedDWA(t, regressionDWR(t), diam.TooBusy))
		for _, event := range []WatchdogEvent{
			WatchdogWriteFailed, WatchdogSuspect, WatchdogRecovered, WatchdogTimedOut,
		} {
			w.observe(c, event)
		}
		sm.stopWatchdog(c)
		<-w.exited
		if len(events) != 7 {
			t.Fatalf("watchdog events = %v, want all seven outcomes", events)
		}
	})
}
