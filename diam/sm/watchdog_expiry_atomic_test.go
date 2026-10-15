package sm

import (
	"slices"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/watchdog"
)

// The old empty check happens before the injected clock is sampled. Admit a
// matching answer there, then resume after the old deadline but before receipt
// + Tw. No sleeps or scheduler ordering are needed (RFC 3539 Appendix A).
func TestWatchdogReceiptAndExpiryAreAtomic(t *testing.T) {
	for _, suspect := range []bool{false, true} {
		for _, validated := range []bool{false, true} {
			name := map[bool]string{false: "pending", true: "suspect"}[suspect] + "/" +
				map[bool]string{false: "validating", true: "credited"}[validated]
			t.Run(name, func(t *testing.T) {
				c := newWatchdogProbeConn()
				defer c.Close()
				signals := newWatchdogSignals()
				request := regressionDWR(t)
				header := *request.Header
				signals.request.Store(&header)
				answer := acceptedDWA(t, request, diam.Success)
				// Large virtual intervals leave actual receipt time safely before
				// the old deadline, regardless of test-machine scheduling.
				const tw = 10 * time.Hour
				base := time.Now()
				window := watchdog.Window{ArmedAt: base.Add(-9 * time.Hour), After: tw}
				oldDeadline := window.ArmedAt.Add(window.After)
				initial := watchdogState{pending: true, suspect: suspect}
				state := initial
				var receipt watchdogReceipt
				var events []WatchdogEvent
				admitted := false
				writes := 0
				unlocked := func(where string) {
					t.Helper()
					if !signals.mu.TryLock() {
						t.Fatalf("%s holds receipt mutex", where)
					}
					signals.mu.Unlock()
				}
				finish := func() {
					t.Helper()
					if kind, _ := processDWAReceipt(c, answer, &signals, nil, receipt); kind != "" {
						t.Fatalf("matching DWA rejected: %s", kind)
					}
				}
				w := connWatchdog{conn: c, signals: &signals,
					interval: func() time.Duration { unlocked("interval"); return tw },
					now: func() time.Time {
						unlocked("clock")
						if !admitted {
							admitted = true
							receipt = signals.receivedMessage(answer)
							if !receipt.at.Before(oldDeadline) {
								t.Fatal("scripted DWA was not timely")
							}
							if validated {
								finish()
							}
						}
						return oldDeadline.Add(time.Hour)
					},
					send:    func() bool { unlocked("write"); writes++; return true },
					observe: func(e WatchdogEvent) { unlocked("observer"); events = append(events, e) },
				}
				alive, waiting := w.advance(&window, &state)
				if !validated {
					if !alive || !waiting || state != initial || len(events) != 0 || c.Closed() {
						t.Fatalf("expiry overtook admitted DWA validation: alive=%v waiting=%v state=%+v events=%v closed=%v", alive, waiting, state, events, c.Closed())
					}
					finish()
					alive, waiting = w.advance(&window, &state)
				}
				wantEvents := []WatchdogEvent(nil)
				if suspect {
					wantEvents = []WatchdogEvent{WatchdogRecovered}
				}
				if !alive || waiting || state.pending || state.suspect || c.Closed() || writes != 0 || !slices.Equal(events, wantEvents) {
					t.Fatalf("expiry overtook timely DWA credit: alive=%v waiting=%v state=%+v events=%v closed=%v writes=%d", alive, waiting, state, events, c.Closed(), writes)
				}
				if window.ArmedAt != receipt.at || window.After != tw || queuedWatchdogCredits(&signals) != 0 || signals.validating != 0 {
					t.Fatalf("receipt deadline or credit lost: window=%+v receipt=%v validating=%d", window, receipt.at, signals.validating)
				}
			})
		}
	}
}

func TestWatchdogExpiryActionsReleaseReceiptMutex(t *testing.T) {
	for _, tc := range []struct {
		name   string
		state  watchdogState
		alive  bool
		writes int
		events []WatchdogEvent
	}{
		{name: "probe", alive: true, writes: 1},
		{name: "suspect", state: watchdogState{pending: true}, alive: true, events: []WatchdogEvent{WatchdogSuspect}},
		{name: "timeout", state: watchdogState{pending: true, suspect: true}, events: []WatchdogEvent{WatchdogTimedOut}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newWatchdogProbeConn()
			defer c.Close()
			signals := newWatchdogSignals()
			check := func(where string) {
				t.Helper()
				if !signals.mu.TryLock() {
					t.Fatalf("%s holds receipt mutex", where)
				}
				signals.mu.Unlock()
			}
			var events []WatchdogEvent
			writes := 0
			w := connWatchdog{conn: c, signals: &signals,
				interval: func() time.Duration { check("interval"); return time.Second },
				send: func() bool {
					check("write")
					writes++
					// A write can trigger concurrent receive work without waiting
					// for expiry's receipt mutex.
					signals.received()
					return true
				},
				observe: func(e WatchdogEvent) { check("observer"); events = append(events, e) },
				timeout: func() { check("timeout"); c.Close() },
			}
			window := watchdog.Window{ArmedAt: time.Now().Add(-2 * time.Second), After: time.Second}
			state := tc.state
			alive, waiting := w.advance(&window, &state)
			if alive != tc.alive || waiting || writes != tc.writes || !slices.Equal(events, tc.events) || c.Closed() == tc.alive {
				t.Fatalf("expiry effects: alive=%v waiting=%v writes=%d events=%v closed=%v", alive, waiting, writes, events, c.Closed())
			}
		})
	}
}
