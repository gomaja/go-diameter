package sm

import (
	"bytes"
	"log/slog"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
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
				startAcceptedTestWatchdog(t, sm, c)
				w := acceptedWatchdogState(t, sm, c)
				w.state.apply(protocol.Input{Kind: protocol.Disconnect, Cause: uint32(DisconnectBusy), Timeout: time.Hour})
				<-w.exited

				before := w.state.snapshot()
				if before.Phase() != protocol.Closing {
					t.Fatalf("test did not enter Closing: %v", before.Phase())
				}
				sequence := w.state.sequence
				answer := acceptedDWA(t, regressionDWR(t), diam.Success)
				switch name {
				case "rejected":
					answer = acceptedDWA(t, regressionDWR(t), diam.TooBusy)
				case "malformed":
					answer.AVP = nil
					mustSMClientAVP(t, answer, avp.ResultCode, avp.Mbit, 0, localhostAddress)
				}
				receiveAcceptedTestWatchdog(w, answer)
				if w.state.sequence != sequence+1 {
					t.Fatal("stale Closing DWA never reached the production adapter")
				}
				select {
				case got := <-events:
					t.Errorf("watchdog event after stopWatchdog returned: %s", got.event)
				default:
				}
				if w.state.snapshot().Watchdog() != before.Watchdog() {
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
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	synctest.Test(t, func(t *testing.T) {
		cfg := newAcceptedWatchdogSettings()
		sm := mustNewStateMachine(t, &cfg, testDict)
		c := newAcceptedWatchdogProbeConn()
		defer close(c.done)
		sm.ServeDIAM(c, regressionCER(t, testDict, 1001))
		w := acceptedWatchdogState(t, sm, c)
		stopAcceptedTestWatchdog(sm, c)
		<-w.exited
		routed := false
		sm.Handle("ALL", diam.HandlerFunc(func(diam.Conn, *diam.Message) { routed = true }))
		timer := w.state.snapshot().Timer(protocol.WatchdogTimer)
		answer := diam.NewRequest(999, 42, testDict).Answer(diam.Success)
		sm.ServeDIAM(c, answer)
		if !routed {
			t.Fatal("application answer did not reach its handler")
		}
		// RFC 6733 §5.6: Closing cannot reset the stopped watchdog's Tw.
		if w.state.snapshot().Timer(protocol.WatchdogTimer) != timer {
			t.Fatal("received activity touched watchdog after stopWatchdog returned")
		}
	})
}

func TestAcceptedWatchdogClosingEvents(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := newAcceptedWatchdogSettings()
		events := acceptedWatchdogEvents(&cfg)
		sm := mustNewStateMachine(t, &cfg)
		c := newAcceptedWatchdogProbeConn()
		defer close(c.done)
		startAcceptedTestWatchdog(t, sm, c)
		w := acceptedWatchdogState(t, sm, c)
		stopAcceptedTestWatchdog(sm, c)
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
		startAcceptedTestWatchdog(t, sm, c)
		w = acceptedWatchdogState(t, sm, c)
		if !expireAcceptedTestWatchdog(w) {
			t.Fatal("DWR publication failed")
		}
		request, err := diam.ReadMessage(bytes.NewReader(<-c.writes), newSMTestDictionary(dict.Base()))
		if err != nil {
			t.Fatal(err)
		}
		invalid := acceptedDWA(t, request, diam.Success)
		invalid.AVP = nil
		receiveAcceptedTestWatchdog(w, invalid)
		receiveAcceptedTestWatchdog(w, acceptedDWA(t, request, diam.Success))
		for _, event := range []WatchdogEvent{
			WatchdogWriteFailed, WatchdogSuspect, WatchdogRecovered, WatchdogTimedOut,
		} {
			w.observe(c, event)
		}
		stopAcceptedTestWatchdog(sm, c)
		<-w.exited
		if len(events) != 7 {
			t.Fatalf("watchdog events = %v, want all seven outcomes", events)
		}
	})
}
