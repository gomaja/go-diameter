package sm

import (
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

// Test helpers must reach the serialized production adapter even when an
// observer or transport has stopped. The adapter/core owns stale-input policy.
func TestAcceptedWatchdogHelpersDeliverAfterShutdown(t *testing.T) {
	for _, shutdown := range []string{"stopped", "closed"} {
		for _, input := range []string{"receive", "expiry"} {
			t.Run(shutdown+"/"+input, func(t *testing.T) {
				cfg := newAcceptedWatchdogSettings()
				cfg.WatchdogInterval = time.Hour
				sm := mustNewStateMachine(t, &cfg)
				c := newAcceptedWatchdogProbeConn()
				defer close(c.done)
				startAcceptedTestWatchdog(t, sm, c)
				w := acceptedWatchdogState(t, sm, c)
				defer w.stop()
				if shutdown == "stopped" {
					w.latchStop()
				} else {
					c.closed.Store(true)
				}
				before := w.state.snapshot().Timer(protocol.WatchdogTimer)
				sequence := w.state.sequence
				// Holding the real admission mutex makes delivery observable:
				// a helper that filters shutdown returns without acquiring it.
				w.state.mu.Lock()
				done := make(chan struct{})
				message := acceptedDWA(t, regressionDWR(t), diam.Success)
				go func() {
					defer close(done)
					if input == "receive" {
						receiveAcceptedTestWatchdog(w, message)
					} else {
						expireAcceptedTestWatchdog(w)
					}
				}()
				select {
				case <-done:
					w.state.mu.Unlock()
					t.Fatal("shutdown helper returned without delivering input to the production adapter")
				case <-time.After(50 * time.Millisecond):
					w.state.mu.Unlock()
				}
				protocolGenerationAwait(t, done)
				if input == "receive" && w.state.sequence != sequence+1 {
					t.Fatal("shutdown receive did not commit an adapter input")
				}
				if input == "expiry" && w.state.snapshot().Timer(protocol.WatchdogTimer) == before {
					t.Fatal("shutdown expiry did not reach the core timer decision")
				}
			})
		}
	}
}
