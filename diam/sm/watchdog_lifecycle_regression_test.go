package sm

import (
	"errors"
	"log/slog"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// RFC 6733 §5.6: Disconnect issued while OnHandshake still runs enters
// Closing before supervisor registration. Deferred registration must preserve
// that Closing decision.
func TestAcceptedWatchdogDisconnectDuringOnHandshake(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	synctest.Test(t, func(t *testing.T) {
		cfg := newAcceptedWatchdogSettings()
		entered := make(chan diam.Conn, 1)
		release := make(chan struct{})
		cfg.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { entered <- c; <-release }
		events := acceptedWatchdogEvents(&cfg)
		sm, peer, cleanup := newAcceptedWatchdogPipe(t, &cfg)
		defer cleanup()
		acceptedPipeHandshake(t, peer)
		c := <-entered
		result := make(chan error, 1)
		go func() { result <- sm.Disconnect(c, DisconnectRebooting, time.Hour) }()
		dpr, err := diam.ReadMessage(peer, testDict)
		if err != nil || dpr.Header.CommandCode != diam.DisconnectPeer {
			t.Fatalf("DPR: %v, %v", dpr, err)
		}
		close(release) // OnHandshake returns; deferred registration runs.
		synctest.Wait()
		_, supervised := sm.watchdogs.Load(c)
		got := make(chan *diam.Message, 1)
		go func() { m, _ := diam.ReadMessage(peer, testDict); got <- m }()
		select {
		case m := <-got:
			if m != nil {
				t.Errorf("written in Closing (supervisor registered=%v): %s", supervised, m.Header)
			}
		case <-time.After(3 * cfg.WatchdogInterval):
		}
		select {
		case e := <-events:
			t.Errorf("watchdog event in Closing: %s", e.event)
		default:
		}
		_ = peer.Close()
		<-result
	})
}

// RFC 6733 §5.6: stop must wait for an admitted terminal close, but a
// transport Close must not hold the mutex needed by a pending DWA observer.
func TestAcceptedWatchdogTerminalCloseLocks(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "DOWN", true: "write failure"}[failure], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := newAcceptedWatchdogSettings()
				sm := mustNewStateMachine(t, &cfg)
				c := newAcceptedWatchdogProbeConn()
				if failure {
					c.writeErr = errors.New("DWR write failed")
				}
				defer close(c.done)
				startAcceptedTestWatchdog(t, sm, c)
				w := acceptedWatchdogState(t, sm, c)
				c.afterClose = func() {
					if w.mu.TryLock() {
						w.mu.Unlock()
					} else {
						t.Error("terminal Close held event mutex; DWA observer could deadlock")
					}
				}
				if failure {
					if expireAcceptedTestWatchdog(w) {
						t.Fatal("failed DWR reported success")
					}
				} else {
					timeoutAcceptedTestWatchdog(w)
				}
				if !c.Closed() {
					t.Error("terminal watchdog failure did not close transport")
				}
				sm.stopWatchdog(c)
				<-w.exited
			})
		})
	}
}

func TestAcceptedWatchdogStopWaitsForTerminalClose(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "DOWN", true: "write failure"}[failure], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := newAcceptedWatchdogSettings()
				sm := mustNewStateMachine(t, &cfg)
				c := newAcceptedWatchdogProbeConn()
				if failure {
					c.writeErr = errors.New("DWR write failed")
				}
				defer close(c.done)
				startAcceptedTestWatchdog(t, sm, c)
				w := acceptedWatchdogState(t, sm, c)
				entered, release := make(chan struct{}), make(chan struct{})
				c.afterClose = func() { close(entered); <-release }
				closed := make(chan struct{})
				go func() {
					if failure {
						expireAcceptedTestWatchdog(w)
					} else {
						timeoutAcceptedTestWatchdog(w)
					}
					close(closed)
				}()
				<-entered
				stopped := make(chan struct{})
				go func() { sm.stopWatchdog(c); close(stopped) }()
				synctest.Wait()
				select {
				case <-stopped:
					t.Error("stop returned before terminal Close completed")
				default:
				}
				close(release)
				<-closed
				<-stopped
				<-w.exited
			})
		})
	}
}

func TestAcceptedWatchdogEndedSupervisorIgnoresStaleDWA(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := newAcceptedWatchdogSettings()
		events := acceptedWatchdogEvents(&cfg)
		sm := mustNewStateMachine(t, &cfg)
		inner := newAcceptedWatchdogProbeConn()
		notify := make(chan struct{})
		c := watchdogOuterCloseNotifier{Conn: inner, closed: notify}
		startAcceptedTestWatchdog(t, sm, c)
		w := acceptedWatchdogState(t, sm, c)
		close(notify)
		<-w.exited
		sm.stopWatchdog(c)
		receiveAcceptedTestWatchdog(w, acceptedDWA(t, regressionDWR(t), diam.Success))
		select {
		case event := <-events:
			t.Errorf("ended supervisor emitted %s through stale pointer after stop", event.event)
		default:
		}
	})
}

// RFC 6733 §5.6: a selected DOWN transition cannot log or close after
// stopWatchdog returns. Prepare the expiry before stop, then execute its effects.
func TestAcceptedWatchdogDownCloseAfterStopReturned(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := newAcceptedWatchdogSettings()
		events := acceptedWatchdogEvents(&cfg)
		sm := mustNewStateMachine(t, &cfg)
		logs := logtest.New()
		c := &closingWatchdogConn{newAcceptedWatchdogProbeConn(), logs.Logger()}
		defer close(c.done)
		startAcceptedTestWatchdog(t, sm, c)
		w := acceptedWatchdogState(t, sm, c)
		expireAcceptedTestWatchdog(w) // DWR publishes Pending.
		expireAcceptedTestWatchdog(w) // Next expiry enters SUSPECT.
		<-c.writes
		<-events
		<-events
		timer := w.state.snapshot().Timer(protocol.WatchdogTimer)
		batch := w.state.prepare(protocol.Input{Kind: protocol.TimerExpired, Timer: protocol.WatchdogTimer, Token: timer.Token, At: timer.Deadline})
		sm.stopWatchdog(c) // Closing wins before selected terminal effects execute.
		w.state.run(batch)
		<-w.exited
		if c.Closed() {
			t.Errorf("DOWN closed the transport after stopWatchdog returned")
		}
		for _, r := range logs.Records() {
			if r.Level >= slog.LevelWarn {
				t.Errorf("record after stop: %s %s", r.Level, r.Message)
			}
		}
		select {
		case e := <-events:
			t.Errorf("event after stop: %s", e.event)
		default:
		}
	})
}
