package sm

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/watchdog"
)

func queuedWatchdogCredits(s *watchdogSignals) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.credit.at.IsZero() {
		return 1
	}
	return 0
}

func TestDisabledClientWatchdogDoesNotRetainReceipts(t *testing.T) {
	p := newProtocolClientWire(t, nil)
	p.send(t, protocolClientCEA(p.cer, diam.Success))
	if result := p.dialResult(t); result.err != nil {
		t.Fatal(result.err)
	}
	state := p.client.Handler.closingConnection(p.conn)
	state.mu.Lock()
	activity := state.client
	state.mu.Unlock()
	// Finish each real dispatch before inspecting retained receive storage.
	dispatched := make(chan struct{}, 1)
	p.client.Handler.Handle("ALL", diam.HandlerFunc(func(diam.Conn, *diam.Message) { dispatched <- struct{}{} }))
	for range 16 {
		p.send(t, diam.NewRequest(999, 4, p.conn.Dictionary()).Answer(diam.Success))
		<-dispatched
		p.send(t, acceptedDWA(t, regressionDWR(t), diam.Success))
		<-dispatched
	}
	activity.mu.Lock()
	defer activity.mu.Unlock()
	if !activity.activity.at.IsZero() || activity.validating != 0 {
		t.Fatalf("disabled watchdog retained %+v activity and %d pending validations", activity.activity, activity.validating)
	}
}

// RFC 3539 §3.4.1 and Appendix A: a callback backlog must not move the
// receipt's Tw reset to the time the watchdog finally processes it.
func TestWatchdogReceiptBacklogDoesNotExtendTw(t *testing.T) {
	for _, dwa := range []bool{false, true} {
		t.Run(map[bool]string{false: "activity", true: "DWA"}[dwa], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := newWatchdogProbeConn()
				signals := newWatchdogSignals()
				events := make(chan WatchdogEvent, 8)
				release, exited := make(chan struct{}), make(chan struct{})
				request := regressionDWR(t)
				header := *request.Header
				signals.request.Store(&header)
				writes := 0
				w := connWatchdog{
					conn: c, done: c.closed, signals: &signals,
					interval: func() time.Duration { return 50 * time.Millisecond },
					send: func() bool {
						writes++
						signals.published()
						events <- WatchdogRequestSent
						if writes == 1 {
							<-release
						}
						return true
					},
					observe: func(e WatchdogEvent) { events <- e },
				}
				go func() { w.run(); close(exited) }()
				defer func() { c.Close(); <-exited }()
				synctest.Wait()
				time.Sleep(50 * time.Millisecond)
				synctest.Wait()
				if got := <-events; got != WatchdogRequestSent {
					t.Fatalf("first event = %s", got)
				}
				time.Sleep(10 * time.Millisecond)
				if dwa {
					answer := acceptedDWA(t, request, diam.Success)
					receipt := signals.receivedMessage(answer)
					if kind, _ := processDWAReceipt(c, answer, &signals, nil, receipt); kind != "" {
						t.Fatalf("DWA rejected: %s", kind)
					}
				} else {
					signals.received()
				}
				time.Sleep(30 * time.Millisecond)
				close(release) // process a receipt recorded at 60ms only at 90ms
				synctest.Wait()
				time.Sleep(20*time.Millisecond - time.Nanosecond)
				synctest.Wait()
				select {
				case got := <-events:
					t.Fatalf("event before receipt + Tw = %s", got)
				default:
				}
				time.Sleep(time.Nanosecond)
				synctest.Wait()
				want := WatchdogSuspect
				if dwa {
					want = WatchdogRequestSent
				}
				select {
				case got := <-events:
					if got != want {
						t.Fatalf("at receipt + Tw: %s, want %s", got, want)
					}
				default:
					t.Fatalf("missing %s at receipt + Tw; processing backlog extended Tw", want)
				}
			})
		})
	}
}

// A generic reset must not return early and leave already validated DWA credit
// pending while a later expiry is considered (RFC 3539 Appendix A OnReceive).
func TestWatchdogExpiryCommitsActivityAndDWAInOrder(t *testing.T) {
	for _, suspect := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "suspect"}[suspect], func(t *testing.T) {
			c := newWatchdogProbeConn()
			signals := newWatchdogSignals()
			window := watchdog.Window{ArmedAt: time.Now().Add(-time.Second), After: time.Second}
			signals.received()
			request := regressionDWR(t)
			header := *request.Header
			signals.request.Store(&header)
			answer := acceptedDWA(t, request, diam.Success)
			receipt := signals.receivedMessage(answer)
			if kind, _ := processDWAReceipt(c, answer, &signals, nil, receipt); kind != "" {
				t.Fatalf("DWA rejected: %s", kind)
			}
			var events []WatchdogEvent
			w := connWatchdog{conn: c, signals: &signals, interval: func() time.Duration { return time.Second },
				observe: func(e WatchdogEvent) { events = append(events, e) }}
			state := watchdogState{pending: true, suspect: suspect}
			alive, waiting := w.advance(&window, &state)
			if !alive || waiting || state.pending || state.suspect {
				t.Fatalf("activity and DWA ready at expiry: state=%+v; DWA credit was not committed", state)
			}
			want := 0
			if suspect {
				want = 1
			}
			if len(events) != want || want == 1 && events[0] != WatchdogRecovered {
				t.Fatalf("recovery events = %v, want %d recoveries", events, want)
			}
		})
	}
}

// A decoded DWA reserves receipt order before waiting for publication/validation.
// Neither a full Tw of backlog nor later ordinary traffic can overtake it.
func TestWatchdogExpiryWaitsForDWADecision(t *testing.T) {
	for _, valid := range []bool{false, true} {
		t.Run(map[bool]string{false: "invalid", true: "credited"}[valid], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := newWatchdogProbeConn()
				signals := newWatchdogSignals()
				answer := acceptedDWA(t, regressionDWR(t), diam.Success)
				window := watchdog.Window{ArmedAt: time.Now(), After: 50 * time.Millisecond}
				w := connWatchdog{conn: c, signals: &signals, interval: func() time.Duration { return 50 * time.Millisecond },
					send:    func() bool { t.Fatal("expiry sent an extra probe"); return false },
					observe: func(e WatchdogEvent) { t.Fatalf("expiry emitted %s before DWA decision", e) }}
				state := watchdogState{pending: true}
				time.Sleep(40 * time.Millisecond)
				receipt := signals.receivedMessage(answer)
				time.Sleep(10 * time.Millisecond)
				signals.received()
				time.Sleep(60 * time.Millisecond)
				alive, waiting := w.advance(&window, &state)
				if !alive || !waiting || !state.pending || state.suspect {
					t.Fatalf("unfinished DWA at expiry: alive=%v waiting=%v state=%+v", alive, waiting, state)
				}
				// Finish validation and advance at the same virtual instant. The
				// latest receipt's deadline (100ms) has already elapsed at 110ms.
				signals.finishDWA(receipt, valid)
				var got WatchdogEvent
				w.send = func() bool { got = WatchdogRequestSent; return true }
				w.observe = func(e WatchdogEvent) { got = e }
				alive, waiting = w.advance(&window, &state)
				want := WatchdogSuspect
				if valid {
					want = WatchdogRequestSent
				}
				if !alive || waiting || got != want {
					t.Fatalf("overdue receipt deadline: alive=%v waiting=%v event=%s, want %s immediately", alive, waiting, got, want)
				}
			})
		})
	}
}
