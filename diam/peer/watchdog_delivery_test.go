package peer

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/sm"
)

type receiptClock struct{ *fakeClock }

func (receiptClock) Now() time.Time { return time.Now() }

// A timeout callback can reach the actor before the ingress worker posts an
// earlier receive. It must wait for that decision, including its DWA credit.
func TestManagerWatchdogExpiryWaitsForAdmittedReceives(t *testing.T) {
	for _, dwa := range []bool{false, true} {
		t.Run(map[bool]string{false: "activity", true: "DWA"}[dwa], func(t *testing.T) {
			a, s, clock := newWatchdogTestActor(t, WatchdogOkay)
			s.ingress = make(chan incoming, 8)
			msg := testDWA(t, a)
			if !dwa {
				var err error
				msg, err = base.BuildDWR(a.m.dictionary(), testBase("known.example.net"), 0)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := s.enqueue(msg); err != nil {
				t.Fatal(err)
			}
			clock.fire()
			a.handle(<-a.events)
			if a.watchdog != WatchdogOkay || !a.pendingWatchdog {
				t.Fatalf("expiry overtook admitted receive: %s Pending=%v", a.watchdog, a.pendingWatchdog)
			}
			in := <-s.ingress
			a.m.processDIAMAt(s, in.msg, in.receivedAt, in.sequence)
			a.handle(<-a.events)
			if a.watchdog != WatchdogOkay || a.pendingWatchdog == dwa {
				t.Fatalf("receive after simultaneous expiry: %s Pending=%v, DWA=%v", a.watchdog, a.pendingWatchdog, dwa)
			}
			if dwa && len(s.writes) != 0 {
				t.Fatalf("credited DWA caused an extra probe: %d writes", len(s.writes))
			}
			if !dwa && (len(s.writes) != 1 || (<-s.writes).msg.Header.CommandCode != diam.DeviceWatchdog) {
				t.Fatal("DWR did not receive its required answer")
			}
		})
	}
}

func TestManagerWatchdogDecodedReceiveInvalidatesDeferredExpiry(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(map[bool]string{false: "invalid header", true: "REOPEN DWA"}[recovery], func(t *testing.T) {
			state := WatchdogOkay
			if recovery {
				state = WatchdogReopen
			}
			a, s, clock := newWatchdogTestActor(t, state)
			s.ingress = make(chan incoming, 8)
			answer := testDWA(t, a)
			if !recovery {
				answer.Header.ApplicationID = 4 // decoded rejection resets Tw without credit
			}
			if err := s.enqueue(answer); err != nil {
				t.Fatal(err)
			}
			clock.fire()
			a.handle(<-a.events)
			if !a.pendingWatchdog || len(s.writes) != 0 {
				t.Fatal("expiry did not wait for admitted answer")
			}
			in := <-s.ingress
			a.m.processDIAMAt(s, in.msg, in.receivedAt, in.sequence)
			a.handle(<-a.events)
			if recovery {
				if a.watchdog != WatchdogReopen || a.numDWA != 1 || a.pendingWatchdog || len(s.writes) != 0 {
					t.Fatalf("credited recovery retained expired work: state=%s NumDWA=%d Pending=%v writes=%d", a.watchdog, a.numDWA, a.pendingWatchdog, len(s.writes))
				}
			} else if a.watchdog != WatchdogOkay || !a.pendingWatchdog || len(s.writes) != 0 {
				t.Fatalf("invalid decoded answer failed reset-only receipt: state=%s Pending=%v writes=%d", a.watchdog, a.pendingWatchdog, len(s.writes))
			}
		})
	}
}

func TestManagerWatchdogDeferredExpiryStopsWithGeneration(t *testing.T) {
	for _, retire := range []bool{false, true} {
		t.Run(map[bool]string{false: "Closing", true: "retired"}[retire], func(t *testing.T) {
			a, s, clock := newWatchdogTestActor(t, WatchdogReopen)
			s.ingress = make(chan incoming, 8)
			answer := testDWA(t, a)
			if err := s.enqueue(answer); err != nil {
				t.Fatal(err)
			}
			clock.fire()
			expiry := <-a.events
			a.handle(expiry)
			if !a.pendingWatchdog || a.numDWA != 0 {
				t.Fatal("expiry overtook admitted recovery answer")
			}
			if retire {
				s.retired.Store(true)
				a.retireResponder(retirementCommand{s: s, reason: diam.SCTPAssociationRestart, done: make(chan struct{})})
			} else {
				a.stop(sm.DisconnectRebooting)
			}

			queued := len(s.writes)
			in := <-s.ingress
			a.handle(event{kind: wireEvent, s: s, msg: in.msg, receivedAt: in.receivedAt, receiveSequence: in.sequence})
			a.handle(expiry) // even a duplicated stale callback stays inert
			if len(s.writes) != queued || a.numDWA != 0 || a.watchdog == WatchdogSuspect {
				t.Fatalf("stale expiry/receive changed generation: state=%s NumDWA=%d writes=%d, want %d", a.watchdog, a.numDWA, len(s.writes), queued)
			}
		})
	}
}

// RFC 3539 §3.4.1, Appendix A: ingress/actor backlog is not part of Tw.
// Restoring processing-time arming must change the remaining 400ms to 1s.
func TestManagerWatchdogReceiptBacklogDoesNotExtendTw(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, s, clock := newWatchdogTestActor(t, WatchdogOkay)
		a.m.cfg.Clock = receiptClock{clock}
		a.m.cfg.Now = time.Now
		s.ingress = make(chan incoming, 8)
		a.m.mu.Lock()
		a.m.sessions[s.c] = s
		a.m.mu.Unlock()
		a.m.wg.Add(1)
		go s.dispatch()
		request, err := base.BuildDWR(a.m.dictionary(), testBase("known.example.net"), 0)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		time.Sleep(100 * time.Millisecond)
		go func() { a.m.ServeDIAM(s.c, request); close(done) }()
		synctest.Wait()
		time.Sleep(600 * time.Millisecond)
		e := <-a.events
		a.delivery = e.delivery
		a.handle(e)
		a.delivery = nil
		e.delivery.finish()
		<-done
		clock.mu.Lock()
		last := clock.timers[len(clock.timers)-1]
		clock.mu.Unlock()
		if last.duration != 400*time.Millisecond {
			t.Fatalf("remaining Tw after 600ms backlog = %s, want 400ms from receipt", last.duration)
		}
	})
}
