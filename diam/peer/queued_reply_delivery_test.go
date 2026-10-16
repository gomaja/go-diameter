package peer

import (
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/sm"
)

type queuedReplyWriteConn struct {
	*fakeConn
	err     error
	short   bool
	entered chan struct{}
	release <-chan struct{}
}

func (c *queuedReplyWriteConn) WriteStream(b []byte, _ uint) (int, error) {
	if c.entered != nil {
		close(c.entered)
		<-c.release
	}
	if c.short {
		return len(b) - 1, nil
	}
	if c.err != nil {
		return 0, c.err
	}
	return len(b), nil
}

func queuedReplyGate(t *testing.T) (chan struct{}, func()) {
	t.Helper()
	ch := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(ch) }) }
	t.Cleanup(release)
	return ch, release
}

// Post directly to the running actor so production owns both completion and
// reporting. Taking the selected writer only installs deterministic barriers;
// its original delivery and protocol token remain intact.
func actorSelectedReply(t *testing.T, a *actor, s *session, request *diam.Message) writeRequest {
	t.Helper()
	a.post(event{kind: wireEvent, s: s, msg: request})
	actorDeliveryFence(t, a)
	w := requiredQueuedWrite(t, s)
	if w.replyDelivery == nil {
		t.Fatal("actor-selected writer has no completion delivery")
	}
	t.Cleanup(w.replyDelivery.finish)
	return w
}

func TestActorQueuedReplySuccessFinishesWithoutActorFeedback(t *testing.T) {
	a, s, _ := newWatchdogTestActor(t, WatchdogOkay)
	s.c = &queuedReplyWriteConn{fakeConn: s.c.(*fakeConn)}
	reportingStartActor(t, a)
	w := actorSelectedReply(t, a, s, watchdogRequest(t))
	defer w.replyDelivery.finish()
	if len(w.replyDelivery.notifications) != 0 {
		t.Fatal("ordinary DWA unexpectedly requires admission reporting")
	}

	actorEntered := make(chan struct{})
	releaseActor, unblockActor := queuedReplyGate(t)
	defer unblockActor()
	a.post(event{testHook: func() { close(actorEntered); <-releaseActor }})
	actorDeliveryWait(t, actorEntered, "blocked actor")

	nextWrite := make(chan struct{})
	releaseNext, unblockNext := queuedReplyGate(t)
	defer unblockNext()
	marker := diam.NewMessage(999, 0, 0, 91, 92, a.m.dictionary())
	s.beforePublication = func(msg *diam.Message) {
		if msg == marker {
			close(nextWrite)
			<-releaseNext
		}
	}
	s.writes <- w
	s.writes <- writeRequest{msg: marker}
	done := orderedReplyWriter(t, s)
	// The production writer reaches its next publication only after the DWA's
	// empty delivery and successful operation completion have both finished.
	actorDeliveryWait(t, nextWrite, "next write while actor is blocked")
	if len(a.events) != 0 {
		t.Fatal("successful queued DWA posted actor feedback")
	}
	s.coreMu.Lock()
	writes := len(s.coreWrites)
	s.coreMu.Unlock()
	if writes != 0 || s.protocolSnapshot().Phase() != protocol.Open {
		t.Fatal("successful queued DWA retained writer ownership or changed phase")
	}
	unblockActor()
	s.close()
	unblockNext()
	actorDeliveryWait(t, done, "successful writer exit")
}

func TestActorQueuedReplyFailurePreservesBlockedQueuedNotice(t *testing.T) {
	for _, result := range []string{"failed", "short"} {
		t.Run(result, func(t *testing.T) {
			a, s, _ := newWatchdogTestActor(t, WatchdogOkay)
			c := &queuedReplyWriteConn{fakeConn: s.c.(*fakeConn), short: result == "short"}
			if result == "failed" {
				c.err = io.ErrClosedPipe
			}
			s.c = c
			queued := make(chan struct{})
			releaseObserver, unblockObserver := queuedReplyGate(t)
			defer unblockObserver()
			events := make(chan diam.ProtocolErrorEvent, 4)
			a.m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) {
				if e.Reply == diam.ProtocolReplyQueued {
					close(queued)
					<-releaseObserver
				}
				events <- e
			}
			reportingStartActor(t, a)
			request := diam.NewMessage(0xeeee, diam.RequestFlag, 0, 71, 72, a.m.dictionary())
			w := actorSelectedReply(t, a, s, request)
			defer w.replyDelivery.finish()
			actorDeliveryWait(t, queued, "actor-owned queued observer")
			s.writes <- w
			done := orderedReplyWriter(t, s)
			actorDeliveryWait(t, done, "failed writer while queued observer is blocked")
			reportingAwaitReplyFailure(t, w.replyDelivery)
			// Neither a blocked queued observer nor its deferred failure may own
			// the actor. This fence uses the actual production runner.
			actorDeliveryFence(t, a)
			select {
			case e := <-events:
				t.Fatalf("failure overtook queued observer: %+v", e)
			default:
			}
			unblockObserver()
			for i, want := range []diam.ProtocolReplyStatus{diam.ProtocolReplyQueued, diam.ProtocolReplyFailed} {
				e := orderedReplyEvent(t, events)
				if e.Reply != want || !e.Message.HasHeader || e.Message.Header.HopByHopID != request.Header.HopByHopID || e.Message.Header.EndToEndID != request.Header.EndToEndID || e.ReplyCode != diam.CommandUnsupported {
					t.Fatalf("notification %d lost order or correlation: %+v", i, e)
				}
				if i == 1 && (!e.Closing || !errors.Is(e.Err, diam.ProtocolReplyFailure)) {
					t.Fatalf("failed reply lost typed closing result: %+v", e)
				}
			}
			if len(events) != 0 {
				t.Fatal("duplicate failed reply notification")
			}
		})
	}
}

func TestActorDPRWriterRetainsControlUntilCompletion(t *testing.T) {
	for _, completion := range []string{"early-DPA", "retirement"} {
		t.Run(completion, func(t *testing.T) {
			a, s, _ := newWatchdogTestActor(t, WatchdogOkay)
			a.cfg.NoAutoReconnect = true
			releaseWrite, unblockWrite := queuedReplyGate(t)
			defer unblockWrite()
			enteredWrite := make(chan struct{})
			s.c = &queuedReplyWriteConn{fakeConn: s.c.(*fakeConn), entered: enteredWrite, release: releaseWrite}
			a.m.mu.Lock()
			a.m.sessions[s.c] = s
			a.m.mu.Unlock()
			reportingStartActor(t, a)
			a.post(event{kind: stop, cause: sm.DisconnectRebooting})
			actorDeliveryFence(t, a)
			w := requiredQueuedWrite(t, s)
			if w.msg.Header.CommandCode != diam.DisconnectPeer || w.msg.Header.CommandFlags&diam.RequestFlag == 0 {
				t.Fatal("Closing did not select DPR")
			}
			defer w.replyDelivery.finish()
			s.writes <- w
			done := orderedReplyWriter(t, s)
			actorDeliveryWait(t, enteredWrite, "DPR transport completion barrier")
			if completion == "early-DPA" {
				answer, err := base.BuildDPA(w.msg, testBase(string(a.cfg.Host)))
				if err != nil {
					t.Fatal(err)
				}
				// Manager commits queue publication before processing a DPA.
				// Its native writer can still own a transport completion pin.
				a.post(event{kind: wireEvent, s: s, msg: answer})
				actorDeliveryFence(t, a)
			} else {
				retired := make(chan struct{})
				var retireErr error
				go func() {
					retireErr = a.m.HandleRetire(s.c, diam.SCTPAssociationRestart)
					close(retired)
				}()
				actorDeliveryWait(t, retired, "retirement acknowledgement without joining writer")
				if retireErr != nil {
					t.Fatal(retireErr)
				}
			}
			controls := s.protocolSnapshot().Controls()
			if len(controls) != 1 || controls[0].Command != diam.DisconnectPeer || controls[0].Logical || controls[0].Writers != 1 {
				t.Fatalf("terminal decision lost outstanding DPR writer: %+v", controls)
			}
			unblockWrite()
			actorDeliveryWait(t, done, "terminal DPR writer exit")
			actorDeliveryFence(t, a)
			if controls := s.protocolSnapshot().Controls(); len(controls) != 0 {
				t.Fatalf("completed DPR retained control ownership: %+v", controls)
			}
		})
	}
}
