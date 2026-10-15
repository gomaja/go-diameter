package protocol

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/watchdog"
)

func disconnectNotices(es []Effect) []Notification {
	var notices []Notification
	for _, e := range es {
		if e.Kind == Notify && e.Notification.Kind == DisconnectNotice {
			notices = append(notices, e.Notification)
		}
	}
	return notices
}

// RFC 6733 §§5.4.2,5.6: an early correlated DPA settles protocol ownership;
// the synchronous frontend retains its selected writer and original deadline
// until the send completes. This send boundary preserves the Disconnect API.
func TestEarlyDPAWaitsForSynchronousWriter(t *testing.T) {
	for _, code := range []uint32{diam.Success, diam.UnableToComply} {
		for _, ending := range []string{"written", "failed", "short", "timeout", "retired", "transport-lost"} {
			t.Run(ending+"/"+diamResultName(code), func(t *testing.T) {
				c := opened(t)
				local := event(Disconnect)
				local.Token = 709
				sent := grant(t, c, fence(t, c, local, false))
				deadline := c.Snapshot().Timer(ClosingTimer)
				answer, err := base.BuildDPAResult(sent.Message, remote(t).Local, code)
				if err != nil {
					t.Fatal(err)
				}
				in := receive(answer)
				in.At = epoch.Add(time.Second)
				wantKinds(t, c.Handle(in))
				controls := c.Snapshot().Controls()
				if c.Snapshot().Phase() != Closing || c.Snapshot().Timer(ClosingTimer) != deadline || len(controls) != 1 || controls[0].Logical || !controls[0].Answered || controls[0].Writers != 1 {
					t.Fatalf("early DPA released send/deadline: snapshot=%+v controls=%+v", c.Snapshot(), controls)
				}
				// A duplicate cannot replace the first result or complete the waiter.
				duplicate, err := base.BuildDPAResult(sent.Message, remote(t).Local, diam.TooBusy)
				if err != nil {
					t.Fatal(err)
				}
				duplicateEffects := c.Handle(receive(duplicate))
				wantKinds(t, duplicateEffects, Discard, Notify)
				if len(disconnectNotices(duplicateEffects)) != 0 || c.Snapshot().Timer(ClosingTimer) != deadline {
					t.Fatal("duplicate DPA changed pending completion")
				}
				finish := complete(sent)
				wantOutcome, wantPhase := Completed, Closed
				switch ending {
				case "failed":
					finish.Err = errors.New("synthetic DPR writer failure")
					wantOutcome = ConnectionClosed
				case "short":
					finish.Bytes--
					wantOutcome = ConnectionClosed
				case "timeout":
					finish = event(TimerExpired)
					finish.Timer, finish.Token, finish.At = ClosingTimer, deadline.Token, deadline.Deadline
					wantOutcome = TimedOut
				case "retired":
					finish = event(Retire)
					wantOutcome, wantPhase = ConnectionClosed, Retired
				case "transport-lost":
					finish = event(TransportLost)
					wantOutcome = ConnectionClosed
				}
				es := c.Handle(finish)
				if c.Snapshot().Phase() != wantPhase || c.Snapshot().Timer(ClosingTimer).Token != 0 {
					t.Fatalf("ending %s phase=%v timer=%+v", ending, c.Snapshot().Phase(), c.Snapshot().Timer(ClosingTimer))
				}
				want := Notification{Kind: DisconnectNotice, Outcome: wantOutcome}
				if ending == "written" {
					want.ResultCode = code
				}
				if got := disconnectNotices(es); len(got) != 1 || got[0] != want {
					t.Fatalf("completion=%+v want=%+v", got, want)
				}
				for _, e := range es {
					if e.Kind == Notify && e.Notification.Kind == DisconnectNotice && e.Token != local.Token {
						t.Fatal("disconnect continuation token lost")
					}
				}
				if ending == "retired" {
					for _, e := range es {
						if e.Kind == Close {
							t.Fatal("retirement selected physical closure")
						}
					}
				} else {
					find(t, es, Close)
				}
				if ending == "timeout" || ending == "retired" || ending == "transport-lost" {
					// Protocol completion cannot dispose an outstanding writer pin.
					if got := c.Snapshot().Controls(); len(got) != 1 || got[0].Writers != 1 {
						t.Fatalf("terminal event lost writer pin: %+v", got)
					}
					wantKinds(t, c.Handle(complete(sent)), ReleaseIDs)
				} else if len(c.Snapshot().Controls()) != 0 {
					t.Fatal("completed writer retained identifiers")
				}
				wantKinds(t, c.Handle(complete(sent)))
				wantKinds(t, c.Handle(receive(answer)))
			})
		}
	}
}

func diamResultName(code uint32) string {
	if code == diam.Success {
		return "success"
	}
	return "unsuccessful"
}

func TestQueuedDPACompletesAtPublishedFrontendBoundary(t *testing.T) {
	c := opened(t, func(cfg *Config) { cfg.QueueWrites = true })
	sent := grant(t, c, fence(t, c, event(Disconnect), false))
	queued := complete(sent)
	queued.Stage = QueueStage
	wantKinds(t, c.Handle(queued))
	answer, err := base.BuildDPA(sent.Message, remote(t).Local)
	if err != nil {
		t.Fatal(err)
	}
	es := c.Handle(receive(answer))
	find(t, es, Close)
	if got := disconnectNotices(es); len(got) != 1 || got[0].Outcome != Completed || got[0].ResultCode != diam.Success {
		t.Fatalf("queued DPA completion=%+v", got)
	}
	if got := c.Snapshot().Controls(); len(got) != 1 || got[0].Writers != 1 || got[0].Logical {
		t.Fatalf("queued completion lost writer pin: %+v", got)
	}
	wantKinds(t, c.Handle(complete(sent)), ReleaseIDs)
}

func TestStopSupervisionAcrossPhases(t *testing.T) {
	for _, name := range []string{"pre", "wait-cea", "candidate", "cea-write", "admission", "open", "suspect", "closing", "closed", "retired"} {
		t.Run(name, func(t *testing.T) {
			configure := func(cfg *Config) { cfg.Watchdog = true; cfg.WatchdogInterval = 6 * time.Second }
			c := machine(t, configure)
			switch name {
			case "pre":
				c.Handle(event(Start))
			case "wait-cea":
				c = machine(t, func(cfg *Config) { configure(cfg); cfg.Role = Initiator })
				grant(t, c, c.Handle(event(Start)))
			case "candidate":
				c.Handle(event(Start))
				find(t, c.Handle(receive(cer(t))), ValidatedCER)
			case "cea-write", "admission":
				sent := find(t, accept(t, c), Send)
				if name == "admission" {
					c.Handle(complete(sent))
				}
			default:
				c = supervised(t, false)
				if name == "suspect" {
					probe(t, c)
					tick(t, c)
				}
				if name == "closing" {
					fence(t, c, receive(request(t, diam.DisconnectPeer)), false)
				}
				if name == "closed" {
					c.Handle(event(Abort))
				}
				if name == "retired" {
					c.Handle(event(Retire))
				}
			}
			before := c.Snapshot()
			es := c.Handle(event(StopSupervision))
			if before.Phase() < Closed && before.Timer(WatchdogTimer).Token != 0 {
				wantKinds(t, es, StopTimer)
				if es[0].Timer != WatchdogTimer || es[0].Token != before.Timer(WatchdogTimer).Token {
					t.Fatalf("wrong timer stopped: %+v", es[0])
				}
			} else {
				wantKinds(t, es)
			}
			after := c.Snapshot()
			if before.Phase() != after.Phase() || before.Ready() != after.Ready() || before.Admission() != after.Admission() || before.Candidate() != after.Candidate() || !reflect.DeepEqual(before.Controls(), after.Controls()) || !reflect.DeepEqual(before.Capabilities(), after.Capabilities()) {
				t.Fatal("stopping supervision changed connection ownership/admission")
			}
			for _, timer := range []TimerKind{HandshakeTimer, RetryTimer, ClosingTimer} {
				if before.Timer(timer) != after.Timer(timer) {
					t.Fatalf("stopping supervision changed timer %v", timer)
				}
			}
			if before.Phase() < Closed && (c.cfg.Watchdog || after.Watchdog().Pending || after.Timer(WatchdogTimer).Token != 0) {
				t.Fatal("supervision remained active")
			}
			wantKinds(t, c.Handle(event(StopSupervision)))
			stale := event(TimerExpired)
			stale.Timer, stale.Token, stale.At = WatchdogTimer, before.Timer(WatchdogTimer).Token, before.Timer(WatchdogTimer).Deadline
			wantKinds(t, c.Handle(stale))
			if name == "pre" {
				sent := find(t, accept(t, c), Send)
				ready := find(t, c.Handle(complete(sent)), HandshakeReady)
				release := event(ReleaseAdmission)
				release.Token = ready.Token
				wantKinds(t, c.Handle(release), Notify)
				if c.Snapshot().Phase() != Open || c.Snapshot().Timer(WatchdogTimer).Token != 0 {
					t.Fatal("later handshake restarted stopped supervision")
				}
			}
		})
	}
}

func TestStoppedSupervisionDisposesSkippedSelectedProbe(t *testing.T) {
	c := supervised(t, false)
	reserved := tick(t, c)
	wantKinds(t, c.Handle(event(StopSupervision)))
	// The executor may already own an allocation/selection obligation. Its
	// skipped result still releases the lease without starting another Tw.
	sent := grant(t, c, reserved)
	skipped := complete(sent)
	skipped.Stage = SkippedStage
	wantKinds(t, c.Handle(skipped), ReleaseIDs)
	if c.Snapshot().Phase() != Open || c.Snapshot().Timer(WatchdogTimer).Token != 0 || c.Snapshot().Watchdog().Pending || len(c.Snapshot().Controls()) != 0 {
		t.Fatal("selected-probe disposal restarted stopped supervision")
	}
}

func TestStoppedSupervisionRetainsFrontendControlAnswerRoutes(t *testing.T) {
	for _, command := range []uint32{diam.DeviceWatchdog, diam.CapabilitiesExchange} {
		for _, handler := range []bool{false, true} {
			c := supervised(t, false)
			probeSend := probe(t, c)
			c.Handle(event(StopSupervision))
			m := dwa(t, probeSend, diam.Success)
			if command == diam.CapabilitiesExchange {
				var err error
				m, err = base.BuildCEA(cer(t), remote(t).Local, diam.Success)
				if err != nil {
					t.Fatal(err)
				}
			}
			in := receive(m)
			in.HasHandler, in.Unhandled = handler, !handler
			before := c.Snapshot().Watchdog()
			es := c.Handle(in)
			if handler {
				wantKinds(t, es, Admit)
				if es[0].Message != m {
					t.Fatal("frontend route lost the original answer")
				}
			} else {
				wantKinds(t, es, Discard, Notify)
				if es[1].Notification.Protocol != diam.ProtocolUnexpectedMessage {
					t.Fatalf("unhandled control answer notice=%+v", es[1].Notification)
				}
			}
			if c.Snapshot().Watchdog() != before || c.Snapshot().Timer(WatchdogTimer).Token != 0 || c.Snapshot().Phase() != Open {
				t.Fatal("late control answer restarted supervision or closed the connection")
			}
		}
	}
}

// RFC 3539 §3.4.1 [2]/Appendix A and #108: a mux miss does not invalidate
// otherwise valid traffic. Rejected application validation remains reset-only.
func TestFrontendUnhandledDiscoverySeparatesActivityAndHealth(t *testing.T) {
	for _, variant := range []string{"unsupported-command", "unsupported-application", "unsupported-application-validation-off", "unhandled-answer"} {
		t.Run(variant, func(t *testing.T) {
			c := supervised(t, false)
			probe(t, c)
			tick(t, c)
			m := diam.NewMessage(999, diam.RequestFlag, 4, 31, 32, c.cfg.Dictionary)
			if variant == "unsupported-application" || variant == "unsupported-application-validation-off" {
				c.cfg.ValidateRequests = variant == "unsupported-application"
				m.Header.ApplicationID = 99
			}
			if variant == "unhandled-answer" {
				m.Header.CommandFlags = 0
			}
			in := receive(m)
			in.Unhandled = true
			in.At = epoch.Add(13 * time.Second)
			es := c.Handle(in)
			if es[0].Kind != StopTimer || es[1].Kind != ArmTimer || es[1].Timer != WatchdogTimer || es[1].Deadline != in.At.Add(6*time.Second) {
				t.Fatalf("receive reset effects=%v", kinds(es))
			}
			state := c.Snapshot().Watchdog()
			if !state.Pending {
				t.Fatal("generic traffic consumed DWR Pending")
			}
			switch variant {
			case "unhandled-answer":
				wantKinds(t, es, StopTimer, ArmTimer, Notify, Admit)
				if state.State != watchdog.Okay || es[2].Notification.Kind != WatchdogNotice || es[2].Notification.Diagnostic != "" {
					t.Fatalf("valid answer failed to recover: state=%+v notice=%+v", state, es[2].Notification)
				}
			case "unsupported-command":
				wantKinds(t, es, StopTimer, ArmTimer, Notify, Send)
				if state.State != watchdog.Okay || es[2].Notification.Kind != WatchdogNotice || resultCode(t, es[3].Message) != diam.CommandUnsupported {
					t.Fatalf("valid mux miss lost recovery or reply: state=%+v effects=%v", state, kinds(es))
				}
			default:
				wantKinds(t, es, StopTimer, ArmTimer, Send)
				if state.State != watchdog.Suspect || resultCode(t, es[2].Message) != diam.ApplicationUnsupported {
					t.Fatalf("rejected application validation earned health credit or changed reply: state=%+v effects=%v", state, kinds(es))
				}
			}
		})
	}
}

// The answer observation is separate from CompleteRequest: a correlated
// rejection already consumes native ownership, but a subsequent valid success
// can still credit the one Pending probe (RFC 3539 Appendix A, #109 contract).
func TestCreditedDWAAlwaysPublishesAnswerObservationOnce(t *testing.T) {
	for _, suspect := range []bool{false, true} {
		for _, rejected := range []bool{false, true} {
			c := supervised(t, false)
			sent := probe(t, c)
			if suspect {
				tick(t, c)
			}
			completions := 0
			if rejected {
				for _, e := range c.Handle(receive(dwa(t, sent, diam.UnableToComply))) {
					if e.Kind == CompleteRequest {
						completions++
					}
				}
			}
			in := receive(dwa(t, sent, diam.Success))
			in.HasHandler = true // Supervision owns a DWA even with an ALL route.
			es := c.Handle(in)
			answers, recoveries := 0, 0
			for _, e := range es {
				if e.Kind == Admit || e.Kind == Send {
					t.Fatal("supervised DWA escaped to a frontend route or generated a reply")
				}
				if e.Kind == CompleteRequest {
					completions++
				}
				if e.Kind == Notify && e.Notification.Kind == WatchdogNotice {
					if e.Notification.Diagnostic == "answer" {
						answers++
					} else if e.Notification.Diagnostic == "" && e.Notification.Watchdog == watchdog.Okay {
						recoveries++
					} else {
						t.Fatalf("unexpected watchdog notice=%+v", e.Notification)
					}
				}
			}
			wantRecoveries := 0
			if suspect {
				wantRecoveries = 1
			}
			if completions != 1 || answers != 1 || recoveries != wantRecoveries || c.Snapshot().Watchdog().Pending || c.Snapshot().Watchdog().State != watchdog.Okay {
				t.Fatalf("suspect=%t rejected=%t native completions=%d answers=%d recoveries=%d state=%+v", suspect, rejected, completions, answers, recoveries, c.Snapshot().Watchdog())
			}
			for _, e := range c.Handle(in) {
				if e.Kind == CompleteRequest || e.Kind == Notify && e.Notification.Kind == WatchdogNotice {
					t.Fatal("duplicate successful answer was credited twice")
				}
			}
		}
	}
}

func TestProtocolNoticeWithoutDecoderErrorHasNoCause(t *testing.T) {
	for _, variant := range []string{"timeout", "discard"} {
		t.Run(variant, func(t *testing.T) {
			c := machine(t)
			var in Input
			if variant == "timeout" {
				c.Handle(event(Start))
				timer := c.Snapshot().Timer(HandshakeTimer)
				in = event(TimerExpired)
				in.Timer, in.Token, in.At = HandshakeTimer, timer.Token, timer.Deadline
			} else {
				c = opened(t)
				in = receive(diam.NewMessage(999, 0, 4, 31, 32, c.cfg.Dictionary))
				in.Kind = Unhandled
			}
			seen := false
			for _, e := range c.Handle(in) {
				if e.Kind == Notify && e.Notification.Protocol != "" {
					seen = true
					if e.Notification.CauseError != nil {
						t.Fatalf("notification fabricated a decoder cause: %#v", e.Notification.CauseError)
					}
				}
			}
			if !seen {
				t.Fatal("fixture did not produce a protocol notice")
			}
		})
	}
}

func TestHandshakeErrorCopyNormalizesTypedNil(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"nil", nil},
		{"message-error", (*diam.MessageError)(nil)},
		{"validation-error", (*diam.ValidationError)(nil)},
		{"failed-result-code", (*base.ErrFailedResultCode)(nil)},
		{"unexpected-avp", (*base.ErrUnexpectedAVP)(nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := copyHandshakeError(tc.err); got != nil {
				t.Fatalf("copied typed nil as non-nil cause: %#v", got)
			}
			if got := newHandshakeResult(tc.err, nil).Err(); got != nil {
				t.Fatalf("handshake result retained typed nil cause: %#v", got)
			}
		})
	}
}

// RFC 6733 §5.6.1 and the existing B6 callback contract: the timer can
// commit Closed before its executor closes the transport. A held OnCER hook
// must then report its own losing admission decision once, without a CEA.
func TestTimedOutCERHookReportsLateContinuationOnce(t *testing.T) {
	c := machine(t, func(cfg *Config) { cfg.Hooks = true })
	c.Handle(event(Start))
	hook := find(t, c.Handle(receive(cer(t))), RunHook)
	timer := c.Snapshot().Timer(HandshakeTimer)
	expired := event(TimerExpired)
	expired.Timer, expired.Token, expired.At = HandshakeTimer, timer.Token, timer.Deadline
	timeoutEffects := c.Handle(expired)
	wantKinds(t, timeoutEffects, StopTimer, Close, Notify)
	if notice := timeoutEffects[2].Notification; notice.Protocol != diam.ProtocolHandshakeTimeout || !notice.Closing {
		t.Fatalf("timeout decision=%+v", notice)
	}
	continued := event(Continue)
	continued.Token, continued.Message = hook.Token, hook.Message
	// TransportClosed is false: the timeout executor is still in its log sink.
	es := c.Handle(continued)
	wantKinds(t, es, Close, Notify)
	if n := es[1].Notification; n.Protocol != diam.ProtocolHandshakeState || !n.Closing || n.ResultCode != 0 || n.Reply != diam.ProtocolReplyNone || n.Message != metadata(hook.Message) {
		t.Fatalf("late CER continuation=%+v", n)
	}
	if c.Snapshot().Phase() != Closed || c.Snapshot().Candidate() != 0 || c.Snapshot().Admission() != 0 || c.Snapshot().Ready() {
		t.Fatal("late hook reopened timed-out admission")
	}
	wantKinds(t, c.Handle(continued))
	wantKinds(t, c.Handle(expired))
}
