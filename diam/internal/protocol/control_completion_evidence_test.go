package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

// #108/#125 publication ownership; RFC 6733 §§5.4,5.6: a write-gate
// cancellation disposes an unpublished control attempt without ending drain.
func TestSkippedDWRPreservesClosing(t *testing.T) {
	for _, queued := range []bool{false, true} {
		t.Run(fmt.Sprint(queued), func(t *testing.T) {
			c := supervised(t, false)
			c.cfg.QueueWrites = queued
			sent := grant(t, c, tick(t, c))
			if queued {
				ack := complete(sent)
				ack.Stage = QueueStage
				c.Handle(ack)
			}
			dprReservation := fence(t, c, event(Disconnect), false)
			deadline := c.Snapshot().Timer(ClosingTimer)
			done := complete(sent)
			done.Stage = SkippedStage
			done.Bytes = 0
			done.Err = diam.ErrConnectionClosing
			es := c.Handle(done)
			wantKinds(t, es, ReleaseIDs)
			if es[0].Reservation.Hop != sent.Message.Header.HopByHopID || c.Snapshot().Phase() != Closing || c.Snapshot().Timer(ClosingTimer) != deadline {
				t.Fatal("skip changed Closing or lost lease")
			}
			wantKinds(t, c.Handle(done))
			dpr := grant(t, c, dprReservation)
			c.Handle(complete(dpr))
			dpa, err := base.BuildDPA(dpr.Message, remote(t).Local)
			if err != nil {
				t.Fatal(err)
			}
			find(t, c.Handle(receive(dpa)), Close)
		})
	}
}

// RFC 6733 §§3,5.3,6.2.1; #108: the answer may beat a retry's publication.
// Its reservation remains pinned until the skipped retry returns, then releases.
func TestSkippedCERRetryAfterAnswer(t *testing.T) {
	c := machine(t, func(cfg *Config) { cfg.Role = Initiator; cfg.CERInterval = time.Second; cfg.MaxRetransmits = 2 })
	first := grant(t, c, c.Handle(event(Start)))
	c.Handle(complete(first))
	timer := c.Snapshot().Timer(RetryTimer)
	expiry := event(TimerExpired)
	expiry.Timer = RetryTimer
	expiry.Token = timer.Token
	expiry.At = timer.Deadline
	retry := find(t, c.Handle(expiry), Send)
	cea, err := base.BuildCEA(first.Message, remote(t).Local, diam.Success)
	if err != nil {
		t.Fatal(err)
	}
	find(t, c.Handle(receive(cea)), HandshakeReady)
	done := complete(retry)
	done.Stage = SkippedStage
	done.Bytes = 0
	done.Err = diam.ErrRequestCompleted
	wantKinds(t, c.Handle(done), ReleaseIDs)
	if c.Snapshot().Phase() != Open || len(c.Snapshot().Controls()) != 0 {
		t.Fatal("skipped retry ended admitted generation or leaked lease")
	}
	wantKinds(t, c.Handle(done))
}

func TestSkippedRetryRetainsPublishedCER(t *testing.T) {
	c := machine(t, func(cfg *Config) { cfg.Role = Initiator; cfg.CERInterval = time.Second; cfg.MaxRetransmits = 2 })
	first := grant(t, c, c.Handle(event(Start)))
	c.Handle(complete(first))
	timer := c.Snapshot().Timer(RetryTimer)
	expiry := event(TimerExpired)
	expiry.Timer = RetryTimer
	expiry.Token = timer.Token
	expiry.At = timer.Deadline
	retry := find(t, c.Handle(expiry), Send)
	done := complete(retry)
	done.Stage = SkippedStage
	done.Bytes = 0
	done.Err = diam.ErrRequestCompleted
	wantKinds(t, c.Handle(done))
	cea, err := base.BuildCEA(first.Message, remote(t).Local, diam.Success)
	if err != nil {
		t.Fatal(err)
	}
	es := c.Handle(receive(cea))
	find(t, es, ReleaseIDs)
	find(t, es, HandshakeReady)
}

func TestRealControlFailureStillCloses(t *testing.T) {
	c := supervised(t, false)
	sent := grant(t, c, tick(t, c))
	done := complete(sent)
	done.Err = errors.New("transport failure")
	find(t, c.Handle(done), Close)
}

func TestSkippedRequiredReplyStillCloses(t *testing.T) {
	for _, err := range []error{nil, diam.ErrConnectionClosing} {
		c := opened(t)
		in := receive(request(t, diam.DeviceWatchdog))
		in.Message.AVP = nil
		sent := find(t, c.Handle(in), Send)
		done := complete(sent)
		done.Stage, done.Bytes, done.Err, done.ReplyCode = SkippedStage, 0, err, diam.MissingAVP
		es := c.Handle(done)
		wantKinds(t, es, Close, Notify)
		n := find(t, es, Notify).Notification
		if n.Protocol != diam.ProtocolInvalidRequest || n.ResultCode != diam.MissingAVP || n.ReplyCode != diam.MissingAVP || n.Reply != diam.ProtocolReplyFailed || c.Snapshot().Phase() != Closed {
			t.Fatalf("required reply skip=%+v", n)
		}
	}
}

// RFC 3539 Appendix A; #108: a retired probe's executor completion cannot
// cancel the next probe selected after an early successful answer.
func TestSkippedOldWriterPreservesNewProbe(t *testing.T) {
	c := supervised(t, false)
	old := grant(t, c, tick(t, c))
	c.Handle(receive(dwa(t, old, diam.Success)))
	next := grant(t, c, tick(t, c))
	done := complete(old)
	done.Stage, done.Bytes, done.Err = SkippedStage, 0, diam.ErrRequestCompleted
	wantKinds(t, c.Handle(done), ReleaseIDs)
	if c.Snapshot().Watchdog().Pending || c.Snapshot().Timer(WatchdogTimer).Token != 0 {
		t.Fatal("old writer changed next tentative probe")
	}
	wantKinds(t, c.Handle(complete(next)), ArmTimer, Notify)
	if !c.Snapshot().Watchdog().Pending {
		t.Fatal("next probe lost publication credit")
	}
}

// RFC 6733 §5.4.3; #108: reconnect policy consumes the first validated DPR
// decision immediately, while the public callback keeps its send boundary.
func TestPeerDisconnectDecisionSurvivesSendFailure(t *testing.T) {
	for _, cause := range []uint32{0, 1, 2} {
		for _, failure := range []string{"queue", "write", "transport-before-fence", "transport-after-send", "retire"} {
			t.Run(fmt.Sprintf("%d/%s", cause, failure), func(t *testing.T) {
				c := opened(t)
				m := request(t, diam.DisconnectPeer)
				for _, a := range m.AVP {
					if a.Code == 273 {
						a.Data = datatype.Enumerated(cause)
					}
				}
				es := c.Handle(receive(m))
				decision := find(t, es, PeerDisconnectDecision)
				if decision.Cause != cause {
					t.Fatal("decision lost cause")
				}
				for _, e := range es {
					if e.Kind == Notify && e.Notification.Kind == PeerDisconnectNotice {
						t.Fatal("public callback preceded DPA boundary")
					}
				}
				before := c.Snapshot()
				got, present := before.PeerDisconnect()
				if !present || got != cause {
					t.Fatal("missing durable validated DPR")
				}
				if failure == "transport-before-fence" {
					c.Handle(event(TransportLost))
				} else {
					ack := event(Frozen)
					ack.Token = find(t, es, FreezeAdmission).Token
					sent := find(t, c.Handle(ack), Send)
					switch failure {
					case "queue", "write":
						done := complete(sent)
						done.Err = errors.New("send failed")
						if failure == "queue" {
							done.Stage = QueueStage
						}
						c.Handle(done)
					case "transport-after-send":
						c.Handle(event(TransportLost))
						c.Handle(complete(sent))
					case "retire":
						c.Handle(event(Retire))
						c.Handle(complete(sent))
					}
				}
				got, present = c.Snapshot().PeerDisconnect()
				if !present || got != cause {
					t.Fatal("terminal outcome erased peer cause")
				}
				if got, present = before.PeerDisconnect(); !present || got != cause {
					t.Fatal("earlier snapshot changed")
				}
			})
		}
	}
}

func TestFirstPeerDisconnectDecisionIsBoundAndStable(t *testing.T) {
	c := opened(t)
	if _, present := c.Snapshot().PeerDisconnect(); present {
		t.Fatal("invented initial DPR")
	}
	bad := request(t, diam.DisconnectPeer)
	bad.AVP[0].Data = datatype.DiameterIdentity("other.example")
	wantKinds(t, c.Handle(receive(bad)), Discard, Notify)
	if _, present := c.Snapshot().PeerDisconnect(); present {
		t.Fatal("unbound DPR set cause")
	}
	first := c.Handle(receive(request(t, diam.DisconnectPeer)))
	find(t, first, PeerDisconnectDecision)
	second := request(t, diam.DisconnectPeer)
	for _, a := range second.AVP {
		if a.Code == 273 {
			a.Data = datatype.Enumerated(2)
		}
	}
	wantKinds(t, c.Handle(receive(second)), Discard)
	ack := event(Frozen)
	ack.Token = find(t, first, FreezeAdmission).Token
	sent := find(t, c.Handle(ack), Send)
	es := c.Handle(complete(sent))
	n := find(t, es, Notify).Notification
	if n.Kind != PeerDisconnectNotice || n.Cause != 0 {
		t.Fatal("public callback lost the first validated cause")
	}
}

func handshakeCompletion(t testing.TB, es []Effect) Notification {
	t.Helper()
	for _, e := range es {
		if e.Kind == Notify && e.Notification.Kind == HandshakeNotice {
			return e.Notification
		}
	}
	t.Fatalf("missing handshake completion in %v", kinds(es))
	return Notification{}
}

// RFC 6733 §§5.3.2,7.1.5; #111 compatibility: retain the parser's semantic
// error and detached CEA, without turning failed admission into negotiated data.
func TestRejectedCEARetainsSemanticCompletion(t *testing.T) {
	for _, variant := range []string{"result", "missing-application", "no-common", "grammar", "decode"} {
		t.Run(variant, func(t *testing.T) {
			c := machine(t, func(cfg *Config) { cfg.Role = Initiator; cfg.ExpectedHost = "remote.example" })
			sent := grant(t, c, c.Handle(event(Start)))
			c.Handle(complete(sent))
			code := uint32(diam.Success)
			if variant == "result" {
				code = diam.UnableToComply
			}
			m, err := base.BuildCEA(sent.Message, remote(t).Local, code)
			if err != nil {
				t.Fatal(err)
			}
			m.AddAVP(diam.NewAVP(281, 0, 0, datatype.UTF8String("peer rejected capability")))
			m.AddAVP(diam.NewAVP(279, 64, 0, &diam.GroupedAVP{AVP: []*diam.AVP{diam.NewAVP(258, 64, 0, datatype.Unsigned32(99))}}))
			in := receive(m)
			switch variant {
			case "missing-application":
				for i := len(m.AVP) - 1; i >= 0; i-- {
					if m.AVP[i].Code == 258 {
						m.AVP = append(m.AVP[:i], m.AVP[i+1:]...)
					}
				}
			case "no-common":
				for _, a := range m.AVP {
					if a.Code == 258 {
						a.Data = datatype.Unsigned32(99)
					}
				}
			case "grammar":
				m.AVP = nil
			case "decode":
				in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPValue, FailedAVP: diam.NewAVP(264, 64, 0, datatype.OctetString("invalid")), Err: fmt.Errorf("decode: %w", base.ErrMissingOriginHost)}
			}
			es := c.Handle(in)
			n := handshakeCompletion(t, es)
			result := n.Handshake
			if n.Outcome != ConnectionClosed || result.Err() == nil || c.Snapshot().Phase() != Closed {
				t.Fatal("rejection lost completion error")
			}
			if c.Snapshot().Capabilities().CEA != nil {
				t.Fatal("rejected CEA published as negotiated")
			}
			switch variant {
			case "result":
				var failed *base.ErrFailedResultCode
				if !errors.As(result.Err(), &failed) || failed.ResultCode != diam.UnableToComply || failed.ErrorMessage != "peer rejected capability" || len(failed.FailedAVP) != 1 {
					t.Fatalf("failed-result detail=%+v error=%v", failed, result.Err())
				}
				failed.ErrorMessage = "mutated"
				failed.FailedAVP[0].Data = &diam.GroupedAVP{}
				var again *base.ErrFailedResultCode
				if !errors.As(result.Err(), &again) || again.ErrorMessage != "peer rejected capability" || len(again.FailedAVP[0].Data.(*diam.GroupedAVP).AVP) != 1 {
					t.Fatal("failed-result evidence aliases error accessor")
				}
			case "missing-application":
				if !errors.Is(result.Err(), base.ErrMissingApplication) {
					t.Fatalf("error=%v", result.Err())
				}
			case "no-common":
				if !errors.Is(result.Err(), base.ErrNoCommonApplication) {
					t.Fatalf("error=%v", result.Err())
				}
			case "grammar", "decode":
				var me *diam.MessageError
				if !errors.As(result.Err(), &me) {
					t.Fatalf("error type=%T", result.Err())
				}
				me.ResultCode = 0
				if variant == "decode" {
					me.FailedAVP.Data = datatype.OctetString("Xnvalid")
					in.Error.FailedAVP.Data = datatype.OctetString("iXvalid")
					var again *diam.MessageError
					if !errors.As(result.Err(), &again) || string(again.FailedAVP.Data.(datatype.OctetString)) != "invalid" {
						t.Fatal("decode evidence aliases input or accessor")
					}
				}
			}
			if variant == "decode" && !errors.Is(result.Err(), base.ErrMissingOriginHost) {
				t.Fatal("wrapped error identity lost")
			}
			if variant != "grammar" && variant != "decode" {
				cea := result.CEA()
				if cea == nil || cea.OriginHost != "remote.example" || cea.VendorID != 1 || cea.ProductName != "test" {
					t.Fatalf("parsed CEA=%+v", cea)
				}
				cea.ErrorMessage = "mutated"
				cea.FailedAVP[0].Data = &diam.GroupedAVP{}
				m.AVP = nil
				if result.CEA().ErrorMessage != "peer rejected capability" || c.Snapshot().Handshake().CEA().ErrorMessage != "peer rejected capability" || len(result.CEA().FailedAVP[0].Data.(*diam.GroupedAVP).AVP) != 1 {
					t.Fatal("handshake detail aliases caller data")
				}
			}
			wantKinds(t, c.Handle(event(Retire)))
		})
	}
}

// RFC 6733 §7.5; #111: semantic errors retain their identities and detached
// AVP evidence even when the parser wraps a validation error.
func TestHandshakeErrorEvidenceIsolation(t *testing.T) {
	for _, variant := range []string{"unexpected-avp", "validation"} {
		t.Run(variant, func(t *testing.T) {
			a := diam.NewAVP(258, 64, 0, datatype.OctetString("original"))
			var source error = &base.ErrUnexpectedAVP{AVP: a}
			if variant == "validation" {
				source = &diam.ValidationError{FailedAVP: a, ResultCode: diam.InvalidAVPValue}
			}
			wrapped := fmt.Errorf("parse: %w", source)
			result := newHandshakeResult(wrapped, nil)
			if result.Err().Error() != wrapped.Error() || result.CEA() != nil {
				t.Fatal("wrapper or absent CEA changed")
			}
			a.Data = datatype.OctetString("Xriginal")
			evidence := func(err error) *diam.AVP {
				if variant == "unexpected-avp" {
					var e *base.ErrUnexpectedAVP
					if !errors.As(err, &e) {
						t.Fatal("lost unexpected AVP type")
					}
					return e.AVP
				}
				var e *diam.ValidationError
				if !errors.As(err, &e) || e.ResultCode != diam.InvalidAVPValue {
					t.Fatal("lost validation identity")
				}
				return e.FailedAVP
			}
			first := evidence(result.Err())
			if string(first.Data.(datatype.OctetString)) != "original" {
				t.Fatal("capture aliases source")
			}
			first.Data = datatype.OctetString("Yriginal")
			if string(evidence(result.Err()).Data.(datatype.OctetString)) != "original" {
				t.Fatal("getter aliases evidence")
			}
		})
	}
}

// #108 reply-failure policy: preserve the detected condition when its first
// report is Failed, and use the writer's post-hook reply code independently.
func TestErrorReplyFailurePreservesOriginalCondition(t *testing.T) {
	for _, stage := range []WriteStage{QueueStage, WrittenStage} {
		for _, variant := range []string{"base-grammar", "decode", "decode-unsupported-application", "unsupported-command", "unsupported-application", "cer-rejection"} {
			t.Run(fmt.Sprintf("%d/%s", stage, variant), func(t *testing.T) {
				c := opened(t)
				in := receive(request(t, diam.DeviceWatchdog))
				kind := diam.ProtocolInvalidRequest
				code := uint32(diam.MissingAVP)
				switch variant {
				case "base-grammar":
					in.Message.AVP = nil
				case "decode":
					in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPValue}
					kind = diam.ProtocolMalformedMessage
					code = diam.InvalidAVPValue
				case "decode-unsupported-application":
					c.cfg.ValidateRequests = true
					in.Message = diam.NewRequest(999, 99, c.cfg.Dictionary)
					in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPValue}
					kind = diam.ProtocolUnsupportedApplication
					code = diam.ApplicationUnsupported
				case "unsupported-command":
					in.Kind = Unhandled
					in.Message = diam.NewRequest(999, 4, c.cfg.Dictionary)
					kind = diam.ProtocolUnsupportedCommand
					code = diam.CommandUnsupported
				case "unsupported-application":
					in.Kind = Unhandled
					in.Message = diam.NewRequest(999, 99, c.cfg.Dictionary)
					kind = diam.ProtocolUnsupportedApplication
					code = diam.ApplicationUnsupported
				case "cer-rejection":
					c = machine(t)
					c.cfg.ExpectedHost = "other.example"
					in = receive(cer(t))
					kind = diam.ProtocolCERRejected
					code = diam.UnableToComply
				}
				sent := find(t, c.Handle(in), Send)
				done := complete(sent)
				done.Stage = stage
				done.ReplyCode = 4001
				done.Err = errors.New("required reply failed")
				es := c.Handle(done)
				find(t, es, Close)
				n := find(t, es, Notify).Notification
				if n.Protocol != kind || n.ResultCode != code || n.Reply != diam.ProtocolReplyFailed || n.ReplyCode != 4001 || !n.Closing || n.Message != metadata(in.Message) {
					t.Fatalf("rejection=%+v want=%v/%d", n, kind, code)
				}
				wantKinds(t, c.Handle(done))
			})
		}
	}
}

func TestErrorReplyBuildFailurePreservesOriginalCondition(t *testing.T) {
	for _, variant := range []string{"grammar", "cer-rejection", "candidate-rejection", "mandatory"} {
		t.Run(variant, func(t *testing.T) {
			c := machine(t)
			in := receive(cer(t))
			kind := diam.ProtocolInvalidRequest
			code := uint32(diam.MissingAVP)
			c.cfg.Local.HostIPAddresses = nil
			switch variant {
			case "grammar":
				in.Message.AVP = nil
			case "cer-rejection":
				c.cfg.ExpectedHost = "other.example"
				kind = diam.ProtocolCERRejected
				code = diam.UnableToComply
			case "candidate-rejection":
				candidate := find(t, c.Handle(in), ValidatedCER)
				in = event(RejectCandidate)
				in.Token = candidate.Token
				in.ResultCode = diam.NoCommonApplication
				kind = diam.ProtocolCERRejected
				code = diam.NoCommonApplication
			case "mandatory":
				c.cfg.RejectUnknownMandatoryAVPs = true
				c.cfg.Dictionary.SetStrict(false)
				in.Message.AddAVP(diam.NewAVP(999999, 64, 0, datatype.Unknown{1, 2, 3, 4}))
				raw, err := in.Message.Serialize()
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := diam.ReadMessage(bytes.NewReader(raw), c.cfg.Dictionary)
				if err != nil {
					t.Fatal(err)
				}
				in.Message = decoded
				kind = diam.ProtocolUnsupportedAVP
				code = diam.AVPUnsupported
			}
			es := c.Handle(in)
			find(t, es, Close)
			n := find(t, es, Notify).Notification
			if n.Protocol != kind || n.ResultCode != code || n.Reply != diam.ProtocolReplyFailed || n.ReplyCode != code || !n.Closing {
				t.Fatalf("build rejection=%+v want=%v/%d", n, kind, code)
			}
		})
	}
}
