package protocol

import (
	"fmt"
	"testing"

	"github.com/gomaja/go-diameter/diam"
)

func TestBoundHeaderlessInputClosureOwnership(t *testing.T) {
	for _, ignore := range []bool{false, true} {
		for _, closing := range []bool{false, true} {
			for _, empty := range []bool{false, true} {
				t.Run(fmt.Sprintf("ignore=%t/closing=%t/empty-message=%t", ignore, closing, empty), func(t *testing.T) {
					c := opened(t, func(cfg *Config) { cfg.IgnoreBoundHeaderlessInput = ignore })
					if closing {
						c.Handle(event(Disconnect))
					}
					phase, timer := c.Phase(), c.Snapshot().Timer(ClosingTimer)
					in := event(Receive)
					in.ErrorInput = true
					in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPLength, Fatal: true}
					if empty {
						in.Message = new(diam.Message)
					}
					effects := c.Handle(in)
					if ignore || closing {
						for _, e := range effects {
							if e.Kind != Discard {
								t.Fatalf("headerless bound callback selected work: %+v", e)
							}
						}
						if c.Phase() != phase || c.Snapshot().Timer(ClosingTimer) != timer {
							t.Fatal("headerless callback changed lifecycle/deadline")
						}
					} else {
						n := protocolNotice(t, effects)
						if c.Phase() != Closed || !n.Closing || n.Protocol != diam.ProtocolMalformedMessage {
							t.Fatalf("ordinary headerless input did not close: %+v phase=%v", n, c.Phase())
						}
					}
				})
			}
		}
	}
}

func TestInitialNonCERCallbackDiagnosticPrecedence(t *testing.T) {
	for _, errorInput := range []bool{false, true} {
		t.Run(fmt.Sprintf("callback=%t", errorInput), func(t *testing.T) {
			c := machine(t)
			c.Handle(event(Start))
			in := receive(request(t, diam.DeviceWatchdog))
			in.Message.Header.CommandFlags |= diam.ProxiableFlag
			in.ErrorInput = errorInput
			wantCode := uint32(diam.InvalidHDRBits)
			if errorInput {
				in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPLength}
				wantCode = diam.InvalidAVPLength
			}
			n := find(t, c.Handle(in), Notify).Notification
			if n.Protocol != diam.ProtocolHandshakeState || n.ResultCode != wantCode || !n.Closing || n.Reply != diam.ProtocolReplyNone || c.Phase() != Closed {
				t.Fatalf("first non-CER disposition changed: %+v phase=%v", n, c.Phase())
			}
			if errorInput {
				cause, ok := n.CauseError.(*diam.MessageError)
				if !ok || cause.ResultCode != wantCode {
					t.Fatalf("header diagnostic lost its typed cause: %T %v", n.CauseError, n.CauseError)
				}
			}
		})
	}
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprintf("headerless/empty-message=%t", empty), func(t *testing.T) {
			c := machine(t, func(cfg *Config) { cfg.IgnoreBoundHeaderlessInput = true })
			c.Handle(event(Start))
			in := event(Receive)
			in.ErrorInput = true
			in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPLength, Fatal: true}
			if empty {
				in.Message = new(diam.Message)
			}
			n := find(t, c.Handle(in), Notify).Notification
			if n.Protocol != diam.ProtocolHandshakeState || n.ResultCode != diam.InvalidAVPLength || !n.Closing || n.CauseError == nil {
				t.Fatalf("headerless admission lost its diagnostic: %+v", n)
			}
		})
	}
}

func TestUncorrelatedCEAErrorDisposition(t *testing.T) {
	for _, readerOwns := range []bool{false, true} {
		for _, coordinate := range []string{"hop", "end"} {
			for _, decoder := range []struct {
				name           string
				code           uint32
				fatal, framing bool
			}{
				{"body", diam.InvalidAVPLength, false, false},
				{"fatal-body", diam.InvalidAVPLength, true, false},
				{"version", diam.UnsupportedVersion, true, true},
				{"message-length", diam.InvalidMessageLength, true, true},
			} {
				t.Run(fmt.Sprintf("reader=%t/%s/%s", readerOwns, coordinate, decoder.name), func(t *testing.T) {
					c := machine(t, func(cfg *Config) {
						cfg.Role, cfg.ReaderOwnsMessageErrorClosure = Initiator, readerOwns
					})
					sent := grant(t, c, c.Handle(event(Start)))
					c.Handle(complete(sent))
					before := c.Snapshot().Timer(HandshakeTimer)
					if before.Token == 0 {
						t.Fatal("CER response deadline was not armed")
					}
					controls := c.Snapshot().Controls()
					in := receive(sent.Message.Answer(diam.Success))
					if coordinate == "hop" {
						in.Message.Header.HopByHopID++
					} else {
						in.Message.Header.EndToEndID++
					}
					in.ErrorInput = true
					in.Error = &diam.MessageError{ResultCode: decoder.code, Fatal: decoder.fatal}
					effects := c.Handle(in)
					n := protocolNotice(t, effects)
					if decoder.framing {
						if n.Protocol != diam.ProtocolCEARejected || n.ResultCode != decoder.code || !n.Closing || c.Phase() != Closed || c.Snapshot().Timer(HandshakeTimer).Token != 0 {
							t.Fatalf("framing failure did not terminate handshake: %+v phase=%v", n, c.Phase())
						}
						return
					}
					if n.Protocol != diam.ProtocolUnexpectedMessage || n.ResultCode != 0 || n.Closing != decoder.fatal {
						t.Fatalf("stray body error lost its discard/fatal disposition: %+v", n)
					}
					closed := decoder.fatal && !readerOwns
					if closed {
						if c.Phase() != Closed || c.Snapshot().Timer(HandshakeTimer).Token != 0 || len(c.Snapshot().Controls()) != 0 {
							t.Fatal("fatal native discard retained handshake work")
						}
					} else {
						if c.Phase() != WaitCEA || c.Snapshot().Timer(HandshakeTimer) != before {
							t.Fatal("reader-owned or recoverable discard changed the CER deadline")
						}
						retained := c.Snapshot().Controls()
						if len(controls) != 1 || len(retained) != 1 || retained[0] != controls[0] {
							t.Fatal("stray body error consumed CER ownership")
						}
					}
					closeSelected := false
					for _, effect := range effects {
						if effect.Kind == Send {
							t.Fatal("uncorrelated CEA selected a wire answer")
						}
						closeSelected = closeSelected || effect.Kind == Close
					}
					if closeSelected != closed {
						t.Fatalf("close selected=%t, want %t", closeSelected, closed)
					}
				})
			}
		}
	}
}
