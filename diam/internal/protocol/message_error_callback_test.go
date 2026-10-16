package protocol

import (
	"fmt"
	"testing"

	"github.com/gomaja/go-diameter/diam"
)

func TestBoundHeaderlessCallbackHasNoProtocolEffect(t *testing.T) {
	for _, closing := range []bool{false, true} {
		for _, empty := range []bool{false, true} {
			t.Run(fmt.Sprintf("closing=%t/empty-message=%t", closing, empty), func(t *testing.T) {
				c := opened(t, func(cfg *Config) { cfg.IgnoreBoundHeaderlessInput = true })
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
				for _, e := range c.Handle(in) {
					if e.Kind != Discard {
						t.Fatalf("headerless bound callback selected work: %+v", e)
					}
				}
				if c.Phase() != phase || c.Snapshot().Timer(ClosingTimer) != timer {
					t.Fatal("headerless callback changed lifecycle/deadline")
				}
			})
		}
	}
}

func TestInitialNonCERCallbackDiagnosticPrecedence(t *testing.T) {
	for _, errorInput := range []bool{false, true} {
		t.Run(fmt.Sprintf("callback=%t", errorInput), func(t *testing.T) {
			c := machine(t, func(cfg *Config) { cfg.InitialNonCERHeaderOnError = true })
			c.Handle(event(Start))
			in := receive(request(t, diam.DeviceWatchdog))
			in.Message.Header.CommandFlags |= diam.ProxiableFlag
			in.ErrorInput = errorInput
			wantCode := uint32(0)
			if errorInput {
				in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPLength}
				wantCode = diam.InvalidHDRBits
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

func TestFatalCEACallbackPrecedesCorrelation(t *testing.T) {
	for _, fatal := range []bool{false, true} {
		t.Run(fmt.Sprintf("fatal=%t", fatal), func(t *testing.T) {
			c := machine(t, func(cfg *Config) { cfg.Role = Initiator; cfg.FatalCEAErrorBeforeCorrelation = true })
			sent := grant(t, c, c.Handle(event(Start)))
			in := receive(sent.Message.Answer(diam.Success))
			in.Message.Header.HopByHopID++
			in.ErrorInput = true
			in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPLength, Fatal: fatal}
			var n Notification
			for _, e := range c.Handle(in) {
				if e.Kind == Notify && e.Notification.Protocol != "" {
					n = e.Notification
				}
			}
			if fatal {
				if n.Protocol != diam.ProtocolCEARejected || n.ResultCode != diam.InvalidAVPLength || !n.Closing || c.Phase() != Closed {
					t.Fatalf("fatal handshake callback was treated as stray: %+v phase=%v", n, c.Phase())
				}
			} else if n.Protocol != diam.ProtocolUnexpectedMessage || n.ResultCode != 0 || n.Closing || c.Phase() != WaitCEA {
				t.Fatalf("recoverable stray changed handshake ownership: %+v phase=%v", n, c.Phase())
			}
		})
	}
}
