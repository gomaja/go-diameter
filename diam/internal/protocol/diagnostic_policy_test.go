package protocol

import (
	"fmt"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

func policyProtocolNotice(t testing.TB, es []Effect) Notification {
	t.Helper()
	for _, e := range es {
		if e.Kind == Notify && e.Notification.Protocol != "" {
			return e.Notification
		}
	}
	t.Fatalf("missing protocol notification in %v", kinds(es))
	return Notification{}
}

func TestReaderOwnsMessageErrorClosure(t *testing.T) {
	for _, reader := range []bool{false, true} {
		t.Run(fmt.Sprintf("reader=%t", reader), func(t *testing.T) {
			c := opened(t, func(cfg *Config) { cfg.ReaderOwnsMessageErrorClosure = reader })
			in := receive(request(t, diam.DeviceWatchdog))
			in.ErrorInput = true
			in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPLength, Fatal: true}
			sent := find(t, c.Handle(in), Send)
			if !sent.Required || sent.CloseAfter == reader {
				t.Fatalf("fatal reply closure=%t, reader ownership=%t", sent.CloseAfter, reader)
			}
			n := policyProtocolNotice(t, c.Handle(complete(sent)))
			if !n.Closing || (c.Phase() == Closed) == reader {
				t.Fatalf("fatality/closure conflated: notice=%+v phase=%v", n, c.Phase())
			}
		})
	}
}

func TestClosingMessageErrorFatalityPolicy(t *testing.T) {
	for _, retain := range []bool{false, true} {
		t.Run(fmt.Sprintf("retain=%t", retain), func(t *testing.T) {
			c := opened(t, func(cfg *Config) {
				cfg.ReaderOwnsMessageErrorClosure = true
				cfg.RetainClosingErrorFatality = retain
			})
			c.Handle(event(Disconnect))
			before := c.Snapshot().Timer(ClosingTimer)
			in := receive(request(t, diam.DisconnectPeer))
			in.ErrorInput = true
			in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPLength, Fatal: true}
			n := policyProtocolNotice(t, c.Handle(in))
			if n.Closing != retain || n.Reply != diam.ProtocolReplyNone || c.Phase() != Closing || c.Snapshot().Timer(ClosingTimer) != before {
				t.Fatalf("Closing report altered transport ownership/deadline: %+v", n)
			}
		})
	}
}

func TestHeaderDiagnosisRetainsSelectedDecoderFatality(t *testing.T) {
	for _, retain := range []bool{false, true} {
		t.Run(fmt.Sprintf("retain=%t", retain), func(t *testing.T) {
			c := opened(t, func(cfg *Config) {
				cfg.ReaderOwnsMessageErrorClosure = true
				cfg.PreserveDecoderFatalityOnHeaderError = retain
			})
			in := receive(request(t, diam.DeviceWatchdog))
			in.Message.Header.CommandFlags |= diam.ProxiableFlag
			in.ErrorInput = true
			in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPLength, Fatal: true}
			sent := find(t, c.Handle(in), Send)
			n := policyProtocolNotice(t, c.Handle(complete(sent)))
			cause, ok := n.CauseError.(*diam.MessageError)
			if !ok || cause.ResultCode != diam.InvalidHDRBits || cause.Fatal != retain || !n.Closing || sent.CloseAfter || c.Phase() != Open {
				t.Fatalf("replacement header cause or original report changed: %+v cause=%#v", n, cause)
			}
		})
	}
}

func TestHeaderErrorDiagnosticClassificationPolicy(t *testing.T) {
	for _, separate := range []bool{false, true} {
		for _, closing := range []bool{false, true} {
			t.Run(fmt.Sprintf("separate=%t/closing=%t", separate, closing), func(t *testing.T) {
				c := opened(t, func(cfg *Config) {
					cfg.ReaderOwnsMessageErrorClosure = true
					cfg.SeparateHeaderErrorDiagnostics = separate
				})
				if closing {
					c.Handle(event(Disconnect))
				}
				in := receive(request(t, diam.DisconnectPeer))
				in.Message.Header.CommandFlags |= diam.ProxiableFlag
				in.ErrorInput = true
				in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPLength}
				es := c.Handle(in)
				if !closing {
					es = c.Handle(complete(find(t, es, Send)))
				}
				n := policyProtocolNotice(t, es)
				kind, diagnostic := diam.ProtocolInvalidHeader, "external-message-error"
				if separate {
					diagnostic = "header-error"
					if closing {
						kind = diam.ProtocolMalformedMessage
					}
				}
				if n.Protocol != kind || n.Diagnostic != diagnostic || n.ResultCode != diam.InvalidHDRBits {
					t.Fatalf("header diagnostic=%+v, want %s/%s", n, kind, diagnostic)
				}
			})
		}
	}
}

func TestCERMessageErrorClosurePolicy(t *testing.T) {
	for _, onlyBits := range []bool{false, true} {
		t.Run(fmt.Sprintf("only-invalid-header-bits=%t", onlyBits), func(t *testing.T) {
			c := opened(t, func(cfg *Config) {
				cfg.ReaderOwnsMessageErrorClosure = true
				cfg.RejectFatalRepeatedCER = true
				cfg.CloseCEROnInvalidHeaderBitsOnly = onlyBits
			})
			in := receive(cer(t))
			in.Message.Header.ApplicationID = 4
			in.ErrorInput = true
			in.Error = &diam.MessageError{ResultCode: diam.UnsupportedVersion, Fatal: true}
			sent := find(t, c.Handle(in), Send)
			if sent.CloseAfter == onlyBits || resultCode(t, sent.Message) != diam.UnsupportedVersion {
				t.Fatalf("CER closure=%t for only-bits=%t", sent.CloseAfter, onlyBits)
			}
			c.Handle(complete(sent))
			if (c.Phase() == Closed) == onlyBits {
				t.Fatalf("CER transport outcome=%v for only-bits=%t", c.Phase(), onlyBits)
			}
		})
	}
}

func TestCompletedCEAValidationPolicy(t *testing.T) {
	for _, validate := range []bool{false, true} {
		t.Run(fmt.Sprintf("validate=%t", validate), func(t *testing.T) {
			c := machine(t, func(cfg *Config) { cfg.Role, cfg.ValidateCompletedCEA = Initiator, validate })
			sent := grant(t, c, c.Handle(event(Start)))
			c.Handle(complete(sent))
			answer, err := base.BuildCEA(sent.Message, remote(t).Local, diam.Success)
			if err != nil {
				t.Fatal(err)
			}
			ready := find(t, c.Handle(receive(answer)), HandshakeReady)
			release := event(ReleaseAdmission)
			release.Token = ready.Token
			c.Handle(release)
			answer.AVP = nil
			n := policyProtocolNotice(t, c.Handle(receive(answer)))
			kind, code := diam.ProtocolUnexpectedMessage, uint32(0)
			if validate {
				kind, code = diam.ProtocolCEARejected, diam.MissingAVP
			}
			if n.Protocol != kind || n.ResultCode != code || n.Closing || c.Phase() != Open {
				t.Fatalf("completed CEA diagnostic=%+v phase=%v", n, c.Phase())
			}
		})
	}
}

func TestDWAOwnershipPrecedesSemanticDiagnosticsPolicy(t *testing.T) {
	for _, ownership := range []bool{false, true} {
		t.Run(fmt.Sprintf("ownership-first=%t", ownership), func(t *testing.T) {
			c := opened(t, func(cfg *Config) {
				cfg.Watchdog, cfg.DWAOwnershipBeforeSemantics = true, ownership
				cfg.WatchdogInterval = 6 * time.Second
			})
			sent := probe(t, c)
			answer := dwa(t, sent, diam.UnableToComply)
			answer.Header.HopByHopID++
			n := policyProtocolNotice(t, c.Handle(receive(answer)))
			kind, code := diam.ProtocolRejectedDWA, uint32(diam.UnableToComply)
			if ownership {
				kind, code = diam.ProtocolUnexpectedMessage, 0
			}
			if n.Protocol != kind || n.ResultCode != code || !c.Snapshot().Watchdog().Pending {
				t.Fatalf("unowned DWA changed diagnosis/ownership: %+v", n)
			}
		})
	}
}

func TestDWAIdentityPrecedesUnsuccessfulResultPolicy(t *testing.T) {
	for _, identity := range []bool{false, true} {
		t.Run(fmt.Sprintf("identity-first=%t", identity), func(t *testing.T) {
			c := opened(t, func(cfg *Config) {
				cfg.Watchdog, cfg.DWAIdentityBeforeResult = true, identity
				cfg.WatchdogInterval = 6 * time.Second
			})
			sent := probe(t, c)
			answer := dwa(t, sent, diam.UnableToComply)
			for _, field := range answer.AVP {
				if field.Code == avp.OriginHost {
					field.Data = datatype.DiameterIdentity("other.example")
				}
			}
			n := policyProtocolNotice(t, c.Handle(receive(answer)))
			kind, code := diam.ProtocolRejectedDWA, uint32(diam.UnableToComply)
			if identity {
				kind, code = diam.ProtocolInvalidDWA, 0
			}
			if n.Protocol != kind || n.ResultCode != code || !c.Snapshot().Watchdog().Pending {
				t.Fatalf("unbound DWA changed diagnosis/ownership: %+v", n)
			}
		})
	}
}

func TestReplyBuilderErrorWrapperPolicy(t *testing.T) {
	for _, preserve := range []bool{false, true} {
		t.Run(fmt.Sprintf("preserve=%t", preserve), func(t *testing.T) {
			c := opened(t, func(cfg *Config) { cfg.PreserveReplyErrorFormatWrapper = preserve })
			empty, err := dict.NewParser()
			if err != nil {
				t.Fatal(err)
			}
			in := receive(diam.NewMessage(diam.DeviceWatchdog, diam.RequestFlag, 0, 1, 2, empty))
			es := c.reject(nil, in, diam.ProtocolInvalidRequest, &diam.MessageError{ResultCode: diam.MissingAVP})
			n := policyProtocolNotice(t, es)
			if got := fmt.Sprintf("%T", n.ReplyError); (got == "*fmt.wrapError") != preserve {
				t.Fatalf("builder wrapper=%s, preserve=%t", got, preserve)
			}
		})
	}
}
