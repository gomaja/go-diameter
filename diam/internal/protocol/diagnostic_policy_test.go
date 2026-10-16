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

func protocolNotice(t testing.TB, es []Effect) Notification {
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
	for _, owner := range []string{"core", "reader", "external-admission"} {
		t.Run(owner, func(t *testing.T) {
			reader := owner != "core"
			c := opened(t, func(cfg *Config) { cfg.ReaderOwnsMessageErrorClosure = owner == "reader" })
			if owner == "external-admission" {
				c = admitted(t, true)
			}
			in := receive(request(t, diam.DeviceWatchdog))
			in.ErrorInput = true
			in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPLength, Fatal: true}
			sent := find(t, c.Handle(in), Send)
			if !sent.Required || sent.CloseAfter == reader {
				t.Fatalf("fatal reply closure=%t, reader ownership=%t", sent.CloseAfter, reader)
			}
			n := protocolNotice(t, c.Handle(complete(sent)))
			if !n.Closing || (c.Phase() == Closed) == reader {
				t.Fatalf("fatality/closure conflated: notice=%+v phase=%v", n, c.Phase())
			}
		})
	}
}

func TestClosingMessageErrorRetainsFatality(t *testing.T) {
	for _, reader := range []bool{false, true} {
		t.Run(fmt.Sprintf("reader=%t", reader), func(t *testing.T) {
			c := opened(t, func(cfg *Config) { cfg.ReaderOwnsMessageErrorClosure = reader })
			c.Handle(event(Disconnect))
			before := c.Snapshot().Timer(ClosingTimer)
			in := receive(request(t, diam.DisconnectPeer))
			in.ErrorInput = true
			in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPLength, Fatal: true}
			n := protocolNotice(t, c.Handle(in))
			if !n.Closing || n.Reply != diam.ProtocolReplyNone || c.Phase() != Closing || c.Snapshot().Timer(ClosingTimer) != before {
				t.Fatalf("Closing report altered fatality/transport ownership/deadline: %+v", n)
			}
		})
	}
}

func TestHeaderDiagnosisRetainsDecoderFatality(t *testing.T) {
	for _, reader := range []bool{false, true} {
		t.Run(fmt.Sprintf("reader=%t", reader), func(t *testing.T) {
			c := opened(t, func(cfg *Config) { cfg.ReaderOwnsMessageErrorClosure = reader })
			in := receive(request(t, diam.DeviceWatchdog))
			in.Message.Header.CommandFlags |= diam.ProxiableFlag
			in.ErrorInput = true
			in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPLength, Fatal: true}
			sent := find(t, c.Handle(in), Send)
			n := protocolNotice(t, c.Handle(complete(sent)))
			cause, ok := n.CauseError.(*diam.MessageError)
			if !ok || cause.ResultCode != diam.InvalidHDRBits || !cause.Fatal || !n.Closing || sent.CloseAfter == reader || (c.Phase() == Closed) == reader {
				t.Fatalf("replacement header cause or original report changed: %+v cause=%#v phase=%v", n, cause, c.Phase())
			}
		})
	}
}

func TestHeaderErrorRetainsInvalidHeaderClassification(t *testing.T) {
	for _, closing := range []bool{false, true} {
		t.Run(fmt.Sprintf("closing=%t", closing), func(t *testing.T) {
			c := opened(t, func(cfg *Config) { cfg.ReaderOwnsMessageErrorClosure = true })
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
			n := protocolNotice(t, es)
			if n.Protocol != diam.ProtocolInvalidHeader || n.Diagnostic != "external-message-error" || n.ResultCode != diam.InvalidHDRBits {
				t.Fatalf("header diagnostic=%+v", n)
			}
		})
	}
}

func TestCERMessageErrorClosurePolicy(t *testing.T) {
	for _, onlyBits := range []bool{false, true} {
		t.Run(fmt.Sprintf("only-invalid-header-bits=%t", onlyBits), func(t *testing.T) {
			c := opened(t, func(cfg *Config) {
				cfg.ReaderOwnsMessageErrorClosure = true
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

func TestCompletedCEAUsesCorrelationDiagnostic(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		t.Run(fmt.Sprintf("duplicate=%t", duplicate), func(t *testing.T) {
			c := machine(t, func(cfg *Config) { cfg.Role = Initiator })
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
			diagnostic := "duplicate-cea"
			if !duplicate {
				answer.Header.HopByHopID++
				diagnostic = "cea-correlation"
			}
			n := protocolNotice(t, c.Handle(receive(answer)))
			if n.Protocol != diam.ProtocolUnexpectedMessage || n.ResultCode != 0 || n.Diagnostic != diagnostic || n.Closing || c.Phase() != Open {
				t.Fatalf("completed CEA diagnostic=%+v phase=%v", n, c.Phase())
			}
		})
	}
}

func TestDWAOwnershipPrecedesSemanticDiagnostics(t *testing.T) {
	c := opened(t, func(cfg *Config) { cfg.Watchdog = true; cfg.WatchdogInterval = 6 * time.Second })
	sent := probe(t, c)
	answer := dwa(t, sent, diam.UnableToComply)
	answer.Header.HopByHopID++
	n := protocolNotice(t, c.Handle(receive(answer)))
	if n.Protocol != diam.ProtocolUnexpectedMessage || n.ResultCode != 0 || n.Diagnostic != "dwa-correlation" || !c.Snapshot().Watchdog().Pending {
		t.Fatalf("unowned DWA changed diagnosis/ownership: %+v", n)
	}
}

func TestDWAIdentityPrecedesUnsuccessfulResult(t *testing.T) {
	c := opened(t, func(cfg *Config) { cfg.Watchdog = true; cfg.WatchdogInterval = 6 * time.Second })
	sent := probe(t, c)
	answer := dwa(t, sent, diam.UnableToComply)
	for _, field := range answer.AVP {
		if field.Code == avp.OriginHost {
			field.Data = datatype.DiameterIdentity("other.example")
		}
	}
	n := protocolNotice(t, c.Handle(receive(answer)))
	if n.Protocol != diam.ProtocolInvalidDWA || n.ResultCode != 0 || !c.Snapshot().Watchdog().Pending {
		t.Fatalf("unbound DWA changed diagnosis/ownership: %+v", n)
	}
}

func TestReplyBuilderErrorRetainsFormatWrapper(t *testing.T) {
	c := opened(t)
	empty, err := dict.NewParser()
	if err != nil {
		t.Fatal(err)
	}
	in := receive(diam.NewMessage(diam.DeviceWatchdog, diam.RequestFlag, 0, 1, 2, empty))
	es := c.reject(nil, in, diam.ProtocolInvalidRequest, &diam.MessageError{ResultCode: diam.MissingAVP})
	n := protocolNotice(t, es)
	if got := fmt.Sprintf("%T", n.ReplyError); got != "*fmt.wrapError" {
		t.Fatalf("builder wrapper=%s, want *fmt.wrapError", got)
	}
}
