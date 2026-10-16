package protocol

import (
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
)

// A generation that has never issued this control command retains the
// frontend's unsolicited-answer grammar diagnostics (RFC 6733 §§3, 5.4–5.5).
func TestInitialUnownedControlAnswerRetainsBodyValidation(t *testing.T) {
	for _, command := range []uint32{diam.DeviceWatchdog, diam.DisconnectPeer} {
		t.Run(controlTestName(command), func(t *testing.T) {
			c := opened(t, func(cfg *Config) { cfg.DWAOwnershipBeforeSemantics = true })
			msg := diam.NewMessage(command, 0, 0, 91, 92, c.cfg.Dictionary)
			n := find(t, c.Handle(receive(msg)), Notify).Notification
			want := diam.ProtocolInvalidDWA
			if command == diam.DisconnectPeer {
				want = diam.ProtocolInvalidDPA
			}
			if n.Protocol != want || n.ResultCode != diam.MissingAVP || n.Closing {
				t.Fatalf("initial unsolicited grammar diagnosis changed: %+v", n)
			}
			in := receive(msg)
			in.ErrorInput = true
			in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPLength}
			n = find(t, c.Handle(in), Notify).Notification
			if n.Protocol != diam.ProtocolMalformedMessage || n.ResultCode != diam.InvalidAVPLength {
				t.Fatalf("initial decoder diagnosis changed: %+v", n)
			}
		})
	}
}

// Unmatched answers keep grammar diagnostics without completing or
// semantically rejecting the local exchange.
func TestUnownedControlAnswerRetainsGrammarDiagnostics(t *testing.T) {
	for _, command := range []uint32{diam.DeviceWatchdog, diam.DisconnectPeer} {
		t.Run(controlTestName(command), func(t *testing.T) {
			c := opened(t, func(cfg *Config) {
				cfg.DWAOwnershipBeforeSemantics = true
				cfg.Watchdog = true
				cfg.WatchdogInterval = 6 * time.Second
			})
			if command == diam.DeviceWatchdog {
				probe(t, c)
			} else {
				sent := grant(t, c, fence(t, c, event(Disconnect), false))
				c.Handle(complete(sent))
			}
			msg := diam.NewMessage(command, 0, 0, 91, 92, c.cfg.Dictionary)
			in := receive(msg)
			n := find(t, c.Handle(in), Notify).Notification
			want := diam.ProtocolInvalidDWA
			if command == diam.DisconnectPeer {
				want = diam.ProtocolInvalidDPA
			}
			if n.Protocol != want || n.ResultCode != diam.MissingAVP {
				t.Fatalf("unowned answer lost grammar diagnosis: %+v", n)
			}
			in.ErrorInput = true
			in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPLength}
			n = find(t, c.Handle(in), Notify).Notification
			if n.Protocol != diam.ProtocolMalformedMessage || n.ResultCode != diam.InvalidAVPLength {
				t.Fatalf("unowned decoded answer semantically rejected: %+v", n)
			}
		})
	}
}

func TestUnownedControlGrammarAfterCompletedExchange(t *testing.T) {
	for _, variant := range []string{"malformed-duplicate", "malformed-stray", "other-command", "new-generation"} {
		t.Run(variant, func(t *testing.T) {
			configure := func(cfg *Config) {
				cfg.DWAOwnershipBeforeSemantics = true
				cfg.Watchdog = true
				cfg.WatchdogInterval = 6 * time.Second
			}
			c := opened(t, configure)
			sent := probe(t, c)
			c.Handle(receive(dwa(t, sent, diam.Success)))
			if len(c.Snapshot().Controls()) != 0 || c.Snapshot().Watchdog().Pending {
				t.Fatal("valid DWA failed to finish exchange")
			}
			msg := diam.NewMessage(diam.DeviceWatchdog, 0, 0, sent.Message.Header.HopByHopID, sent.Message.Header.EndToEndID, c.cfg.Dictionary)
			want, code := diam.ProtocolInvalidDWA, uint32(diam.MissingAVP)
			switch variant {
			case "malformed-stray":
				msg.Header.HopByHopID++
			case "other-command":
				msg.Header.CommandCode = diam.DisconnectPeer
				want, code = diam.ProtocolInvalidDPA, diam.MissingAVP
			case "new-generation":
				c = opened(t, configure)
				want, code = diam.ProtocolInvalidDWA, diam.MissingAVP
			}
			notice := find(t, c.Handle(receive(msg)), Notify).Notification
			if notice.Protocol != want || notice.ResultCode != code || notice.Closing {
				t.Fatalf("completed exchange changed grammar diagnosis: %+v want %s/%d", notice, want, code)
			}
			if c.Snapshot().Phase() != Open || c.Snapshot().Watchdog().Pending {
				t.Fatal("unowned answer reopened an exchange or closed the generation")
			}
		})
	}
}

func TestRejectedDWAIdentityPrecedesResult(t *testing.T) {
	c := opened(t, func(cfg *Config) {
		cfg.DWAIdentityBeforeResult = true
		cfg.Watchdog = true
		cfg.WatchdogInterval = 6 * time.Second
	})
	sent := probe(t, c)
	msg := dwa(t, sent, diam.UnableToComply)
	for _, field := range msg.AVP {
		if field.Code == avp.OriginHost {
			field.Data = datatype.DiameterIdentity("other.example")
		}
	}
	n := find(t, c.Handle(receive(msg)), Notify).Notification
	if n.Protocol != diam.ProtocolInvalidDWA || n.ResultCode != 0 {
		t.Fatalf("unbound result was interpreted: %+v", n)
	}
	if c.Snapshot().Controls()[0].Answered {
		t.Fatal("unbound rejection consumed native ownership")
	}
}

func TestUnownedDWAResultCannotRejectExchange(t *testing.T) {
	for _, state := range []string{"initial", "current", "completed"} {
		t.Run(state, func(t *testing.T) {
			c := opened(t, func(cfg *Config) {
				cfg.DWAOwnershipBeforeSemantics = true
				cfg.Watchdog = true
				cfg.WatchdogInterval = 6 * time.Second
			})
			sent := Effect{Message: request(t, diam.DeviceWatchdog)}
			if state != "initial" {
				sent = probe(t, c)
			}
			if state == "completed" {
				c.Handle(receive(dwa(t, sent, diam.Success)))
			}
			msg := dwa(t, sent, diam.UnableToComply)
			if state == "current" {
				msg.Header.HopByHopID++
			}
			n := find(t, c.Handle(receive(msg)), Notify).Notification
			if n.Protocol != diam.ProtocolUnexpectedMessage || n.ResultCode != 0 {
				t.Fatalf("unowned result rejected an exchange: %+v", n)
			}
		})
	}
}

func controlTestName(command uint32) string {
	if command == diam.DeviceWatchdog {
		return "DWA"
	}
	return "DPA"
}
