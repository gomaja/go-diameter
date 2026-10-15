package protocol

import (
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

func withoutDictionary(m *diam.Message) *diam.Message {
	d, _ := dict.New()
	out := diam.NewMessage(m.Header.CommandCode, m.Header.CommandFlags, m.Header.ApplicationID, m.Header.HopByHopID, m.Header.EndToEndID, d)
	out.AVP = base.CloneAVPs(m.AVP)
	return out
}

// RFC 6733 §§5.3–5.6,7; #108: shared builders may fail against a supplied
// message dictionary. A required reply failure always closes and reports Failed.
func TestBuilderFailuresClose(t *testing.T) {
	for _, variant := range []string{"error", "cea-reject", "candidate-reject"} {
		t.Run(variant, func(t *testing.T) {
			c := opened(t)
			in := receive(withoutDictionary(request(t, diam.DeviceWatchdog)))
			var es []Effect
			switch variant {
			case "error":
				in.Message.AVP = nil
				es = c.Handle(in)
			case "cea-reject":
				c = machine(t, func(cfg *Config) { cfg.ExpectedHost = "other.example"; cfg.Local.HostIPAddresses = nil })
				es = c.Handle(receive(cer(t)))
			case "candidate-reject":
				c = machine(t)
				candidate := find(t, c.Handle(receive(cer(t))), ValidatedCER)
				c.cfg.Local.HostIPAddresses = nil
				in = event(RejectCandidate)
				in.Token = candidate.Token
				in.ResultCode = diam.NoCommonApplication
				es = c.Handle(in)
			}
			find(t, es, Close)
			n := find(t, es, Notify).Notification
			kind, code := diam.ProtocolCERRejected, uint32(diam.UnableToComply)
			switch variant {
			case "error":
				kind, code = diam.ProtocolInvalidRequest, diam.MissingAVP
			case "candidate-reject":
				code = diam.NoCommonApplication
			}
			if n.Protocol != kind || n.ResultCode != code || n.ReplyCode != code || n.Reply != diam.ProtocolReplyFailed || !n.Closing {
				t.Fatalf("failure=%+v", n)
			}
		})
	}
}

// #108: malformed answer input never elicits an answer; fatal framing closes.
func TestMalformedAnswerAndExecutorInputs(t *testing.T) {
	for _, fatal := range []bool{false, true} {
		c := opened(t)
		in := receive(diam.NewMessage(999, 0, 4, 1, 2, c.cfg.Dictionary))
		in.Error = &diam.MessageError{ResultCode: diam.InvalidMessageLength, Fatal: fatal}
		es := c.Handle(in)
		if fatal {
			wantKinds(t, es, Close, Notify)
		} else {
			wantKinds(t, es, Discard, Notify)
		}
	}
	c := opened(t)
	wantKinds(t, c.Handle(receive(nil)), Close, Notify)
	c = opened(t)
	wantKinds(t, c.Handle(event(InputKind(255))))
	in := event(TimerExpired)
	in.Timer = TimerKind(255)
	wantKinds(t, c.Handle(in))
	in = event(Unhandled)
	wantKinds(t, c.Handle(in), Discard)
	in.Message = diam.NewMessage(999, 0, 4, 1, 2, c.cfg.Dictionary)
	wantKinds(t, c.Handle(in), Discard, Notify)
	in.Message.Header.CommandFlags = diam.RequestFlag
	in.Message.Header.ApplicationID = 99
	sent := find(t, c.Handle(in), Send)
	if resultCode(t, sent.Message) != diam.ApplicationUnsupported {
		t.Fatal("unhandled membership")
	}
	// No watchdog owner: a stray DWA is discarded after ordinary base grammar.
	m, err := base.BuildDWA(request(t, diam.DeviceWatchdog), remote(t).Local)
	if err != nil {
		t.Fatal(err)
	}
	wantKinds(t, c.Handle(receive(m)), Discard, Notify)
	m, err = base.BuildCEA(cer(t), remote(t).Local, diam.Success)
	if err != nil {
		t.Fatal(err)
	}
	wantKinds(t, c.Handle(receive(m)), Discard, Notify)
}

// RFC 6733 §§5.3,5.6.4; #108: hooks can invalidate a previously decoded
// request, while neither hook completion nor crossed DPR can reopen admission.
func TestHookAndFenceEdges(t *testing.T) {
	c := machine(t, func(cfg *Config) { cfg.Hooks = true })
	hook := find(t, c.Handle(receive(cer(t))), RunHook)
	in := event(Continue)
	in.Token = hook.Token
	in.Message = &diam.Message{}
	wantKinds(t, c.Handle(in), Close, Notify)
	c = opened(t)
	c.cfg.Hooks = true
	hook = find(t, c.Handle(receive(request(t, diam.DeviceWatchdog))), RunHook)
	in = event(Continue)
	in.Token = hook.Token
	in.Message = request(t, diam.DeviceWatchdog)
	in.Message.AVP = nil
	wantKinds(t, c.Handle(in), Discard, Notify)
	c = opened(t)
	c.Handle(receive(request(t, diam.DisconnectPeer)))
	wantKinds(t, c.Handle(receive(request(t, diam.DisconnectPeer))), Discard)
}

// RFC 6733 §§2.4,5.3 and #108: relay advertisement accepts the full remote
// offer; identity comparison folds ASCII in either operand and no other bytes.
func TestRelayAndIdentityBoundaries(t *testing.T) {
	c := machine(t, func(cfg *Config) {
		cfg.Local.AuthApplicationID = []*diam.AVP{diam.NewAVP(258, 64, 0, datatype.Unsigned32(0xffffffff))}
	})
	find(t, c.Handle(receive(cer(t))), ValidatedCER)
	apps := c.Snapshot().Capabilities().CommonApplications
	if len(apps) != 1 || apps[0] != 4 {
		t.Fatalf("relay apps=%v", apps)
	}
	for _, tt := range []struct {
		a, b string
		want bool
	}{{"remote.example", "REMOTE.EXAMPLE", true}, {"remote.example", "remotf.example", false}, {"å", "Å", false}, {"a", "aa", false}} {
		if equalIdentity(tt.a, tt.b) != tt.want {
			t.Fatalf("identity %q %q", tt.a, tt.b)
		}
	}
	// Queued probe publication arriving after Closing cannot change supervision.
	c = supervised(t, false)
	selected := grant(t, c, tick(t, c))
	c.Handle(event(Disconnect))
	before := c.Snapshot().Watchdog()
	c.Handle(complete(selected))
	if c.Snapshot().Watchdog() != before {
		t.Fatal("late publication changed watchdog")
	}
	// Recovery without a DWA reaches the Appendix A missed-probe sentinel.
	c = machine(t, func(cfg *Config) { cfg.Watchdog = true; cfg.Recovery = true; cfg.WatchdogInterval = 6 * time.Second })
	sent := find(t, accept(t, c), Send)
	ready := find(t, c.Handle(complete(sent)), HandshakeReady)
	release := event(ReleaseAdmission)
	release.Token = ready.Token
	sent = grant(t, c, c.Handle(release))
	c.Handle(complete(sent))
	tick(t, c)
	find(t, tick(t, c), Close)
}

// RFC 6733 §§3,6.2.1; #108: every correlation coordinate is independent.
func TestControlCorrelationCoordinates(t *testing.T) {
	for _, variant := range []string{"valid", "no-request", "no-message", "no-header", "settled", "application", "request-bit", "command", "hop", "end"} {
		t.Run(variant, func(t *testing.T) {
			c := machine(t)
			r := &control{logical: true, command: diam.DeviceWatchdog, header: diam.Header{HopByHopID: 0, EndToEndID: 0}}
			m := diam.NewMessage(diam.DeviceWatchdog, 0, 0, 0, 0, c.cfg.Dictionary)
			m.Header.HopByHopID, m.Header.EndToEndID = 0, 0
			switch variant {
			case "no-request":
				r = nil
			case "no-message":
				m = nil
			case "no-header":
				m.Header = nil
			case "settled":
				r.logical = false
			case "application":
				m.Header.ApplicationID = 4
			case "request-bit":
				m.Header.CommandFlags = diam.RequestFlag
			case "command":
				m.Header.CommandCode = diam.DisconnectPeer
			case "hop":
				m.Header.HopByHopID = 1
			case "end":
				m.Header.EndToEndID = 1
			}
			if c.matches(r, m) != (variant == "valid") {
				t.Fatal("correlation coordinate ignored")
			}
		})
	}
}
