package protocol

import (
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/watchdog"
)

func completedCEACore(t testing.TB, ready bool) (*Core, *diam.Message) {
	t.Helper()
	c := machine(t, func(cfg *Config) {
		cfg.Role = Initiator
		cfg.Hooks = true
		cfg.Watchdog = true
		cfg.WatchdogInterval = 6 * time.Second
	})
	sent := grant(t, c, c.Handle(event(Start)))
	c.Handle(complete(sent))
	answer, err := base.BuildCEA(sent.Message, remote(t).Local, diam.Success)
	if err != nil {
		t.Fatal(err)
	}
	callback := find(t, c.Handle(receive(answer)), HandshakeReady)
	if ready {
		release := event(ReleaseAdmission)
		release.Token = callback.Token
		c.Handle(release)
	}
	return c, answer
}

func completedCEAShape(m *diam.Message, shape string) {
	switch shape {
	case "missing":
		m.AVP = nil
	case "flags":
		m.Header.CommandFlags |= diam.RetransmittedFlag
	case "identity":
		for _, a := range m.AVP {
			if a.Code == avp.OriginHost {
				a.Data = datatype.DiameterIdentity("")
			}
		}
	case "error":
		m.Header.CommandFlags |= diam.ErrorFlag
	case "protocol-result":
		for _, a := range m.AVP {
			if a.Code == avp.ResultCode {
				a.Data = datatype.Unsigned32(diam.TooBusy)
			}
		}
	}
}

func TestCompletedCEAPrecedesValidation(t *testing.T) {
	for _, correlation := range []string{"matched", "hop", "end"} {
		for _, shape := range []string{"valid", "missing", "flags", "identity", "error", "protocol-result"} {
			t.Run(correlation+"/"+shape, func(t *testing.T) {
				c, answer := completedCEACore(t, true)
				probe(t, c)
				tick(t, c)
				completedCEAShape(answer, shape)
				switch correlation {
				case "hop":
					answer.Header.HopByHopID++
				case "end":
					answer.Header.EndToEndID++
				}
				in := receive(answer)
				in.At = epoch.Add(13 * time.Second)
				es := c.Handle(in)
				wantKinds(t, es, StopTimer, ArmTimer, Discard, Notify)
				n := es[len(es)-1].Notification
				wantDiagnostic := "duplicate-cea"
				if correlation != "matched" {
					wantDiagnostic = "cea-correlation"
				}
				if n.Protocol != diam.ProtocolUnexpectedMessage || n.ResultCode != 0 || n.Closing || n.Diagnostic != wantDiagnostic {
					t.Fatalf("completed CEA revalidated: %+v", n)
				}
				if c.Snapshot().Phase() != Open || c.Snapshot().Watchdog().State != watchdog.Suspect || !c.Snapshot().Watchdog().Pending || c.Snapshot().Timer(WatchdogTimer).Deadline != in.At.Add(6*time.Second) {
					t.Fatalf("completed CEA changed admission or health/activity policy: %+v", c.Snapshot())
				}
			})
		}
	}
}

func TestCompletedCEAAdmissionAndClosingGates(t *testing.T) {
	for _, shape := range []string{"valid", "missing", "flags", "identity", "error", "protocol-result"} {
		for _, phase := range []string{"admission", "closing", "closed", "retired"} {
			t.Run(phase+"/"+shape, func(t *testing.T) {
				c, answer := completedCEACore(t, phase != "admission")
				completedCEAShape(answer, shape)
				switch phase {
				case "closing":
					c.Handle(event(Disconnect))
				case "closed":
					c.Handle(event(Abort))
				case "retired":
					c.Handle(event(Retire))
				}
				before := c.Snapshot()
				es := c.Handle(receive(answer))
				switch phase {
				case "admission":
					wantKinds(t, es, Hold)
					if es[0].Input.Message == answer {
						t.Fatal("held CEA did not detach its message")
					}
				case "closing":
					wantKinds(t, es, Discard)
				default:
					wantKinds(t, es)
				}
				after := c.Snapshot()
				if before.Phase() != after.Phase() || before.Ready() != after.Ready() || before.Timer(ClosingTimer) != after.Timer(ClosingTimer) || before.Timer(WatchdogTimer) != after.Timer(WatchdogTimer) {
					t.Fatal("late CEA crossed admission or closure gate")
				}
			})
		}
	}
}

func TestCompletedCEAErrorAndAcceptedControls(t *testing.T) {
	for _, role := range []string{"initiator", "responder"} {
		for _, shape := range []string{"valid", "missing", "flags", "decode", "fatal", "application", "request"} {
			t.Run(role+"/"+shape, func(t *testing.T) {
				c, answer := completedCEACore(t, true)
				if role == "responder" {
					c = opened(t)
				}
				completedCEAShape(answer, shape)
				in := receive(answer)
				in.HasHandler = true
				wantKind, wantCode, wantClose := diam.ProtocolUnexpectedMessage, uint32(0), false
				switch shape {
				case "missing":
					if role == "responder" {
						wantKind, wantCode = diam.ProtocolCEARejected, diam.MissingAVP
					}
				case "flags":
					if role == "responder" {
						wantKind, wantCode = diam.ProtocolInvalidHeader, diam.InvalidHDRBits
					}
				case "decode", "fatal":
					in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPLength}
					wantKind, wantCode = diam.ProtocolMalformedMessage, diam.InvalidAVPLength
					if shape == "fatal" {
						in.Error.Fatal, in.Error.ResultCode = true, diam.UnsupportedVersion
						wantCode, wantClose = diam.UnsupportedVersion, true
					}
				case "application":
					answer.Header.ApplicationID = 4
					wantKind, wantCode = diam.ProtocolInvalidHeader, diam.InvalidHDRBits
				case "request":
					answer.Header.CommandFlags |= diam.RequestFlag
				}
				es := c.Handle(in)
				if shape == "valid" && role == "responder" {
					wantKinds(t, es, Admit)
					return
				}
				if shape == "request" && role == "initiator" {
					find(t, es, RunHook)
					return
				}
				n := find(t, es, Notify).Notification
				if n.Protocol != wantKind || n.ResultCode != wantCode || n.Closing != wantClose {
					t.Fatalf("boundary disposition changed: %+v want=%s/%d closing=%t", n, wantKind, wantCode, wantClose)
				}
			})
		}
	}
}
