package protocol

import (
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/watchdog"
)

func supervised(t testing.TB, recovery bool) *Core {
	return opened(t, func(cfg *Config) {
		cfg.Watchdog = true
		cfg.WatchdogInterval = 6 * time.Second
		cfg.Recovery = recovery
	})
}
func tick(t testing.TB, c *Core) []Effect {
	t.Helper()
	timer := c.Snapshot().Timer(WatchdogTimer)
	in := event(TimerExpired)
	in.Timer = WatchdogTimer
	in.Token = timer.Token
	in.At = timer.Deadline
	return c.Handle(in)
}
func probe(t testing.TB, c *Core) Effect {
	t.Helper()
	sent := grant(t, c, tick(t, c))
	done := complete(sent)
	done.At = epoch.Add(6 * time.Second)
	c.Handle(done)
	return sent
}
func dwa(t testing.TB, sent Effect, code uint32) *diam.Message {
	t.Helper()
	m, err := base.BuildDWA(sent.Message, remote(t).Local)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range m.AVP {
		if a.Code == 268 {
			a.Data = datatype.Unsigned32(code)
		}
	}
	if code >= 3000 && code < 4000 {
		m.Header.CommandFlags |= diam.ErrorFlag
	}
	return m
}

// RFC 3539 §3.4.1 and Appendix A; #108/#128: activity, Pending and healthy
// recovery are distinct, and receipt time excludes observer/queue latency.
func TestWatchdogActivityCreditAndExpiry(t *testing.T) {
	c := supervised(t, false)
	sent := probe(t, c)
	if !c.Snapshot().Watchdog().Pending {
		t.Fatal("probe not pending")
	}
	tick(t, c)
	if c.Snapshot().Watchdog().State != watchdog.Suspect {
		t.Fatal("missing SUSPECT")
	}
	bad := receive(dwa(t, sent, diam.Success))
	bad.Message.Header.EndToEndID++
	bad.At = epoch.Add(13 * time.Second)
	c.Handle(bad)
	if c.Snapshot().Watchdog().State != watchdog.Suspect || !c.Snapshot().Watchdog().Pending {
		t.Fatal("uncorrelated DWA credited")
	}
	if c.Snapshot().Timer(WatchdogTimer).Deadline != bad.At.Add(6*time.Second) {
		t.Fatal("activity did not reset from receipt")
	}
	good := receive(dwa(t, sent, diam.Success))
	good.At = bad.At
	c.Handle(good)
	if c.Snapshot().Watchdog().State != watchdog.Okay || c.Snapshot().Watchdog().Pending {
		t.Fatal("valid DWA not credited")
	}
}

func TestWatchdogInvalidAndRejectedDWA(t *testing.T) {
	for _, variant := range []string{"body", "host", "realm", "error-bit", "hop", "end", "zero-result", "rejected"} {
		t.Run(variant, func(t *testing.T) {
			c := supervised(t, false)
			sent := probe(t, c)
			tick(t, c)
			m := dwa(t, sent, diam.Success)
			switch variant {
			case "body":
				m.AVP = nil
			case "host":
				m.AVP[1].Data = datatype.DiameterIdentity("other.example")
			case "realm":
				m.AVP[2].Data = datatype.DiameterIdentity("other.example")
			case "error-bit":
				m.Header.CommandFlags |= diam.ErrorFlag
			case "hop":
				m.Header.HopByHopID++
			case "end":
				m.Header.EndToEndID++
			case "zero-result":
				m.AVP[0].Data = datatype.Unsigned32(0)
			case "rejected":
				m = dwa(t, sent, diam.UnableToComply)
			}
			es := c.Handle(receive(m))
			find(t, es, Notify)
			if variant == "zero-result" && find(t, es, Notify).Notification.Protocol != diam.ProtocolRejectedDWA {
				t.Fatal("parsed non-success Result-Code lost rejection classification")
			}
			state := c.Snapshot().Watchdog()
			if state.State != watchdog.Suspect || !state.Pending {
				t.Fatal("invalid answer restored health")
			}
			r := c.Snapshot().Controls()
			if variant == "rejected" || variant == "zero-result" {
				if len(r) != 1 || !r[0].Answered {
					t.Fatal("valid rejection did not settle in-flight ownership")
				}
			} else {
				if len(r) != 1 || r[0].Answered {
					t.Fatal("bad answer consumed ownership")
				}
			}
		})
	}
}

func TestNonDWARecoversWithoutClearingPending(t *testing.T) {
	c := supervised(t, false)
	probe(t, c)
	tick(t, c)
	in := receive(diam.NewRequest(999, 4, c.cfg.Dictionary))
	in.At = epoch.Add(13 * time.Second)
	es := c.Handle(in)
	find(t, es, Admit)
	state := c.Snapshot().Watchdog()
	if state.State != watchdog.Okay || !state.Pending {
		t.Fatal("non-DWA recovery changed Pending")
	}
	tick(t, c)
	es = tick(t, c)
	find(t, es, Close)
}

func TestWatchdogBacklogAndEarlyAnswer(t *testing.T) {
	c := supervised(t, false)
	sent := probe(t, c)
	timer := c.Snapshot().Timer(WatchdogTimer)
	expiry := event(TimerExpired)
	expiry.Timer = WatchdogTimer
	expiry.Token = timer.Token
	expiry.At = timer.Deadline
	expiry.AfterReceive = 2
	wantKinds(t, c.Handle(expiry))
	in := receive(dwa(t, sent, diam.Success))
	in.Sequence = 2
	in.At = timer.Deadline.Add(-time.Second)
	c.Handle(in)
	if c.Snapshot().Watchdog().State != watchdog.Okay || c.Snapshot().Watchdog().Pending {
		t.Fatal("expiry overtook admitted answer")
	}
	c = supervised(t, false)
	sent = grant(t, c, tick(t, c))
	in = receive(dwa(t, sent, diam.Success))
	in.At = epoch.Add(7 * time.Second)
	c.Handle(in)
	c.Handle(complete(sent))
	if c.Snapshot().Watchdog().Pending {
		t.Fatal("late write restored Pending")
	}
}

func TestWatchdogRecoveryNeedsThreeAnswers(t *testing.T) {
	c := machine(t, func(cfg *Config) { cfg.Watchdog = true; cfg.Recovery = true; cfg.WatchdogInterval = 6 * time.Second })
	sent := find(t, accept(t, c), Send)
	ready := find(t, c.Handle(complete(sent)), HandshakeReady)
	release := event(ReleaseAdmission)
	release.Token = ready.Token
	probeSend := grant(t, c, c.Handle(release))
	c.Handle(complete(probeSend))
	for i := 0; i < 3; i++ {
		app := receive(diam.NewRequest(999, 4, c.cfg.Dictionary))
		wantKinds(t, c.Handle(app), StopTimer, ArmTimer, Discard)
		c.Handle(receive(dwa(t, probeSend, diam.Success)))
		if i < 2 {
			if c.Snapshot().Watchdog().State != watchdog.Reopen {
				t.Fatal("premature recovery")
			}
			probeSend = grant(t, c, tick(t, c))
			c.Handle(complete(probeSend))
		}
	}
	if c.Snapshot().Watchdog().State != watchdog.Okay {
		t.Fatal("three responses did not recover")
	}
}

func TestClosingInvalidatesQueuedProbe(t *testing.T) {
	c := supervised(t, false)
	reserve := find(t, tick(t, c), ReserveIDs)
	dpr := receive(request(t, diam.DisconnectPeer))
	es := c.Handle(dpr)
	find(t, es, FreezeAdmission)
	late := event(ReserveResult)
	late.Token = reserve.Token
	late.Reservation = Reservation{Token: 123}
	wantKinds(t, c.Handle(late), ReleaseIDs)
	before := c.Snapshot().Watchdog()
	c.Handle(receive(diam.NewMessage(diam.DeviceWatchdog, 0, 0, 0, 0, c.cfg.Dictionary)))
	if c.Snapshot().Watchdog() != before {
		t.Fatal("Closing credited watchdog")
	}
}

// #108 watchdog validation order and repeated CER; RFC 3539 §3.4.1 [2].
// Receipt resets Tw independently from validity and from health/probe credit.
func TestDecodedActivityRequiresValidityForRecovery(t *testing.T) {
	for _, variant := range []string{"malformed-repeat", "invalid-repeat", "valid-repeat", "wrong-host-dwr", "wrong-host-dpr", "bad-header", "decode-error", "bad-body", "unsupported-app", "unsolicited-cea", "fatal-framing"} {
		t.Run(variant, func(t *testing.T) {
			c := supervised(t, false)
			probe(t, c)
			tick(t, c)
			in := receive(request(t, diam.DeviceWatchdog))
			in.At = epoch.Add(13 * time.Second)
			switch variant {
			case "malformed-repeat", "invalid-repeat", "valid-repeat":
				in.Message = cer(t)
				if variant == "malformed-repeat" {
					in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPValue}
				}
				if variant == "invalid-repeat" {
					in.Message.AVP = nil
				}
			case "wrong-host-dwr", "wrong-host-dpr":
				if variant == "wrong-host-dpr" {
					in.Message = request(t, diam.DisconnectPeer)
				}
				for _, a := range in.Message.AVP {
					if a.Code == 264 {
						a.Data = datatype.DiameterIdentity("other.example")
					}
				}
			case "bad-header":
				in.Message.Header.CommandFlags |= diam.ErrorFlag
			case "decode-error":
				in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPValue}
			case "bad-body":
				in.Message.AVP = nil
			case "unsupported-app":
				c.cfg.ValidateRequests = true
				in.Message = diam.NewRequest(999, 99, c.cfg.Dictionary)
			case "unsolicited-cea":
				in.Message.Header.CommandCode = diam.CapabilitiesExchange
				in.Message.Header.CommandFlags = 0
			case "fatal-framing":
				in.Error = &diam.MessageError{Fatal: true, ResultCode: diam.InvalidMessageLength}
			}
			es := c.Handle(in)
			if variant == "fatal-framing" {
				if !find(t, es, Send).CloseAfter {
					t.Fatal("fatal frame did not select closure")
				}
				return
			}
			if len(es) < 2 || es[0].Kind != StopTimer || es[1].Kind != ArmTimer || es[1].Timer != WatchdogTimer || es[1].Deadline != in.At.Add(6*time.Second) {
				t.Fatalf("receipt timer effects=%v", kinds(es))
			}
			state := c.Snapshot().Watchdog()
			wantState := watchdog.Suspect
			if variant == "valid-repeat" {
				wantState = watchdog.Okay
			}
			if state.State != wantState || !state.Pending {
				t.Fatalf("state=%+v want=%s Pending=true", state, wantState)
			}
			if variant == "malformed-repeat" || variant == "invalid-repeat" {
				wantKinds(t, es, StopTimer, ArmTimer, Discard, Notify)
			}
			if variant == "valid-repeat" {
				wantKinds(t, es, StopTimer, ArmTimer, Notify, Discard, Notify)
			}
		})
	}
}
