package protocol

import (
	"errors"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

func request(t testing.TB, cmd uint32) *diam.Message {
	t.Helper()
	cfg := remote(t)
	var m *diam.Message
	var err error
	switch cmd {
	case diam.CapabilitiesExchange:
		return cer(t)
	case diam.DeviceWatchdog:
		m, err = base.BuildDWR(cfg.Dictionary, cfg.Local, 0)
	case diam.DisconnectPeer:
		m, err = base.BuildDPR(cfg.Dictionary, cfg.Local, 0)
	}
	if err != nil {
		t.Fatal(err)
	}
	m.Header.HopByHopID = 80
	m.Header.EndToEndID = 90
	return m
}
func fence(t testing.TB, c *Core, in Input, inFlight bool) []Effect {
	t.Helper()
	es := c.Handle(in)
	e := find(t, es, FreezeAdmission)
	ack := event(Frozen)
	ack.Token = e.Token
	ack.InFlight = inFlight
	return c.Handle(ack)
}
func resultCode(t testing.TB, m *diam.Message) uint32 {
	t.Helper()
	a, err := m.FindAVP(268, 0)
	if err != nil {
		t.Fatal(err)
	}
	return uint32(a.Data.(datatype.Unsigned32))
}

// RFC 6733 §§5.4–5.6; #108/#125: native write admission freezes before DPA.
func TestClosingFenceAndDPR(t *testing.T) {
	for _, flight := range []bool{false, true} {
		t.Run(map[bool]string{false: "idle", true: "inflight"}[flight], func(t *testing.T) {
			c := opened(t)
			in := receive(request(t, diam.DisconnectPeer))
			es := c.Handle(in)
			wantKinds(t, es, PeerDisconnectDecision, ArmTimer, FreezeAdmission)
			if c.Snapshot().Phase() != Closing || c.Snapshot().Frozen() {
				t.Fatal("Closing fence state")
			}
			ack := event(Frozen)
			ack.Token = find(t, es, FreezeAdmission).Token
			ack.InFlight = flight
			es = c.Handle(ack)
			wantKinds(t, es, Send)
			answer := es[0]
			want := uint32(diam.Success)
			if flight {
				want = diam.UnableToComply
			}
			if resultCode(t, answer.Message) != want {
				t.Fatalf("DPA result=%d", resultCode(t, answer.Message))
			}
			if answer.Message.Header.HopByHopID != 80 || answer.Message.Header.EndToEndID != 90 {
				t.Fatal("DPA correlation")
			}
			done := complete(answer)
			done.ReplyCode = want
			es = c.Handle(done)
			wantKinds(t, es, Notify)
			if es[0].Notification.Kind != PeerDisconnectNotice {
				t.Fatal("missing disconnect notice")
			}
			before := c.Snapshot().Timer(ClosingTimer)
			repeat := receive(request(t, diam.DisconnectPeer))
			repeat.InFlight = flight
			repeat.At = epoch.Add(time.Second)
			es = c.Handle(repeat)
			wantKinds(t, es, Send)
			wantKinds(t, c.Handle(complete(es[0])))
			if c.Snapshot().Timer(ClosingTimer) != before {
				t.Fatal("repeated DPR extended deadline")
			}
			if c.Snapshot().Phase() != Closing {
				t.Fatal("DPA sender closed before peer")
			}
		})
	}
}

func TestClosingDropsBeforeValidation(t *testing.T) {
	c := opened(t)
	local := event(Disconnect)
	local.Timeout = 5 * time.Second
	grant(t, c, fence(t, c, local, false))
	for _, cmd := range []uint32{diam.CapabilitiesExchange, diam.DeviceWatchdog, 999} {
		for _, flags := range []uint8{0, diam.RequestFlag} {
			for _, malformed := range []bool{false, true} {
				m := diam.NewMessage(cmd, flags, 0, 1, 2, c.cfg.Dictionary)
				in := receive(m)
				if malformed {
					in.Error = &diam.MessageError{ResultCode: diam.MissingAVP}
				}
				wantKinds(t, c.Handle(in), Discard)
			}
		}
	}
	owned := receive(diam.NewMessage(999, 0, 4, 1, 2, c.cfg.Dictionary))
	owned.Ownership = 17
	es := c.Handle(owned)
	wantKinds(t, es, Admit)
	if es[0].Ownership != 17 {
		t.Fatal("drain claim lost")
	}
	wantKinds(t, c.Handle(receive(owned.Message)), Discard)
}

// RFC 6733 §§3,5.4.2,6.2.1; #108: explicit DPR ownership, both IDs and host,
// including zero IDs, precede result interpretation. Error DPA still closes.
func TestDPACorrelationAndFailureClosure(t *testing.T) {
	for _, variant := range []string{"hop", "end", "host", "realm-case", "success", "unsuccessful", "zero", "malformed"} {
		t.Run(variant, func(t *testing.T) {
			c := opened(t)
			local := event(Disconnect)
			local.Timeout = 5 * time.Second
			es := fence(t, c, local, false)
			reservation := find(t, es, ReserveIDs)
			grantIn := event(ReserveResult)
			grantIn.Token = reservation.Token
			grantIn.Reservation = Reservation{Token: 123, Hop: 30, End: 40}
			if variant == "zero" {
				grantIn.Reservation.Hop, grantIn.Reservation.End = 0, 0
			}
			sent := find(t, c.Handle(grantIn), Send)
			c.Handle(complete(sent))
			code := uint32(diam.Success)
			if variant == "unsuccessful" {
				code = diam.UnableToComply
			}
			answer, err := base.BuildDPAResult(sent.Message, remote(t).Local, code)
			if err != nil {
				t.Fatal(err)
			}
			switch variant {
			case "hop":
				answer.Header.HopByHopID++
			case "end":
				answer.Header.EndToEndID++
			case "host":
				answer.AVP[1].Data = datatype.DiameterIdentity("different.example")
			case "realm-case":
				answer.AVP[1].Data = datatype.DiameterIdentity("REMOTE.EXAMPLE")
			case "malformed":
				answer.AVP = nil
			}
			es = c.Handle(receive(answer))
			if variant == "hop" || variant == "end" || variant == "host" || variant == "malformed" {
				if c.Snapshot().Phase() != Closing {
					t.Fatal("invalid DPA completed disconnect")
				}
				find(t, es, Notify)
			} else {
				find(t, es, Close)
				if c.Snapshot().Phase() != Closed {
					t.Fatal("matched DPA did not close")
				}
				wantKinds(t, c.Handle(receive(answer)))
			}
		})
	}
	c := opened(t)
	fence(t, c, receive(request(t, diam.DisconnectPeer)), false)
	unsolicited, _ := base.BuildDPA(request(t, diam.DisconnectPeer), remote(t).Local)
	find(t, c.Handle(receive(unsolicited)), Notify)
	if c.Snapshot().Phase() != Closing {
		t.Fatal("received-only DPR owns unsolicited DPA")
	}
}

// RFC 6733 §5.6 and #108: timeout/retirement remain available with a blocked writer.
func TestClosingDeadlineAndRetirement(t *testing.T) {
	for _, retire := range []bool{false, true} {
		c := opened(t)
		local := event(Disconnect)
		sent := grant(t, c, fence(t, c, local, false))
		timer := c.Snapshot().Timer(ClosingTimer)
		in := event(TimerExpired)
		in.Timer = ClosingTimer
		in.Token = timer.Token
		in.At = timer.Deadline
		if retire {
			in = event(Retire)
		}
		es := c.Handle(in)
		if retire {
			if c.Snapshot().Phase() != Retired {
				t.Fatal("not retired")
			}
		} else {
			find(t, es, Close)
		}
		done := complete(sent)
		es = c.Handle(done)
		wantKinds(t, es, ReleaseIDs)
		wantKinds(t, c.Handle(done))
	}
}

// #108/#128 local policy: required reply failure closes at build, admission or
// full write completion; Queued is never reported as Written.
func TestRequiredReplyStages(t *testing.T) {
	for _, queued := range []bool{false, true} {
		for _, failure := range []string{"queue", "write", "short", "success"} {
			t.Run(map[bool]string{false: "sync", true: "queued"}[queued]+"/"+failure, func(t *testing.T) {
				c := opened(t, func(cfg *Config) { cfg.QueueWrites = queued })
				sent := find(t, c.Handle(receive(request(t, diam.DeviceWatchdog))), Send)
				done := complete(sent)
				done.ReplyCode = diam.Success
				if failure == "queue" {
					done.Stage = QueueStage
					done.Err = errors.New("full")
				}
				if failure == "write" {
					done.Err = errors.New("write")
				}
				if failure == "short" {
					done.Bytes--
				}
				es := c.Handle(done)
				if failure == "success" {
					wantKinds(t, es)
					if c.Snapshot().Phase() != Open {
						t.Fatal("successful required reply closed")
					}
				} else {
					find(t, es, Close)
					notice := find(t, es, Notify)
					if notice.Notification.Reply != diam.ProtocolReplyFailed || notice.Notification.Protocol != diam.ProtocolReplyFailure {
						t.Fatal("failure reporting")
					}
				}
			})
		}
	}
}

func TestQueuedRejectionClosesAfterWrite(t *testing.T) {
	c := machine(t, func(cfg *Config) { cfg.QueueWrites = true })
	bad := cer(t)
	bad.AVP = nil
	sent := find(t, c.Handle(receive(bad)), Send)
	in := complete(sent)
	in.Stage = QueueStage
	in.ReplyCode = diam.MissingAVP
	es := c.Handle(in)
	wantKinds(t, es, Notify)
	if es[0].Notification.Reply != diam.ProtocolReplyQueued {
		t.Fatal("queued reported written")
	}
	in.Stage = WrittenStage
	es = c.Handle(in)
	find(t, es, Close)
}

func TestQueuedErrorReportAndFailureOrder(t *testing.T) {
	c := opened(t, func(cfg *Config) { cfg.QueueWrites = true })
	m := diam.NewRequest(999, 4, c.cfg.Dictionary)
	in := receive(m)
	in.Kind = Unhandled
	sent := find(t, c.Handle(in), Send)
	ack := complete(sent)
	ack.Stage = QueueStage
	ack.ReplyCode = diam.CommandUnsupported
	es := c.Handle(ack)
	wantKinds(t, es, Notify)
	queued := es[0].Notification
	if queued.Protocol != diam.ProtocolUnsupportedCommand || queued.ResultCode != diam.CommandUnsupported || queued.Reply != diam.ProtocolReplyQueued || queued.ReplyCode != diam.CommandUnsupported || queued.Closing || queued.Message != metadata(m) {
		t.Fatalf("queue outcome=%+v", queued)
	}
	ack.Stage = WrittenStage
	ack.Err = errors.New("late failure")
	es = c.Handle(ack)
	wantKinds(t, es, Close, Notify)
	failed := es[1].Notification
	if failed.Protocol != diam.ProtocolReplyFailure || failed.ResultCode != 0 || failed.Reply != diam.ProtocolReplyFailed || failed.ReplyCode != diam.CommandUnsupported || !failed.Closing || failed.Message != metadata(m) {
		t.Fatalf("late failure=%+v", failed)
	}
}
