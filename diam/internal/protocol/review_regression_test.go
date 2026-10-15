package protocol

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

// RFC 3539 Appendix A send/publication separation; #108/#128. One selected
// probe retains its reservation until publication or cancellation completes.
func TestTentativeWatchdogProbeDoesNotOverlap(t *testing.T) {
	for _, allocated := range []bool{false, true} {
		t.Run(fmt.Sprint(allocated), func(t *testing.T) {
			c := supervised(t, false)
			reservation := find(t, tick(t, c), ReserveIDs)
			var sent Effect
			if allocated {
				sent = grant(t, c, []Effect{reservation})
			}
			activity := receive(cer(t))
			activity.At = epoch.Add(7 * time.Second)
			c.Handle(activity)
			wantKinds(t, tick(t, c), StopTimer, ArmTimer)
			if c.Snapshot().Watchdog().Pending {
				t.Fatal("unpublished probe became Pending")
			}
			if !allocated {
				sent = grant(t, c, []Effect{reservation})
			}
			c.Handle(complete(sent))
			if len(c.Snapshot().Controls()) != 1 || !c.Snapshot().Watchdog().Pending {
				t.Fatal("lost selected probe")
			}
			es := c.Handle(event(Retire))
			releases := 0
			for _, e := range es {
				if e.Kind == ReleaseIDs {
					releases++
				}
			}
			if releases != 1 {
				t.Fatalf("reservation releases=%d", releases)
			}
		})
	}
}

// RFC 6733 §§5.3–5.6: a hook continuation remains the original protocol
// operation; it cannot create a second candidate or rebind an open peer.
func TestHookCannotChangeProtocolCoordinates(t *testing.T) {
	for _, phase := range []string{"pre", "open", "closing"} {
		for _, coordinate := range []string{"command", "application", "request", "hop", "end", "body"} {
			t.Run(phase+"/"+coordinate, func(t *testing.T) {
				c := machine(t, func(cfg *Config) { cfg.Hooks = true })
				m := cer(t)
				if phase != "pre" {
					c = opened(t)
					c.cfg.Hooks = true
					m = request(t, diam.DeviceWatchdog)
				}
				hook := find(t, c.Handle(receive(m)), RunHook)
				if phase == "closing" {
					c.Handle(event(Disconnect))
				}
				before := c.Snapshot().Capabilities()
				in := event(Continue)
				in.Token = hook.Token
				in.Message = copyMessage(m)
				switch coordinate {
				case "command":
					if phase == "pre" {
						in.Message = request(t, diam.DeviceWatchdog)
					} else {
						in.Message = cer(t)
					}
				case "application":
					in.Message.Header.ApplicationID = 4
				case "request":
					in.Message.Header.CommandFlags = 0
				case "hop":
					in.Message.Header.HopByHopID++
				case "end":
					in.Message.Header.EndToEndID++
				case "body":
					in.Message.AddAVP(diam.NewAVP(264, 64, 0, datatype.DiameterIdentity("duplicate.example")))
				}
				es := c.Handle(in)
				if c.Snapshot().Candidate() != 0 || !reflect.DeepEqual(before, c.Snapshot().Capabilities()) {
					t.Fatal("hook changed peer binding")
				}
				for _, e := range es {
					if e.Kind == ValidatedCER || e.Kind == Admit {
						t.Fatal("hook changed operation")
					}
				}
				if coordinate == "body" {
					if phase == "pre" {
						sent := find(t, es, Send)
						find(t, c.Handle(complete(sent)), Close)
					} else {
						wantKinds(t, es, Discard, Notify)
					}
				} else if c.Snapshot().Phase() != Closed {
					t.Fatalf("invalid hook left phase=%v effects=%v", c.Snapshot().Phase(), kinds(es))
				}
			})
		}
	}
}

// RFC 6733 §§5.3.1–5.3.2; full remote offer and common applications differ.
func TestRemoteApplicationOfferIsComplete(t *testing.T) {
	for _, role := range []Role{Responder, Initiator} {
		t.Run(fmt.Sprint(role), func(t *testing.T) {
			c := machine(t, func(cfg *Config) { cfg.Role = role })
			m := cer(t)
			m.AddAVP(diam.NewAVP(258, 64, 0, datatype.Unsigned32(99)))
			if role == Initiator {
				sent := grant(t, c, c.Handle(event(Start)))
				cfg := remote(t)
				cfg.Local.AuthApplicationID = append(cfg.Local.AuthApplicationID, diam.NewAVP(258, 64, 0, datatype.Unsigned32(99)))
				var err error
				m, err = base.BuildCEA(sent.Message, cfg.Local, diam.Success)
				if err != nil {
					t.Fatal(err)
				}
			}
			c.Handle(receive(m))
			caps := c.Snapshot().Capabilities()
			if !reflect.DeepEqual(caps.RemoteApplications, []uint32{4, 99}) || !reflect.DeepEqual(caps.CommonApplications, []uint32{4}) {
				t.Fatalf("remote=%v common=%v", caps.RemoteApplications, caps.CommonApplications)
			}
		})
	}
}

// #108: unsuccessful DWA settles native in-flight ownership without credit.
// A later valid correlated success may clear the separately retained Pending.
func TestDWACompletesNativeOwnershipOnce(t *testing.T) {
	c := supervised(t, false)
	sent := probe(t, c)
	tick(t, c)
	for i, code := range []uint32{diam.UnableToComply, diam.UnableToComply, diam.Success, diam.Success} {
		es := c.Handle(receive(dwa(t, sent, code)))
		completions := 0
		for _, e := range es {
			if e.Kind == CompleteRequest {
				completions++
			}
		}
		want := 0
		if i == 0 {
			want = 1
		}
		if completions != want {
			t.Fatalf("answer=%d completions=%d want=%d", i, completions, want)
		}
	}
	if c.Snapshot().Watchdog().Pending {
		t.Fatal("later valid success lost credit")
	}
}

// RFC 6733 §5.4; #108 crossed/repeated DPR policy: the first received DPR
// is observable even after a local Disconnect, without extending Closing.
func TestCrossedDPRNotifiesPeerOnce(t *testing.T) {
	for _, queued := range []bool{false, true} {
		t.Run(fmt.Sprint(queued), func(t *testing.T) {
			c := opened(t, func(cfg *Config) { cfg.QueueWrites = queued })
			grant(t, c, fence(t, c, event(Disconnect), false))
			deadline := c.Snapshot().Timer(ClosingTimer)
			for i := 0; i < 2; i++ {
				m := request(t, diam.DisconnectPeer)
				for _, a := range m.AVP {
					if a.Code == 273 {
						a.Data = datatype.Enumerated(i + 1)
					}
				}
				sent := find(t, c.Handle(receive(m)), Send)
				done := complete(sent)
				done.ReplyCode = diam.Success
				if queued {
					done.Stage = QueueStage
				}
				es := c.Handle(done)
				notices := 0
				for _, e := range es {
					if e.Kind == Notify && e.Notification.Kind == PeerDisconnectNotice {
						notices++
						if e.Notification.Cause != 1 {
							t.Fatal("remote cause lost")
						}
					}
				}
				want := 1 - i
				if notices != want {
					t.Fatalf("DPR=%d notices=%d want=%d", i, notices, want)
				}
				if queued {
					done.Stage = WrittenStage
					wantKinds(t, c.Handle(done))
				}
				if c.Snapshot().Timer(ClosingTimer) != deadline {
					t.Fatal("crossed DPR moved deadline")
				}
			}
		})
	}
}

// RFC 6733 §§5.3,6.10: security is established by the transport before CER;
// the core snapshots it and never requests an in-band TLS upgrade.
func TestTransportSecuritySnapshot(t *testing.T) {
	c := machine(t, func(cfg *Config) { cfg.TLS = true })
	m := cer(t)
	m.AddAVP(diam.NewAVP(299, 64, 0, datatype.Unsigned32(1)))
	find(t, c.Handle(receive(m)), ValidatedCER)
	if !c.Snapshot().Capabilities().TLS {
		t.Fatal("established security omitted")
	}
}

// #108: a synchronous owner cannot publish a handshake on queue admission.
func TestSynchronousHandshakeWaitsForWritten(t *testing.T) {
	c := machine(t)
	sent := find(t, accept(t, c), Send)
	queued := complete(sent)
	queued.Stage = QueueStage
	wantKinds(t, c.Handle(queued))
	release := event(ReleaseAdmission)
	release.Token = c.Snapshot().Admission()
	wantKinds(t, c.Handle(release))
	if c.Snapshot().Ready() {
		t.Fatal("queue admission released application barrier")
	}
	find(t, c.Handle(complete(sent)), HandshakeReady)
}
