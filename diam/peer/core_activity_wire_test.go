package peer

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

type coreActivityWire struct {
	m        *Manager
	c        net.Conn
	clock    *fakeClock
	events   chan diam.ProtocolErrorEvent
	a        *actor
	s        *session
	listener net.Listener
	dialed   bool
}

// The fixture enters through Manager's TCP accept/dial paths and exchanges
// actual CER/CEA frames. Only timer delivery and the actor completion fence are
// controlled by the test; protocol inputs always arrive through the socket.
func newCoreActivityWire(t *testing.T, dialed bool) *coreActivityWire {
	t.Helper()
	p := &coreActivityWire{clock: &fakeClock{}, events: make(chan diam.ProtocolErrorEvent, 32), dialed: dialed}
	cfg := testSettings("local.example.net")
	cfg.ValidateRequests = true
	cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) { p.events <- e }
	var err error
	p.m, err = New(Config{Settings: cfg, Clock: p.clock, Timers: Timers{TwInit: time.Hour}, watchdogTiming: &watchdogTiming{floor: time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	peer := PeerConfig{Host: "known.example.net", NoAutoReconnect: true}
	var server *diam.Server
	if dialed {
		p.listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = p.listener.Close() })
		peer.Endpoints = []Endpoint{{Network: "tcp", Address: p.listener.Addr().String()}}
	}
	if err := p.m.AddPeer(peer); err != nil {
		t.Fatal(err)
	}
	if dialed {
		if err := p.m.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
	} else {
		p.listener, server = startReceiver(t, p.m)
	}
	t.Cleanup(func() { closeManager(t, p.m, server) })
	t.Cleanup(func() {
		if p.c != nil {
			_ = p.c.Close()
		}
	})
	p.connect(t)
	return p
}

func (p *coreActivityWire) connect(t *testing.T) {
	t.Helper()
	var err error
	if p.dialed {
		if err := p.listener.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		p.c, err = p.listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		cer := read(t, p.c)
		if cer.Header.CommandCode != diam.CapabilitiesExchange || cer.Header.CommandFlags&diam.RequestFlag == 0 {
			t.Fatalf("want CER, got %+v", cer.Header)
		}
		write(t, p.c, correlationCEA(t, cer, "known.example.net"))
		awaitState(t, p.m, IOpen)
	} else {
		p.c, err = net.Dial("tcp", p.listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		write(t, p.c, capabilitiesExchangeRequest(t))
		if answer := read(t, p.c); answer.Header.CommandCode != diam.CapabilitiesExchange || code(t, answer) != diam.Success {
			t.Fatalf("handshake answer: %+v", answer)
		}
		awaitState(t, p.m, ROpen)
	}
	p.m.mu.RLock()
	p.a = p.m.peers["known.example.net"]
	p.s = p.a.activeSession.Load()
	p.m.mu.RUnlock()
	p.fence(t)
	if p.s == nil {
		t.Fatal("admitted connection has no session")
	}
}

// commit waits for the actor to finish the preceding decision, including all
// deferred watchdog work. No message or timer is injected by this fence.
func (p *coreActivityWire) fence(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	go func() { p.a.commit(event{kind: "test-activity-fence"}, newProtocolDelivery()); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("actor did not finish its production receive decision")
	}
}

type coreActivityState struct {
	health  WatchdogState
	pending bool
	num     int
	timer   Timer
	token   uint64
}

func (p *coreActivityWire) state(t *testing.T) coreActivityState {
	t.Helper()
	var state coreActivityState
	d := newProtocolDelivery()
	p.a.commit(event{testHook: func() {
		state = coreActivityState{p.a.watchdog, p.a.pendingWatchdog, p.a.numDWA, p.a.wdTimer, p.a.wdToken}
	}}, d)
	return state
}

func (p *coreActivityWire) expire(t *testing.T) {
	t.Helper()
	state := p.state(t)
	timer, ok := state.timer.(*fakeTimer)
	if !ok {
		t.Fatalf("production watchdog timer = %T", state.timer)
	}
	timer.mu.Lock()
	active := timer.active
	timer.active = false
	timer.mu.Unlock()
	if !active {
		t.Fatal("production watchdog timer was already stopped")
	}
	timer.f()
	p.fence(t)
}

func (p *coreActivityWire) suspect(t *testing.T) *diam.Message {
	t.Helper()
	if got := p.state(t); got.health != WatchdogOkay || got.pending {
		t.Fatalf("initial watchdog = %+v", got)
	}
	p.expire(t)
	probe := read(t, p.c)
	if probe.Header.CommandCode != diam.DeviceWatchdog || probe.Header.CommandFlags&diam.RequestFlag == 0 {
		t.Fatalf("want owned DWR, got %+v", probe.Header)
	}
	p.expire(t)
	if got := p.state(t); got.health != WatchdogSuspect || !got.pending || p.m.Peers()[0].Eligible {
		t.Fatalf("unanswered probe did not reach SUSPECT: %+v", got)
	}
	return probe
}

func (p *coreActivityWire) receiveError(t *testing.T, msg *diam.Message, reply bool) {
	t.Helper()
	write(t, p.c, msg)
	if reply {
		answer := read(t, p.c)
		if answer.Header.CommandCode != msg.Header.CommandCode || answer.Header.HopByHopID != msg.Header.HopByHopID || answer.Header.EndToEndID != msg.Header.EndToEndID || answer.Header.CommandFlags&diam.RequestFlag != 0 || code(t, answer) == diam.Success {
			t.Fatalf("invalid request response = %+v", answer)
		}
	}
	e := protocolErrorReceive(t, p.events)
	if e.Conn != p.s.c || !e.Message.HasHeader || e.Message.Header.CommandCode != msg.Header.CommandCode || e.Message.Header.HopByHopID != msg.Header.HopByHopID || e.Message.Header.EndToEndID != msg.Header.EndToEndID || e.Closing {
		t.Fatalf("invalid input notification = %+v", e)
	}
	wantReply := diam.ProtocolReplyNone
	if reply {
		wantReply = diam.ProtocolReplyQueued
	}
	if e.Reply != wantReply {
		t.Fatalf("invalid input reply disposition = %v, want %v", e.Reply, wantReply)
	}
	p.fence(t)
}

func coreActivityFault(t *testing.T, p *coreActivityWire, fault string) (*diam.Message, bool) {
	t.Helper()
	m := watchdogRequest(t)
	reply := true
	switch fault {
	case "repeated-cer", "malformed-repeated-cer":
		m = capabilitiesExchangeRequest(t)
		m.AVP = nil
		reply = false
		if fault == "malformed-repeated-cer" {
			m.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2}))
		}
	case "decode":
		m.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2}))
	case "header":
		m.Header.ApplicationID = 9
	case "grammar":
		m.AVP = nil
	case "request-validation":
		m = outboundRequest("local.example.net", "example.net")
		m.AVP = nil
	case "application":
		m = diam.NewMessage(0xfedc, diam.RequestFlag, 0xfefe, 123, 124, p.m.dictionary())
	case "bound-host", "bound-host-dpr":
		if fault == "bound-host-dpr" {
			m = closingDPR(t, p.m)
		}
		host, err := m.FindAVP(avp.OriginHost, 0)
		if err != nil {
			t.Fatal(err)
		}
		host.Data = datatype.DiameterIdentity("other.example.net")
		reply = false
	case "unsolicited-cea":
		m = correlationCEA(t, capabilitiesExchangeRequest(t), "known.example.net")
		reply = false
	case "unsolicited-dpa":
		var err error
		m, err = base.BuildDPA(closingDPR(t, p.m), testBase("known.example.net"))
		if err != nil {
			t.Fatal(err)
		}
		reply = false
	default:
		t.Fatalf("unknown activity fault %q", fault)
	}
	return m, reply
}

// RFC 3539 §3.4.1 [2], Appendix A, and the adopted #108 receive policy:
// decoded invalid traffic refreshes Tw independently of watchdog health and
// Pending. RFC 6733 §§3, 5.3–5.5, 6.2.1 govern validation and answer ownership.
func TestManagerCoreInvalidActivityTCP(t *testing.T) {
	for _, dialed := range []bool{false, true} {
		for _, fault := range []string{"malformed-repeated-cer", "repeated-cer", "decode", "header", "grammar", "request-validation", "application", "bound-host", "bound-host-dpr", "unsolicited-cea", "unsolicited-dpa"} {
			t.Run(fmt.Sprintf("dialed=%t/%s", dialed, fault), func(t *testing.T) {
				p := newCoreActivityWire(t, dialed)
				p.suspect(t)
				before := p.state(t)
				msg, reply := coreActivityFault(t, p, fault)
				p.receiveError(t, msg, reply)
				after := p.state(t)
				if after.timer == nil || after.timer == before.timer || after.token == before.token {
					t.Errorf("decoded invalid receipt did not reset Tw: before=%+v after=%+v", before, after)
				}
				if after.health != WatchdogSuspect || after.pending != before.pending || after.num != before.num || p.m.Peers()[0].Eligible {
					t.Errorf("decoded invalid receipt earned health or Pending credit: before=%+v after=%+v", before, after)
				}
				p.m.pendingMu.Lock()
				controls := len(p.m.controls[p.s])
				p.m.pendingMu.Unlock()
				if controls != 1 || !p.s.requests.HasPending() {
					t.Errorf("invalid receipt changed outstanding DWR ownership: controls=%d nativePending=%t", controls, p.s.requests.HasPending())
				}
				// A callback selected by the old timer must be harmless after reset.
				before.timer.(*fakeTimer).f()
				stale := p.state(t)
				if stale != after {
					t.Errorf("pre-receipt timer changed refreshed watchdog: before=%+v after=%+v", after, stale)
				}
			})
		}
	}
}

// Valid non-DWA traffic restores SUSPECT but cannot complete the owned DWR.
// Only its successful correlated DWA releases Pending (RFC 3539 Appendix A).
func TestManagerCoreValidActivityAndOwnedDWATCP(t *testing.T) {
	for _, dialed := range []bool{false, true} {
		t.Run(fmt.Sprintf("dialed=%t", dialed), func(t *testing.T) {
			p := newCoreActivityWire(t, dialed)
			probe := p.suspect(t)
			request := watchdogRequest(t)
			write(t, p.c, request)
			answer := read(t, p.c)
			if answer.Header.CommandCode != diam.DeviceWatchdog || answer.Header.HopByHopID != request.Header.HopByHopID || answer.Header.EndToEndID != request.Header.EndToEndID || code(t, answer) != diam.Success {
				t.Fatalf("valid DWR response = %+v", answer)
			}
			if got := p.state(t); got.health != WatchdogOkay || !got.pending || !p.m.Peers()[0].Eligible {
				t.Fatalf("valid DWR changed probe ownership or failed recovery: %+v", got)
			}
			dwa, err := base.BuildDWA(probe, testBase("known.example.net"))
			if err != nil {
				t.Fatal(err)
			}
			write(t, p.c, dwa)
			// A following request's response fences the preceding wire receive; the
			// Manager's ingress queue preserves connection order through dispatch.
			write(t, p.c, watchdogRequest(t))
			_ = read(t, p.c)
			if got := p.state(t); got.health != WatchdogOkay || got.pending || p.s.requests.HasPending() {
				t.Fatalf("owned successful DWA retained watchdog/native ownership: %+v", got)
			}
			p.m.pendingMu.Lock()
			controls := len(p.m.controls[p.s])
			p.m.pendingMu.Unlock()
			if controls != 0 {
				t.Fatalf("owned DWA retained %d control identifiers", controls)
			}
		})
	}
}

// Reconnect enters REOPEN through the real transport lifecycle. The adopted
// #108 policy refreshes Tw on decoded traffic while preserving Appendix A's
// three successful DWA requirement and application admission gate.
func TestManagerCoreReopenActivityTCP(t *testing.T) {
	for _, dialed := range []bool{false, true} {
		for _, fault := range []string{"valid-dwr", "decode", "repeated-cer"} {
			t.Run(fmt.Sprintf("dialed=%t/%s", dialed, fault), func(t *testing.T) {
				p := newCoreActivityWire(t, dialed)
				_ = p.c.Close()
				awaitState(t, p.m, Closed)
				p.fence(t)
				if p.a.watchdog != WatchdogDown {
					t.Fatalf("transport loss watchdog = %s", p.a.watchdog)
				}
				if dialed {
					p.a.post(event{kind: start})
				}
				p.connect(t)
				probe := read(t, p.c)
				if probe.Header.CommandCode != diam.DeviceWatchdog || probe.Header.CommandFlags&diam.RequestFlag == 0 {
					t.Fatalf("REOPEN probe = %+v", probe.Header)
				}
				before := p.state(t)
				if before.health != WatchdogReopen || !before.pending || before.num != 0 || p.m.Peers()[0].Eligible {
					t.Fatalf("reconnect bypassed REOPEN: %+v", before)
				}
				if fault == "valid-dwr" {
					write(t, p.c, watchdogRequest(t))
					_ = read(t, p.c)
					p.fence(t)
				} else {
					msg, reply := coreActivityFault(t, p, fault)
					p.receiveError(t, msg, reply)
				}
				after := p.state(t)
				if after.timer == nil || after.timer == before.timer || after.token == before.token || after.health != WatchdogReopen || !after.pending || after.num != 0 || p.m.Peers()[0].Eligible {
					t.Errorf("REOPEN activity failed reset-only contract: before=%+v after=%+v", before, after)
				}
				for want := 1; want <= 3; want++ {
					dwa, err := base.BuildDWA(probe, testBase("known.example.net"))
					if err != nil {
						t.Fatal(err)
					}
					write(t, p.c, dwa)
					write(t, p.c, watchdogRequest(t))
					_ = read(t, p.c)
					got := p.state(t)
					if got.pending || got.num != want || (got.health == WatchdogOkay) != (want == 3) || p.m.Peers()[0].Eligible != (want == 3) {
						t.Fatalf("recovery DWA %d: %+v", want, got)
					}
					if want != 3 {
						p.expire(t)
						probe = read(t, p.c)
					}
				}
			})
		}
	}
}
