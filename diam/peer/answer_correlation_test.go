package peer

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/sm"
)

// The TCP peer controls every answer; the fake clock makes retaining the
// original admission/disconnect deadline observable without timing races.
func correlationDial(t *testing.T, clock *fakeClock) (*Manager, net.Conn, *diam.Message, <-chan diam.ProtocolErrorEvent) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	_ = l.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
	events := make(chan diam.ProtocolErrorEvent, 32)
	settings := testSettings("local.example.net")
	settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
	m, err := New(Config{Settings: settings, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeManager(t, m, nil) })
	if err := m.AddPeer(PeerConfig{Host: "known.example.net", NoAutoReconnect: true, Endpoints: []Endpoint{{Network: "tcp", Address: l.Addr().String()}}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	cer := read(t, c)
	if cer.Header.CommandCode != diam.CapabilitiesExchange {
		t.Fatalf("not CER: %v", cer.Header)
	}
	awaitState(t, m, WaitICEA)
	return m, c, cer, events
}

func correlationCEA(t *testing.T, cer *diam.Message, host string) *diam.Message {
	t.Helper()
	cea, err := base.BuildCEA(cer, testBase(host), diam.Success)
	if err != nil {
		t.Fatal(err)
	}
	return cea
}

func correlationEvent(t *testing.T, events <-chan diam.ProtocolErrorEvent, kind diam.ProtocolErrorKind, closing bool) diam.ProtocolErrorEvent {
	t.Helper()
	e := protocolErrorReceive(t, events)
	if e.Err.Kind() != kind || e.Closing != closing || e.Reply != diam.ProtocolReplyNone {
		t.Fatalf("unexpected protocol event: %+v", e)
	}
	return e
}

func correlationEOF(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	n, err := c.Read(b[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF without reply: bytes=%d err=%v", n, err)
	}
}

func TestManagerCEACorrelationOnWire(t *testing.T) {
	for _, field := range []string{"Hop-by-Hop", "End-to-End"} {
		for _, finish := range []string{"good answer", "original deadline"} {
			t.Run(field+"/"+finish, func(t *testing.T) {
				clock := &fakeClock{}
				m, c, cer, events := correlationDial(t, clock)
				mark := clock.timerCount()
				bad := correlationCEA(t, cer, "known.example.net")
				if field == "Hop-by-Hop" {
					bad.Header.HopByHopID++
				} else {
					bad.Header.EndToEndID++
				}
				// Repeat the bad answer: neither duplicate may consume the pending CER.
				for range 2 {
					write(t, c, bad)
					correlationEvent(t, events, diam.ProtocolUnexpectedMessage, false)
					if p := m.Peers()[0]; p.State != WaitICEA || p.Eligible || p.Realm != "" {
						t.Fatalf("bad CEA admitted peer: %+v", p)
					}
					if got := clock.timerCount(); got != mark {
						t.Fatalf("bad CEA rearmed deadline: %d -> %d", mark, got)
					}
				}
				if finish == "original deadline" {
					clock.fire()
					correlationEvent(t, events, diam.ProtocolHandshakeTimeout, true)
					correlationEOF(t, c)
					awaitState(t, m, Closed)
					return
				}
				good := correlationCEA(t, cer, "KNOWN.EXAMPLE.NET")
				write(t, c, good)
				awaitState(t, m, IOpen)
				if p := m.Peers()[0]; !p.Eligible || p.Realm != "example.net" {
					t.Fatalf("missing admitted identity: %+v", p)
				}
				// Duplicate CEA cannot replace the identity learned on admission.
				write(t, c, correlationCEA(t, cer, "other.example.net"))
				write(t, c, reviewDWR(t))
				if answer := read(t, c); answer.Header.CommandCode != diam.DeviceWatchdog || code(t, answer) != diam.Success {
					t.Fatalf("duplicate CEA disturbed admission: %v", answer)
				}
				awaitState(t, m, IOpen)
			})
		}
	}
}

func TestManagerCEAConfiguredHostOnWire(t *testing.T) {
	m, c, cer, events := correlationDial(t, &fakeClock{})
	write(t, c, correlationCEA(t, cer, "other.example.net"))
	correlationEvent(t, events, diam.ProtocolCEARejected, true)
	correlationEOF(t, c)
	awaitState(t, m, Closed)
}

func TestManagerCEACrossedConnectionsOnWire(t *testing.T) {
	m1, c1, cer1, events1 := correlationDial(t, &fakeClock{})
	m2, c2, cer2, events2 := correlationDial(t, &fakeClock{})
	// Distinct End-to-End values avoid assuming randomized allocators differ.
	bad1 := correlationCEA(t, cer2, "known.example.net")
	if bad1.Header.HopByHopID == cer1.Header.HopByHopID && bad1.Header.EndToEndID == cer1.Header.EndToEndID {
		bad1.Header.EndToEndID++
	}
	bad2 := correlationCEA(t, cer1, "known.example.net")
	if bad2.Header.HopByHopID == cer2.Header.HopByHopID && bad2.Header.EndToEndID == cer2.Header.EndToEndID {
		bad2.Header.EndToEndID++
	}
	write(t, c1, bad1)
	write(t, c2, bad2)
	correlationEvent(t, events1, diam.ProtocolUnexpectedMessage, false)
	correlationEvent(t, events2, diam.ProtocolUnexpectedMessage, false)
	if m1.Peers()[0].State != WaitICEA || m2.Peers()[0].State != WaitICEA {
		t.Fatal("crossed CEA admitted or closed a connection")
	}
	write(t, c1, correlationCEA(t, cer1, "known.example.net"))
	write(t, c2, correlationCEA(t, cer2, "known.example.net"))
	awaitState(t, m1, IOpen)
	awaitState(t, m2, IOpen)
}

func correlationReceiver(t *testing.T) (*Manager, net.Conn, *fakeClock, <-chan diam.ProtocolErrorEvent) {
	t.Helper()
	clock := &fakeClock{}
	events := make(chan diam.ProtocolErrorEvent, 32)
	settings := testSettings("local.example.net")
	settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
	m, err := New(Config{Settings: settings, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	if err = m.AddPeer(PeerConfig{Host: "known.example.net", NoAutoReconnect: true}); err != nil {
		t.Fatal(err)
	}
	l, srv := startReceiverWithHandlers(t, m, 8)
	t.Cleanup(func() { closeManager(t, m, srv) })
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	write(t, c, reviewCER(t))
	if code(t, read(t, c)) != diam.Success {
		t.Fatal("CEA rejected")
	}
	awaitState(t, m, ROpen)
	return m, c, clock, events
}

func TestManagerDPARequiresLocalDPROnWire(t *testing.T) {
	m, c, clock, events := correlationReceiver(t)
	dpr, err := base.BuildDPR(m.dictionary(), testBase("known.example.net"), uint32(sm.DisconnectBusy))
	if err != nil {
		t.Fatal(err)
	}
	write(t, c, dpr)
	if answer := read(t, c); answer.Header.CommandCode != diam.DisconnectPeer || code(t, answer) != diam.Success {
		t.Fatalf("not DPA: %v", answer)
	}
	awaitState(t, m, Closing)
	mark := clock.timerCount()
	// Closing due solely to a received DPR does not own a pending local DPR.
	// Zero identifiers are legal values, not evidence that a request exists.
	unsolicited, err := base.BuildDPA(dpr, testBase("known.example.net"))
	if err != nil {
		t.Fatal(err)
	}
	unsolicited.Header.HopByHopID, unsolicited.Header.EndToEndID = 0, 0
	for range 2 {
		write(t, c, unsolicited)
		correlationEvent(t, events, diam.ProtocolInvalidDPA, false)
		if m.Peers()[0].State != Closing {
			t.Fatal("unsolicited zero-ID DPA completed disconnect")
		}
		if clock.timerCount() != mark {
			t.Fatal("unsolicited DPA extended Closing")
		}
	}
	clock.fire()
	correlationEvent(t, events, diam.ProtocolDisconnectTimeout, true)
	correlationEOF(t, c)
}

func TestManagerDPAIdentityPrecedesResultOnWire(t *testing.T) {
	m, c, _, events := correlationReceiver(t)
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		done <- m.Close(ctx, sm.DisconnectRebooting)
	}()
	dpr := read(t, c)
	bad, err := base.BuildDPA(dpr, testBase("other.example.net"))
	if err != nil {
		t.Fatal(err)
	}
	result, _ := bad.FindAVP(avp.ResultCode, 0)
	result.Data = datatype.Unsigned32(diam.UnableToComply)
	write(t, c, bad)
	e := correlationEvent(t, events, diam.ProtocolInvalidDPA, false)
	if e.Err.ResultCode() != 0 {
		t.Fatalf("unbound peer result interpreted: %+v", e)
	}
	if m.Peers()[0].State != Closing {
		t.Fatal("unbound DPA closed peer")
	}
	good, err := base.BuildDPA(dpr, testBase("KNOWN.EXAMPLE.NET"))
	if err != nil {
		t.Fatal(err)
	}
	write(t, c, good)
	correlationEOF(t, c)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("valid DPA did not complete close")
	}
}

func TestManagerDPAOwnership(t *testing.T) {
	for _, fault := range []string{"no request", "stale generation", "wrong command", "zero identifiers"} {
		t.Run(fault, func(t *testing.T) {
			a, s, _ := failureReportingActor(t)
			a.state, a.i, a.active = IOpen, s, s
			a.stop(sm.DisconnectRebooting)
			dpr := (<-s.writes).msg
			gen, command := a.pendingDPRGen, a.pendingDPRCommand
			switch fault {
			case "no request":
				a.pendingDPRGen = 0
			case "stale generation":
				a.pendingDPRGen = s.gen + 1
			case "wrong command":
				a.pendingDPRCommand = diam.DeviceWatchdog
			case "zero identifiers":
				dpr.Header.HopByHopID, dpr.Header.EndToEndID = 0, 0
				a.pendingDPR, a.pendingDPREnd = 0, 0
			}
			answer, err := base.BuildDPA(dpr, testBase("known.example.net"))
			if err != nil {
				t.Fatal(err)
			}
			var events []diam.ProtocolErrorEvent
			a.m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events = append(events, e) }
			a.onWire(event{s: s, msg: answer})
			if fault != "zero identifiers" {
				if a.state != Closing || s.c.Closed() || len(events) != 1 || events[0].Err.Kind() != diam.ProtocolInvalidDPA {
					t.Fatalf("unowned DPA completed disconnect: state=%s closed=%t events=%v", a.state, s.c.Closed(), events)
				}
				// A rejected answer must leave the actual owned request consumable.
				a.pendingDPRGen, a.pendingDPRCommand = gen, command
				a.onWire(event{s: s, msg: answer})
			} else if len(events) != 0 {
				t.Fatalf("owned zero identifiers rejected: %v", events)
			}
			if a.state != Closed || !s.c.Closed() || a.pendingDPRGen != 0 || a.pendingDPRCommand != 0 {
				t.Fatalf("owned DPA did not release disconnect: state=%s gen=%d command=%d", a.state, a.pendingDPRGen, a.pendingDPRCommand)
			}
		})
	}
}

func TestManagerBoundRequestsOnWire(t *testing.T) {
	for _, command := range []uint32{diam.DeviceWatchdog, diam.DisconnectPeer} {
		t.Run(map[uint32]string{diam.DeviceWatchdog: "DWR", diam.DisconnectPeer: "DPR"}[command], func(t *testing.T) {
			m, c, clock, events := correlationReceiver(t)
			cfg := testBase("other.example.net")
			var request *diam.Message
			var err error
			kind := diam.ProtocolInvalidDWR
			if command == diam.DeviceWatchdog {
				request, err = base.BuildDWR(m.dictionary(), cfg, 0)
			} else {
				request, err = base.BuildDPR(m.dictionary(), cfg, uint32(sm.DisconnectBusy))
				kind = diam.ProtocolInvalidDPR
			}
			if err != nil {
				t.Fatal(err)
			}
			write(t, c, request)
			correlationEvent(t, events, kind, false)
			if p := m.Peers()[0]; p.State != ROpen || !p.Eligible {
				t.Fatalf("wrong-host request changed admission: %+v", p)
			}
			host, _ := request.FindAVP(avp.OriginHost, 0)
			host.Data = datatype.DiameterIdentity("KNOWN.EXAMPLE.NET")
			write(t, c, request)
			answer := read(t, c)
			if answer.Header.CommandCode != command || answer.Header.HopByHopID != request.Header.HopByHopID || answer.Header.EndToEndID != request.Header.EndToEndID || code(t, answer) != diam.Success {
				t.Fatalf("bound request not answered: %v", answer)
			}
			if command == diam.DisconnectPeer {
				awaitState(t, m, Closing)
				clock.fire()
				correlationEvent(t, events, diam.ProtocolDisconnectTimeout, true)
				correlationEOF(t, c)
			}
		})
	}
}
