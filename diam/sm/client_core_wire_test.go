package sm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
)

// This fixture enters through the public Dial API. In particular, it does not
// manufacture an activity handler or deliver input directly to a core.
func newClientCoreTCP(t *testing.T, configure func(*Client)) *protocolClientWire {
	return newClientCoreTCPDial(t, configure, func(c *Client, addr string) (diam.Conn, error) { return c.Dial(addr) })
}

func newClientCoreTCPDial(t *testing.T, configure func(*Client), dial func(*Client, string) (diam.Conn, error)) *protocolClientWire {
	t.Helper()
	testDict := newSMTestDictionary(creditcontrol.Dictionary())
	cfg := cloneTestSettings(clientSettings, testDict)
	cfg.AuthApplicationID = []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4))}
	p := &protocolClientWire{events: make(chan diam.ProtocolErrorEvent, 32), dialed: make(chan protocolClientDialResult, 1), logs: logtest.New()}
	cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) { p.events <- e }
	p.client = &Client{Handler: mustNewStateMachine(t, cfg, testDict), Logger: p.logs.Logger(), Dict: testDict, RetransmitInterval: time.Second}
	if configure != nil {
		configure(p.client)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := dial(p.client, listener.Addr().String())
		p.dialed <- protocolClientDialResult{conn: c, err: err}
	}()
	p.peer, err = listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.peer.Close() })
	if err := p.peer.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	p.cer, err = diam.ReadMessage(p.peer, testDict)
	if err != nil || p.cer.Header.CommandCode != diam.CapabilitiesExchange || p.cer.Header.CommandFlags&diam.RequestFlag == 0 {
		t.Fatalf("CER=%v error=%v", p.cer, err)
	}
	return p
}

func admitClientCoreTCP(t *testing.T, p *protocolClientWire) {
	t.Helper()
	p.send(t, protocolClientCEA(p.cer, diam.Success))
	result := p.dialResult(t)
	if result.err != nil || result.conn == nil {
		t.Fatalf("Dial = %+v", result)
	}
	p.conn = result.conn
	t.Cleanup(p.conn.Close)
}

// RFC 3539 §3.4.1 [2], Appendix A, and the #108 receive policy: all
// decoded activity resets Tw; invalid traffic cannot recover SUSPECT.
func TestClientCoreInvalidActivityTCP(t *testing.T) {
	for _, fault := range []string{"repeated-cer", "malformed-repeated-cer", "decode", "header", "grammar", "request-validation", "application", "bound-host", "bound-host-dpr", "unsolicited-cea", "unsolicited-dpa"} {
		t.Run(fault, func(t *testing.T) {
			events := make(chan acceptedWatchdogEvent, 32)
			p := newClientCoreTCP(t, func(c *Client) {
				c.EnableWatchdog = true
				c.Handler.cfg.ValidateRequests = true
				c.WatchdogInterval = time.Hour
				c.watchdogTiming = &watchdogTiming{floor: time.Millisecond}
				c.OnWatchdogConnEvent = func(conn diam.Conn, event WatchdogEvent) { events <- acceptedWatchdogEvent{conn: conn, event: event} }
			})
			admitClientCoreTCP(t, p)
			state := p.client.Handler.acceptedCore(p.conn, nil, false)
			if state == nil {
				t.Fatal("admitted connection lost its production core")
			}
			awaitProductionWatchdogTimer(t, state, false)
			expireClientTestWatchdog(state)
			probe := acceptedWatchdogOnWire(t, p.peer)
			awaitAcceptedEvent(t, events, WatchdogRequestSent, p.conn)
			awaitProductionWatchdogTimer(t, state, true)
			expireClientTestWatchdog(state)
			awaitAcceptedEvent(t, events, WatchdogSuspect, p.conn)
			before := state.snapshot()
			m := regressionDWR(t)
			setWireIdentity(t, m, avp.OriginHost, "peer.example")
			setWireIdentity(t, m, avp.OriginRealm, "example")
			answer := true
			switch fault {
			case "repeated-cer", "malformed-repeated-cer":
				m = regressionCER(t, p.client.Dict, 4)
				m.AVP = nil
				answer = false
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
				m = baseSessionRequest(diam.ReAuth)
				m.AVP = m.AVP[1:]
			case "application":
				m = diam.NewMessage(0xfedc, diam.RequestFlag, 0xfefe, 123, 124, p.client.Dict)
			case "bound-host", "bound-host-dpr":
				if fault == "bound-host-dpr" {
					m.Header.CommandCode = diam.DisconnectPeer
					m.AddAVP(diam.NewAVP(avp.DisconnectCause, avp.Mbit, 0, datatype.Enumerated(0)))
				}
				setWireIdentity(t, m, avp.OriginHost, "another.example")
				answer = false
			case "unsolicited-cea":
				m = protocolClientCEA(p.cer, diam.Success)
				answer = false
			case "unsolicited-dpa":
				m = acceptedDWA(t, probe, diam.Success)
				m.Header.CommandCode = diam.DisconnectPeer
				answer = false
			}
			p.send(t, m)
			if answer {
				if _, err := diam.ReadMessage(p.peer, p.client.Dict); err != nil {
					t.Fatal(err)
				}
			}
			_ = protocolEvent(t, p.events)
			assertInvalidActivityTimerReset(t, state, before)
			select {
			case e := <-events:
				t.Fatalf("invalid activity emitted %s", e.event)
			default:
			}
			valid := acceptedDWA(t, probe, diam.Success)
			setWireIdentity(t, valid, avp.OriginHost, "peer.example")
			setWireIdentity(t, valid, avp.OriginRealm, "example")
			p.send(t, valid)
			seen := make(map[WatchdogEvent]bool)
			for range 2 {
				event := awaitCorrelationRecovery(t, events, p.conn)
				if seen[event] {
					t.Fatalf("duplicate positive-control recovery %s", event)
				}
				seen[event] = true
			}
		})
	}
}

func awaitProductionWatchdogTimer(t *testing.T, state *acceptedHandshake, pending bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		state.mu.Lock()
		snapshot := state.core.Snapshot()
		ready := state.watchdog != nil && state.timers[protocol.WatchdogTimer] != nil && snapshot.Ready() && snapshot.Timer(protocol.WatchdogTimer).Token != 0 && snapshot.Watchdog().Pending == pending
		state.mu.Unlock()
		if ready {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("watchdog admission/publication did not install its production timer")
		}
		runtime.Gosched()
	}
}

// A decoded invalid frame resets the production timer without changing health.
// The pre-receipt timer token must be inert after that receipt.
func assertInvalidActivityTimerReset(t *testing.T, state *acceptedHandshake, before protocol.Snapshot) {
	t.Helper()
	after := state.snapshot()
	previous := before.Timer(protocol.WatchdogTimer)
	current := after.Timer(protocol.WatchdogTimer)
	if current.Token == 0 || current.Token == previous.Token || after.Phase() != protocol.Open || after.Watchdog() != before.Watchdog() {
		t.Fatalf("invalid receipt changed health or failed to reset its production timer: before=%+v after=%+v", before, after)
	}
	state.apply(protocol.Input{Kind: protocol.TimerExpired, Timer: protocol.WatchdogTimer, Token: previous.Token, At: previous.Deadline})
	stale := state.snapshot()
	if stale.Timer(protocol.WatchdogTimer) != current || stale.Watchdog() != after.Watchdog() || stale.Phase() != protocol.Open {
		t.Fatal("timer selected before invalid receipt changed the refreshed watchdog state")
	}
}

// RFC 6733 §§3, 6.2.1: a pre-hook continuation retains its coordinates.
func TestClientCoreHookCoordinatesTCP(t *testing.T) {
	for _, command := range []string{"CER", "DWR"} {
		for _, coordinate := range []string{"command", "application", "direction", "hop", "end"} {
			t.Run(fmt.Sprintf("%s/%s", command, coordinate), func(t *testing.T) {
				p := newClientCoreTCP(t, func(c *Client) {
					hook := func(_ diam.Conn, m *diam.Message) {
						switch coordinate {
						case "command":
							m.Header.CommandCode++
						case "application":
							m.Header.ApplicationID++
						case "direction":
							m.Header.CommandFlags ^= diam.RequestFlag
						case "hop":
							m.Header.HopByHopID++
						case "end":
							m.Header.EndToEndID++
						}
					}
					if command == "CER" {
						c.Handler.cfg.OnCER = hook
					} else {
						c.Handler.cfg.OnDWR = hook
					}
				})
				admitClientCoreTCP(t, p)
				m := regressionDWR(t)
				setWireIdentity(t, m, avp.OriginHost, "peer.example")
				setWireIdentity(t, m, avp.OriginRealm, "example")
				if command == "CER" {
					m = regressionCER(t, p.client.Dict, 4)
				}
				p.send(t, m)
				if err := p.peer.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
					t.Fatal(err)
				}
				var b [1]byte
				if n, err := p.peer.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
					t.Fatalf("coordinate-changing hook: bytes=%x err=%v, want closure", b[:n], err)
				}
				logs := p.logs.Records()
				if len(logs) != 1 || logs[0].Level != slog.LevelError || logError(logs[0]) == nil {
					t.Fatalf("hook failure logs=%v", logs)
				}
			})
		}
	}
}

// RFC 6733 §§3, 5.3, 6.2.1: a stray CEA cannot complete or consume
// the live CER exchange, including one with a recoverable decoding error.
func TestClientCoreCEACorrelationTCP(t *testing.T) {
	for _, fault := range []string{"hop", "end", "malformed-hop", "malformed-end"} {
		t.Run(fault, func(t *testing.T) {
			p := newClientCoreTCP(t, nil)
			m := protocolClientCEA(p.cer, diam.Success)
			switch fault {
			case "hop", "malformed-hop":
				m.Header.HopByHopID++
			case "end", "malformed-end":
				m.Header.EndToEndID++
			}
			if fault == "malformed-hop" || fault == "malformed-end" {
				m.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2}))
			}
			header := p.send(t, m)
			event := protocolEvent(t, p.events)
			if event.Err.Kind() != diam.ProtocolUnexpectedMessage || !event.Message.HasHeader || event.Message.Header.HopByHopID != header.HopByHopID || event.Message.Header.EndToEndID != header.EndToEndID || event.Closing {
				t.Fatalf("stray CEA event = %+v", event)
			}
			select {
			case result := <-p.dialed:
				if result.conn != nil {
					result.conn.Close()
				}
				t.Fatalf("stray CEA completed Dial: %+v", result)
			default:
			}
			admitClientCoreTCP(t, p)
		})
	}
}

// RFC 6733 §§5.3.2, 7.1: the public handshake error retains parsed CEA
// evidence and concrete parser identities after validation in the core.
func TestClientCoreCEARejectionTCP(t *testing.T) {
	for _, fault := range []string{"missing-host", "duplicate-host", "result", "no-common-application"} {
		t.Run(fault, func(t *testing.T) {
			p := newClientCoreTCP(t, nil)
			m := protocolClientCEA(p.cer, diam.Success)
			switch fault {
			case "missing-host":
				removeWireAVP(m, avp.OriginHost)
			case "duplicate-host":
				m.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
			case "result":
				a, _ := m.FindAVP(avp.ResultCode, 0)
				a.Data = datatype.Unsigned32(diam.UnableToComply)
				m.AddAVP(diam.NewAVP(avp.ErrorMessage, 0, 0, datatype.UTF8String("synthetic rejection")))
			case "no-common-application":
				a, _ := m.FindAVP(avp.AuthApplicationID, 0)
				a.Data = datatype.Unsigned32(0x00fffffe)
			}
			p.send(t, m)
			result := p.dialResult(t)
			if result.conn != nil || result.err == nil {
				t.Fatalf("rejected CEA admitted: %+v", result)
			}
			switch fault {
			case "missing-host":
				var message *diam.MessageError
				var validation *diam.ValidationError
				if !errors.As(result.err, &message) || message.ResultCode != diam.MissingAVP || !errors.As(result.err, &validation) {
					t.Fatalf("missing-host error = %T %v", result.err, result.err)
				}
			case "duplicate-host":
				var message *diam.MessageError
				if !errors.As(result.err, &message) || message.ResultCode != diam.AVPOccursTooManyTimes {
					t.Fatalf("duplicate-host error = %T %v", result.err, result.err)
				}
			case "result":
				var failed *smparser.ErrFailedResultCode
				if !errors.As(result.err, &failed) || failed.CEA == nil || failed.ResultCode != diam.UnableToComply || failed.OriginHost != "peer.example" || failed.ProductName != "peer" || failed.ErrorMessage != "synthetic rejection" {
					t.Fatalf("rejection lost parsed CEA: %T %v", result.err, result.err)
				}
			case "no-common-application":
				if !errors.Is(result.err, smparser.ErrNoCommonApplication) {
					t.Fatalf("application error = %T %v", result.err, result.err)
				}
			}
			p.closed(t)
		})
	}
}

func TestClientCoreCERBudgetTCP(t *testing.T) {
	for _, budget := range []int{0, 2} {
		t.Run(fmt.Sprint(budget), func(t *testing.T) {
			p := newClientCoreTCP(t, func(c *Client) { c.RetransmitInterval = 30 * time.Millisecond; c.MaxRetransmits = uint(budget) })
			for range budget {
				m, err := diam.ReadMessage(p.peer, p.client.Dict)
				if err != nil || m.Header.CommandCode != diam.CapabilitiesExchange || m.Header.CommandFlags&diam.RequestFlag == 0 || m.Header.HopByHopID != p.cer.Header.HopByHopID || m.Header.EndToEndID != p.cer.Header.EndToEndID {
					t.Fatalf("CER retransmission = %v, %v", m, err)
				}
			}
			if result := p.dialResult(t); result.conn != nil || !errors.Is(result.err, ErrHandshakeTimeout) {
				t.Fatalf("budget result = %+v", result)
			}
			p.closed(t)
		})
	}
}

func TestClientCoreWaitCEACancellationTCP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p := newClientCoreTCPDial(t, nil, func(c *Client, addr string) (diam.Conn, error) { return c.DialContext(ctx, "tcp", addr, nil) })
	cancel()
	if result := p.dialResult(t); result.conn != nil || !errors.Is(result.err, context.Canceled) {
		t.Fatalf("canceled result = %+v", result)
	}
	p.closed(t)
}

// RFC 6733 §§5.4.2, 5.6: Closing fences new application input before
// validation or hooks; only a DPA correlated to the selected DPR completes it.
func TestClientCoreClosingTCP(t *testing.T) {
	var delivered atomic.Int32
	var hooks atomic.Int32
	p := newClientCoreTCP(t, func(c *Client) {
		c.Handler.HandleIdx(diam.CommandIndex{AppID: 0, Code: 0xeeff, Request: false}, diam.HandlerFunc(func(diam.Conn, *diam.Message) { delivered.Add(1) }))
		c.Handler.cfg.OnDWR = func(diam.Conn, *diam.Message) { hooks.Add(1) }
	})
	admitClientCoreTCP(t, p)
	// Positive control: the same route is live before Closing.
	p.send(t, diam.NewMessage(0xeeff, 0, 0, 101, 102, p.client.Dict))
	deadline := time.Now().Add(10 * time.Second)
	for delivered.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if delivered.Load() != 1 {
		t.Fatal("application positive control did not reach production handler")
	}
	done := make(chan error, 1)
	go func() { done <- p.client.Handler.Disconnect(p.conn, DisconnectRebooting, time.Hour) }()
	request, err := diam.ReadMessage(p.peer, p.client.Dict)
	if err != nil || request.Header.CommandCode != diam.DisconnectPeer || request.Header.CommandFlags&diam.RequestFlag == 0 {
		t.Fatalf("DPR=%v %v", request, err)
	}
	p.send(t, diam.NewMessage(0xeeff, 0, 0, 103, 104, p.client.Dict))
	p.send(t, regressionDWR(t))
	wrong := acceptedDWA(t, request, diam.Success)
	wrong.Header.EndToEndID++
	setWireIdentity(t, wrong, avp.OriginHost, "peer.example")
	setWireIdentity(t, wrong, avp.OriginRealm, "example")
	p.send(t, wrong)
	event := protocolEvent(t, p.events)
	if event.Err.Kind() != diam.ProtocolUnexpectedMessage {
		t.Fatalf("wrong DPA event=%+v", event)
	}
	select {
	case err := <-done:
		t.Fatalf("wrong DPA completed Disconnect: %v", err)
	default:
	}
	answer := acceptedDWA(t, request, diam.Success)
	setWireIdentity(t, answer, avp.OriginHost, "peer.example")
	setWireIdentity(t, answer, avp.OriginRealm, "example")
	p.send(t, answer)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Disconnect: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("matching DPA did not complete Disconnect")
	}
	p.closed(t)
	if delivered.Load() != 1 || hooks.Load() != 0 {
		t.Fatalf("Closing admitted callbacks: application=%d DWR=%d", delivered.Load(), hooks.Load())
	}
}

// RFC 3539 Appendix A and the #108 publication boundary permit one
// tentative DWR while its actual TCP writer has not returned.
func TestClientCoreTentativeProbeTCP(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var attempts atomic.Int32
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	events := make(chan acceptedWatchdogEvent, 32)
	p := newClientCoreTCPDial(t, func(c *Client) {
		c.EnableWatchdog = true
		c.WatchdogInterval = time.Hour
		c.watchdogTiming = &watchdogTiming{floor: time.Millisecond}
		c.OnWatchdogConnEvent = func(conn diam.Conn, event WatchdogEvent) { events <- acceptedWatchdogEvent{conn: conn, event: event} }
	}, func(c *Client, addr string) (diam.Conn, error) {
		raw, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		return c.NewConn(&acceptedCoreBlockedTCP{Conn: raw, entered: entered, release: release, attempts: &attempts, once: &once}, addr)
	})
	admitClientCoreTCP(t, p)
	state := p.client.Handler.acceptedCore(p.conn, nil, false)
	if state == nil {
		t.Fatal("admitted connection lost its production core")
	}
	awaitProductionWatchdogTimer(t, state, false)
	probeDone := make(chan struct{})
	go func() { expireClientTestWatchdog(state); close(probeDone) }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("DWR writer did not enter")
	}
	admitted := make(chan struct{}, 1)
	p.client.Handler.HandleIdx(diam.CommandIndex{Code: 0xeeff, Request: false}, diam.HandlerFunc(func(diam.Conn, *diam.Message) { admitted <- struct{}{} }))
	p.send(t, diam.NewMessage(0xeeff, 0, 0, 99, 100, p.client.Dict))
	select {
	case <-admitted:
	case <-time.After(10 * time.Second):
		t.Fatal("activity blocked behind selected writer")
	}
	for range 3 {
		before := state.snapshot().Timer(protocol.WatchdogTimer)
		if before.Token == 0 {
			t.Fatal("inbound activity did not arm the production watchdog timer")
		}
		expired := make(chan struct{})
		go func() { expireClientTestWatchdog(state); close(expired) }()
		select {
		case <-expired:
		case <-time.After(10 * time.Second):
			t.Fatal("blocked probe expiry waited behind its selected writer")
		}
		if after := state.snapshot().Timer(protocol.WatchdogTimer); after.Token == 0 || after.Token == before.Token {
			t.Fatal("blocked probe expiry did not rearm the watchdog timer")
		}
	}
	if attempts.Load() != 1 || p.conn.Closed() {
		t.Fatalf("unpublished probe: attempts=%d closed=%t", attempts.Load(), p.conn.Closed())
	}
	select {
	case e := <-events:
		t.Fatalf("unpublished probe emitted %s", e.event)
	default:
	}
	close(release)
	protocolGenerationAwait(t, probeDone)
	probe := acceptedWatchdogOnWire(t, p.peer)
	awaitAcceptedEvent(t, events, WatchdogRequestSent, p.conn)
	valid := acceptedDWA(t, probe, diam.Success)
	setWireIdentity(t, valid, avp.OriginHost, "peer.example")
	setWireIdentity(t, valid, avp.OriginRealm, "example")
	p.send(t, valid)
	awaitAcceptedEvent(t, events, WatchdogAnswerReceived, p.conn)
	if err := p.peer.SetReadDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if m, err := diam.ReadMessage(p.peer, p.client.Dict); err == nil {
		t.Fatalf("second probe escaped before a fresh Tw: %v", m)
	} else {
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("premature probe check: %v", err)
		}
	}
	if attempts.Load() != 1 {
		t.Fatalf("duplicate tentative probe: %d", attempts.Load())
	}
}

func TestClientCoreHookBoundariesTCP(t *testing.T) {
	var cer, dwa atomic.Int32
	p := newClientCoreTCP(t, func(c *Client) {
		c.Handler.cfg.OnCER = func(diam.Conn, *diam.Message) { cer.Add(1) }
		c.Handler.cfg.OnDWA = func(diam.Conn, *diam.Message) { dwa.Add(1) }
	})
	admitClientCoreTCP(t, p)
	malformed := regressionCER(t, p.client.Dict, 4)
	malformed.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2}))
	p.send(t, malformed)
	_ = protocolEvent(t, p.events)
	if cer.Load() != 0 {
		t.Fatalf("malformed repeat invoked OnCER %d times", cer.Load())
	}
	p.send(t, regressionCER(t, p.client.Dict, 4))
	_ = protocolEvent(t, p.events)
	if cer.Load() != 1 {
		t.Fatalf("decoded repeat invoked OnCER %d times", cer.Load())
	}
	bad := regressionDWR(t)
	bad.AVP = nil
	p.send(t, bad)
	answer, err := diam.ReadMessage(p.peer, p.client.Dict)
	if err != nil || !testResultCode(answer, diam.MissingAVP) {
		t.Fatalf("automatic error DWA=%v %v", answer, err)
	}
	_ = protocolEvent(t, p.events)
	if dwa.Load() != 0 {
		t.Fatalf("automatic error invoked OnDWA %d times", dwa.Load())
	}
	malformedDWR := regressionDWR(t)
	malformedDWR.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2}))
	p.send(t, malformedDWR)
	answer, err = diam.ReadMessage(p.peer, p.client.Dict)
	if err != nil || !testResultCode(answer, diam.InvalidAVPLength) {
		t.Fatalf("decoding-error DWA=%v %v", answer, err)
	}
	_ = protocolEvent(t, p.events)
	if dwa.Load() != 0 {
		t.Fatalf("decoding-error answer invoked OnDWA %d times", dwa.Load())
	}
	good := regressionDWR(t)
	setWireIdentity(t, good, avp.OriginHost, "peer.example")
	setWireIdentity(t, good, avp.OriginRealm, "example")
	p.send(t, good)
	answer, err = diam.ReadMessage(p.peer, p.client.Dict)
	if err != nil || !testResultCode(answer, diam.Success) {
		t.Fatalf("normal DWA=%v %v", answer, err)
	}
	if dwa.Load() != 1 {
		t.Fatalf("normal DWA hook count=%d", dwa.Load())
	}
}

// A writer that already entered the TCP boundary must report its real
// failure even after Closing stopped watchdog observations (RFC 6733 §5.6).
func TestClientCoreAttemptedWriteFailureTCP(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(fmt.Sprint(short), func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			failure := errors.New("synthetic client DWR failure")
			wireFailure := failure
			if short {
				wireFailure = nil
			}
			events := make(chan acceptedWatchdogEvent, 16)
			p := newClientCoreTCPDial(t, func(c *Client) {
				c.EnableWatchdog = true
				c.WatchdogInterval = 40 * time.Millisecond
				c.watchdogTiming = &watchdogTiming{floor: time.Millisecond}
				c.OnWatchdogConnEvent = func(conn diam.Conn, event WatchdogEvent) { events <- acceptedWatchdogEvent{conn: conn, event: event} }
			}, func(c *Client, addr string) (diam.Conn, error) {
				raw, err := net.Dial("tcp", addr)
				if err != nil {
					return nil, err
				}
				return c.NewConn(&acceptedWriterFailureTCP{Conn: raw, entered: entered, release: release, err: wireFailure}, addr)
			})
			admitClientCoreTCP(t, p)
			state := p.client.Handler.acceptedCore(p.conn, nil, false)
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("DWR did not enter real TCP writer")
			}
			// This native application writer waits behind the DWR. Its gate
			// rejection proves Closing latched before the failed writer returns.
			gated := make(chan error, 1)
			go func() {
				_, err := diam.NewMessage(0xeeff, diam.RequestFlag, 0, 31, 32, p.client.Dict).WriteTo(p.conn)
				gated <- err
			}()
			finished := make(chan error, 1)
			go func() { finished <- p.client.Handler.Disconnect(p.conn, DisconnectBusy, time.Hour) }()
			select {
			case err := <-gated:
				if !errors.Is(err, diam.ErrConnectionClosing) {
					t.Fatalf("native Closing fence=%v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Disconnect did not latch the native Closing fence")
			}
			unblock()
			select {
			case err := <-finished:
				want := wireFailure
				if short {
					want = io.ErrShortWrite
				}
				if !errors.Is(err, ErrDisconnectClosed) && !errors.Is(err, want) {
					t.Fatalf("failed writer Disconnect=%v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("attempted writer failure did not release Disconnect")
			}
			p.closed(t)
			protocolGenerationAwait(t, mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, p.conn).DispatchDone())
			if state != nil {
				if phase := state.snapshot().Phase(); phase != protocol.Closed {
					t.Errorf("attempted DWR failure left phase=%v", phase)
				}
				if controls := state.snapshot().Controls(); len(controls) != 0 {
					t.Errorf("failed DWR retained control leases: %+v", controls)
				}
				state.mu.Lock()
				selected := len(state.writes)
				state.mu.Unlock()
				if selected != 0 {
					t.Errorf("failed DWR retained %d native writer tickets", selected)
				}
			}
			if records := p.logs.RecordsWithMessage("sm: watchdog request failed; closing connection"); len(records) != 0 {
				t.Fatalf("stopped Client watchdog emitted failure logs: %v", records)
			}
			select {
			case e := <-events:
				t.Fatalf("Closing leaked watchdog observation %s", e.event)
			default:
			}
		})
	}
}
