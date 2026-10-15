package sm

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

type correlationGenerationConn struct {
	*handshakeConn
	generation uint64
	retired    diam.RetirementReason
}

func (c *correlationGenerationConn) Generation() uint64                      { return c.generation }
func (c *correlationGenerationConn) RetirementReason() diam.RetirementReason { return c.retired }

func TestAnswerCorrelationGenerationAndZeroIdentifiers(t *testing.T) {
	c := &correlationGenerationConn{handshakeConn: newHandshakeConn(), generation: 1}
	request := diam.NewMessage(diam.DisconnectPeer, diam.RequestFlag, 0, 0, 0, c.Dictionary())
	request.Header.HopByHopID, request.Header.EndToEndID = 0, 0
	r := correlateAnswer(c, request)
	answer := request.Answer(diam.Success)
	if !r.matches(c, answer) {
		t.Fatal("explicitly owned zero identifiers did not match")
	}
	for _, fault := range []string{"generation", "retired", "connection", "command", "application", "direction"} {
		t.Run(fault, func(t *testing.T) {
			d := &correlationGenerationConn{handshakeConn: c.handshakeConn, generation: c.generation}
			candidate := request.Answer(diam.Success)
			target := diam.Conn(c)
			switch fault {
			case "generation":
				c.generation++
				defer func() { c.generation-- }()
			case "retired":
				c.retired = diam.AcceptedCERRenewal
				defer func() { c.retired = 0 }()
			case "connection":
				target = d
			case "command":
				candidate.Header.CommandCode = diam.DeviceWatchdog
			case "application":
				candidate.Header.ApplicationID = 4
			case "direction":
				candidate.Header.CommandFlags |= diam.RequestFlag
			}
			if r.matches(target, candidate) {
				t.Fatal("unrelated answer matched its request")
			}
		})
	}
}

func TestDPAConsumesPendingOnce(t *testing.T) {
	c := newHandshakeConn()
	c.SetContext(smpeer.NewContext(context.Background(), &smpeer.Metadata{OriginHost: "peer.example", OriginRealm: "example"}))
	sm := mustNewStateMachine(t, testMessageErrorSettings())
	events := make(chan diam.ProtocolErrorEvent, 32)
	sm.cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
	request := diam.NewMessage(diam.DisconnectPeer, diam.RequestFlag, 0, 0, 0, c.Dictionary())
	request.Header.HopByHopID, request.Header.EndToEndID = 0, 0
	p := &pendingDisconnect{request: correlateAnswer(c, request), result: make(chan uint32, 1)}
	sm.disconnects.pending = map[diam.Conn]*pendingDisconnect{c: p}
	answer := request.Answer(diam.Success)
	answer.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
	answer.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	handleDPA(sm)(c, answer)
	select {
	case <-p.result:
	default:
		t.Fatal("owned zero-ID DPA did not complete")
	}
	// Even after the waiter drains result, concurrent duplicates cannot reuse it.
	const copies = 12
	done := make(chan struct{}, copies)
	for range copies {
		go func() { handleDPA(sm)(c, answer); done <- struct{}{} }()
	}
	for range copies {
		<-done
		event := protocolEvent(t, events)
		if event.Conn != c || event.Err.Kind() != diam.ProtocolUnexpectedMessage || event.Closing || event.Reply != diam.ProtocolReplyNone {
			t.Fatalf("duplicate DPA notification = %+v", event)
		}
	}
	select {
	case <-p.result:
		t.Fatal("duplicate DPA completed pending DPR twice")
	default:
	}
}

func setWireIdentity(t *testing.T, m *diam.Message, code uint32, value string) {
	t.Helper()
	a, err := m.FindAVP(code, 0)
	if err != nil {
		t.Fatal(err)
	}
	a.Data = datatype.DiameterIdentity(value)
}

// RFC 6733 §§3, 5.3, 6.2.1: an unrelated answer cannot consume the CER,
// publish metadata, run OnHandshake, or cancel the original deadline.
func TestClientCEACorrelationWire(t *testing.T) {
	for _, which := range []string{"hop", "end", "both", "rejected-body"} {
		t.Run(which, func(t *testing.T) {
			var calls atomic.Int32
			p := newProtocolClientWire(t, func(c *Client) {
				c.Handler.cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) { calls.Add(1) }
			})
			bad := protocolClientCEA(p.cer, diam.Success)
			if which != "end" {
				bad.Header.HopByHopID++
			}
			if which == "end" || which == "both" {
				bad.Header.EndToEndID++
			}
			if which == "rejected-body" {
				bad.AVP = nil // Correlation precedes interpreting an untrusted body.
			}
			header := p.send(t, bad)
			select {
			case e := <-p.events:
				assertProtocolEvent(t, e, p.conn, &header, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
			case result := <-p.dialed:
				t.Fatalf("uncorrelated CEA completed Dial: %+v", result)
			case <-time.After(time.Second):
				t.Fatal("uncorrelated CEA was not reported")
			}
			if meta, ok := smpeer.FromContext(p.conn.Context()); ok || meta != nil || calls.Load() != 0 {
				t.Fatalf("uncorrelated CEA published metadata/callback: %+v, %d", meta, calls.Load())
			}
			good := protocolClientCEA(p.cer, diam.Success)
			setWireIdentity(t, good, avp.OriginHost, "remote.example")
			p.send(t, good)
			if result := p.dialResult(t); result.err != nil || result.conn != p.conn {
				t.Fatalf("correct CEA after stray: %+v", result)
			}
			meta, ok := smpeer.FromContext(p.conn.Context())
			if !ok || meta.OriginHost != "remote.example" || meta.OriginHost == p.client.Handler.cfg.OriginHost || calls.Load() != 1 {
				t.Fatalf("learned identity/callback = %+v, %d", meta, calls.Load())
			}
			header = p.send(t, good)
			assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, &header, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
			if calls.Load() != 1 {
				t.Fatal("duplicate CEA repeated OnHandshake")
			}
		})
	}
}

func TestClientCEAStrayKeepsDeadlineWire(t *testing.T) {
	p := newProtocolClientWire(t, func(c *Client) { c.RetransmitInterval = 180 * time.Millisecond })
	start := time.Now()
	for range 3 {
		bad := protocolClientCEA(p.cer, diam.Success)
		bad.Header.EndToEndID++
		header := p.send(t, bad)
		select {
		case e := <-p.events:
			assertProtocolEvent(t, e, p.conn, &header, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
		case result := <-p.dialed:
			t.Fatalf("stray CEA ended admission: %+v", result)
		}
		time.Sleep(40 * time.Millisecond)
	}
	if result := p.dialResult(t); !errors.Is(result.err, ErrHandshakeTimeout) {
		t.Fatalf("stray answers replaced deadline: %+v", result)
	}
	if elapsed := time.Since(start); elapsed < 140*time.Millisecond || elapsed > 260*time.Millisecond {
		t.Fatalf("original CER deadline changed: %s", elapsed)
	}
	assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, nil, diam.ProtocolHandshakeTimeout, 0, true, diam.ProtocolReplyNone, 0)
}

func TestClientCEACrossedConnectionsWire(t *testing.T) {
	a := newProtocolClientWire(t, nil)
	b := newProtocolClientWire(t, func(c *Client) { c.Handler = a.client.Handler })
	for _, pair := range []struct{ to, from *protocolClientWire }{{a, b}, {b, a}} {
		header := pair.to.send(t, protocolClientCEA(pair.from.cer, diam.Success))
		select {
		case e := <-a.events:
			assertProtocolEvent(t, e, pair.to.conn, &header, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
		case result := <-pair.to.dialed:
			t.Fatalf("another connection's CEA admitted peer: %+v", result)
		}
	}
	for _, p := range []*protocolClientWire{a, b} {
		p.send(t, protocolClientCEA(p.cer, diam.Success))
		if result := p.dialResult(t); result.err != nil {
			t.Fatal(result.err)
		}
	}
}

func newIdentityWire(t *testing.T, mode string) *protocolWire {
	t.Helper()
	if mode == "accepted" {
		return newProtocolWire(t, nil, true)
	}
	p := newProtocolClientWire(t, nil)
	p.send(t, protocolClientCEA(p.cer, diam.Success))
	if result := p.dialResult(t); result.err != nil {
		t.Fatal(result.err)
	}
	return &protocolWire{sm: p.client.Handler, peer: p.peer, conn: p.conn, events: p.events, logs: p.logs}
}

func boundWireAnswer(t *testing.T, p *protocolWire, request *diam.Message, result uint32) *diam.Message {
	t.Helper()
	meta, ok := smpeer.FromContext(p.conn.Context())
	if !ok {
		t.Fatal("missing peer identity")
	}
	m := request.Answer(result)
	m.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, meta.OriginHost))
	m.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, meta.OriginRealm))
	return m
}

// RFC 6733 §§3, 5.4.2, 6.2.1, 6.3: only the pending DPR's answer can
// release Disconnect, and peer identity is checked before Result-Code.
func TestDPACorrelationIdentityWire(t *testing.T) {
	for _, mode := range []string{"accepted", "dialed"} {
		for _, which := range []string{"hop", "end", "host", "host-before-result", "case"} {
			t.Run(mode+"/"+which, func(t *testing.T) {
				p := newIdentityWire(t, mode)
				result := make(chan error, 1)
				go func() { result <- p.sm.Disconnect(p.conn, DisconnectBusy, 2*time.Second) }()
				request, err := diam.ReadMessage(p.peer, p.conn.Dictionary())
				if err != nil || request.Header.CommandCode != diam.DisconnectPeer {
					t.Fatalf("DPR = %v, %v", request, err)
				}
				answer := boundWireAnswer(t, p, request, diam.Success)
				switch which {
				case "hop":
					answer.Header.HopByHopID++
				case "end":
					answer.Header.EndToEndID++
				case "host", "host-before-result":
					setWireIdentity(t, answer, avp.OriginHost, "stranger.example")
					if which == "host-before-result" {
						code, _ := answer.FindAVP(avp.ResultCode, 0)
						code.Data = datatype.Unsigned32(5012)
					}
				case "case":
					meta, _ := smpeer.FromContext(p.conn.Context())
					setWireIdentity(t, answer, avp.OriginHost, strings.ToUpper(string(meta.OriginHost)))
				}
				header := p.send(t, answer)
				if which != "case" {
					select {
					case e := <-p.events:
						assertProtocolEvent(t, e, p.conn, &header, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
					case err := <-result:
						t.Fatalf("mismatched DPA completed Disconnect: %v", err)
					}
					p.send(t, boundWireAnswer(t, p, request, diam.Success))
				}
				select {
				case err := <-result:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("matching DPA did not complete Disconnect")
				}
			})
		}
	}
}

func TestBoundIdentityASCIIWire(t *testing.T) {
	for _, scenario := range []string{"DWR-host", "DPR-host", "DWA-host", "DWA-realm"} {
		t.Run(scenario, func(t *testing.T) {
			p := newProtocolClientWire(t, nil)
			cea := protocolClientCEA(p.cer, diam.Success)
			setWireIdentity(t, cea, avp.OriginHost, "known.example")
			setWireIdentity(t, cea, avp.OriginRealm, "some.example")
			p.send(t, cea)
			if result := p.dialResult(t); result.err != nil {
				t.Fatal(result.err)
			}
			var request *diam.Message
			var kind diam.ProtocolErrorKind
			if strings.HasPrefix(scenario, "DWA") {
				request = p.cer.Answer(diam.Success)
				request.Header.CommandCode = diam.DeviceWatchdog
				request.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("known.example")))
				request.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("some.example")))
				field, value := uint32(avp.OriginHost), "Known.example"
				if scenario == "DWA-realm" {
					field, value = avp.OriginRealm, "ſome.example"
				}
				setWireIdentity(t, request, field, value)
				// Route through the production DWA handler with an owned probe.
				signals := newWatchdogSignals()
				header := *request.Header
				signals.request.Store(&header)
				// The TCP decoder still supplies the body and identity bytes.
				p.client.Handler.Handle("DWA", handleDWA(p.client.Handler, &signals, nil))
				kind = diam.ProtocolInvalidDWA
			} else {
				command := uint32(diam.DeviceWatchdog)
				kind = diam.ProtocolInvalidRequest
				if scenario == "DPR-host" {
					command = diam.DisconnectPeer
				}
				request = diam.NewRequest(command, 0, p.conn.Dictionary())
				request.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("Known.example")))
				request.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("some.example")))
				if command == diam.DisconnectPeer {
					request.AddAVP(diam.NewAVP(avp.DisconnectCause, avp.Mbit, 0, datatype.Enumerated(0)))
				}
			}
			header := p.send(t, request)
			reply, replyCode := diam.ProtocolReplyNone, uint32(0)
			if header.CommandFlags&diam.RequestFlag != 0 {
				reply, replyCode = diam.ProtocolReplyWritten, diam.InvalidAVPValue
			}
			select {
			case e := <-p.events:
				assertProtocolEvent(t, e, p.conn, &header, kind, diam.InvalidAVPValue, false, reply, replyCode)
			case <-time.After(100 * time.Millisecond):
				t.Fatal("Unicode lookalike was accepted as the bound ASCII identity")
			}
			if header.CommandFlags&diam.RequestFlag != 0 {
				answer, err := diam.ReadMessage(p.peer, p.conn.Dictionary())
				if err != nil || !testResultCode(answer, diam.InvalidAVPValue) || answer.Header.HopByHopID != header.HopByHopID || answer.Header.EndToEndID != header.EndToEndID {
					t.Fatalf("invalid identity answer=%v error=%v", answer, err)
				}
			}
		})
	}
}

func TestBaseRequestBoundHostWire(t *testing.T) {
	for _, mode := range []string{"accepted", "dialed"} {
		for _, cmd := range []uint32{diam.DeviceWatchdog, diam.DisconnectPeer} {
			t.Run(mode+"/"+map[uint32]string{diam.DeviceWatchdog: "DWR", diam.DisconnectPeer: "DPR"}[cmd], func(t *testing.T) {
				p := newIdentityWire(t, mode)
				meta, _ := smpeer.FromContext(p.conn.Context())
				request := diam.NewRequest(cmd, 0, p.conn.Dictionary())
				request.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("stranger.example")))
				request.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, meta.OriginRealm))
				if cmd == diam.DisconnectPeer {
					request.AddAVP(diam.NewAVP(avp.DisconnectCause, avp.Mbit, 0, datatype.Enumerated(0)))
				}
				header := p.send(t, request)
				kind := diam.ProtocolInvalidDWR
				if cmd == diam.DisconnectPeer {
					kind = diam.ProtocolInvalidDPR
				}
				select {
				case e := <-p.events:
					assertProtocolEvent(t, e, p.conn, &header, kind, 0, false, diam.ProtocolReplyNone, 0)
				case <-time.After(100 * time.Millisecond):
					t.Fatal("wrong-host request was not discarded")
				}
				if p.sm.acceptedClosing(p.conn) {
					t.Fatal("wrong-host DPR entered Closing")
				}
				setWireIdentity(t, request, avp.OriginHost, strings.ToUpper(string(meta.OriginHost)))
				request.Header.HopByHopID++
				header = p.send(t, request)
				answer, err := diam.ReadMessage(p.peer, p.conn.Dictionary())
				if err != nil || answer.Header.CommandCode != cmd || answer.Header.HopByHopID != header.HopByHopID || !testResultCode(answer, diam.Success) {
					t.Fatalf("bound-host answer = %v, %v", answer, err)
				}
			})
		}
	}
}
