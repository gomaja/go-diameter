package sm

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

func closingContractWire(t *testing.T, mode string, configure func(*Settings)) *protocolWire {
	t.Helper()
	if mode == "accepted" {
		return newProtocolWire(t, configure, true)
	}
	c := newProtocolClientWire(t, func(c *Client) {
		if configure != nil {
			configure(c.Handler.cfg)
		}
	})
	c.send(t, protocolClientCEA(c.cer, diam.Success))
	if result := c.dialResult(t); result.err != nil {
		t.Fatal(result.err)
	}
	return &protocolWire{sm: c.client.Handler, conn: c.conn, peer: c.peer, events: c.events, logs: c.logs}
}

func closingContractDPR(t *testing.T, p *protocolWire, hop uint32) *diam.Message {
	m := acceptedDPR(t)
	if meta, ok := smpeer.FromContext(p.conn.Context()); ok && meta != nil {
		for _, a := range m.AVP {
			if a.Code == avp.OriginHost {
				a.Data = meta.OriginHost
			}
			if a.Code == avp.OriginRealm {
				a.Data = meta.OriginRealm
			}
		}
	}
	m.Header.HopByHopID, m.Header.EndToEndID = hop, hop+1
	return m
}

func enterContractClosing(t *testing.T, p *protocolWire, local bool, timeout time.Duration) <-chan error {
	t.Helper()
	if local {
		result := make(chan error, 1)
		go func() { result <- p.sm.Disconnect(p.conn, DisconnectBusy, timeout) }()
		m, err := diam.ReadMessage(p.peer, p.conn.Dictionary())
		if err != nil || m.Header.CommandCode != diam.DisconnectPeer || m.Header.CommandFlags&diam.RequestFlag == 0 {
			t.Fatalf("DPR=%v error=%v", m, err)
		}
		return result
	}
	p.send(t, closingContractDPR(t, p, 100))
	m, err := diam.ReadMessage(p.peer, p.conn.Dictionary())
	if err != nil || !testResultCode(m, diam.Success) {
		t.Fatalf("DPA=%v error=%v", m, err)
	}
	return nil
}

func contractSilence(t *testing.T, p *protocolWire, duration time.Duration) {
	t.Helper()
	if err := p.peer.SetReadDeadline(time.Now().Add(duration)); err != nil {
		t.Fatal(err)
	}
	m, err := diam.ReadMessage(p.peer, p.conn.Dictionary())
	if e, ok := err.(net.Error); !ok || !e.Timeout() {
		t.Fatalf("Closing must be silent; message=%v error=%v", m, err)
	}
	if err := p.peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestClosingContractAdmissionWire(t *testing.T) {
	for _, mode := range []string{"accepted", "dialed"} {
		for _, local := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/local=%t", mode, local), func(t *testing.T) {
				var calls atomic.Int32
				p := closingContractWire(t, mode, func(c *Settings) {
					c.DPRCloseTimeout = 3 * time.Second
					c.ValidateRequests = true
					c.RejectUnknownMandatoryAVPs = true
					c.OnCER = func(diam.Conn, *diam.Message) { calls.Add(1) }
					c.OnDWR = func(diam.Conn, *diam.Message) { calls.Add(1) }
				})
				p.sm.Handle("ALL", diam.HandlerFunc(func(diam.Conn, *diam.Message) { calls.Add(1) }))
				enterContractClosing(t, p, local, 3*time.Second)
				before := calls.Load()
				for _, cmd := range []uint32{diam.CapabilitiesExchange, diam.DeviceWatchdog, diam.ReAuth, diam.SessionTermination, diam.AbortSession, diam.Accounting, 272, 0xfedc} {
					for _, request := range []bool{false, true} {
						flags := uint8(0)
						if request {
							flags = diam.RequestFlag
						}
						m := diam.NewMessage(cmd, flags, 0, 77, 78, p.conn.Dictionary())
						if cmd == 272 {
							m.Header.ApplicationID = 4
						}
						// Missing grammar, unsupported applications, invalid base headers and
						// unknown mandatory AVPs all must be gated before validation.
						m.AddAVP(diam.NewAVP(0xfedcab, avp.Mbit, 0, datatype.Unknown([]byte{1, 2, 3, 4})))
						p.send(t, m)
					}
				}
				malformed := regressionDWR(t)
				malformed.Header.ApplicationID = 9
				malformed.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown([]byte{1, 2})))
				p.send(t, malformed)
				contractSilence(t, p, 80*time.Millisecond)
				if calls.Load() != before {
					t.Fatalf("Closing called hook/handler %d times", calls.Load()-before)
				}
				select {
				case e := <-p.events:
					t.Fatalf("Closing called protocol hook: %+v", e)
				default:
				}
			})
		}
	}
}

func TestClosingContractOutstandingAnswerWire(t *testing.T) {
	for _, mode := range []string{"accepted", "dialed"} {
		for _, local := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/local=%t", mode, local), func(t *testing.T) {
				p := closingContractWire(t, mode, func(c *Settings) { c.DPRCloseTimeout = 3 * time.Second })
				answers := make(chan *diam.Message, 8)
				p.sm.Handle("ALL", diam.HandlerFunc(func(_ diam.Conn, m *diam.Message) { answers <- m }))
				request := diam.NewMessage(272, diam.RequestFlag, 4, 900, 901, p.conn.Dictionary())
				if _, err := request.WriteTo(p.conn); err != nil {
					t.Fatal(err)
				}
				if _, err := diam.ReadMessage(p.peer, p.conn.Dictionary()); err != nil {
					t.Fatal(err)
				}
				if local {
					enterContractClosing(t, p, true, 3*time.Second)
				} else {
					p.send(t, closingContractDPR(t, p, 100))
					a, err := diam.ReadMessage(p.peer, p.conn.Dictionary())
					if err != nil || !testResultCode(a, diam.UnableToComply) {
						t.Fatalf("DPR with own request in flight: DPA=%v error=%v", a, err)
					}
				}
				correct := request.Answer(diam.Success)
				for _, fault := range []string{"hop", "end", "command", "application"} {
					wrong := request.Answer(diam.Success)
					switch fault {
					case "hop":
						wrong.Header.HopByHopID++
					case "end":
						wrong.Header.EndToEndID++
					case "command":
						wrong.Header.CommandCode++
					case "application":
						wrong.Header.ApplicationID++
					}
					p.send(t, wrong)
				}
				p.send(t, correct)
				select {
				case a := <-answers:
					if a.Header.HopByHopID != 900 || a.Header.EndToEndID != 901 || a.Header.CommandCode != 272 || a.Header.ApplicationID != 4 {
						t.Fatalf("unmatched answer reached handler: %v", a)
					}
				case <-time.After(time.Second):
					t.Fatal("pre-Closing request answer did not complete")
				}
				p.send(t, correct)
				contractSilence(t, p, 60*time.Millisecond)
				select {
				case a := <-answers:
					t.Fatalf("duplicate/unmatched Closing answer dispatched: %v", a)
				default:
				}
			})
		}
	}
}

func TestClosingContractCrossedDeadlineWire(t *testing.T) {
	for _, mode := range []string{"accepted", "dialed"} {
		t.Run(mode, func(t *testing.T) {
			var callbacks atomic.Int32
			p := closingContractWire(t, mode, func(c *Settings) {
				c.DPRCloseTimeout = 60 * time.Millisecond
				c.OnDPR = func(diam.Conn, DisconnectCause) { callbacks.Add(1) }
			})
			result := enterContractClosing(t, p, true, 600*time.Millisecond)
			for _, hop := range []uint32{200, 202, 204} {
				p.send(t, closingContractDPR(t, p, hop))
				a, err := diam.ReadMessage(p.peer, p.conn.Dictionary())
				if err != nil || !testResultCode(a, diam.Success) || a.Header.HopByHopID != hop || a.Header.EndToEndID != hop+1 {
					t.Fatalf("crossed DPA=%v error=%v", a, err)
				}
			}
			contractSilence(t, p, 150*time.Millisecond)
			if callbacks.Load() != 1 {
				t.Fatalf("repeated DPR called observer %d times", callbacks.Load())
			}
			if err := <-result; err != ErrDisconnectTimeout {
				t.Fatalf("disconnect=%v", err)
			}
		})
	}
}

func TestClosingContractClientWatchdogWire(t *testing.T) {
	for _, local := range []bool{false, true} {
		t.Run(fmt.Sprintf("local=%t", local), func(t *testing.T) {
			c := newProtocolClientWire(t, func(c *Client) {
				c.EnableWatchdog = true
				c.WatchdogInterval = 200 * time.Millisecond
				c.watchdogTiming = &watchdogTiming{floor: time.Millisecond}
				c.Handler.cfg.DPRCloseTimeout = 2 * time.Second
			})
			c.send(t, protocolClientCEA(c.cer, diam.Success))
			if r := c.dialResult(t); r.err != nil {
				t.Fatal(r.err)
			}
			p := &protocolWire{sm: c.client.Handler, conn: c.conn, peer: c.peer, events: c.events, logs: c.logs}
			enterContractClosing(t, p, local, 2*time.Second)
			contractSilence(t, p, 350*time.Millisecond)
			if p.conn.Closed() {
				t.Fatal("watchdog closed Closing transport")
			}
		})
	}
}

func TestClosingContractMalformedDPRWire(t *testing.T) {
	for _, mode := range []string{"accepted", "dialed"} {
		for _, fault := range []string{"header", "decode", "mandatory", "grammar", "body"} {
			t.Run(mode+"/"+fault, func(t *testing.T) {
				p := closingContractWire(t, mode, func(c *Settings) {
					c.DPRCloseTimeout = 3 * time.Second
					c.ValidateRequests = true
					c.RejectUnknownMandatoryAVPs = true
				})
				enterContractClosing(t, p, false, 3*time.Second)
				m := closingContractDPR(t, p, 200)
				kind, code := diam.ProtocolInvalidDPR, uint32(0)
				switch fault {
				case "header":
					m.Header.ApplicationID = 9
				case "decode":
					m.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown([]byte{1, 2})))
					kind, code = diam.ProtocolMalformedMessage, diam.InvalidAVPLength
				case "mandatory":
					m.AddAVP(diam.NewAVP(0xfedcab, avp.Mbit, 0, datatype.Unknown([]byte{1, 2, 3, 4})))
					kind, code = diam.ProtocolUnsupportedAVP, diam.AVPUnsupported
				case "grammar":
					m.AVP = nil
					kind, code = diam.ProtocolInvalidRequest, diam.MissingAVP
				case "body":
					for _, a := range m.AVP {
						if a.Code == avp.OriginHost {
							a.Data = datatype.DiameterIdentity("wrong.example")
						}
					}
				}
				header := p.send(t, m)
				contractSilence(t, p, 50*time.Millisecond)
				if fault == "header" {
					select {
					case e := <-p.events:
						t.Fatalf("ineligible DPR called hook: %+v", e)
					default:
					}
					return
				}
				assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, &header, kind, code, false, diam.ProtocolReplyNone, 0)
			})
		}
	}
}

func TestClosingContractRepeatedReceiverTimerWire(t *testing.T) {
	for _, mode := range []string{"accepted", "dialed"} {
		t.Run(mode, func(t *testing.T) {
			p := closingContractWire(t, mode, func(c *Settings) { c.DPRCloseTimeout = 400 * time.Millisecond })
			started := time.Now()
			enterContractClosing(t, p, false, time.Second)
			var sameTimer func() bool
			if mode == "accepted" {
				state := p.sm.acceptedCore(p.conn, nil, false)
				first := state.snapshot().Timer(protocol.ClosingTimer)
				if first.Token == 0 || first.Deadline.IsZero() {
					t.Fatal("received DPR installed no receiver timer")
				}
				sameTimer = func() bool { return state.snapshot().Timer(protocol.ClosingTimer) == first }
			} else {
				state := p.sm.closingConnection(p.conn)
				state.mu.Lock()
				first := state.timer
				state.mu.Unlock()
				if first == nil {
					t.Fatal("received DPR installed no receiver timer")
				}
				sameTimer = func() bool {
					state.mu.Lock()
					defer state.mu.Unlock()
					return state.timer == first
				}
			}
			time.Sleep(180 * time.Millisecond)
			p.send(t, closingContractDPR(t, p, 300))
			a, err := diam.ReadMessage(p.peer, p.conn.Dictionary())
			if err != nil || !testResultCode(a, diam.Success) {
				t.Fatalf("repeated DPA=%v error=%v", a, err)
			}
			if !sameTimer() {
				t.Fatal("repeated DPR replaced original receiver timer")
			}
			p.closed(t)
			if time.Since(started) > 550*time.Millisecond {
				t.Fatal("repeated DPR extended original receiver deadline")
			}
			assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, nil, diam.ProtocolDisconnectTimeout, 0, true, diam.ProtocolReplyNone, 0)
		})
	}
}

func TestClosingContractClientStalePublication(t *testing.T) {
	cli := newLivenessClient(t)
	c := newWatchdogProbeConn()
	activity := newWatchdogActivity()
	activity.stopWatchdog()
	if cli.dwr(c, 0, &activity.watchdogSignals) {
		t.Fatal("stale publisher succeeded after logical Closing")
	}
	select {
	case <-c.writes:
		t.Fatal("stale publisher wrote after Closing")
	default:
	}
}

func TestClosingContractClientIndependentLatches(t *testing.T) {
	first, second := newWatchdogActivity(), newWatchdogActivity()
	second.publicationMu.Lock()
	defer second.publicationMu.Unlock()
	stopped := make(chan struct{})
	go func() { first.stopWatchdog(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Closing waited for an unrelated connection's publication")
	}
}

func TestClosingContractRejectedDWAInFlightWire(t *testing.T) {
	for _, mode := range []string{"accepted", "dialed"} {
		for _, fault := range []string{"valid", "protocol error", "permanent error", "mismatch", "identity", "malformed"} {
			t.Run(mode+"/"+fault, func(t *testing.T) {
				var p *protocolWire
				if mode == "accepted" {
					p = closingContractWire(t, mode, func(c *Settings) {
						c.EnableWatchdog = true
						c.WatchdogInterval = 200 * time.Millisecond
						c.watchdogTiming = &watchdogTiming{floor: time.Millisecond}
						c.DPRCloseTimeout = 2 * time.Second
					})
				} else {
					c := newProtocolClientWire(t, func(c *Client) {
						c.EnableWatchdog = true
						c.WatchdogInterval = 200 * time.Millisecond
						c.watchdogTiming = &watchdogTiming{floor: time.Millisecond}
						c.Handler.cfg.DPRCloseTimeout = 2 * time.Second
					})
					c.send(t, protocolClientCEA(c.cer, diam.Success))
					if r := c.dialResult(t); r.err != nil {
						t.Fatal(r.err)
					}
					p = &protocolWire{sm: c.client.Handler, conn: c.conn, peer: c.peer, events: c.events, logs: c.logs}
				}
				dwr, err := diam.ReadMessage(p.peer, p.conn.Dictionary())
				if err != nil || dwr.Header.CommandCode != diam.DeviceWatchdog {
					t.Fatalf("DWR=%v error=%v", dwr, err)
				}
				answer := boundWireAnswer(t, p, dwr, diam.UnableToComply)
				switch fault {
				case "permanent error":
					answer.Header.CommandFlags |= diam.ErrorFlag | diam.ProxiableFlag
				case "protocol error":
					answer.Header.CommandFlags |= diam.ErrorFlag | diam.ProxiableFlag
					field, findErr := answer.FindAVP(avp.ResultCode, 0)
					if findErr != nil {
						t.Fatal(findErr)
					}
					field.Data = datatype.Unsigned32(diam.TooBusy)
				case "mismatch":
					answer.Header.HopByHopID++
				case "identity":
					setWireIdentity(t, answer, avp.OriginHost, "wrong.example")
				case "malformed":
					answer.AVP = answer.AVP[:1]
				}
				p.send(t, answer)
				e := protocolEvent(t, p.events)
				wantKind, wantCode := diam.ProtocolRejectedDWA, uint32(diam.UnableToComply)
				if fault == "protocol error" {
					wantCode = diam.TooBusy
				}
				if fault == "malformed" {
					wantKind, wantCode = diam.ProtocolInvalidDWA, diam.MissingAVP
				}
				if e.Err.Kind() != wantKind || e.Err.ResultCode() != wantCode || e.Reply != diam.ProtocolReplyNone {
					t.Fatalf("rejected DWA=%+v", e)
				}
				p.send(t, closingContractDPR(t, p, 400))
				dpa, err := diam.ReadMessage(p.peer, p.conn.Dictionary())
				want := uint32(diam.UnableToComply)
				if fault == "valid" || fault == "protocol error" || fault == "permanent error" {
					want = diam.Success
				}
				if err != nil || !testResultCode(dpa, want) {
					t.Fatalf("DPR after rejected DWA: DPA=%v error=%v want=%d", dpa, err, want)
				}
			})
		}
	}
}

type closingQueueHandler struct {
	diam.Handler
	entered  chan struct{}
	release  chan struct{}
	finished chan struct{}
}

func (h *closingQueueHandler) Unwrap() diam.Handler { return h.Handler }
func (h *closingQueueHandler) ServeDIAM(c diam.Conn, m *diam.Message) {
	if m.Header.ApplicationID == 4 && m.Header.CommandCode == 272 && m.Header.CommandFlags&diam.RequestFlag != 0 {
		close(h.entered)
		<-h.release
		defer close(h.finished)
	}
	h.Handler.ServeDIAM(c, m)
}

func TestClosingContractClientEOFQueuedAdmissionWire(t *testing.T) {
	var calls atomic.Int32
	h := &closingQueueHandler{entered: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{})}
	c := newProtocolClientWire(t, func(c *Client) {
		c.Handler.Handle("ALL", diam.HandlerFunc(func(diam.Conn, *diam.Message) { calls.Add(1) }))
	}, func(s *diam.Server) { h.Handler = s.Handler; s.Handler = h; s.MaxConcurrentHandlers = 2 })
	c.send(t, protocolClientCEA(c.cer, diam.Success))
	if r := c.dialResult(t); r.err != nil {
		t.Fatal(r.err)
	}
	p := &protocolWire{sm: c.client.Handler, conn: c.conn, peer: c.peer, events: c.events, logs: c.logs}
	enterContractClosing(t, p, false, 3*time.Second)
	p.send(t, diam.NewMessage(272, diam.RequestFlag, 4, 700, 701, p.conn.Dictionary()))
	<-h.entered
	if err := p.peer.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	p.conn.Close()
	<-mustConnAs[diam.CloseNotifier](t, p.conn).CloseNotify()
	time.Sleep(10 * time.Millisecond) // let the close cleanup observer run
	// A read EOF must leave Closing latched while decoded callbacks remain.
	if !p.sm.isClosing(p.conn) {
		t.Error("EOF removed Closing before queued callback finished")
	}
	close(h.release)
	<-h.finished
	if calls.Load() != 0 {
		t.Fatal("queued post-DPR request reached handler after EOF")
	}
}
