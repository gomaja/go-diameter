package peer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/sm"
)

func closingPeer(t *testing.T, dialed bool) (*Manager, net.Conn, *fakeClock, <-chan diam.ProtocolErrorEvent) {
	t.Helper()
	if !dialed {
		m, c, clock, events := correlationReceiver(t)
		clock.waitTimers(t, 2) // pre-CER deadline and the first watchdog
		return m, c, clock, events
	}
	clock := &fakeClock{}
	m, c, cer, events := correlationDial(t, clock)
	mark := clock.timerCount()
	write(t, c, correlationCEA(t, cer, "known.example.net"))
	awaitState(t, m, IOpen)
	clock.waitTimers(t, mark+1) // first watchdog after the Connect and CER deadlines
	return m, c, clock, events
}

func closingDPR(t *testing.T, m *Manager) *diam.Message {
	t.Helper()
	dpr, err := base.BuildDPR(m.dictionary(), testBase("known.example.net"), uint32(sm.DisconnectBusy))
	if err != nil {
		t.Fatal(err)
	}
	return dpr
}

func closingStart(t *testing.T, m *Manager, c net.Conn, local bool, result uint32) (*diam.Message, <-chan error) {
	t.Helper()
	var done <-chan error
	var dpr *diam.Message
	if local {
		out := make(chan error, 1)
		done = out
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			out <- m.Close(ctx, sm.DisconnectRebooting)
		}()
		dpr = read(t, c)
		if dpr.Header.CommandCode != diam.DisconnectPeer || dpr.Header.CommandFlags&diam.RequestFlag == 0 {
			t.Fatalf("want DPR, got %+v", dpr.Header)
		}
	} else {
		dpr = closingDPR(t, m)
		write(t, c, dpr)
		answer := read(t, c)
		if answer.Header.CommandCode != diam.DisconnectPeer || answer.Header.HopByHopID != dpr.Header.HopByHopID || answer.Header.EndToEndID != dpr.Header.EndToEndID || code(t, answer) != result {
			t.Fatalf("DPA result=%d, want %d; header=%+v", code(t, answer), result, answer.Header)
		}
	}
	awaitState(t, m, Closing)
	return dpr, done
}

func closingSilence(t *testing.T, c net.Conn, events <-chan diam.ProtocolErrorEvent) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
	var b [1]byte
	n, err := c.Read(b[:])
	var timeout net.Error
	if n != 0 || !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("Closing traffic was not silently dropped: bytes=%d err=%v", n, err)
	}
	select {
	case e := <-events:
		t.Fatalf("Closing traffic invoked protocol hook: %+v", e)
	default:
	}
}

// RFC 6733 §5.6 and the Closing admission policy: reject new work before
// header/body validation, error-answer construction and watchdog receipt.
func TestManagerClosingAdmissionOnWire(t *testing.T) {
	commands := []struct {
		name string
		code uint32
		app  uint32
	}{{"CER", diam.CapabilitiesExchange, 0}, {"DWR", diam.DeviceWatchdog, 0}, {"application", 272, 4}, {"session", 258, 0}, {"unsupported", 999, 0}, {"non-base DPR", diam.DisconnectPeer, 4}}
	for _, dialed := range []bool{false, true} {
		for _, local := range []bool{false, true} {
			for _, command := range commands {
				for _, request := range []bool{false, true} {
					for _, malformed := range []string{"valid", "header", "body"} {
						name := fmt.Sprintf("dialed=%t/local=%t/%s/request=%t/%s", dialed, local, command.name, request, malformed)
						t.Run(name, func(t *testing.T) {
							m, c, clock, events := closingPeer(t, dialed)
							closingStart(t, m, c, local, diam.Success)
							mark := clock.timerCount()
							msg := diam.NewRequest(command.code, command.app, m.dictionary())
							switch command.code {
							case diam.CapabilitiesExchange:
								msg = reviewCER(t)
							case diam.DeviceWatchdog:
								msg = reviewDWR(t)
							}
							if !request {
								msg = msg.Answer(diam.Success)
							}
							switch malformed {
							case "header":
								msg.Header.ApplicationID = 0x00ffffff
							case "body":
								if request {
									msg.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2}))
								} else {
									msg.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("other.example.net")))
									msg.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("known.example.net")))
								}
							}
							write(t, c, msg)
							closingSilence(t, c, events)
							if m.Peers()[0].State != Closing || clock.timerCount() != mark {
								t.Fatal("discarded message changed Closing or its original deadline")
							}
						})
					}
				}
			}
		}
	}
}

func closingPending(t *testing.T, m *Manager, c net.Conn) (*diam.Message, <-chan sendResult) {
	t.Helper()
	out := make(chan sendResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		answer, err := m.Send(ctx, outboundRequest("known.example.net", "example.net"))
		out <- sendResult{answer: answer, err: err}
	}()
	request := read(t, c)
	if request.Header.CommandCode != 272 || request.Header.ApplicationID != 4 {
		t.Fatalf("want outstanding application request, got %+v", request.Header)
	}
	return request, out
}

// A connection-owned answer remains admitted in Closing; unmatched answers
// have no effects. Receipt must not renew the original disconnect timeout.
func TestManagerClosingPendingAnswerOnWire(t *testing.T) {
	for _, dialed := range []bool{false, true} {
		for _, local := range []bool{false, true} {
			t.Run(fmt.Sprintf("dialed=%t/local=%t", dialed, local), func(t *testing.T) {
				m, c, clock, events := closingPeer(t, dialed)
				request, result := closingPending(t, m, c)
				closingStart(t, m, c, local, diam.UnableToComply)
				mark := clock.timerCount()
				for _, mismatch := range []string{"hop", "end", "command", "application"} {
					bad := request.Answer(diam.Success)
					switch mismatch {
					case "hop":
						bad.Header.HopByHopID++
					case "end":
						bad.Header.EndToEndID++
					case "command":
						bad.Header.CommandCode++
					case "application":
						bad.Header.ApplicationID++
					}
					write(t, c, bad)
					closingSilence(t, c, events)
					select {
					case got := <-result:
						t.Fatalf("mismatched answer completed request: %+v", got)
					default:
					}
				}
				answer := request.Answer(diam.Success)
				write(t, c, answer)
				select {
				case got := <-result:
					if got.err != nil || got.answer == nil || got.answer.Header.EndToEndID != request.Header.EndToEndID {
						t.Fatalf("pre-Closing answer did not complete normally: %+v", got)
					}
				case <-time.After(time.Second):
					t.Fatal("pre-Closing matched answer was dropped")
				}
				// A duplicate is now new work, even though its identifiers matched.
				write(t, c, answer)
				closingSilence(t, c, events)
				if clock.timerCount() != mark || m.Peers()[0].State != Closing {
					t.Fatal("matched answer extended Closing deadline")
				}
				clock.fire()
				correlationEOF(t, c)
				correlationEvent(t, events, diam.ProtocolDisconnectTimeout, true)
			})
		}
	}
}

// Crossed/repeated DPRs are the Closing interoperability exception. They
// preserve both request identifiers and the first disconnect deadline.
func TestManagerClosingRepeatedDPROnWire(t *testing.T) {
	for _, dialed := range []bool{false, true} {
		for _, local := range []bool{false, true} {
			t.Run(fmt.Sprintf("dialed=%t/local=%t", dialed, local), func(t *testing.T) {
				m, c, clock, events := closingPeer(t, dialed)
				closingStart(t, m, c, local, diam.Success)
				mark := clock.timerCount()
				dpr := closingDPR(t, m)
				for range 3 {
					write(t, c, dpr)
					answer := read(t, c)
					if code(t, answer) != diam.Success || answer.Header.HopByHopID != dpr.Header.HopByHopID || answer.Header.EndToEndID != dpr.Header.EndToEndID {
						t.Fatalf("crossed/repeated DPR lost correlation: %+v", answer.Header)
					}
					if clock.timerCount() != mark || m.Peers()[0].State != Closing {
						t.Fatal("crossed/repeated DPR renewed original Closing deadline")
					}
				}
				clock.fire()
				correlationEOF(t, c)
				correlationEvent(t, events, diam.ProtocolDisconnectTimeout, true)
			})
		}
	}
}

// RFC 6733 §5.4 directs transport disconnect after a valid DPA regardless of
// its Result-Code; the rejected-answer notification retains that code.
func TestManagerClosingEveryValidDPAOnWire(t *testing.T) {
	for _, dialed := range []bool{false, true} {
		for _, result := range []uint32{diam.Success, diam.TooBusy, diam.UnableToComply} {
			t.Run(fmt.Sprintf("dialed=%t/result=%d", dialed, result), func(t *testing.T) {
				m, c, _, events := closingPeer(t, dialed)
				dpr, done := closingStart(t, m, c, true, diam.Success)
				answer, err := base.BuildDPA(dpr, testBase("known.example.net"))
				if err != nil {
					t.Fatal(err)
				}
				field, err := answer.FindAVP(avp.ResultCode, 0)
				if err != nil {
					t.Fatal(err)
				}
				field.Data = datatype.Unsigned32(result)
				if result >= 3000 && result < 4000 {
					answer.Header.CommandFlags |= diam.ErrorFlag
				}
				write(t, c, answer)
				correlationEOF(t, c)
				if result != diam.Success {
					e := correlationEvent(t, events, diam.ProtocolPeerRejected, true)
					if e.Err.ResultCode() != result {
						t.Fatalf("DPA failure result lost: %+v", e)
					}
				}
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("valid DPA did not finish Manager close")
				}
			})
		}
	}
}

// An unanswered DWR is also a request sent on this connection. Closing
// invalidates its watchdog credit but retains the in-flight DPR decision.
func TestManagerClosingOutstandingWatchdogOnWire(t *testing.T) {
	for _, dialed := range []bool{false, true} {
		for _, local := range []bool{false, true} {
			t.Run(fmt.Sprintf("dialed=%t/local=%t", dialed, local), func(t *testing.T) {
				m, c, clock, _ := closingPeer(t, dialed)
				clock.fire()
				probe := read(t, c)
				if probe.Header.CommandCode != diam.DeviceWatchdog || probe.Header.CommandFlags&diam.RequestFlag == 0 {
					t.Fatalf("want unanswered DWR, got %+v", probe.Header)
				}
				closingStart(t, m, c, local, diam.UnableToComply)
				// A crossed DPR must see the same pending probe after watchdog
				// timers/credit have been stopped by logical Closing.
				write(t, c, closingDPR(t, m))
				if answer := read(t, c); code(t, answer) != diam.UnableToComply {
					t.Fatalf("unanswered pre-Closing DWR lost: DPA Result-Code=%d", code(t, answer))
				}
			})
		}
	}
}

func TestManagerClosingInFlightDisconnectOnWire(t *testing.T) {
	for _, dialed := range []bool{false, true} {
		for _, local := range []bool{false, true} {
			t.Run(fmt.Sprintf("dialed=%t/local=%t", dialed, local), func(t *testing.T) {
				m, c, _, events := closingPeer(t, dialed)
				_, pending := closingPending(t, m, c)
				dpr, done := closingStart(t, m, c, local, diam.UnableToComply)
				if local {
					answer, err := base.BuildDPA(dpr, testBase("known.example.net"))
					if err != nil {
						t.Fatal(err)
					}
					field, err := answer.FindAVP(avp.ResultCode, 0)
					if err != nil {
						t.Fatal(err)
					}
					field.Data = datatype.Unsigned32(diam.UnableToComply)
					write(t, c, answer)
					correlationEOF(t, c)
					correlationEvent(t, events, diam.ProtocolPeerRejected, true)
					if err := <-done; err != nil {
						t.Fatal(err)
					}
				} else {
					// The DPR sender disconnects even after an unsuccessful DPA.
					_ = c.Close()
					awaitState(t, m, Closed)
				}
				select {
				case result := <-pending:
					if result.answer != nil || !errors.Is(result.err, ErrFailover) {
						t.Fatalf("unanswered request disposition=%+v", result)
					}
				case <-time.After(time.Second):
					t.Fatal("disconnect retained unanswered application request")
				}
			})
		}
	}
}

// A Manager Send reservation must see logical Closing while DPR/DPA queue
// admission is running, before the final peer snapshot publication.
func TestManagerClosingBeforeEffects(t *testing.T) {
	for _, local := range []bool{false, true} {
		t.Run(fmt.Sprint(local), func(t *testing.T) {
			m, actors, sessions := outboundTestManager(t)
			a, s := actors[0], sessions[0]
			var checked bool
			s.beforeAdmission = func() {
				checked = true
				if m.usable(a, 4) != nil {
					t.Error("new request remains admissible during Closing effects")
				}
			}
			if local {
				a.stop(sm.DisconnectRebooting)
			} else {
				dpr, err := base.BuildDPR(m.dictionary(), testBase("a.example.net"), uint32(sm.DisconnectBusy))
				if err != nil {
					t.Fatal(err)
				}
				a.onWire(event{s: s, msg: dpr})
			}
			if !checked || a.state != Closing {
				t.Fatalf("disconnect effect not checked: checked=%t state=%s", checked, a.state)
			}
		})
	}
}

func TestManagerClosingMalformedDPROnWire(t *testing.T) {
	for _, dialed := range []bool{false, true} {
		for _, local := range []bool{false, true} {
			for _, malformed := range []string{"decoded structure", "decoder error"} {
				t.Run(fmt.Sprintf("dialed=%t/local=%t/%s", dialed, local, malformed), func(t *testing.T) {
					m, c, clock, events := closingPeer(t, dialed)
					closingStart(t, m, c, local, diam.Success)
					mark := clock.timerCount()
					dpr := closingDPR(t, m)
					kind, result := diam.ProtocolInvalidRequest, uint32(diam.AVPOccursTooManyTimes)
					if malformed == "decoder error" {
						dpr.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2}))
						kind, result = diam.ProtocolMalformedMessage, diam.InvalidAVPLength
					} else {
						dpr.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("known.example.net")))
					}
					write(t, c, dpr)
					e := correlationEvent(t, events, kind, false)
					if e.Err.ResultCode() != result {
						t.Fatalf("malformed DPR result changed: %+v", e)
					}
					closingSilence(t, c, events)
					if m.Peers()[0].State != Closing || clock.timerCount() != mark {
						t.Fatal("malformed DPR changed Closing deadline")
					}
				})
			}
		}
	}
}

func TestManagerClosingAnsweredWatchdogOnWire(t *testing.T) {
	for _, dialed := range []bool{false, true} {
		for _, result := range []uint32{diam.Success, diam.UnableToComply, diam.TooBusy, diam.AVPUnsupported} {
			t.Run(fmt.Sprintf("dialed=%t/result=%d", dialed, result), func(t *testing.T) {
				m, c, clock, events := closingPeer(t, dialed)
				clock.fire()
				probe := read(t, c)
				answer, err := base.BuildDWA(probe, testBase("known.example.net"))
				if err != nil {
					t.Fatal(err)
				}
				field, err := answer.FindAVP(avp.ResultCode, 0)
				if err != nil {
					t.Fatal(err)
				}
				field.Data = datatype.Unsigned32(result)
				if result >= 3000 && result < 4000 || result == diam.AVPUnsupported {
					answer.Header.CommandFlags |= diam.ErrorFlag | diam.ProxiableFlag
				}
				if result == diam.AVPUnsupported {
					// Verified Erratum 4615: a 5001 answer carries one Failed-AVP
					// holding the unsupported AVP.
					answer.AddAVP(diam.NewAVP(avp.FailedAVP, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{diam.NewAVP(0xfffe, avp.Mbit, 0, datatype.OctetString("unsupported"))}}))
				}
				write(t, c, answer)
				if result != diam.Success {
					e := correlationEvent(t, events, diam.ProtocolRejectedDWA, false)
					if e.Err.ResultCode() != result {
						t.Fatalf("rejected DWA diagnostics changed: %+v", e)
					}
				}
				// The failed probe retains watchdog Pending/credit policy, but
				// it has received an answer and is no longer a §5.4 in-flight request.
				closingStart(t, m, c, false, diam.Success)
			})
		}
	}
}

func TestManagerClosingInvalidWatchdogStillInFlightOnWire(t *testing.T) {
	for _, fault := range []string{"hop", "end", "host", "realm", "missing host", "duplicate result", "flags"} {
		t.Run(fault, func(t *testing.T) {
			m, c, clock, events := closingPeer(t, false)
			clock.fire()
			probe := read(t, c)
			answer, err := base.BuildDWA(probe, testBase("known.example.net"))
			if err != nil {
				t.Fatal(err)
			}
			result, err := answer.FindAVP(avp.ResultCode, 0)
			if err != nil {
				t.Fatal(err)
			}
			result.Data = datatype.Unsigned32(diam.UnableToComply)
			switch fault {
			case "hop":
				answer.Header.HopByHopID++
			case "end":
				answer.Header.EndToEndID++
			case "host", "realm":
				code := uint32(avp.OriginHost)
				if fault == "realm" {
					code = avp.OriginRealm
				}
				field, err := answer.FindAVP(code, 0)
				if err != nil {
					t.Fatal(err)
				}
				field.Data = datatype.DiameterIdentity("other.example.net")
			case "missing host":
				for i, field := range answer.AVP {
					if field.Code == avp.OriginHost {
						answer.AVP = append(answer.AVP[:i], answer.AVP[i+1:]...)
						answer.Header.MessageLength = uint32(answer.Len())
						break
					}
				}
			case "duplicate result":
				answer.AddAVP(diam.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.UnableToComply)))
			case "flags":
				answer.Header.CommandFlags |= diam.ProxiableFlag
			}
			write(t, c, answer)
			e := protocolErrorReceive(t, events)
			if e.Closing || e.Reply != diam.ProtocolReplyNone {
				t.Fatalf("invalid DWA changed existing policy: %+v", e)
			}
			closingStart(t, m, c, false, diam.UnableToComply)
		})
	}
}

func TestManagerClosingPendingGenerationOnWire(t *testing.T) {
	m, c, _, events := closingPeer(t, false)
	request, result := closingPending(t, m, c)
	closingStart(t, m, c, false, diam.UnableToComply)
	m.mu.RLock()
	s := m.peers["known.example.net"].activeSession.Load()
	m.mu.RUnlock()
	m.pendingMu.Lock()
	p := m.pending[s][request.Header.HopByHopID]
	attempt := p.entries[s]
	stale := attempt
	stale.generation++
	p.entries[s] = stale
	m.pendingMu.Unlock()
	answer := request.Answer(diam.Success)
	write(t, c, answer)
	closingSilence(t, c, events)
	select {
	case got := <-result:
		t.Fatalf("stale-generation request completed: %+v", got)
	default:
	}
	m.pendingMu.Lock()
	p.entries[s] = attempt
	m.pendingMu.Unlock()
	write(t, c, answer)
	select {
	case got := <-result:
		if got.err != nil || got.answer == nil {
			t.Fatalf("current-generation answer failed: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("current-generation answer dropped")
	}
}

func TestManagerClosingReservedAnswerOnWire(t *testing.T) {
	for _, sent := range []bool{false, true} {
		t.Run(fmt.Sprintf("sent=%t", sent), func(t *testing.T) {
			m, c, clock, events := closingPeer(t, false)
			m.mu.RLock()
			s := m.peers["known.example.net"].activeSession.Load()
			m.mu.RUnlock()
			entered, release := make(chan struct{}), make(chan struct{})
			var armed, held, released atomic.Bool
			unblock := func() {
				if released.CompareAndSwap(false, true) {
					close(release)
				}
			}
			t.Cleanup(unblock)
			s.beforeAdmission = func() {
				if armed.Load() && held.CompareAndSwap(false, true) {
					close(entered)
					<-release
				}
			}
			var alreadySent *diam.Message
			var sentResult <-chan sendResult
			if sent {
				alreadySent, sentResult = closingPending(t, m, c)
			}
			armed.Store(true)
			result := make(chan sendResult, 1)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				answer, err := m.Send(ctx, outboundRequest("known.example.net", "example.net"))
				result <- sendResult{answer: answer, err: err}
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("request reservation did not reach queue admission")
			}
			m.pendingMu.Lock()
			var synthetic *diam.Message
			for hop, p := range m.pending[s] {
				if p.entries[s].writing {
					continue
				}
				synthetic = p.msg.Answer(diam.Success)
				synthetic.Header.HopByHopID = hop
				break
			}
			m.pendingMu.Unlock()
			if synthetic == nil {
				t.Fatal("held Send has no unsent pending reservation")
			}
			dpaResult := uint32(diam.Success)
			if sent {
				dpaResult = diam.UnableToComply
			}
			closingStart(t, m, c, false, dpaResult)
			mark := clock.timerCount()
			write(t, c, synthetic)
			closingSilence(t, c, events)
			if sent {
				write(t, c, alreadySent.Answer(diam.Success))
				select {
				case got := <-sentResult:
					if got.err != nil || got.answer == nil {
						t.Fatalf("sent request was failed during Closing: %+v", got)
					}
				case <-time.After(time.Second):
					t.Fatal("sent request no longer drains during Closing")
				}
			}
			// Releasing the queue must never make an unsent reservation eligible.
			unblock()
			select {
			case got := <-result:
				if got.answer != nil || !errors.Is(got.err, ErrFailover) {
					t.Fatalf("unsent reservation disposition=%+v, want failover", got)
				}
			case <-time.After(time.Second):
				t.Error("Closing did not dispose of unsent reservation")
			}
			write(t, c, synthetic)
			closingSilence(t, c, events)
			if clock.timerCount() != mark {
				t.Fatal("reservation disposition renewed Closing deadline")
			}
		})
	}
}

// A selected writer can still be waiting before the transport sees any byte.
// RFC 6733 §§5.4–5.6 exclude that unsent work from Closing's frozen drain set.
func TestManagerClosingBeforeTransportOnWire(t *testing.T) {
	for _, local := range []bool{false, true} {
		t.Run(fmt.Sprintf("local=%t", local), func(t *testing.T) {
			m, c, _, events := closingPeer(t, false)
			m.mu.RLock()
			s := m.peers["known.example.net"].activeSession.Load()
			m.mu.RUnlock()
			entered, release := make(chan struct{}), make(chan struct{})
			var released atomic.Bool
			unblock := func() {
				if released.CompareAndSwap(false, true) {
					close(release)
				}
			}
			t.Cleanup(unblock)
			s.beforePublication = func(msg *diam.Message) {
				if msg.Header.ApplicationID != 0 {
					close(entered)
					<-release
				}
			}
			result := make(chan sendResult, 1)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				answer, err := m.Send(ctx, outboundRequest("known.example.net", "example.net"))
				result <- sendResult{answer: answer, err: err}
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("writer did not reach transport barrier")
			}
			m.pendingMu.Lock()
			var synthetic *diam.Message
			for hop, p := range m.pending[s] {
				synthetic = p.msg.Answer(diam.Success)
				synthetic.Header.HopByHopID = hop
				break
			}
			m.pendingMu.Unlock()
			if synthetic == nil {
				t.Fatal("writer has no pending reservation")
			}
			if local {
				m.mu.RLock()
				a := m.peers["known.example.net"]
				m.mu.RUnlock()
				a.post(event{kind: stop, cause: sm.DisconnectRebooting})
			} else {
				write(t, c, closingDPR(t, m))
			}
			awaitState(t, m, Closing)
			m.pendingMu.Lock()
			admitted := m.pendingAnswerLocked(s, synthetic) != nil
			m.pendingMu.Unlock()
			if admitted {
				t.Error("writer selected before transport acquired Closing drain eligibility")
			}
			unblock()
			disconnect := read(t, c)
			if disconnect.Header.CommandCode != diam.DisconnectPeer || (!local && code(t, disconnect) != diam.Success) {
				t.Fatalf("unsent writer appeared on wire or affected DPA: %+v", disconnect)
			}
			write(t, c, synthetic)
			closingSilence(t, c, events)
			select {
			case got := <-result:
				if got.answer != nil || !errors.Is(got.err, ErrFailover) {
					t.Fatalf("unsent writer disposition=%+v", got)
				}
			case <-time.After(time.Second):
				t.Fatal("Closing retained unsent selected writer")
			}
		})
	}
}

func TestManagerClosingSentFailoverAnswerOnWire(t *testing.T) {
	clock := &fakeClock{}
	events := make(chan diam.ProtocolErrorEvent, 16)
	settings := testSettings("local.example.net")
	settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
	m, err := New(Config{Settings: settings, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []datatype.DiameterIdentity{"a.example.net", "b.example.net"} {
		if err := m.AddPeer(PeerConfig{Host: host, NoAutoReconnect: true}); err != nil {
			t.Fatal(err)
		}
	}
	l, srv := startReceiverWithHandlers(t, m, 8)
	t.Cleanup(func() { closeManager(t, m, srv) })
	peers := make([]net.Conn, 0, 2)
	for _, host := range []string{"a.example.net", "b.example.net"} {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		cer, err := base.BuildCER(m.dictionary(), testBase(host))
		if err != nil {
			t.Fatal(err)
		}
		write(t, c, cer)
		if code(t, read(t, c)) != diam.Success {
			t.Fatal("receiver handshake rejected")
		}
		peers = append(peers, c)
	}
	if err := m.SetRoutes([]Route{{Realm: "example.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"a.example.net", "b.example.net"}}}); err != nil {
		t.Fatal(err)
	}
	// A valid DWR reply follows each actor's completed admission/publication.
	for i, c := range peers {
		dwr, err := base.BuildDWR(m.dictionary(), testBase([]string{"a.example.net", "b.example.net"}[i]), 0)
		if err != nil {
			t.Fatal(err)
		}
		write(t, c, dwr)
		if code(t, read(t, c)) != diam.Success {
			t.Fatal("peer admission did not finish")
		}
	}
	m.mu.RLock()
	s := m.peers["b.example.net"].activeSession.Load()
	m.mu.RUnlock()
	entered, release := make(chan struct{}), make(chan struct{})
	var released atomic.Bool
	unblock := func() {
		if released.CompareAndSwap(false, true) {
			close(release)
		}
	}
	t.Cleanup(unblock)
	s.afterAdmission = func() { close(entered); <-release }
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := sendAsync(m, ctx, outboundRequest("", "example.net"))
	original := read(t, peers[0])
	_ = peers[0].Close()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("retry did not reach admitted reservation barrier")
	}
	sent := read(t, peers[1])
	if sent.Header.EndToEndID != original.Header.EndToEndID || sent.Header.CommandFlags&diam.RetransmittedFlag == 0 {
		t.Fatal("alternate did not receive the retry")
	}
	m.pendingMu.Lock()
	p := m.pending[s][sent.Header.HopByHopID]
	m.pendingMu.Unlock()
	dpr, err := base.BuildDPR(m.dictionary(), testBase("b.example.net"), uint32(sm.DisconnectBusy))
	if err != nil {
		t.Fatal(err)
	}
	write(t, peers[1], dpr)
	if answer := read(t, peers[1]); answer.Header.CommandCode != diam.DisconnectPeer || code(t, answer) != diam.UnableToComply {
		t.Fatalf("published retry was not in flight: %+v", answer)
	}
	unblock()
	deadline := time.Now().Add(time.Second)
	for {
		m.pendingMu.Lock()
		done, retrying := p.done, p.failovering
		m.pendingMu.Unlock()
		if done {
			t.Fatal("Closing failed over a request whose retry was already sent")
		}
		if !retrying {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("retry did not finish queue admission")
		}
		time.Sleep(time.Millisecond)
	}
	write(t, peers[1], sent.Answer(diam.Success))
	select {
	case got := <-result:
		if got.err != nil || got.answer == nil {
			t.Fatalf("sent retry did not drain: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("sent retry answer was dropped")
	}
	closingSilence(t, peers[1], events)
}

func TestManagerClosingUnpublishedWatchdogOnWire(t *testing.T) {
	m, c, clock, events := closingPeer(t, false)
	m.mu.RLock()
	s := m.peers["known.example.net"].activeSession.Load()
	m.mu.RUnlock()
	entered, release := make(chan struct{}), make(chan struct{})
	var released atomic.Bool
	unblock := func() {
		if released.CompareAndSwap(false, true) {
			close(release)
		}
	}
	t.Cleanup(unblock)
	s.beforePublication = func(msg *diam.Message) {
		if msg.Header.CommandCode == diam.DeviceWatchdog && msg.Header.CommandFlags&diam.RequestFlag != 0 {
			close(entered)
			<-release
		}
	}
	clock.fire()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("watchdog did not reach transport barrier")
	}
	dpr := closingDPR(t, m)
	write(t, c, dpr)
	awaitState(t, m, Closing)
	unblock()
	answer := read(t, c)
	if answer.Header.CommandCode != diam.DisconnectPeer || code(t, answer) != diam.Success || answer.Header.HopByHopID != dpr.Header.HopByHopID || answer.Header.EndToEndID != dpr.Header.EndToEndID {
		t.Fatalf("unsent watchdog affected Closing: code=%d header=%+v", code(t, answer), answer.Header)
	}
	closingSilence(t, c, events)
}
