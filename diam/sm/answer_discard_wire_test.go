package sm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// The complete 28-byte CEA contains an eight-byte AVP claiming twelve bytes.
// Unlike a missing AVP, this exercises Server's nonfatal MessageError path.
func malformedCEAWire(t *testing.T, p *protocolClientWire, fault string) (diam.Header, []byte) {
	t.Helper()
	h := *p.cer.Header
	h.CommandFlags, h.MessageLength = 0, 28
	switch fault {
	case "hop", "fatal", "command", "application", "request":
		h.HopByHopID++
	case "end":
		h.EndToEndID++
	}
	switch fault {
	case "fatal":
		h.Version = 2
	case "command":
		h.CommandCode = diam.DeviceWatchdog
	case "application":
		h.ApplicationID = 4
	case "request":
		h.CommandFlags = diam.RequestFlag
	}
	wire := append(h.Serialize(), 0, 0, 1, 8, avp.Mbit, 0, 0, 12)
	m, err := diam.ReadMessage(bytes.NewReader(wire), p.conn.Dictionary())
	var me *diam.MessageError
	if m == nil || m.Header == nil || !errors.As(err, &me) || me.Fatal != (fault == "fatal") ||
		me.ResultCode != map[bool]uint32{false: diam.InvalidAVPLength, true: diam.UnsupportedVersion}[fault == "fatal"] {
		t.Fatalf("malformed CEA did not reach the intended decoder path: message=%v error=%v", m, err)
	}
	return h, wire
}

func TestClientMalformedCEACorrelationWire(t *testing.T) {
	for _, identifier := range []string{"hop", "end"} {
		for _, finish := range []string{"correct", "deadline"} {
			t.Run(identifier+"/"+finish, func(t *testing.T) {
				var calls atomic.Int32
				p := newProtocolClientWire(t, func(c *Client) {
					c.RetransmitInterval = 400 * time.Millisecond
					c.Handler.cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) { calls.Add(1) }
				})
				start := time.Now()
				if finish == "deadline" {
					time.Sleep(200 * time.Millisecond)
				}
				header, wire := malformedCEAWire(t, p, identifier)
				writeSMErrorWire(t, p.peer, wire)
				assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, &header, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
				if _, ok := smpeer.FromContext(p.conn.Context()); ok || p.conn.Closed() || calls.Load() != 0 {
					t.Fatal("malformed stray CEA changed admission or identity")
				}
				select {
				case result := <-p.dialed:
					t.Fatalf("malformed stray CEA completed admission: %+v", result)
				default:
				}
				if finish == "deadline" {
					if result := p.dialResult(t); !errors.Is(result.err, ErrHandshakeTimeout) {
						t.Fatalf("malformed stray replaced original deadline: %+v", result)
					}
					if elapsed := time.Since(start); elapsed < 300*time.Millisecond || elapsed > 550*time.Millisecond {
						t.Fatalf("malformed stray changed original deadline: %s", elapsed)
					}
					assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, nil, diam.ProtocolHandshakeTimeout, 0, true, diam.ProtocolReplyNone, 0)
					return
				}
				p.send(t, protocolClientCEA(p.cer, diam.Success))
				if result := p.dialResult(t); result.err != nil || result.conn != p.conn || calls.Load() != 1 {
					t.Fatalf("correct CEA after malformed stray failed admission: %+v calls=%d", result, calls.Load())
				}
				meta, ok := smpeer.FromContext(p.conn.Context())
				if !ok || meta.OriginHost != "peer.example" {
					t.Fatalf("correlated CEA identity missing: %+v", meta)
				}
			})
		}
	}
}

func TestClientMalformedCEAKeepsRejectionWire(t *testing.T) {
	for _, fault := range []string{"correlated", "fatal", "command", "application", "request"} {
		t.Run(fault, func(t *testing.T) {
			p := newProtocolClientWire(t, nil)
			header, wire := malformedCEAWire(t, p, fault)
			writeSMErrorWire(t, p.peer, wire)
			code := uint32(diam.InvalidAVPLength)
			if fault == "fatal" {
				code = diam.UnsupportedVersion
			}
			assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, &header, diam.ProtocolHandshakeState, code, true, diam.ProtocolReplyNone, 0)
			if result := p.dialResult(t); result.err == nil || result.conn != nil {
				t.Fatalf("malformed correlated/non-CEA/fatal frame admitted: %+v", result)
			}
			p.closed(t)
		})
	}
}

type discardLogObservation struct {
	event   diam.ProtocolErrorEvent
	records []slog.Record
}

func discardLogCallback(events chan<- discardLogObservation) func(diam.ProtocolErrorEvent) {
	return func(e diam.ProtocolErrorEvent) {
		r := e.Conn.Logger().Handler().(*logtest.Recorder)
		events <- discardLogObservation{e, r.Records()}
	}
}

func assertDiscardWarning(t *testing.T, records []slog.Record, command, mismatch string) {
	t.Helper()
	if len(records) != 1 || records[0].Level != slog.LevelWarn || !strings.Contains(records[0].Message, command) ||
		!strings.Contains(records[0].Message, mismatch) || !logtest.HasAttr(records[0], "message.hop_by_hop_id") {
		t.Fatalf("discard warning missing or incorrect: %+v; want Warn naming %s %s before notification", records, command, mismatch)
	}
}

func TestCEADiscardLogsBeforeNotificationWire(t *testing.T) {
	for _, callback := range []bool{false, true} {
		for _, identifier := range []string{"hop", "end"} {
			t.Run(fmt.Sprintf("callback=%t/%s", callback, identifier), func(t *testing.T) {
				observations := make(chan discardLogObservation, 1)
				p := newProtocolClientWire(t, func(c *Client) {
					c.RetransmitInterval = 2 * time.Second
					c.Handler.cfg.OnProtocolError = nil
					if callback {
						c.Handler.cfg.OnProtocolError = discardLogCallback(observations)
					}
				})
				answer := protocolClientCEA(p.cer, diam.Success)
				if identifier == "hop" {
					answer.Header.HopByHopID++
				} else {
					answer.Header.EndToEndID++
				}
				header := p.send(t, answer)
				ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				defer cancel()
				records, _ := p.logs.Wait(ctx, 1)
				assertDiscardWarning(t, records, "CEA", "identifiers mismatch")
				if callback {
					observation := <-observations
					assertProtocolEvent(t, observation.event, p.conn, &header, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
					assertDiscardWarning(t, observation.records, "CEA", "identifiers mismatch")
				}
				if _, ok := smpeer.FromContext(p.conn.Context()); ok || p.conn.Closed() {
					t.Fatal("CEA discard diagnostic changed admission")
				}
				select {
				case result := <-p.dialed:
					t.Fatalf("CEA discard diagnostic completed admission: %+v", result)
				default:
				}
				p.send(t, protocolClientCEA(p.cer, diam.Success))
				if result := p.dialResult(t); result.err != nil {
					t.Fatal(result.err)
				}
			})
		}
	}
}

func TestDPADiscardLogsBeforeNotificationWire(t *testing.T) {
	for _, mode := range []string{"accepted", "dialed"} {
		for _, callback := range []bool{false, true} {
			for _, mismatch := range []string{"end", "host"} {
				t.Run(fmt.Sprintf("%s/callback=%t/%s", mode, callback, mismatch), func(t *testing.T) {
					observations := make(chan discardLogObservation, 1)
					configure := func(cfg *Settings) {
						cfg.OnProtocolError = nil
						if callback {
							cfg.OnProtocolError = discardLogCallback(observations)
						}
					}
					var p *protocolWire
					if mode == "accepted" {
						p = newProtocolWire(t, configure, true)
					} else {
						c := newProtocolClientWire(t, func(c *Client) { configure(c.Handler.cfg) })
						c.send(t, protocolClientCEA(c.cer, diam.Success))
						if result := c.dialResult(t); result.err != nil {
							t.Fatal(result.err)
						}
						p = &protocolWire{sm: c.client.Handler, conn: c.conn, peer: c.peer, events: c.events, logs: c.logs}
					}
					result := make(chan error, 1)
					go func() { result <- p.sm.Disconnect(p.conn, DisconnectBusy, 2*time.Second) }()
					request, err := diam.ReadMessage(p.peer, p.conn.Dictionary())
					if err != nil || request.Header.CommandCode != diam.DisconnectPeer {
						t.Fatalf("DPR=%v error=%v", request, err)
					}
					closing := p.sm.acceptedClosing(p.conn)
					var acceptedState *acceptedHandshake
					var controls []protocol.ControlSnapshot
					if mode == "accepted" {
						acceptedState = p.sm.acceptedCore(p.conn, nil, false)
						if acceptedState == nil {
							t.Fatal("accepted disconnect has no generation core")
						}
						// The peer can read the DPR before its writer returns. Wait
						// for that independent pin disposal before comparing state.
						deadline := time.Now().Add(10 * time.Second)
						for {
							controls = acceptedState.snapshot().Controls()
							if len(controls) == 1 && controls[0].Command == diam.DisconnectPeer && controls[0].Logical && controls[0].Writers == 0 {
								break
							}
							if time.Now().After(deadline) {
								t.Fatalf("DPR writer did not reach its pending-answer boundary: %+v", controls)
							}
							time.Sleep(time.Millisecond)
						}
					}
					answer := boundWireAnswer(t, p, request, diam.Success)
					want := "identifiers mismatch"
					if mismatch == "end" {
						answer.Header.EndToEndID++
					} else {
						setWireIdentity(t, answer, avp.OriginHost, "stranger.example")
						want = "Origin-Host mismatch"
					}
					header := p.send(t, answer)
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					records, _ := p.logs.Wait(ctx, 1)
					assertDiscardWarning(t, records, "DPA", want)
					if callback {
						observation := <-observations
						assertProtocolEvent(t, observation.event, p.conn, &header, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
						assertDiscardWarning(t, observation.records, "DPA", want)
					}
					var unchanged bool
					if mode == "accepted" {
						unchanged = slices.Equal(acceptedState.snapshot().Controls(), controls)
					} else {
						state := p.sm.acceptedCore(p.conn, nil, false)
						unchanged = len(state.snapshot().Controls()) != 0
					}
					if !unchanged || p.conn.Closed() || p.sm.acceptedClosing(p.conn) != closing {
						t.Fatal("DPA diagnostic changed pending DPR or Closing")
					}
					select {
					case err := <-result:
						t.Fatalf("DPA diagnostic completed disconnect: %v", err)
					default:
					}
					p.send(t, boundWireAnswer(t, p, request, diam.Success))
					select {
					case err := <-result:
						if err != nil {
							t.Fatal(err)
						}
					case <-time.After(10 * time.Second):
						t.Fatal("matching DPA no longer completed disconnect")
					}
				})
			}
		}
	}
}
