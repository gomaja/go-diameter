package peer

import (
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

// Install logging before Manager and its native TCP connections are created.
// These tests run serially and restore the default after fixture cleanup.
func publicErrorLog(t *testing.T) *logtest.Recorder {
	t.Helper()
	previous := slog.Default()
	records := logtest.New()
	slog.SetDefault(records.Logger())
	t.Cleanup(func() { slog.SetDefault(previous) })
	return records
}

func publicErrorDWR(t *testing.T, p *coreActivityWire) {
	t.Helper()
	request := watchdogRequest(t)
	write(t, p.c, request)
	answer := read(t, p.c)
	if answer.Header.CommandCode != diam.DeviceWatchdog || answer.Header.CommandFlags&diam.RequestFlag != 0 || answer.Header.HopByHopID != request.Header.HopByHopID || answer.Header.EndToEndID != request.Header.EndToEndID || code(t, answer) != diam.Success {
		t.Fatalf("subsequent TCP DWR failed: %+v", answer.Header)
	}
	p.fence(t)
}

func publicErrorLogCheck(t *testing.T, records *logtest.Recorder, start int, command uint32, wantType, wantText string) {
	t.Helper()
	got := records.Records()[start:]
	if len(got) != 1 {
		t.Fatalf("diagnostic logs=%v; want one", got)
	}
	record := got[0]
	cause := logtest.Attr(record, "error").Any()
	if record.Level != slog.LevelWarn || record.Message != "peer: protocol error" || fmt.Sprintf("%T", cause) != wantType || fmt.Sprint(cause) != wantText || logtest.Attr(record, "peer_host").String() != "known.example.net" || logtest.Attr(record, "message.command_code").Uint64() != uint64(command) {
		t.Fatalf("diagnostic level=%s message=%q cause=%T(%v) host=%v command=%v", record.Level, record.Message, cause, cause, logtest.Attr(record, "peer_host"), logtest.Attr(record, "message.command_code"))
	}
}

func TestManagerBoundHeaderlessErrorCallbackIgnoredTCP(t *testing.T) {
	for _, dialed := range []bool{false, true} {
		for _, headerless := range []bool{false, true} {
			t.Run(fmt.Sprintf("dialed=%t/headerless=%t", dialed, headerless), func(t *testing.T) {
				records := publicErrorLog(t)
				p := newCoreActivityWire(t, dialed)
				start := len(records.Records())
				var message *diam.Message
				if headerless {
					message = &diam.Message{}
				}
				if err := p.m.HandleMessageError(p.s.c, message, &diam.MessageError{ResultCode: diam.InvalidAVPLength, Fatal: true}); err != nil {
					t.Fatal(err)
				}
				publicErrorDWR(t, p)
				if len(records.Records()) != start {
					t.Fatal("headerless callback produced a diagnostic")
				}
				select {
				case e := <-p.events:
					t.Fatalf("headerless callback reported %+v", e)
				default:
				}
			})
		}
	}
}

// Closing in a public decoder notification describes the supplied fatality.
// The native reader owns transport closure; a direct callback can still send
// without moving the existing watchdog deadline.
func TestManagerFatalBodyCallbackPreservesLiveTransportTCP(t *testing.T) {
	for _, dialed := range []bool{false, true} {
		for _, command := range []uint32{diam.CapabilitiesExchange, diam.DeviceWatchdog, diam.DisconnectPeer} {
			for _, request := range []bool{false, true} {
				t.Run(fmt.Sprintf("dialed=%t/command=%d/request=%t", dialed, command, request), func(t *testing.T) {
					records := publicErrorLog(t)
					p := newCoreActivityWire(t, dialed)
					start := len(records.Records())
					before := p.state(t)
					message := watchdogRequest(t)
					switch command {
					case diam.CapabilitiesExchange:
						message = capabilitiesExchangeRequest(t)
					case diam.DisconnectPeer:
						message = closingDPR(t, p.m)
					}
					if !request {
						message = message.Answer(diam.Success)
					}
					description := &diam.MessageError{ResultCode: diam.InvalidAVPLength, Fatal: true, Err: errors.New("callback body failure")}
					if err := p.m.HandleMessageError(p.s.c, message, description); err != nil {
						t.Fatal(err)
					}
					event := protocolErrorReceive(t, p.events)
					reply := diam.ProtocolReplyNone
					var replyCode uint32
					if request {
						reply = diam.ProtocolReplyQueued
						replyCode = diam.InvalidAVPLength
					}
					protocolErrorCheck(t, event, p.s.c, *message.Header, diam.ProtocolMalformedMessage, diam.InvalidAVPLength, true, reply, replyCode)
					if request {
						answer := read(t, p.c)
						if answer.Header.CommandCode != command || answer.Header.HopByHopID != message.Header.HopByHopID || answer.Header.EndToEndID != message.Header.EndToEndID || code(t, answer) != diam.InvalidAVPLength {
							t.Fatalf("callback error answer=%+v", answer.Header)
						}
					}
					if after := p.state(t); after.timer != before.timer || after.token != before.token || after.health != before.health || after.pending != before.pending || after.num != before.num {
						t.Fatalf("fatal callback changed watchdog state/deadline: before=%+v after=%+v", before, after)
					}
					publicErrorDWR(t, p)
					if p.s.c.Closed() || len(records.Records()) != start {
						t.Fatal("direct body callback closed or logged the transport")
					}
					select {
					case extra := <-p.events:
						t.Fatalf("extra callback notification=%+v", extra)
					default:
					}
				})
			}
		}
	}
}

func TestManagerOpenInitiatorCEAPreservesValidationDiagnosticTCP(t *testing.T) {
	for _, header := range []bool{false, true} {
		t.Run(fmt.Sprintf("header=%t", header), func(t *testing.T) {
			records := publicErrorLog(t)
			p := newCoreActivityWire(t, true)
			message := correlationCEA(t, capabilitiesExchangeRequest(t), "known.example.net")
			kind, result, text := diam.ProtocolCEARejected, uint32(diam.MissingAVP), "diameter message error 5005: Diameter validation failed (5005): required AVP missing"
			if header {
				message.Header.CommandFlags |= diam.ProxiableFlag
				kind, result, text = diam.ProtocolInvalidHeader, diam.InvalidHDRBits, "diameter message error 3008: invalid base command flags (RFC 6733 §§3, 3.2)"
			} else {
				message.AVP = nil
			}
			start := len(records.Records())
			write(t, p.c, message)
			event := protocolErrorReceive(t, p.events)
			expected := *message.Header
			expected.MessageLength = uint32(message.Len())
			protocolErrorCheck(t, event, p.s.c, expected, kind, result, false, diam.ProtocolReplyNone, 0, 0)
			publicErrorDWR(t, p)
			publicErrorLogCheck(t, records, start, diam.CapabilitiesExchange, "*diam.MessageError", text)
		})
	}
}

func TestManagerClosingDPRPreservesDecoderDiagnosticTCP(t *testing.T) {
	for _, dialed := range []bool{false, true} {
		for _, fault := range []string{"grammar", "callback-header", "fatal-callback-header"} {
			t.Run(fmt.Sprintf("dialed=%t/%s", dialed, fault), func(t *testing.T) {
				records := publicErrorLog(t)
				p := newCoreActivityWire(t, dialed)
				p.a.post(event{kind: stop})
				local := read(t, p.c)
				if local.Header.CommandCode != diam.DisconnectPeer {
					t.Fatalf("local shutdown=%+v", local.Header)
				}
				p.fence(t)
				start := len(records.Records())
				message := closingDPR(t, p.m)
				kind, result, text := diam.ProtocolInvalidRequest, uint32(diam.MissingAVP), "diameter message error 5005: Diameter validation failed (5005): required AVP missing"
				fatal := fault == "fatal-callback-header"
				if fault == "grammar" {
					message.AVP = nil
					write(t, p.c, message)
				} else {
					message.Header.CommandFlags |= diam.ProxiableFlag
					kind, result, text = diam.ProtocolMalformedMessage, diam.InvalidHDRBits, "diameter message error 3008: invalid base command flags (RFC 6733 §§3, 3.2)"
					if err := p.m.HandleMessageError(p.s.c, message, &diam.MessageError{ResultCode: diam.InvalidAVPLength, Fatal: fatal}); err != nil {
						t.Fatal(err)
					}
				}
				event := protocolErrorReceive(t, p.events)
				expected := *message.Header
				if fault == "grammar" {
					expected.MessageLength = uint32(message.Len())
				}
				stream := ^uint(0)
				if fault == "grammar" {
					stream = 0
				}
				protocolErrorCheck(t, event, p.s.c, expected, kind, result, fatal, diam.ProtocolReplyNone, 0, stream)
				p.fence(t)
				publicErrorLogCheck(t, records, start, diam.DisconnectPeer, "*diam.MessageError", text)
				// A later valid crossed DPR still gets its normal DPA in Closing.
				crossed := closingDPR(t, p.m)
				write(t, p.c, crossed)
				answer := read(t, p.c)
				if answer.Header.CommandCode != diam.DisconnectPeer || answer.Header.HopByHopID != crossed.Header.HopByHopID || answer.Header.EndToEndID != crossed.Header.EndToEndID || code(t, answer) != diam.Success {
					t.Fatalf("crossed DPR after malformed callback=%+v", answer.Header)
				}
			})
		}
	}
}

func TestManagerControlAnswerErrorIdentityTCP(t *testing.T) {
	for _, scenario := range []string{"unmatched-cea", "unowned-dwa", "unmatched-dpa", "dpa-identifiers", "dpa-host", "dpa-result"} {
		t.Run(scenario, func(t *testing.T) {
			records := publicErrorLog(t)
			p := newCoreActivityWire(t, false)
			var message *diam.Message
			var err error
			kind, result, closing := diam.ProtocolUnexpectedMessage, uint32(0), false
			text := "peer: unmatched answer (RFC 6733 §6.2.1)"
			switch scenario {
			case "unmatched-cea":
				message = correlationCEA(t, capabilitiesExchangeRequest(t), "known.example.net")
			case "unowned-dwa":
				message, err = base.BuildDWA(watchdogRequest(t), testBase("known.example.net"))
				kind, text = diam.ProtocolInvalidDWA, "peer: unsolicited or mismatched DWA"
			case "unmatched-dpa":
				message, err = base.BuildDPA(closingDPR(t, p.m), testBase("known.example.net"))
			default:
				p.a.post(event{kind: stop})
				local := read(t, p.c)
				p.fence(t)
				message, err = base.BuildDPA(local, testBase("known.example.net"))
				kind = diam.ProtocolInvalidDPA
				switch scenario {
				case "dpa-identifiers":
					message.Header.HopByHopID++
					text = "peer: DPA identifiers mismatch"
				case "dpa-host":
					field, e := message.FindAVP(avp.OriginHost, 0)
					if e != nil {
						t.Fatal(e)
					}
					field.Data = datatype.DiameterIdentity("other.example.net")
					text = "peer: DPA Origin-Host mismatch"
				case "dpa-result":
					field, e := message.FindAVP(avp.ResultCode, 0)
					if e != nil {
						t.Fatal(e)
					}
					field.Data = datatype.Unsigned32(diam.UnableToComply)
					kind, result, closing, text = diam.ProtocolPeerRejected, diam.UnableToComply, true, "peer: DPA Result-Code 5012"
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			start := len(records.Records())
			write(t, p.c, message)
			event := protocolErrorReceive(t, p.events)
			expected := *message.Header
			expected.MessageLength = uint32(message.Len())
			protocolErrorCheck(t, event, p.s.c, expected, kind, result, closing, diam.ProtocolReplyNone, 0, 0)
			p.fence(t)
			publicErrorLogCheck(t, records, start, message.Header.CommandCode, "*errors.errorString", text)
			if closing {
				correlationEOF(t, p.c)
			} else if scenario == "dpa-identifiers" || scenario == "dpa-host" {
				p.clock.fire()
				correlationEOF(t, p.c)
			} else {
				publicErrorDWR(t, p)
			}
		})
	}
}

func TestManagerPendingCEAErrorIdentityTCP(t *testing.T) {
	records := publicErrorLog(t)
	m, c, cer, events := correlationDial(t, &fakeClock{})
	m.mu.RLock()
	a := m.peers["known.example.net"]
	m.mu.RUnlock()
	var s *session
	a.commit(event{testHook: func() { s = a.i }}, newProtocolDelivery())
	message := correlationCEA(t, cer, "known.example.net")
	message.Header.HopByHopID++
	start := len(records.Records())
	write(t, c, message)
	notice := protocolErrorReceive(t, events)
	expected := *message.Header
	expected.MessageLength = uint32(message.Len())
	protocolErrorCheck(t, notice, s.c, expected, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0, 0)
	a.commit(event{}, newProtocolDelivery())
	publicErrorLogCheck(t, records, start, diam.CapabilitiesExchange, "*errors.errorString", "peer: CEA identifiers mismatch")
	write(t, c, correlationCEA(t, cer, "known.example.net"))
	awaitState(t, m, IOpen)
	publicErrorDWR(t, &coreActivityWire{m: m, c: c, a: a, s: s})
}
