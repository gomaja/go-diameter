package sm

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

func TestProtocolErrorCERValidationVariantsWire(t *testing.T) {
	for _, admitted := range []bool{false, true} {
		for _, tc := range []struct {
			name                       string
			validate, unknown, missing bool
			multiple, invalidBits      bool
			kind                       diam.ProtocolErrorKind
			code                       uint32
			log                        string
		}{
			{"A4_unknown_validation_off", false, true, false, false, false, diam.ProtocolUnsupportedAVP, 5001, "sm: unsupported mandatory AVP"},
			{"A4_unknown_validation_on", true, true, false, false, false, diam.ProtocolUnsupportedAVP, 5001, "sm: unsupported mandatory AVP"},
			{"A4_multiple_unknown", false, true, false, true, false, diam.ProtocolUnsupportedAVP, 5001, "sm: unsupported mandatory AVP"},
			{"A5_missing_Origin_Host", true, false, true, false, false, diam.ProtocolInvalidRequest, 5005, "sm: invalid request"},
			{"A5_invalid_AVP_bits", true, false, false, false, true, diam.ProtocolInvalidRequest, 3009, "sm: invalid request"},
			{"A4_before_A5", true, true, true, false, false, diam.ProtocolUnsupportedAVP, 5001, "sm: unsupported mandatory AVP"},
		} {
			t.Run(fmt.Sprintf("admitted=%t/%s", admitted, tc.name), func(t *testing.T) {
				p := newProtocolWire(t, func(c *Settings) {
					c.ValidateRequests = tc.validate
					c.RejectUnknownMandatoryAVPs = tc.unknown
					c.HandshakeTimeout = -1
				}, admitted)
				cer := regressionCER(t, dict.Default, 1001)
				if tc.missing {
					for i, a := range cer.AVP {
						if a.Code == avp.OriginHost {
							cer.AVP = append(cer.AVP[:i], cer.AVP[i+1:]...)
							break
						}
					}
				}
				if tc.unknown {
					cer.AddAVP(diam.NewAVP(0x00fedcab, avp.Mbit, 0, datatype.Unknown{1, 2, 3, 4}))
				}
				if tc.multiple {
					cer.AddAVP(diam.NewAVP(0x00fedcac, avp.Mbit, 0, datatype.Unknown{5, 6, 7, 8}))
				}
				if tc.invalidBits {
					// RFC 6733 §§4.1, 7.1.3: V with Vendor-Id zero yields 3009.
					for i, a := range cer.AVP {
						if a.Code == avp.VendorID {
							cer.AVP[i] = diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(0))
							cer.AVP[i].Flags |= avp.Vbit
							break
						}
					}
				}
				header := p.send(t, cer)
				answer, err := diam.ReadMessage(p.peer, dict.Default)
				flags := uint8(0)
				if tc.code == 3009 {
					flags = diam.ErrorFlag // RFC 6733 §§7.1.3, 7.2.
				}
				if err != nil || !testResultCode(answer, tc.code) || answer.Header.CommandCode != diam.CapabilitiesExchange || answer.Header.ApplicationID != 0 || answer.Header.CommandFlags != flags || answer.Header.HopByHopID != header.HopByHopID || answer.Header.EndToEndID != header.EndToEndID {
					t.Fatalf("CER answer=%v %v", answer, err)
				}
				var failed []*diam.AVP
				for _, a := range answer.AVP {
					if a.Code == avp.FailedAVP && a.VendorID == 0 {
						failed = append(failed, a)
					}
				}
				if len(failed) != 1 {
					t.Fatalf("Failed-AVP containers=%d, want one (RFC 6733 §7.1.5, Verified Erratum 4615)", len(failed))
				}
				wantFailed := []byte{0, 0, 1, 8, 0x40, 0, 0, 8} // Missing Origin-Host, §7.5.
				if tc.unknown {
					wantFailed = []byte{0, 0xfe, 0xdc, 0xab, 0x40, 0, 0, 12, 1, 2, 3, 4}
				}
				if tc.multiple {
					wantFailed = append(wantFailed, 0, 0xfe, 0xdc, 0xac, 0x40, 0, 0, 12, 5, 6, 7, 8)
				}
				if tc.invalidBits {
					wantFailed = []byte{0, 0, 1, 10, 0xc0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0}
				}
				if got := failed[0].Data.Serialize(); !bytes.Equal(got, wantFailed) {
					t.Fatalf("Failed-AVP bytes=%x, want %x", got, wantFailed)
				}
				if !admitted {
					p.closed(t)
				}
				assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, &header, tc.kind, tc.code, !admitted, diam.ProtocolReplyWritten, tc.code)
				if admitted {
					p.usable(t)
				}
				select {
				case extra := <-p.events:
					t.Fatalf("extra event=%+v", extra)
				default:
				}
				wantLogs := 1
				if !admitted {
					wantLogs = 2
				}
				logs := p.logs.Records()
				if len(logs) != wantLogs || logs[0].Level != slog.LevelWarn || logs[0].Message != tc.log {
					t.Fatalf("logs=%v", logs)
				}
				if !admitted && (logs[1].Level != slog.LevelWarn || logs[1].Message != "sm: rejected CER; closing connection") {
					t.Fatalf("close log=%v", logs[1])
				}
			})
		}
	}
}

func TestProtocolErrorNestedUnknownMandatoryWire(t *testing.T) {
	p := newProtocolWire(t, func(c *Settings) { c.ValidateRequests = true; c.RejectUnknownMandatoryAVPs = true }, true)
	request := unknownRequest(true, avp.Mbit)
	request.AddAVP(diam.NewAVP(0xfedd, avp.Mbit|avp.Vbit, 10415, datatype.Unknown("second")))
	header := p.send(t, request)
	answer, err := diam.ReadMessage(p.peer, dict.Default)
	if err != nil || !testResultCode(answer, 5001) || answer.Header.CommandFlags != diam.ProxiableFlag || answer.Header.HopByHopID != header.HopByHopID || answer.Header.EndToEndID != header.EndToEndID {
		t.Fatalf("answer=%v %v", answer, err)
	}
	var failed []*diam.AVP
	for _, a := range answer.AVP {
		if a.Code == avp.FailedAVP && a.VendorID == 0 {
			failed = append(failed, a)
		}
	}
	if len(failed) != 1 {
		t.Fatalf("Failed-AVP containers=%d, want one (RFC 6733 §7.1.5, Erratum 4615)", len(failed))
	}
	roots := failed[0].Data.(*diam.GroupedAVP).AVP
	if len(roots) != 2 || roots[0].Code != avp.VendorSpecificApplicationID || roots[1].Code != 0xfedd || roots[1].VendorID != 10415 || !bytes.Equal(roots[1].Data.Serialize(), []byte("second")) {
		t.Fatalf("Failed-AVP roots=%v", roots)
	}
	leaves := roots[0].Data.(*diam.GroupedAVP).AVP
	if len(leaves) != 1 || leaves[0].Code != 0xfedc || leaves[0].VendorID != 10415 || leaves[0].Flags&avp.Mbit == 0 || !bytes.Equal(leaves[0].Data.Serialize(), []byte("bad")) {
		t.Fatalf("nested evidence=%v", leaves)
	}
	assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, &header, diam.ProtocolUnsupportedAVP, 5001, false, diam.ProtocolReplyWritten, 5001)
	p.usable(t)
	select {
	case extra := <-p.events:
		t.Fatalf("multiple offending AVPs produced extra event=%+v", extra)
	default:
	}
	if logs := p.logs.Records(); len(logs) != 1 || logs[0].Message != "sm: unsupported mandatory AVP" || logs[0].Level != slog.LevelWarn {
		t.Fatalf("logs=%v", logs)
	}
}

type protocolVariantWire struct {
	conn   diam.Conn
	peer   net.Conn
	events <-chan diam.ProtocolErrorEvent
	logs   *logtest.Recorder
	send   func(*testing.T, *diam.Message) diam.Header
}

func protocolVariantRARHandler(t *testing.T) diam.HandlerFunc {
	t.Helper()
	return func(c diam.Conn, m *diam.Message) {
		answer := m.Answer(0)
		answer.AddAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("test-session")))
		answer.AddAVP(diam.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(2001)))
		answer.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("local.example")))
		answer.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
		if _, err := answer.WriteTo(c); err != nil {
			t.Error(err)
		}
	}
}

func newProtocolVariantWire(t *testing.T, client, validate, rejectUnknown bool) *protocolVariantWire {
	t.Helper()
	if client {
		p := newProtocolClientWire(t, func(c *Client) {
			c.Handler.cfg.ValidateRequests = validate
			c.Handler.cfg.RejectUnknownMandatoryAVPs = rejectUnknown
			c.Handler.HandleFunc("RAR", protocolVariantRARHandler(t))
		})
		p.send(t, protocolClientCEA(p.cer, 2001))
		if result := p.dialResult(t); result.err != nil || result.conn != p.conn {
			t.Fatalf("client Dial=%+v", result)
		}
		return &protocolVariantWire{conn: p.conn, peer: p.peer, events: p.events, logs: p.logs, send: p.send}
	}
	p := newProtocolWire(t, func(c *Settings) { c.ValidateRequests = validate; c.RejectUnknownMandatoryAVPs = rejectUnknown }, true)
	p.sm.HandleFunc("RAR", protocolVariantRARHandler(t))
	return &protocolVariantWire{conn: p.conn, peer: p.peer, events: p.events, logs: p.logs, send: p.send}
}

func protocolVariantRAR() *diam.Message {
	m := unknownRequest(false, 0)
	m.AVP = m.AVP[:len(m.AVP)-1]
	return m
}

func (p *protocolVariantWire) usable(t *testing.T) {
	t.Helper()
	header := p.send(t, regressionDWR(t))
	answer, err := diam.ReadMessage(p.peer, dict.Default)
	if err != nil || !testResultCode(answer, 2001) || answer.Header.CommandCode != diam.DeviceWatchdog || answer.Header.HopByHopID != header.HopByHopID || answer.Header.EndToEndID != header.EndToEndID || p.conn.Closed() {
		t.Fatalf("following DWR=%v %v", answer, err)
	}
}

func TestProtocolErrorValidationResultVariantsWire(t *testing.T) {
	for _, client := range []bool{false, true} {
		for _, validate := range []bool{false, true} {
			for _, tc := range []struct {
				name   string
				code   uint32
				change func(*diam.Message)
			}{
				{"unknown_command", 3001, func(m *diam.Message) { m.Header.CommandCode = 0x00ffff01 }},
				{"request_E", 3008, func(m *diam.Message) { m.Header.CommandFlags |= diam.ErrorFlag }},
				{"invalid_AVP_V_bit", 3009, func(m *diam.Message) { m.AVP[0].Flags |= avp.Vbit }},
				{"missing_required", 5005, func(m *diam.Message) { m.AVP = m.AVP[:len(m.AVP)-1] }},
				{"misplaced_fixed", 5008, func(m *diam.Message) { session := m.AVP[0]; m.AVP = append(m.AVP[1:], session) }},
				{"duplicate_fixed", 5009, func(m *diam.Message) {
					m.AddAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("second-session")))
				}},
			} {
				t.Run(fmt.Sprintf("client=%t/validate=%t/%s", client, validate, tc.name), func(t *testing.T) {
					p := newProtocolVariantWire(t, client, validate, false)
					request := protocolVariantRAR()
					tc.change(request)
					header := p.send(t, request)
					answer, err := diam.ReadMessage(p.peer, dict.Default)
					wantCode := uint32(2001)
					if validate || tc.code == 3001 {
						wantCode = tc.code
					}
					wantFlags := uint8(diam.ProxiableFlag)
					if wantCode >= 3000 && wantCode < 4000 {
						wantFlags |= diam.ErrorFlag
					}
					if err != nil || !testResultCode(answer, wantCode) || answer.Header.HopByHopID != header.HopByHopID || answer.Header.EndToEndID != header.EndToEndID || answer.Header.CommandFlags != wantFlags {
						t.Fatalf("answer=%v %v want code=%d flags=%x", answer, err, wantCode, wantFlags)
					}
					wantLog := ""
					wantLevel := slog.LevelWarn
					if validate {
						assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, &header, diam.ProtocolInvalidRequest, tc.code, false, diam.ProtocolReplyWritten, tc.code)
						wantLog = "sm: invalid request"
					} else if tc.code == 3001 {
						assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, &header, diam.ProtocolUnsupportedCommand, 3001, false, diam.ProtocolReplyWritten, 3001)
						wantLog, wantLevel = "sm: unsupported command answered", slog.LevelInfo
					}
					p.usable(t)
					select {
					case extra := <-p.events:
						t.Fatalf("extra protocol event=%+v", extra)
					default:
					}
					logs := p.logs.Records()
					wantCount := 0
					if wantLog != "" {
						wantCount = 1
					}
					if len(logs) != wantCount || wantCount != 0 && (logs[0].Message != wantLog || logs[0].Level != wantLevel) {
						t.Fatalf("logs=%v", logs)
					}
				})
			}
		}
	}
}

func TestProtocolErrorDecodeAndUnknownPrecedenceVariantsWire(t *testing.T) {
	for _, client := range []bool{false, true} {
		for _, validate := range []bool{false, true} {
			for _, tc := range []struct {
				name    string
				kind    diam.ProtocolErrorKind
				code    uint32
				message func() *diam.Message
				log     string
			}{
				{"invalid_payload_value", diam.ProtocolMalformedMessage, 5004, func() *diam.Message {
					m := protocolVariantRAR()
					m.AddAVP(diam.NewAVP(avp.HostIPAddress, avp.Mbit, 0, datatype.Unknown{255, 255, 1}))
					return m
				}, "diam: malformed message"},
				{"invalid_payload_length", diam.ProtocolMalformedMessage, 5014, func() *diam.Message {
					m := protocolVariantRAR()
					m.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2}))
					return m
				}, "diam: malformed message"},
				{"unknown_before_missing_required", diam.ProtocolUnsupportedAVP, 5001, func() *diam.Message {
					m := unknownRequest(true, avp.Mbit)
					for i, a := range m.AVP {
						if a.Code == avp.ReAuthRequestType {
							m.AVP = append(m.AVP[:i], m.AVP[i+1:]...)
							break
						}
					}
					return m
				}, "sm: unsupported mandatory AVP"},
			} {
				t.Run(fmt.Sprintf("client=%t/validate=%t/%s", client, validate, tc.name), func(t *testing.T) {
					p := newProtocolVariantWire(t, client, validate, true)
					header := p.send(t, tc.message())
					answer, err := diam.ReadMessage(p.peer, dict.Default)
					if err != nil || !testResultCode(answer, tc.code) || answer.Header.CommandFlags != diam.ProxiableFlag || answer.Header.HopByHopID != header.HopByHopID || answer.Header.EndToEndID != header.EndToEndID {
						t.Fatalf("answer=%v %v", answer, err)
					}
					assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, &header, tc.kind, tc.code, false, diam.ProtocolReplyWritten, tc.code)
					p.usable(t)
					select {
					case extra := <-p.events:
						t.Fatalf("extra event=%+v", extra)
					default:
					}
					if logs := p.logs.Records(); len(logs) != 1 || logs[0].Message != tc.log || logs[0].Level != slog.LevelWarn {
						t.Fatalf("logs=%v", logs)
					}
				})
			}
		}
	}
}
