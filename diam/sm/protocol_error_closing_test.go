package sm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
)

func (p *protocolWire) closed(t *testing.T) {
	t.Helper()
	var b [1]byte
	if n, err := p.peer.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("read after close=%x %v", b[:n], err)
	}
}

func TestProtocolErrorClosingWire(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	for _, tc := range []struct {
		name    string
		message func(*testing.T) *diam.Message
		kind    diam.ProtocolErrorKind
		code    uint32
		answer  bool
		log     string
	}{
		{"B1_pre_CER", func(t *testing.T) *diam.Message { return regressionDWR(t) }, diam.ProtocolHandshakeState, 0, false, "sm: message before CER; closing connection"},
		{"B3_CER_missing_origin", func(*testing.T) *diam.Message {
			return diam.NewMessage(diam.CapabilitiesExchange, diam.RequestFlag, 0, 17, 18, testDict)
		}, diam.ProtocolCERRejected, 5005, true, "sm: rejected CER; closing connection"},
		{"B3_CER_no_common_app", func(t *testing.T) *diam.Message { return regressionCER(t, testDict, 999999) }, diam.ProtocolCERRejected, 5010, true, "sm: rejected CER; closing connection"},
		{"B3_CER_no_common_security", func(t *testing.T) *diam.Message {
			m := regressionCER(t, testDict, 1001)
			m.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unsigned32(1)))
			return m
		}, diam.ProtocolCERRejected, 5017, true, "sm: rejected CER; closing connection"},
		{"B3_CER_missing_app", func(t *testing.T) *diam.Message {
			m := regressionCER(t, testDict, 1001)
			m.AVP = m.AVP[:len(m.AVP)-1]
			return m
		}, diam.ProtocolCERRejected, 5010, true, "sm: rejected CER; closing connection"},
		{"B4_CER_header", func(t *testing.T) *diam.Message {
			m := regressionCER(t, testDict, 1001)
			m.Header.ApplicationID = 9
			return m
		}, diam.ProtocolInvalidHeader, 3008, true, "sm: invalid message header"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newProtocolWire(t, nil, false)
			h := p.send(t, tc.message(t))
			if tc.answer {
				a, err := diam.ReadMessage(p.peer, testDict)
				if err != nil || !testResultCode(a, tc.code) || a.Header.HopByHopID != h.HopByHopID || a.Header.EndToEndID != h.EndToEndID {
					t.Fatalf("answer=%v %v", a, err)
				}
				if a.Header.CommandFlags&diam.ErrorFlag != map[bool]uint8{true: diam.ErrorFlag, false: 0}[tc.code >= 3000 && tc.code < 4000] {
					t.Fatalf("E-bit=%x", a.Header.CommandFlags)
				}
			}
			p.closed(t)
			reply := diam.ProtocolReplyNone
			replyCode := uint32(0)
			if tc.answer {
				reply = diam.ProtocolReplyWritten
				replyCode = tc.code
			}
			assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, &h, tc.kind, tc.code, true, reply, replyCode)
			logs := p.logs.Records()
			want := 1
			if tc.name == "B4_CER_header" {
				want = 2
			}
			if len(logs) != want || logs[0].Level != slog.LevelWarn || logs[0].Message != tc.log {
				t.Fatalf("logs=%v", logs)
			}
		})
	}
}

func TestProtocolErrorB13FatalWire(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	for _, admitted := range []bool{false, true} {
		for _, answer := range []bool{false, true} {
			for _, tc := range []struct {
				name    string
				version uint8
				length  uint32
				code    uint32
			}{{"version", 2, 20, 5011}, {"short", 1, 16, 5015}, {"unaligned", 1, 21, 5015}} {
				t.Run(fmt.Sprintf("%s/admitted=%t/answer=%t", tc.name, admitted, answer), func(t *testing.T) {
					p := newProtocolWire(t, nil, admitted)
					flags := uint8(diam.RequestFlag)
					if answer {
						flags = 0
					}
					h := diam.Header{Version: tc.version, MessageLength: tc.length, CommandFlags: flags, CommandCode: diam.CapabilitiesExchange, HopByHopID: 0x34567812, EndToEndID: 0x45678123}
					wire := h.Serialize()
					writeSMErrorWire(t, p.peer, wire)
					if !answer {
						a, err := diam.ReadMessage(p.peer, testDict)
						if err != nil || !testResultCode(a, tc.code) || a.Header.CommandFlags&diam.ErrorFlag != 0 || a.Header.HopByHopID != h.HopByHopID {
							t.Fatalf("answer=%v %v", a, err)
						}
					}
					p.closed(t)
					kind := diam.ProtocolMalformedMessage
					rc := tc.code
					reply := diam.ProtocolReplyNone
					replyCode := uint32(0)
					if !answer {
						reply = diam.ProtocolReplyWritten
						replyCode = tc.code
					}
					if !admitted && answer {
						kind = diam.ProtocolHandshakeState
					}
					assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, &h, kind, rc, true, reply, replyCode)
					want := 2
					if !admitted {
						want = 3
					}
					waitLog(t, p.logs, want)
					logs := p.logs.Records()
					if len(logs) != want || logs[0].Message != "diam: malformed message" || logs[len(logs)-1].Message != "diam: malformed message; closing connection" {
						t.Fatalf("logs=%v", logs)
					}
				})
			}
		}
	}
}

func TestProtocolErrorB5HandshakeTimeoutWire(t *testing.T) {
	p := newProtocolWire(t, func(c *Settings) { c.HandshakeTimeout = 20 * time.Millisecond }, false)
	p.closed(t)
	assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, nil, diam.ProtocolHandshakeTimeout, 0, true, diam.ProtocolReplyNone, 0)
	if logs := p.logs.Records(); len(logs) != 1 || logs[0].Message != "sm: handshake timeout; closing connection" {
		t.Fatalf("logs=%v", logs)
	}
}

func protocolDPA(request *diam.Message, code uint32) *diam.Message {
	a := request.Answer(code)
	a.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
	a.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	return a
}

func TestProtocolErrorDisconnectWire(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	for _, kind := range []string{"A12_invalid_DPA", "A13_wrong_DPA_ID", "B9_rejected_DPA", "B10_DPA_timeout"} {
		t.Run(kind, func(t *testing.T) {
			p := newProtocolWire(t, nil, true)
			done := make(chan error, 1)
			timeout := time.Second
			if kind == "B10_DPA_timeout" {
				timeout = 20 * time.Millisecond
			}
			go func() { done <- p.sm.Disconnect(p.conn, DisconnectRebooting, timeout) }()
			dpr, err := diam.ReadMessage(p.peer, testDict)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "B10_DPA_timeout" {
				p.closed(t)
				assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, nil, diam.ProtocolDisconnectTimeout, 0, true, diam.ProtocolReplyNone, 0)
				if err := <-done; !errors.Is(err, ErrDisconnectTimeout) {
					t.Fatal(err)
				}
				return
			}
			code := uint32(2001)
			if kind == "B9_rejected_DPA" {
				code = 5012
			}
			a := protocolDPA(dpr, code)
			if kind == "A12_invalid_DPA" {
				a.AVP = a.AVP[:1]
			}
			if kind == "A13_wrong_DPA_ID" {
				a.Header.HopByHopID++
			}
			h := p.send(t, a)
			wantKind := diam.ProtocolInvalidDPA
			wantCode := uint32(0)
			closing := false
			if kind == "A13_wrong_DPA_ID" {
				wantKind = diam.ProtocolUnexpectedMessage
			}
			if kind == "B9_rejected_DPA" {
				wantKind = diam.ProtocolPeerRejected
				wantCode = 5012
				closing = true
			}
			assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, &h, wantKind, wantCode, closing, diam.ProtocolReplyNone, 0)
			if !closing {
				select {
				case err := <-done:
					t.Fatalf("bad DPA completed Disconnect: %v", err)
				default:
				}
				p.send(t, protocolDPA(dpr, 2001))
			}
			p.closed(t)
			if err := <-done; closing && err == nil || !closing && err != nil {
				t.Fatalf("Disconnect=%v", err)
			}
			logs := p.logs.Records()
			want := 0
			wantLog := ""
			if kind == "A12_invalid_DPA" {
				want = 1
				wantLog = "sm: invalid DPA"
			}
			if kind == "A13_wrong_DPA_ID" {
				want = 1
				wantLog = "sm: DPA identifiers mismatch; answer discarded"
			}
			if len(logs) != want || want == 1 && (logs[0].Message != wantLog || logs[0].Level != slog.LevelWarn) {
				t.Fatalf("logs=%v", logs)
			}
		})
	}
}

func TestProtocolErrorB11WaitReturnsWire(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	p := newProtocolWire(t, func(c *Settings) { c.DPRCloseTimeout = 20 * time.Millisecond }, true)
	m := diam.NewMessage(diam.DisconnectPeer, diam.RequestFlag, 0, 17, 18, testDict)
	m.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
	m.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	m.AddAVP(diam.NewAVP(avp.DisconnectCause, avp.Mbit, 0, datatype.Enumerated(0)))
	p.send(t, m)
	if a, err := diam.ReadMessage(p.peer, testDict); err != nil || !testResultCode(a, 2001) {
		t.Fatalf("DPA=%v %v", a, err)
	}
	p.closed(t)
	assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, nil, diam.ProtocolDisconnectTimeout, 0, true, diam.ProtocolReplyNone, 0)
	if logs := p.logs.Records(); len(logs) != 1 || logs[0].Message != "sm: Wait-Returns timeout; closing connection" {
		t.Fatalf("logs=%v", logs)
	}
}

func TestProtocolErrorA17DirectOwnershipWire(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	p := newProtocolWire(t, nil, true)
	request := regressionDWR(t)
	wire, err := request.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := diam.ReadMessage(bytes.NewReader(wire), testDict)
	if err != nil {
		t.Fatal(err)
	}
	// A custom decoder may invoke the public ownership API directly; its
	// resulting answer must still be written on the real admitted connection.
	if err := p.sm.HandleMessageError(p.conn, decoded, &diam.MessageError{ResultCode: 5004}); err != nil {
		t.Fatal(err)
	}
	if a, err := diam.ReadMessage(p.peer, testDict); err != nil || !testResultCode(a, 5004) {
		t.Fatalf("answer=%v %v", a, err)
	}
	h, _ := diam.DecodeHeader(wire)
	assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, h, diam.ProtocolMalformedMessage, 5004, false, diam.ProtocolReplyWritten, 5004)
	p.usable(t)
	if logs := p.logs.Records(); len(logs) != 0 {
		t.Fatalf("logs=%v", logs)
	}
}

func TestProtocolErrorFatalHeaderOverrideWire(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	p := newProtocolWire(t, nil, true)
	wire := testSMErrorHeader(2, 20, diam.RequestFlag)
	binary.BigEndian.PutUint32(wire[8:12], 9)
	writeSMErrorWire(t, p.peer, wire)
	if a, err := diam.ReadMessage(p.peer, testDict); err != nil || !testResultCode(a, 3008) {
		t.Fatalf("answer=%v %v", a, err)
	}
	p.closed(t)
	h := &diam.Header{Version: 2, MessageLength: 20, CommandFlags: diam.RequestFlag, CommandCode: diam.CapabilitiesExchange, ApplicationID: 9, HopByHopID: 0x01020304, EndToEndID: 0x05060708}
	assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, h, diam.ProtocolInvalidHeader, 3008, true, diam.ProtocolReplyWritten, 3008)
}
