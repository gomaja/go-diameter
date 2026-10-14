package sm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

type protocolWire struct {
	sm     *StateMachine
	peer   net.Conn
	conn   diam.Conn
	events chan diam.ProtocolErrorEvent
	logs   *logtest.Recorder
}

func TestProtocolErrorRetainedWire(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*Settings)
		message   func(*testing.T) *diam.Message
		kind      diam.ProtocolErrorKind
		code      uint32
		answer    bool
		log       string
		level     slog.Level
	}{
		{"A1_invalid_payload", nil, func(t *testing.T) *diam.Message {
			m := regressionDWR(t)
			m.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown([]byte{1, 2})))
			return m
		}, diam.ProtocolMalformedMessage, 5014, true, "diam: malformed message", slog.LevelWarn},
		{"A2_malformed_answer", nil, func(t *testing.T) *diam.Message {
			m := diam.NewMessage(diam.DeviceWatchdog, 0, 0, 17, 18, dict.Default)
			m.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.Unknown([]byte{0})))
			return m
		}, diam.ProtocolUnexpectedMessage, 0, false, "sm: unhandled answer discarded", slog.LevelWarn},
		{"A3_invalid_header_request", nil, func(t *testing.T) *diam.Message { m := regressionDWR(t); m.Header.ApplicationID = 9; return m }, diam.ProtocolInvalidHeader, 3008, true, "sm: invalid message header", slog.LevelWarn},
		{"A3_invalid_header_answer", nil, func(t *testing.T) *diam.Message {
			return diam.NewMessage(diam.DeviceWatchdog, 0, 9, 17, 18, dict.Default)
		}, diam.ProtocolInvalidHeader, 3008, false, "sm: invalid message header", slog.LevelWarn},
		{"A4_unknown_mandatory", func(c *Settings) { c.RejectUnknownMandatoryAVPs = true }, func(t *testing.T) *diam.Message {
			m := regressionDWR(t)
			m.AddAVP(diam.NewAVP(0xfedcab, avp.Mbit, 0, datatype.Unknown([]byte{1, 2, 3, 4})))
			return m
		}, diam.ProtocolUnsupportedAVP, 5001, true, "sm: unsupported mandatory AVP", slog.LevelWarn},
		{"A5_invalid_request", func(c *Settings) { c.ValidateRequests = true }, func(t *testing.T) *diam.Message { m := regressionDWR(t); m.AVP = m.AVP[:1]; return m }, diam.ProtocolInvalidRequest, 5005, true, "sm: invalid request", slog.LevelWarn},
		{"A6_unsupported_command", nil, func(*testing.T) *diam.Message {
			return diam.NewMessage(0xfedc, diam.RequestFlag, 0, 17, 18, dict.Default)
		}, diam.ProtocolUnsupportedCommand, 3001, true, "sm: unsupported command answered", slog.LevelInfo},
		{"A7_unsupported_application", nil, func(*testing.T) *diam.Message {
			return diam.NewMessage(0xfedc, diam.RequestFlag, 0xfefe, 17, 18, dict.Default)
		}, diam.ProtocolUnsupportedApplication, 3007, true, "sm: unsupported command answered", slog.LevelInfo},
		{"A7_validation_precedence", func(c *Settings) { c.ValidateRequests = true }, func(*testing.T) *diam.Message {
			return diam.NewMessage(0xfedc, diam.RequestFlag, 0xfefe, 17, 18, dict.Default)
		}, diam.ProtocolUnsupportedApplication, 3007, true, "sm: unsupported command answered", slog.LevelInfo},
		{"A9_invalid_DWA", func(c *Settings) {
			c.EnableWatchdog = true
			c.WatchdogInterval = time.Hour
			c.Dict = dict.New(dict.Base, dict.NASREQ)
			c.Dict.SetStrict(false)
			c.AcctApplicationID = []*diam.AVP{diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001))}
			// Inject a dictionary/type mismatch to reach the parser's failure
			// path; ordinary invalid numeric payloads take B16 or A10 instead.
			if err := c.Dict.Load(strings.NewReader(`<diameter><application id="0"><avp name="Result-Code" code="268" must="M"><data type="Address"/></avp></application></diameter>`)); err != nil {
				t.Fatal(err)
			}
		}, func(*testing.T) *diam.Message {
			m := diam.NewMessage(diam.DeviceWatchdog, 0, 0, 17, 18, dict.Default)
			m.AddAVP(diam.NewAVP(avp.ResultCode, avp.Mbit, 0, localhostAddress))
			return m
		}, diam.ProtocolInvalidDWA, 0, false, "sm: invalid DWA", slog.LevelWarn},
		{"A10_rejected_DWA", func(c *Settings) { c.EnableWatchdog = true; c.WatchdogInterval = time.Hour }, func(*testing.T) *diam.Message {
			m := diam.NewMessage(diam.DeviceWatchdog, 0, 0, 17, 18, dict.Default)
			m.AddAVP(diam.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(5012)))
			return m
		}, diam.ProtocolRejectedDWA, 5012, false, "sm: rejected DWA", slog.LevelWarn},
		{"A11_invalid_DPR", nil, func(*testing.T) *diam.Message {
			return diam.NewMessage(diam.DisconnectPeer, diam.RequestFlag, 0, 17, 18, dict.Default)
		}, diam.ProtocolInvalidDPR, 0, false, "sm: invalid DPR", slog.LevelWarn},
		{"A13_unmatched_DPA", nil, func(*testing.T) *diam.Message {
			return diam.NewMessage(diam.DisconnectPeer, 0, 0, 17, 18, dict.Default)
		}, diam.ProtocolUnexpectedMessage, 0, false, "", slog.LevelWarn},
		{"A14_admitted_CER", nil, func(t *testing.T) *diam.Message { return regressionCER(t, dict.Default, 1001) }, diam.ProtocolUnexpectedMessage, 0, false, "sm: ignoring CER on admitted connection; accepted CER renewal is disabled or ineligible", slog.LevelWarn},
		{"A16_unhandled_answer", nil, func(*testing.T) *diam.Message { return diam.NewMessage(0xfedc, 0, 0, 17, 18, dict.Default) }, diam.ProtocolUnexpectedMessage, 0, false, "sm: unhandled answer discarded", slog.LevelWarn},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newProtocolWire(t, tc.configure, true)
			m := tc.message(t)
			h := p.send(t, m)
			if tc.answer {
				a, err := diam.ReadMessage(p.peer, dict.Default)
				if err != nil || !testResultCode(a, tc.code) || a.Header.HopByHopID != h.HopByHopID || a.Header.EndToEndID != h.EndToEndID || a.Header.CommandFlags&diam.ErrorFlag != map[bool]uint8{true: diam.ErrorFlag, false: 0}[tc.code >= 3000 && tc.code < 4000] {
					t.Fatalf("answer=%v err=%v", a, err)
				}
			}
			e := protocolEvent(t, p.events)
			reply := diam.ProtocolReplyNone
			replyCode := uint32(0)
			if tc.answer {
				reply = diam.ProtocolReplyWritten
				replyCode = tc.code
			}
			assertProtocolEvent(t, e, p.conn, &h, tc.kind, tc.code, false, reply, replyCode)
			p.usable(t)
			records := p.logs.Records()
			want := 0
			if tc.log != "" {
				want = 1
			}
			if len(records) != want || want > 0 && (records[0].Message != tc.log || records[0].Level != tc.level) {
				t.Fatalf("logs=%v", records)
			}
			select {
			case extra := <-p.events:
				t.Fatalf("duplicate notification %+v", extra)
			default:
			}
		})
	}
}

func TestProtocolErrorMalformedWire(t *testing.T) {
	for _, answer := range []bool{false, true} {
		t.Run(fmt.Sprintf("A1_A2_answer=%t", answer), func(t *testing.T) {
			p := newProtocolWire(t, nil, true)
			flags := uint8(diam.RequestFlag)
			if answer {
				flags = 0
			}
			wire := testSMErrorMessage(t, flags, []byte{0, 0, 1, 2, avp.Mbit, 0xff, 0xff, 0xff})
			binary.BigEndian.PutUint32(wire[12:16], 0x12345678)
			writeSMErrorWire(t, p.peer, wire)
			h, _ := diam.DecodeHeader(wire)
			if !answer {
				a, err := diam.ReadMessage(p.peer, dict.Default)
				if err != nil || !testResultCode(a, 5014) {
					t.Fatalf("error answer=%v %v", a, err)
				}
			}
			e := protocolEvent(t, p.events)
			reply := diam.ProtocolReplyNone
			code := uint32(0)
			if !answer {
				reply = diam.ProtocolReplyWritten
				code = 5014
			}
			assertProtocolEvent(t, e, p.conn, h, diam.ProtocolMalformedMessage, 5014, false, reply, code)
			p.usable(t)
			if logs := p.logs.Records(); len(logs) != 1 || logs[0].Message != "diam: malformed message" {
				t.Fatalf("logs=%v", logs)
			}
		})
	}
}

func newProtocolWire(t *testing.T, configure func(*Settings), admit bool) *protocolWire {
	t.Helper()
	p := &protocolWire{events: make(chan diam.ProtocolErrorEvent, 32), logs: logtest.New()}
	cfg := testMessageErrorSettings()
	cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) { p.events <- e }
	if configure != nil {
		configure(cfg)
	}
	p.sm = mustNewStateMachine(t, cfg)
	opened := make(chan diam.Conn, 1)
	dictionary := cfg.Dict
	if dictionary == nil {
		dictionary = dict.Default
	}
	srv := diamtest.NewUnstartedServer(p.sm, dictionary)
	srv.Config.Logger = p.logs.Logger()
	srv.Config.OnNewConnection = func(c diam.Conn) { opened <- c }
	srv.Start()
	t.Cleanup(srv.Close)
	var err error
	p.peer, err = net.DialTimeout("tcp", srv.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.peer.Close() })
	if err := p.peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case p.conn = <-opened:
	case <-time.After(3 * time.Second):
		t.Fatal("accepted Conn missing")
	}
	if admit {
		writeValidSMErrorCER(t, p.peer)
		if m, err := diam.ReadMessage(p.peer, dict.Default); err != nil || !testResultCode(m, diam.Success) {
			t.Fatalf("handshake: %v %v", m, err)
		}
	}
	return p
}

func protocolEvent(t *testing.T, events <-chan diam.ProtocolErrorEvent) diam.ProtocolErrorEvent {
	t.Helper()
	select {
	case e := <-events:
		return e
	case <-time.After(3 * time.Second):
		t.Fatal("protocol notification missing")
		return diam.ProtocolErrorEvent{}
	}
}

func (p *protocolWire) send(t *testing.T, m *diam.Message) diam.Header {
	t.Helper()
	wire, err := m.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	writeSMErrorWire(t, p.peer, wire)
	h, err := diam.DecodeHeader(wire)
	if err != nil {
		t.Fatal(err)
	}
	return *h
}

func assertProtocolEvent(t *testing.T, e diam.ProtocolErrorEvent, c diam.Conn, header *diam.Header, kind diam.ProtocolErrorKind, code uint32, closing bool, reply diam.ProtocolReplyStatus, replyCode uint32) {
	t.Helper()
	var typed *diam.ProtocolError
	if e.Conn != c || !errors.As(e.Err, &typed) || !errors.Is(e.Err, kind) || typed.Kind() != kind || typed.ResultCode() != code || e.Closing != closing || e.Reply != reply || e.ReplyCode != replyCode {
		t.Fatalf("notification=%+v error=%v, want Conn=%p kind=%s code=%d closing=%t reply=%d/%d", e, e.Err, c, kind, code, closing, reply, replyCode)
	}
	if e.Message.HasHeader != (header != nil) || header != nil && e.Message.Header != *header || e.Message.Stream != 0 {
		t.Fatalf("metadata=%+v, want header=%+v stream=0", e.Message, header)
	}
}

func (p *protocolWire) usable(t *testing.T) {
	t.Helper()
	m := regressionDWR(t)
	m.Header.HopByHopID = 0x99887766
	m.Header.EndToEndID = 0x88776655
	p.send(t, m)
	a, err := diam.ReadMessage(p.peer, dict.Default)
	if err != nil || a.Header.HopByHopID != 0x99887766 || a.Header.EndToEndID != 0x88776655 || !testResultCode(a, diam.Success) || p.conn.Closed() {
		t.Fatalf("following DWR: %v %v closed=%t", a, err, p.conn.Closed())
	}
}

func TestProtocolErrorA8InvalidDWR(t *testing.T) {
	p := newProtocolWire(t, nil, true)
	m := diam.NewMessage(diam.DeviceWatchdog, diam.RequestFlag, 0, 0x1234, 0x5678, dict.Default)
	m.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
	h := p.send(t, m)
	e := protocolEvent(t, p.events)
	assertProtocolEvent(t, e, p.conn, &h, diam.ProtocolInvalidDWR, 0, false, diam.ProtocolReplyNone, 0)
	p.usable(t)
	records := p.logs.Records()
	if len(records) != 1 || records[0].Level != slog.LevelWarn || records[0].Message != "sm: invalid DWR" {
		t.Fatalf("records=%v", records)
	}
	select {
	case extra := <-p.events:
		t.Fatalf("extra notification: %+v", extra)
	default:
	}
}
