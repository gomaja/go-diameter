package peer

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/dict/nasreq"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
)

// A nested Result-Code must not replace the validator's failing top-level code.
func TestProtocolErrorManagerDWAResultCodeOnWire(t *testing.T) {
	for _, tc := range []struct {
		name      string
		strict    bool
		duplicate bool
	}{
		{"strict nested success", true, false},
		{"non-strict nested success", false, false},
		{"earlier top-level success", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dictionary := newTestDictionary(dict.Base(), nasreq.Dictionary())
			dictionary.SetStrict(tc.strict)
			events := make(chan diam.ProtocolErrorEvent, 4)
			records := logtest.New()
			clock := &fakeClock{}
			settings := testSettings("local.example.net")
			settings.Dict = dictionary
			settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
			m, err := New(Config{Settings: settings, Clock: clock, Logger: records.Logger()})
			if err != nil {
				t.Fatal(err)
			}
			if err := m.AddPeer(PeerConfig{Host: "known.example.net"}); err != nil {
				t.Fatal(err)
			}
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := &diam.Server{Dict: dictionary}
			server.Dict = m.cfg.Settings.Dict
			if err := m.BindServer(server); err != nil {
				t.Fatal(err)
			}
			go func() { _ = server.Serve(l) }()
			t.Cleanup(func() { closeManager(t, m, server) })
			remote, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = remote.Close() })
			capabilities := m.baseSettings(nil)
			capabilities.OriginHost = "known.example.net"
			cer, err := base.BuildCER(dictionary, capabilities)
			if err != nil {
				t.Fatal(err)
			}
			write(t, remote, cer)
			if answer := read(t, remote); code(t, answer) != 2001 {
				t.Fatalf("handshake failed: %v", answer)
			}
			awaitState(t, m, ROpen)
			originalConn := round2SessionConn(t, m, remote)
			clock.fire()
			request := read(t, remote)
			if request.Header.CommandCode != diam.DeviceWatchdog || request.Header.CommandFlags&diam.RequestFlag == 0 {
				t.Fatalf("not DWR: %+v", request.Header)
			}
			answer, err := base.BuildDWA(request, testBase("known.example.net"))
			if err != nil {
				t.Fatal(err)
			}
			for _, field := range answer.AVP {
				if field.Code == avp.ResultCode && field.VendorID == 0 {
					field.Data = datatype.Unsigned32(5012)
				}
			}
			if tc.duplicate {
				answer.AVP = append([]*diam.AVP{diam.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(2001))}, answer.AVP...)
			} else {
				round2PrependNestedResult(answer, 2001)
			}
			answer.Header.MessageLength = uint32(answer.Len())
			write(t, remote, answer)
			e := protocolErrorReceive(t, events)
			protocolErrorCheck(t, e, originalConn, *answer.Header, diam.ProtocolRejectedDWA, 5012, false, diam.ProtocolReplyNone, 0, 0)
			logged := round2CheckOnlyProtocolLog(t, records)
			if logged.Error() != "peer: DWA Result-Code is not success" || !errors.Is(logged, errDWAResultCode) {
				t.Fatalf("DWA diagnostic changed: %v", logged)
			}
			// A rejected DWA neither answers an answer nor closes the connection.
			next := reviewDWR(t)
			write(t, remote, next)
			response := read(t, remote)
			if code(t, response) != 2001 || response.Header.HopByHopID != next.Header.HopByHopID || response.Header.EndToEndID != next.Header.EndToEndID {
				t.Fatalf("unexpected answer: %+v", response)
			}
			round2NoExtraProtocolEvent(t, events)
		})
	}
}

// CEA failure notifications must report the parser's decision, including a
// malformed Address preserved by a non-strict decoder (RFC 6733 §§5.3.2, 7.1.5).
func TestProtocolErrorManagerCEAParserCodeOnWire(t *testing.T) {
	for _, tc := range []struct {
		name   string
		strict bool
		result uint32
		mutate func(*diam.Message)
	}{
		{"strict nested success", true, 5012, func(m *diam.Message) { round2PrependNestedResult(m, 2001) }},
		{"non-strict nested success", false, 5012, func(m *diam.Message) { round2PrependNestedResult(m, 2001) }},
		{"non-strict malformed Address", false, 5004, func(m *diam.Message) {
			for _, a := range m.AVP {
				if a.Code == avp.ResultCode {
					a.Data = datatype.Unsigned32(2001)
				}
				if a.Code == avp.HostIPAddress {
					a.Data = datatype.Unknown{0xff, 0xff, 0x01}
				}
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = l.Close() })
			if err := l.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			dictionary := newTestDictionary(dict.Base(), nasreq.Dictionary())
			dictionary.SetStrict(tc.strict)
			records := logtest.New()
			events := make(chan diam.ProtocolErrorEvent, 4)
			settings := testSettings("local.example.net")
			settings.Dict = dictionary
			settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
			m, err := New(Config{Settings: settings, Logger: records.Logger()})
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
			remote, err := l.Accept()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = remote.Close() })
			request := read(t, remote)
			if request.Header.CommandCode != diam.CapabilitiesExchange || request.Header.CommandFlags&diam.RequestFlag == 0 {
				t.Fatalf("not CER: %+v", request.Header)
			}
			originalConn := round2SessionConn(t, m, remote)
			answer, err := base.BuildCEA(request, testBase("known.example.net"), 5012)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(answer)
			answer.Header.MessageLength = uint32(answer.Len())
			write(t, remote, answer)
			e := protocolErrorReceive(t, events)
			protocolErrorCheck(t, e, originalConn, *answer.Header, diam.ProtocolCEARejected, tc.result, true, diam.ProtocolReplyNone, 0, 0)
			logged := round2CheckOnlyProtocolLog(t, records)
			if tc.result == 5004 {
				var parseErr *diam.MessageError
				if !errors.As(logged, &parseErr) || parseErr.ResultCode != 5004 || parseErr.FailedAVP == nil || parseErr.FailedAVP.Code != avp.HostIPAddress {
					t.Fatalf("parser error changed: %v", logged)
				}
			} else {
				var parseErr *smparser.ErrFailedResultCode
				if !errors.As(logged, &parseErr) || parseErr.ResultCode != 5012 {
					t.Fatalf("parser error changed: %v", logged)
				}
			}
			if err := remote.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			var b [1]byte
			if n, err := remote.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("want EOF without an answer, got bytes=%d err=%v", n, err)
			}
			awaitState(t, m, Closed)
			round2NoExtraProtocolEvent(t, events)
		})
	}
}

func round2PrependNestedResult(m *diam.Message, result uint32) {
	failed := diam.NewAVP(avp.FailedAVP, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{diam.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(result))}})
	m.AVP = append([]*diam.AVP{failed}, m.AVP...)
}

func round2SessionConn(t *testing.T, m *Manager, remote net.Conn) diam.Conn {
	t.Helper()
	m.mu.RLock()
	defer m.mu.RUnlock()
	for conn := range m.sessions {
		if conn.RemoteAddr().String() == remote.LocalAddr().String() && conn.LocalAddr().String() == remote.RemoteAddr().String() {
			return conn
		}
	}
	t.Fatal("original managed connection missing")
	return nil
}

func round2CheckOnlyProtocolLog(t *testing.T, records *logtest.Recorder) error {
	t.Helper()
	got := records.Records()
	if len(got) != 1 || got[0].Level != slog.LevelWarn || got[0].Message != "peer: protocol error" {
		t.Fatalf("protocol logs changed: %v", got)
	}
	err, ok := logtest.Attr(got[0], "error").Any().(error)
	if !ok {
		t.Fatalf("protocol error missing from log: %v", got[0])
	}
	return err
}

func round2NoExtraProtocolEvent(t *testing.T, events <-chan diam.ProtocolErrorEvent) {
	t.Helper()
	select {
	case extra := <-events:
		t.Fatalf("duplicate protocol event: %+v", extra)
	default:
	}
}
