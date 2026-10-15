package sm

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

type protocolClientDialResult struct {
	conn diam.Conn
	err  error
}

type protocolClientWire struct {
	client *Client
	peer   net.Conn
	conn   diam.Conn
	cer    *diam.Message
	events chan diam.ProtocolErrorEvent
	dialed chan protocolClientDialResult
	logs   *logtest.Recorder
}

func newProtocolClientWire(t *testing.T, configure func(*Client), serverOptions ...func(*diam.Server)) *protocolClientWire {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())
	clientSettings := cloneTestSettings(clientSettings, testDict)

	t.Helper()
	p := &protocolClientWire{events: make(chan diam.ProtocolErrorEvent, 16), dialed: make(chan protocolClientDialResult, 1), logs: logtest.New()}
	settings := *clientSettings
	settings.AuthApplicationID = []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4))}
	settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { p.events <- e }
	p.client = &Client{Handler: mustNewStateMachine(t, &settings, testDict), Logger: p.logs.Logger(), RetransmitInterval: time.Second, Dict: testDict}
	if configure != nil {
		configure(p.client)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	opened := make(chan diam.Conn, 1)
	go func() {
		c, err := p.client.dial(func(activity *watchdogActivity) (diam.Conn, error) {
			server := p.client.server("tcp", listener.Addr().String(), nil, activity)
			for _, option := range serverOptions {
				option(server)
			}
			server.OnNewConnection = func(c diam.Conn) { opened <- c }
			return server.Dial(time.Second)
		})
		p.dialed <- protocolClientDialResult{conn: c, err: err}
	}()
	p.peer, err = listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.peer.Close() })
	if err := p.peer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case p.conn = <-opened:
	case <-time.After(3 * time.Second):
		t.Fatal("client connection missing")
	}
	t.Cleanup(p.conn.Close)
	p.cer, err = diam.ReadMessage(p.peer, testDict)
	if err != nil || p.cer.Header.CommandCode != diam.CapabilitiesExchange || p.cer.Header.CommandFlags&diam.RequestFlag == 0 {
		t.Fatalf("CER=%v error=%v", p.cer, err)
	}
	return p
}

func protocolClientCEA(request *diam.Message, code uint32) *diam.Message {
	answer := request.Answer(code)
	answer.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
	answer.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	answer.AddAVP(diam.NewAVP(avp.HostIPAddress, avp.Mbit, 0, localhostAddress))
	answer.AddAVP(diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(13)))
	answer.AddAVP(diam.NewAVP(avp.ProductName, 0, 0, datatype.UTF8String("peer")))
	answer.AddAVP(diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)))
	return answer
}

func (p *protocolClientWire) send(t *testing.T, message *diam.Message) diam.Header {
	t.Helper()
	wire, err := message.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	writeSMErrorWire(t, p.peer, wire)
	header, err := diam.DecodeHeader(wire)
	if err != nil {
		t.Fatal(err)
	}
	return *header
}

func (p *protocolClientWire) dialResult(t *testing.T) protocolClientDialResult {
	t.Helper()
	select {
	case result := <-p.dialed:
		return result
	case <-time.After(3 * time.Second):
		t.Fatal("client Dial did not finish")
		return protocolClientDialResult{}
	}
}

func (p *protocolClientWire) closed(t *testing.T) {
	t.Helper()
	if err := p.peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if n, err := p.peer.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("unexpected bytes or open transport after rejection: n=%d error=%v", n, err)
	}
}

func (p *protocolClientWire) noExtraEvents(t *testing.T) {
	t.Helper()
	select {
	case extra := <-p.events:
		t.Fatalf("extra notification: %+v", extra)
	default:
	}
}

func TestProtocolErrorClientA15RepeatedCEAWire(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	p := newProtocolClientWire(t, nil)
	cea := protocolClientCEA(p.cer, 2001)
	p.send(t, cea)
	result := p.dialResult(t)
	if result.err != nil || result.conn != p.conn {
		t.Fatalf("Dial=%p %v", result.conn, result.err)
	}
	header := p.send(t, cea)
	assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, &header, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
	request := regressionDWR(t)
	setWireIdentity(t, request, avp.OriginHost, "peer.example")
	setWireIdentity(t, request, avp.OriginRealm, "example")
	dwrHeader := p.send(t, request)
	answer, err := diam.ReadMessage(p.peer, testDict)
	if err != nil || !testResultCode(answer, 2001) || answer.Header.CommandCode != diam.DeviceWatchdog || answer.Header.HopByHopID != dwrHeader.HopByHopID || p.conn.Closed() {
		t.Fatalf("connection changed after duplicate CEA: %v %v", answer, err)
	}
	p.noExtraEvents(t)
	if logs := p.logs.Records(); len(logs) != 0 {
		t.Fatalf("duplicate CEA logging changed: %v", logs)
	}
}

func TestProtocolErrorClientB2WaitCEARejectedWire(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		name := "non_CEA"
		if malformed {
			name = "malformed_non_CEA"
		}
		t.Run(name, func(t *testing.T) {
			p := newProtocolClientWire(t, nil)
			header := diam.Header{Version: 1, MessageLength: 28, CommandFlags: diam.RequestFlag, CommandCode: diam.DeviceWatchdog, HopByHopID: 0x12345678, EndToEndID: 0x87654321}
			code := uint32(0)
			if malformed {
				wire := append(header.Serialize(), 0, 0, 1, 2, avp.Mbit, 0xff, 0xff, 0xff)
				writeSMErrorWire(t, p.peer, wire)
				code = 5014
			} else {
				header = p.send(t, regressionDWR(t))
			}
			assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, &header, diam.ProtocolHandshakeState, code, true, diam.ProtocolReplyNone, 0)
			if result := p.dialResult(t); result.err == nil || result.conn != nil {
				t.Fatalf("unexpected successful Dial: %+v", result)
			}
			p.closed(t)
			p.noExtraEvents(t)
			logs := p.logs.Records()
			want := 1
			if malformed {
				want = 2
			}
			if len(logs) != want || logs[want-1].Level != slog.LevelWarn || logs[want-1].Message != "sm: Wait-I-CEA rejected message; closing connection" || malformed && (logs[0].Message != "diam: malformed message" || logs[0].Level != slog.LevelWarn) {
				t.Fatalf("logs=%v", logs)
			}
		})
	}
}

func TestProtocolErrorClientB7RejectedCEAWire(t *testing.T) {
	for _, tc := range []struct {
		name   string
		code   uint32
		mutate func(*diam.Message)
	}{
		{"missing_Origin_Host", 0, func(m *diam.Message) {
			for i, a := range m.AVP {
				if a.Code == avp.OriginHost {
					m.AVP = append(m.AVP[:i], m.AVP[i+1:]...)
					return
				}
			}
		}},
		{"failed_Result_Code", 5012, func(m *diam.Message) { a, _ := m.FindAVP(avp.ResultCode, 0); a.Data = datatype.Unsigned32(5012) }},
		{"no_common_application", 0, func(m *diam.Message) {
			a, _ := m.FindAVP(avp.AuthApplicationID, 0)
			a.Data = datatype.Unsigned32(0x00fffffe)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newProtocolClientWire(t, nil)
			cea := protocolClientCEA(p.cer, 2001)
			tc.mutate(cea)
			header := p.send(t, cea)
			assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, &header, diam.ProtocolCEARejected, tc.code, true, diam.ProtocolReplyNone, 0)
			if result := p.dialResult(t); result.err == nil || result.conn != nil {
				t.Fatalf("rejected CEA admitted: %+v", result)
			}
			p.closed(t)
			p.noExtraEvents(t)
			if logs := p.logs.Records(); len(logs) != 1 || logs[0].Message != "sm: CEA rejected; closing connection" || logs[0].Level != slog.LevelWarn {
				t.Fatalf("logs=%v", logs)
			}
		})
	}
}

func TestProtocolErrorClientB8CEABudgetTimeoutWire(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	p := newProtocolClientWire(t, func(c *Client) { c.RetransmitInterval = 20 * time.Millisecond; c.MaxRetransmits = 2 })
	for range 2 {
		cer, err := diam.ReadMessage(p.peer, testDict)
		if err != nil || cer.Header.CommandCode != diam.CapabilitiesExchange || cer.Header.HopByHopID != p.cer.Header.HopByHopID || cer.Header.EndToEndID != p.cer.Header.EndToEndID {
			t.Fatalf("CER retransmission=%v %v", cer, err)
		}
	}
	assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, nil, diam.ProtocolHandshakeTimeout, 0, true, diam.ProtocolReplyNone, 0)
	if result := p.dialResult(t); !errors.Is(result.err, ErrHandshakeTimeout) || result.conn != nil {
		t.Fatalf("timeout Dial=%+v", result)
	}
	p.closed(t)
	p.noExtraEvents(t)
	if logs := p.logs.Records(); len(logs) != 1 || logs[0].Message != "sm: CEA timeout; closing connection" || logs[0].Level != slog.LevelWarn {
		t.Fatalf("logs=%v", logs)
	}
}

func TestProtocolErrorClientB12WatchdogTimeoutWire(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	watchdogEvents := make(chan WatchdogEvent, 8)
	watchdogConns := make(chan diam.Conn, 8)
	p := newProtocolClientWire(t, func(c *Client) {
		c.EnableWatchdog = true
		c.WatchdogInterval = 20 * time.Millisecond
		c.watchdogTiming = &watchdogTiming{floor: time.Millisecond}
		c.OnWatchdogConnEvent = func(conn diam.Conn, event WatchdogEvent) { watchdogConns <- conn; watchdogEvents <- event }
	})
	p.send(t, protocolClientCEA(p.cer, 2001))
	if result := p.dialResult(t); result.err != nil || result.conn != p.conn {
		t.Fatalf("Dial=%+v", result)
	}
	dwr, err := diam.ReadMessage(p.peer, testDict)
	if err != nil || dwr.Header.CommandCode != diam.DeviceWatchdog || dwr.Header.CommandFlags&diam.RequestFlag == 0 {
		t.Fatalf("DWR=%v %v", dwr, err)
	}
	assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, nil, diam.ProtocolWatchdogTimeout, 0, true, diam.ProtocolReplyNone, 0)
	p.closed(t)
	p.noExtraEvents(t)
	for _, want := range []WatchdogEvent{WatchdogRequestSent, WatchdogSuspect, WatchdogTimedOut} {
		select {
		case got := <-watchdogEvents:
			if got != want || <-watchdogConns != p.conn {
				t.Fatalf("watchdog event=%v want %v", got, want)
			}
		case <-time.After(time.Second):
			t.Fatal("watchdog event missing")
		}
	}
	select {
	case extra := <-watchdogEvents:
		t.Fatalf("extra watchdog event=%v", extra)
	default:
	}
	if logs := p.logs.Records(); len(logs) != 1 || logs[0].Message != "sm: watchdog timeout; closing connection" || logs[0].Level != slog.LevelWarn {
		t.Fatalf("logs=%v", logs)
	}
}
