package sm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

var errProtocolLocalWrite = errors.New("injected TCP write failure")

type protocolLocalFaults struct {
	write, address atomic.Bool
	attempts       chan []byte
}

type protocolLocalConn struct {
	net.Conn
	faults *protocolLocalFaults
}

func (c *protocolLocalConn) Write(b []byte) (int, error) {
	if c.faults.write.Load() {
		c.faults.attempts <- append([]byte(nil), b...)
		return 0, errProtocolLocalWrite
	}
	return c.Conn.Write(b)
}

func (c *protocolLocalConn) LocalAddr() net.Addr {
	if c.faults.address.Load() {
		return protocolLocalBadAddr{}
	}
	return c.Conn.LocalAddr()
}

type protocolLocalBadAddr struct{}

func (protocolLocalBadAddr) Network() string { return "tcp" }
func (protocolLocalBadAddr) String() string  { return "invalid-local-address" }

type protocolLocalListener struct {
	net.Listener
	faults *protocolLocalFaults
}

func (l *protocolLocalListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &protocolLocalConn{Conn: c, faults: l.faults}, nil
}

type protocolLocalWire struct {
	*protocolWire
	faults *protocolLocalFaults
	marker chan diam.Header
}

func newProtocolLocalWire(t *testing.T, configure func(*Settings, *protocolLocalFaults), admit bool) *protocolLocalWire {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	t.Helper()
	p := &protocolLocalWire{
		protocolWire: &protocolWire{events: make(chan diam.ProtocolErrorEvent, 16), logs: logtest.New()},
		faults:       &protocolLocalFaults{attempts: make(chan []byte, 8)},
		marker:       make(chan diam.Header, 1),
	}
	cfg := testMessageErrorSettings(testDict)
	cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) { p.events <- e }
	if configure != nil {
		configure(cfg, p.faults)
	}
	p.sm = mustNewStateMachine(t, cfg, testDict)
	p.sm.HandleIdx(diam.CommandIndex{AppID: 0, Code: 0xeefe, Request: false}, diam.HandlerFunc(func(_ diam.Conn, message *diam.Message) {
		p.marker <- *message.Header
	}))
	server := diamtest.NewUnstartedServer(p.sm, testDict)
	server.Listener = &protocolLocalListener{Listener: server.Listener, faults: p.faults}
	server.Config.Logger = p.logs.Logger()
	accepted := make(chan diam.Conn, 1)
	server.Config.OnNewConnection = func(c diam.Conn) { accepted <- c }
	server.Start()
	t.Cleanup(server.Close)
	var err error
	p.peer, err = net.DialTimeout("tcp", server.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.peer.Close() })
	if err := p.peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case p.conn = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("accepted connection missing")
	}
	if admit {
		p.handshake(t)
	}
	return p
}

func (p *protocolLocalWire) reading(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	t.Helper()
	// A failed buffered TCP write stays failed, even when the transport's
	// injected fault is removed. Prove retained reader/dispatch state with a
	// registered answer that needs no reply, rather than attempting recovery.
	message := diam.NewMessage(0xeefe, 0, 0, 0x86aa, 0x86bb, testDict)
	header := p.send(t, message)
	select {
	case observed := <-p.marker:
		if observed != header || p.conn.Closed() {
			t.Fatalf("retained dispatch=%+v closed=%t", observed, p.conn.Closed())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("local write failure stopped inbound dispatch")
	}
	if err := p.peer.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	_, err := p.peer.Read(b[:])
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("failed answer wrote bytes or closed connection: %v", err)
	}
	if err := p.peer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
}

func (p *protocolLocalWire) handshake(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	t.Helper()
	p.send(t, regressionCER(t, testDict, 1001))
	answer, err := diam.ReadMessage(p.peer, testDict)
	if err != nil || !testResultCode(answer, diam.Success) {
		t.Fatalf("handshake: %v %v", answer, err)
	}
}

func (p *protocolLocalWire) eof(t *testing.T) {
	t.Helper()
	var b [1]byte
	if n, err := p.peer.Read(b[:]); n != 0 || err != io.EOF {
		t.Fatalf("failed answer transmitted bytes or kept connection: n=%d err=%v", n, err)
	}
	select {
	case <-mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, p.conn).DispatchDone():
	case <-time.After(3 * time.Second):
		t.Fatal("connection dispatch did not finish")
	}
	if !p.conn.Closed() {
		t.Fatal("connection not closed")
	}
}

func protocolLocalLogs(t *testing.T, records *logtest.Recorder, messages ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	logs, err := records.Wait(ctx, len(messages))
	if err != nil || len(logs) != len(messages) {
		t.Fatalf("logs=%v err=%v, want %v", logs, err, messages)
	}
	for i, message := range messages {
		level := slog.LevelError
		if message == "diam: malformed message" || message == "sm: unsupported mandatory AVP" || message == "sm: invalid request" || message == "sm: rejected CER; closing connection" {
			level = slog.LevelWarn
		}
		if logs[i].Message != message || logs[i].Level != level {
			t.Fatalf("record[%d]=%v, want %s %s", i, logs[i], level, message)
		}
	}
}

func protocolLocalNoEvents(t *testing.T, events <-chan diam.ProtocolErrorEvent) {
	t.Helper()
	select {
	case event := <-events:
		t.Fatalf("local failure produced protocol notification: %+v", event)
	default:
	}
}

func (p *protocolLocalWire) attemptedAnswer(t *testing.T, header diam.Header, code uint32, failedAVP bool) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	t.Helper()
	var wire []byte
	select {
	case wire = <-p.faults.attempts:
	default:
		t.Fatal("answer did not reach failing TCP Write")
	}
	answer, err := diam.ReadMessage(bytes.NewReader(wire), testDict)
	if err != nil || !testResultCode(answer, code) || answer.Header.CommandCode != header.CommandCode || answer.Header.HopByHopID != header.HopByHopID || answer.Header.EndToEndID != header.EndToEndID {
		t.Fatalf("attempted answer=%v err=%v, want code %d and original identifiers", answer, err, code)
	}
	wantError := uint8(0)
	if code >= 3000 && code < 4000 {
		wantError = diam.ErrorFlag
	}
	if answer.Header.CommandFlags&diam.RequestFlag != 0 || answer.Header.CommandFlags&diam.ErrorFlag != wantError {
		t.Fatalf("attempted answer flags=%x", answer.Header.CommandFlags)
	}
	containers := 0
	for _, field := range answer.AVP {
		if field.Code == avp.FailedAVP && field.VendorID == 0 {
			containers++
		}
	}
	if containers != 0 && !failedAVP || containers != 1 && failedAVP {
		t.Fatalf("Failed-AVP containers=%d, wanted=%t", containers, failedAVP)
	}
	logs := p.logs.Records()
	for i := len(logs) - 1; i >= 0; i-- {
		if logs[i].Level != slog.LevelError {
			continue
		}
		if err, ok := logtest.Attr(logs[i], "error").Any().(error); !ok || !errors.Is(err, errProtocolLocalWrite) {
			t.Fatalf("local write error identity lost: %v", logs)
		}
		return
	}
	t.Fatalf("local write error log missing: %v", logs)
}

func TestProtocolErrorLocalErrorAnswerWriteFailure(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	for _, condition := range []string{"malformed", "unsupported_command", "unknown_mandatory", "request_validation"} {
		t.Run(condition, func(t *testing.T) {
			p := newProtocolLocalWire(t, func(cfg *Settings, _ *protocolLocalFaults) {
				cfg.RejectUnknownMandatoryAVPs = condition == "unknown_mandatory"
				cfg.ValidateRequests = condition == "request_validation"
			}, true)
			m := regressionDWR(t)
			kind, code, closing := diam.ProtocolMalformedMessage, uint32(5014), true
			logs := []string{"diam: malformed message", "sm: error answer failed"}
			switch condition {
			case "malformed":
				m.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown([]byte{1, 2})))
			case "unsupported_command":
				m = diam.NewMessage(0xfedc, diam.RequestFlag, 0, 0x8601, 0x8602, testDict)
				kind, code = diam.ProtocolUnsupportedCommand, 3001
				logs = []string{"sm: error answer failed"}
			case "unknown_mandatory":
				m.AddAVP(diam.NewAVP(0xfedcab, avp.Mbit, 0, datatype.Unknown([]byte{1, 2, 3, 4})))
				kind, code, closing = diam.ProtocolUnsupportedAVP, 5001, false
				logs = []string{"sm: unsupported mandatory AVP", "sm: error answer failed"}
			case "request_validation":
				m.AVP = m.AVP[:1]
				kind, code, closing = diam.ProtocolInvalidRequest, 5005, false
				logs = []string{"sm: invalid request", "sm: error answer failed"}
			}
			p.faults.write.Store(true)
			header := p.send(t, m)
			event := protocolEvent(t, p.events)
			assertProtocolEvent(t, event, p.conn, &header, kind, code, closing, diam.ProtocolReplyFailed, code)
			protocolLocalLogs(t, p.logs, logs...)
			if attempts := len(p.faults.attempts); attempts != 1 {
				t.Fatalf("failed answer write attempts=%d, want one", attempts)
			}
			p.attemptedAnswer(t, header, code, condition != "unsupported_command")
			if closing {
				p.eof(t)
			} else {
				if p.conn.Closed() {
					t.Fatal("answer failure changed retained-connection policy")
				}
				p.faults.write.Store(false)
				p.reading(t)
			}
			protocolLocalNoEvents(t, p.events)
		})
	}
}

func TestProtocolErrorLocalCERBuildAndWriteFailure(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	for _, rejected := range []bool{false, true} {
		for _, failure := range []string{"build", "write"} {
			t.Run(fmt.Sprintf("rejected=%t/%s", rejected, failure), func(t *testing.T) {
				var cerCalls, ceaCalls, handshakeCalls atomic.Int32
				p := newProtocolLocalWire(t, func(cfg *Settings, _ *protocolLocalFaults) {
					cfg.OnCER = func(diam.Conn, *diam.Message) { cerCalls.Add(1) }
					cfg.OnCEA = func(diam.Conn, *diam.Message) { ceaCalls.Add(1) }
					cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) { handshakeCalls.Add(1) }
				}, false)
				p.faults.write.Store(failure == "write")
				p.faults.address.Store(failure == "build")
				app := uint32(1001)
				if rejected {
					app = 999999
				}
				header := p.send(t, regressionCER(t, testDict, app))
				if rejected {
					event := protocolEvent(t, p.events)
					assertProtocolEvent(t, event, p.conn, &header, diam.ProtocolCERRejected, 5010, true, diam.ProtocolReplyFailed, 5010)
				}
				p.eof(t)
				logs := []string{"sm: CEA failed; closing connection"}
				if rejected {
					logs = append([]string{"sm: rejected CER; closing connection"}, logs...)
				}
				protocolLocalLogs(t, p.logs, logs...)
				wantCEA := int32(0)
				if failure == "write" {
					wantCEA = 1
				}
				if cerCalls.Load() != 1 || ceaCalls.Load() != wantCEA || handshakeCalls.Load() != 0 {
					t.Fatalf("hooks CER=%d CEA=%d handshake=%d", cerCalls.Load(), ceaCalls.Load(), handshakeCalls.Load())
				}
				if len(p.faults.attempts) != int(wantCEA) {
					t.Fatalf("write attempts=%d, want %d", len(p.faults.attempts), wantCEA)
				}
				if failure == "write" {
					code := uint32(diam.Success)
					if rejected {
						code = diam.NoCommonApplication
					}
					p.attemptedAnswer(t, header, code, false)
				}
				protocolLocalNoEvents(t, p.events)
			})
		}
	}
}

func TestProtocolErrorLocalInitialCERErrorAnswerFailure(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	for _, failure := range []string{"build", "write"} {
		for _, condition := range []string{"malformed", "unknown_mandatory", "request_validation"} {
			t.Run(failure+"/"+condition, func(t *testing.T) {
				p := newProtocolLocalWire(t, func(cfg *Settings, _ *protocolLocalFaults) {
					cfg.RejectUnknownMandatoryAVPs = condition == "unknown_mandatory"
					cfg.ValidateRequests = condition == "request_validation"
				}, false)
				m := regressionCER(t, testDict, 1001)
				kind, code := diam.ProtocolMalformedMessage, uint32(5014)
				logs := []string{"diam: malformed message", "sm: error answer failed"}
				switch condition {
				case "malformed":
					m.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown([]byte{1, 2})))
				case "unknown_mandatory":
					m.AddAVP(diam.NewAVP(0xfedcab, avp.Mbit, 0, datatype.Unknown([]byte{1, 2, 3, 4})))
					kind, code = diam.ProtocolUnsupportedAVP, 5001
					logs = []string{"sm: unsupported mandatory AVP", "sm: error answer failed", "sm: rejected CER; closing connection"}
				case "request_validation":
					for i, field := range m.AVP {
						if field.Code == avp.OriginRealm {
							m.AVP = append(m.AVP[:i], m.AVP[i+1:]...)
							break
						}
					}
					kind, code = diam.ProtocolInvalidRequest, 5005
					logs = []string{"sm: invalid request", "sm: error answer failed", "sm: rejected CER; closing connection"}
				}
				p.faults.address.Store(failure == "build")
				p.faults.write.Store(failure == "write")
				header := p.send(t, m)
				event := protocolEvent(t, p.events)
				assertProtocolEvent(t, event, p.conn, &header, kind, code, true, diam.ProtocolReplyFailed, code)
				protocolLocalLogs(t, p.logs, logs...)
				if failure == "build" {
					if len(p.faults.attempts) != 0 {
						t.Fatal("build failure reached transport Write")
					}
				} else {
					if len(p.faults.attempts) != 1 {
						t.Fatalf("write attempts=%d, want one", len(p.faults.attempts))
					}
					p.attemptedAnswer(t, header, code, true)
				}
				p.eof(t)
				protocolLocalNoEvents(t, p.events)
			})
		}
	}
}

func TestProtocolErrorLocalValidDWRDPRWriteFailure(t *testing.T) {
	for _, command := range []string{"DWR", "DPR"} {
		t.Run(command, func(t *testing.T) {
			var dwrCalls, dwaCalls, dprCalls atomic.Int32
			p := newProtocolLocalWire(t, func(cfg *Settings, _ *protocolLocalFaults) {
				cfg.OnDWR = func(diam.Conn, *diam.Message) { dwrCalls.Add(1) }
				cfg.OnDWA = func(diam.Conn, *diam.Message) { dwaCalls.Add(1) }
				cfg.OnDPR = func(diam.Conn, DisconnectCause) { dprCalls.Add(1) }
			}, true)
			p.faults.write.Store(true)
			m, log := regressionDWR(t), "sm: DWA failed"
			if command == "DPR" {
				m, log = acceptedDPR(t), "sm: DPA failed; closing connection"
			}
			header := p.send(t, m)
			protocolLocalLogs(t, p.logs, log)
			if len(p.faults.attempts) != 1 {
				t.Fatalf("write attempts=%d", len(p.faults.attempts))
			}
			p.attemptedAnswer(t, header, diam.Success, false)
			if command == "DPR" {
				p.eof(t)
				if dwrCalls.Load() != 0 || dwaCalls.Load() != 0 || dprCalls.Load() != 0 {
					t.Fatal("failed DPA reached hooks")
				}
			} else {
				if p.conn.Closed() || dwrCalls.Load() != 1 || dwaCalls.Load() != 1 || dprCalls.Load() != 0 {
					t.Fatal("failed DWA changed state or hook behavior")
				}
				p.faults.write.Store(false)
				p.reading(t)
			}
			protocolLocalNoEvents(t, p.events)
		})
	}
}

func TestProtocolErrorLocalWatchdogWriteFailure(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	watchdogEvents := make(chan acceptedWatchdogEvent, 4)
	p := newProtocolLocalWire(t, func(cfg *Settings, faults *protocolLocalFaults) {
		cfg.EnableWatchdog = true
		cfg.WatchdogInterval = 10 * time.Millisecond
		cfg.watchdogTiming = &watchdogTiming{floor: time.Millisecond}
		cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) { faults.write.Store(true) }
		cfg.OnWatchdogConnEvent = func(c diam.Conn, e WatchdogEvent) { watchdogEvents <- acceptedWatchdogEvent{conn: c, event: e} }
	}, true)
	p.eof(t)
	protocolLocalLogs(t, p.logs, "sm: watchdog request failed; closing connection")
	if len(p.faults.attempts) != 1 {
		t.Fatalf("watchdog write attempts=%d", len(p.faults.attempts))
	}
	request, err := diam.ReadMessage(bytes.NewReader(<-p.faults.attempts), testDict)
	if err != nil || request.Header.CommandCode != diam.DeviceWatchdog || request.Header.CommandFlags&diam.RequestFlag == 0 {
		t.Fatalf("failed watchdog write=%v %v", request, err)
	}
	select {
	case event := <-watchdogEvents:
		if event.conn != p.conn || event.event != WatchdogWriteFailed {
			t.Fatalf("watchdog event=%+v", event)
		}
	default:
		t.Fatal("existing watchdog write-failure event missing")
	}
	protocolLocalNoEvents(t, p.events)
}

func TestProtocolErrorLocalOnHandshakePanic(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())
	serverSettings := cloneTestSettings(serverSettings,
		testDict)
	clientSettings := cloneTestSettings(clientSettings,
		testDict)

	records := logtest.New()
	events := make(chan diam.ProtocolErrorEvent, 4)
	entered := make(chan diam.Conn, 1)
	server := diamtest.NewServer(mustNewStateMachine(t, serverSettings, testDict), testDict)
	t.Cleanup(server.Close)
	cfg := *clientSettings
	cfg.OnProtocolError = func(event diam.ProtocolErrorEvent) { events <- event }
	cfg.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { entered <- c; panic("injected handshake callback panic") }
	client := newLivenessClient(t)
	client.EnableWatchdog = false
	client.Handler = mustNewStateMachine(t, &cfg, testDict)
	client.Logger = records.Logger()
	client.RetransmitInterval = time.Second
	c, err := client.Dial(server.Addr)
	if c != nil {
		c.Close()
		t.Fatal("failed handshake returned a connection")
	}
	if err == nil || !strings.Contains(err.Error(), "OnHandshake terminated") {
		t.Fatalf("Dial error=%v", err)
	}
	var actual diam.Conn
	select {
	case actual = <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("OnHandshake not entered")
	}
	select {
	case <-mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, actual).DispatchDone():
	case <-time.After(3 * time.Second):
		t.Fatal("panic dispatch did not finish")
	}
	protocolLocalLogs(t, records, "sm: OnHandshake terminated; closing connection", "diam: panic serving connection")
	if !actual.Closed() {
		t.Fatal("handshake panic did not close connection")
	}
	protocolLocalNoEvents(t, events)
}
