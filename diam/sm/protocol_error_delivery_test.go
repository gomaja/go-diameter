package sm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"
	"github.com/gomaja/go-diameter/diam/dict/nasreq"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

func newProtocolDeliveryWire(t *testing.T, mode int, admit bool, configure func(*Settings), serverOptions ...func(*diam.Server)) *protocolWire {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	t.Helper()
	p := &protocolWire{events: make(chan diam.ProtocolErrorEvent, 16), logs: logtest.New()}
	cfg := testMessageErrorSettings(testDict)
	cfg.OnProtocolError = func(event diam.ProtocolErrorEvent) { p.events <- event }
	if configure != nil {
		configure(cfg)
	}
	p.sm = mustNewStateMachine(t, cfg, testDict)
	dictionary := cfg.Dict
	if dictionary == nil {
		dictionary = testDict
	}
	server := diamtest.NewUnstartedServer(p.sm, dictionary)
	server.Config.MaxConcurrentHandlers = mode
	server.Config.Logger = p.logs.Logger()
	opened := make(chan diam.Conn, 1)
	server.Config.OnNewConnection = func(c diam.Conn) { opened <- c }
	for _, option := range serverOptions {
		option(server.Config)
	}
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
	p.conn = protocolGenerationAwait(t, opened)
	if admit {
		writeValidSMErrorCER(t, p.peer)
		answer, err := diam.ReadMessage(p.peer, testDict)
		if err != nil || !testResultCode(answer, diam.Success) {
			t.Fatalf("handshake = %v, %v", answer, err)
		}
	}
	return p
}

func TestProtocolErrorCallbackPanicBoundaries(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	for _, variant := range []string{"handler", "concurrent_handler", "reader", "timer"} {
		t.Run(variant, func(t *testing.T) {
			events := make(chan diam.ProtocolErrorEvent, 4)
			mode := 0
			if variant == "concurrent_handler" {
				mode = -1
			}
			p := newProtocolDeliveryWire(t, mode, variant != "timer", func(cfg *Settings) {
				if variant == "timer" {
					cfg.HandshakeTimeout = 50 * time.Millisecond
				}
				cfg.OnProtocolError = func(event diam.ProtocolErrorEvent) { events <- event; panic("protocol-panic-value") }
			})
			count := 2
			if variant == "timer" {
				count = 1
			}
			for i := 0; i < count; i++ {
				var header *diam.Header
				var kind diam.ProtocolErrorKind
				var code uint32
				reply, replyCode := diam.ProtocolReplyNone, uint32(0)
				if variant == "reader" {
					wire := (&diam.Header{Version: 1, MessageLength: 28, CommandFlags: diam.RequestFlag, CommandCode: diam.DeviceWatchdog, HopByHopID: uint32(0x86d0 + i), EndToEndID: uint32(0x86e0 + i)}).Serialize()
					wire = append(wire, 0, 0, 1, 2, avp.Mbit, 0xff, 0xff, 0xff)
					writeSMErrorWire(t, p.peer, wire)
					header, _ = diam.DecodeHeader(wire)
					answer, err := diam.ReadMessage(p.peer, testDict)
					if err != nil || !testResultCode(answer, diam.InvalidAVPLength) || answer.Header.HopByHopID != header.HopByHopID {
						t.Fatalf("malformed request answer = %v, %v", answer, err)
					}
					kind, code, reply, replyCode = diam.ProtocolMalformedMessage, diam.InvalidAVPLength, diam.ProtocolReplyWritten, diam.InvalidAVPLength
				} else if variant != "timer" {
					h := p.send(t, protocolGenerationInvalidDWR(t, uint32(0x86d0+i)))
					header = &h
					protocolGenerationErrorAnswer(t, p.peer, h)
					kind, code, reply, replyCode = diam.ProtocolInvalidRequest, diam.MissingAVP, diam.ProtocolReplyWritten, diam.MissingAVP
				} else {
					kind = diam.ProtocolHandshakeTimeout
				}
				event := protocolGenerationAwait(t, events)
				assertProtocolEvent(t, event, p.conn, header, kind, code, variant == "timer", reply, replyCode)
				if variant != "timer" {
					p.usable(t)
				} else {
					regressionClosed(t, p.peer)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if _, err := p.logs.Wait(ctx, 2*count); err != nil {
				t.Fatal(err)
			}
			records := p.logs.RecordsWithMessage("diam: protocol error callback panicked")
			if len(records) != count {
				t.Fatalf("panic records = %v", records)
			}
			for _, record := range records {
				stack := logtest.Attr(record, "stack").String()
				if record.Level != slog.LevelError || logtest.Attr(record, "panic").String() != "protocol-panic-value" || len(stack) == 0 || len(stack) > 64<<10 || !strings.Contains(stack, "TestProtocolErrorCallbackPanicBoundaries") {
					t.Fatalf("panic record = %v", record)
				}
			}
			if records := p.logs.Records(); len(records) != 2*count {
				t.Fatalf("unexpected log records = %v", records)
			}
		})
	}
}

func TestProtocolErrorBlockingCallbackFollowsAnswerAndLogs(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	entered := make(chan diam.ProtocolErrorEvent, 1)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	p := newProtocolDeliveryWire(t, 0, true, func(cfg *Settings) {
		cfg.OnProtocolError = func(event diam.ProtocolErrorEvent) { entered <- event; <-release }
	})
	t.Cleanup(unblock)
	request := diam.NewMessage(0xfedc, diam.RequestFlag, 0, 0x86b0, 0x86b1, testDict)
	header := p.send(t, request)
	answer, err := diam.ReadMessage(p.peer, testDict)
	if err != nil || !testResultCode(answer, diam.CommandUnsupported) || answer.Header.HopByHopID != header.HopByHopID {
		t.Fatalf("unsupported command answer = %v, %v", answer, err)
	}
	event := protocolGenerationAwait(t, entered)
	assertProtocolEvent(t, event, p.conn, &header, diam.ProtocolUnsupportedCommand, diam.CommandUnsupported, false, diam.ProtocolReplyWritten, diam.CommandUnsupported)
	if records := p.logs.Records(); len(records) != 1 || records[0].Message != "sm: unsupported command answered" || records[0].Level != slog.LevelInfo {
		t.Fatalf("records before callback returns = %v", records)
	}
	following := regressionDWR(t)
	setWireIdentity(t, following, avp.OriginHost, "peer.example")
	requestHeader := p.send(t, following)
	if err := p.peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	n, err := p.peer.Read(one[:])
	var timeout net.Error
	if n != 0 || !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("blocked sequential callback did not hold worker: read=%d, %v", n, err)
	}
	if p.conn.Closed() {
		t.Fatal("blocking callback closed connection")
	}
	unblock()
	if err := p.peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	answer, err = diam.ReadMessage(p.peer, testDict)
	if err != nil || !testResultCode(answer, diam.Success) || answer.Header.HopByHopID != requestHeader.HopByHopID {
		t.Fatalf("following DWA after callback return = %v, %v", answer, err)
	}
}

func TestProtocolErrorCallbacksOverlapOnSameConnection(t *testing.T) {
	for _, mode := range []int{2, -1} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			entered := make(chan diam.ProtocolErrorEvent, 2)
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			p := newProtocolDeliveryWire(t, mode, true, func(cfg *Settings) {
				cfg.OnProtocolError = func(event diam.ProtocolErrorEvent) { entered <- event; <-release }
			})
			t.Cleanup(unblock)
			firstHeader := p.send(t, protocolGenerationInvalidDWR(t, 0x86c0))
			secondHeader := p.send(t, protocolGenerationInvalidDWR(t, 0x86c2))
			seen := make(map[uint32]bool)
			for i := 0; i < 2; i++ {
				event := protocolGenerationAwait(t, entered)
				header := firstHeader
				if event.Message.Header.HopByHopID == secondHeader.HopByHopID {
					header = secondHeader
				}
				assertProtocolEvent(t, event, p.conn, &header, diam.ProtocolInvalidRequest, diam.MissingAVP, false, diam.ProtocolReplyWritten, diam.MissingAVP)
				if seen[header.HopByHopID] {
					t.Fatalf("duplicate callback for %x", header.HopByHopID)
				}
				seen[header.HopByHopID] = true
			}
			for range 2 {
				answer, err := diam.ReadMessage(p.peer, p.conn.Dictionary())
				if err != nil || !testResultCode(answer, diam.MissingAVP) || !seen[answer.Header.HopByHopID] {
					t.Fatalf("overlapping callback answer = %v, %v", answer, err)
				}
			}
			if mode == -1 {
				p.usable(t)
			}
			unblock()
			p.usable(t)
			if records := p.logs.Records(); len(records) != 2 || records[0].Message != "sm: invalid request" || records[1].Message != "sm: invalid request" {
				t.Fatalf("concurrent logs = %v", records)
			}
		})
	}
}

func TestProtocolErrorWatchdogCallbackCanStopSupervision(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	for _, invalid := range []bool{false, true} {
		t.Run(fmt.Sprintf("invalid=%t", invalid), func(t *testing.T) {
			events := make(chan diam.ProtocolErrorEvent, 1)
			watchdog := make(chan WatchdogEvent, 4)
			var machine atomic.Pointer[StateMachine]
			p := newProtocolDeliveryWire(t, 0, true, func(cfg *Settings) {
				cfg.EnableWatchdog, cfg.WatchdogInterval = true, time.Hour
				cfg.Dict = newTestDictionary(dict.Base(), nasreq.Dictionary())
				cfg.Dict.SetStrict(false)
				cfg.AuthApplicationID = []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001))}
				if invalid {
					// A dictionary/type mismatch must fail the unconditional base type check.
					if err := cfg.Dict.Load(strings.NewReader(`<diameter><application id="0"><avp name="Result-Code" code="268"><data type="Address"/></avp></application></diameter>`)); err != nil {
						t.Fatal(err)
					}
				}
				cfg.OnWatchdogConnEvent = func(_ diam.Conn, event WatchdogEvent) { watchdog <- event }
				cfg.OnProtocolError = func(event diam.ProtocolErrorEvent) {
					// stopWatchdog acquires the same publication mutex as DWA handling.
					machine.Load().stopWatchdog(event.Conn)
					events <- event
				}
			})
			machine.Store(p.sm)
			m := diam.NewMessage(diam.DeviceWatchdog, 0, 0, 0x86a0, 0x86a1, testDict)
			var payload datatype.Type = datatype.Unsigned32(diam.UnableToComply)
			kind, code, logMessage := diam.ProtocolRejectedDWA, uint32(diam.UnableToComply), "sm: rejected DWA"
			if invalid {
				payload = localhostAddress
				kind, code, logMessage = diam.ProtocolInvalidDWA, diam.InvalidAVPLength, "sm: invalid DWA"
			}
			m.AddAVP(diam.NewAVP(avp.ResultCode, avp.Mbit, 0, payload))
			m.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
			m.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
			header := p.send(t, m)
			event := protocolGenerationAwait(t, events)
			assertProtocolEvent(t, event, p.conn, &header, kind, code, false, diam.ProtocolReplyNone, 0)
			if observed := protocolGenerationAwait(t, watchdog); observed != WatchdogInvalidAnswer {
				t.Fatalf("watchdog event = %s", observed)
			}
			p.usable(t)
			if records := p.logs.Records(); len(records) != 1 || records[0].Message != logMessage || records[0].Level != slog.LevelWarn {
				t.Fatalf("DWA logs = %v", records)
			}
		})
	}
}

func TestProtocolErrorCallbackMayCloseConnectionAfterAnswer(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	events := make(chan diam.ProtocolErrorEvent, 1)
	p := newProtocolDeliveryWire(t, 0, true, func(cfg *Settings) {
		cfg.OnProtocolError = func(event diam.ProtocolErrorEvent) { event.Conn.Close(); events <- event }
	})
	header := p.send(t, diam.NewMessage(0xfedc, diam.RequestFlag, 0, 0x86f0, 0x86f1, testDict))
	answer, err := diam.ReadMessage(p.peer, testDict)
	if err != nil || !testResultCode(answer, diam.CommandUnsupported) || answer.Header.HopByHopID != header.HopByHopID {
		t.Fatalf("answer before callback close = %v, %v", answer, err)
	}
	event := protocolGenerationAwait(t, events)
	assertProtocolEvent(t, event, p.conn, &header, diam.ProtocolUnsupportedCommand, diam.CommandUnsupported, false, diam.ProtocolReplyWritten, diam.CommandUnsupported)
	regressionClosed(t, p.peer)
	if !p.conn.Closed() {
		t.Fatal("callback Close did not close connection")
	}
}

func TestProtocolErrorNilCallbackDoesNoWork(t *testing.T) {
	machine := mustNewStateMachine(t, testMessageErrorSettings())
	allocations := testing.AllocsPerRun(100, func() {
		machine.protocolError(nil, nil, diam.ProtocolMalformedMessage, diam.InvalidAVPLength, true, diam.ProtocolReplyFailed, diam.InvalidAVPLength)
	})
	if allocations != 0 {
		t.Fatalf("nil callback allocated %g objects per report", allocations)
	}
}

type protocolRenamedLogHandler struct{ slog.Handler }

func (h protocolRenamedLogHandler) Handle(ctx context.Context, record slog.Record) error {
	copy := slog.NewRecord(record.Time, record.Level, "renamed protocol diagnostic", record.PC)
	record.Attrs(func(attribute slog.Attr) bool { copy.AddAttrs(attribute); return true })
	return h.Handler.Handle(ctx, copy)
}

func (h protocolRenamedLogHandler) WithAttrs(attributes []slog.Attr) slog.Handler {
	return protocolRenamedLogHandler{h.Handler.WithAttrs(attributes)}
}

func (h protocolRenamedLogHandler) WithGroup(group string) slog.Handler {
	return protocolRenamedLogHandler{h.Handler.WithGroup(group)}
}

func TestProtocolErrorClassificationIndependentOfLogging(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("disabled=%t", disabled), func(t *testing.T) {
			p := newProtocolDeliveryWire(t, 0, true, nil, func(server *diam.Server) {
				if disabled {
					server.Logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.Level(128)}))
				} else {
					server.Logger = slog.New(protocolRenamedLogHandler{server.Logger.Handler()})
				}
			})
			header := p.send(t, protocolGenerationInvalidDWR(t, 0x86aa))
			event := protocolGenerationAwait(t, p.events)
			assertProtocolEvent(t, event, p.conn, &header, diam.ProtocolInvalidRequest, diam.MissingAVP, false, diam.ProtocolReplyWritten, diam.MissingAVP)
			protocolGenerationErrorAnswer(t, p.peer, header)
			p.usable(t)
			records := p.logs.Records()
			if disabled {
				if len(records) != 0 || p.conn.Logger().Enabled(context.Background(), slog.LevelError) {
					t.Fatalf("disabled logger produced %v", records)
				}
			} else if len(records) != 1 || records[0].Message != "renamed protocol diagnostic" || records[0].Level != slog.LevelWarn {
				t.Fatalf("renamed diagnostic = %v", records)
			}
		})
	}
}
