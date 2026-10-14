package diam

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

type protocolObserverHandler struct {
	onEvent func(ProtocolErrorEvent)
	served  atomic.Int32
}

func (h *protocolObserverHandler) ServeDIAM(Conn, *Message)                 { h.served.Add(1) }
func (h *protocolObserverHandler) HandleProtocolError(e ProtocolErrorEvent) { h.onEvent(e) }

type protocolErrorHandler struct {
	*protocolObserverHandler
	onError func(Conn, *Message, *MessageError) error
}

type protocolObserverWrapper struct {
	Handler
	onEvent func(ProtocolErrorEvent)
}

func (h *protocolObserverWrapper) Unwrap() Handler                              { return h.Handler }
func (h *protocolObserverWrapper) HandleProtocolError(event ProtocolErrorEvent) { h.onEvent(event) }

func (h *protocolErrorHandler) HandleMessageError(c Conn, m *Message, e *MessageError) error {
	return h.onError(c, m, e)
}

func receiveProtocolEvent(t *testing.T, events <-chan ProtocolErrorEvent) ProtocolErrorEvent {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(5 * time.Second):
		t.Fatal("protocol notification missing")
		return ProtocolErrorEvent{}
	}
}

func TestProtocolErrorB14B15ServerFallbackWire(t *testing.T) {
	for _, flags := range []uint8{RequestFlag, 0} {
		for _, failure := range []string{"absent", "declined", "failed"} {
			for _, wiring := range []string{"direct", "unwrap", "route", "ALL"} {
				t.Run(fmt.Sprintf("flags=%d/%s/%s", flags, failure, wiring), func(t *testing.T) {
					events := make(chan ProtocolErrorEvent, 2)
					records := logtest.New()
					observer := &protocolObserverHandler{onEvent: func(e ProtocolErrorEvent) { events <- e }}
					var handler Handler = observer
					if failure != "absent" {
						handler = &protocolErrorHandler{observer, func(Conn, *Message, *MessageError) error {
							if failure == "declined" {
								return errors.ErrUnsupported
							}
							return errors.New("synthetic handler failure")
						}}
					}
					switch wiring {
					case "unwrap":
						handler = unwrapHandler{unwrapHandler{handler}}
					case "route", "ALL":
						mux := NewServeMux()
						if wiring == "route" {
							mux.HandleIdx(CommandIndex{AppID: 0, Code: CapabilitiesExchange, Request: flags != 0}, unwrapHandler{handler})
						} else {
							mux.HandleIdx(CommandIndex{AppID: 0, Code: CapabilitiesExchange, Request: flags != 0}, HandlerFunc(func(Conn, *Message) {}))
							mux.Handle("ALL", unwrapHandler{handler})
						}
						handler = unwrapHandler{mux}
					}
					accepted := make(chan Conn, 1)
					addr := reportingTCPServer(t, &Server{Handler: handler, Logger: records.Logger(), OnNewConnection: func(c Conn) { accepted <- c }})
					remote := reportingDial(t, addr)
					original := <-accepted
					wire := testFramedMessage(t, flags, []byte{0, 0, 1, 2, avp.Mbit, 255, 255, 255})
					if _, err := remote.Write(wire); err != nil {
						t.Fatal(err)
					}
					event := receiveProtocolEvent(t, events)
					assertProtocolWireEvent(t, event, original, wire, ProtocolMalformedMessage, InvalidAVPLength)
					wantReply := ProtocolReplyNone
					if failure == "failed" {
						wantReply = ProtocolReplyUnknown
					}
					if !event.Closing || event.Reply != wantReply || event.ReplyCode != 0 {
						t.Fatalf("event=%+v", event)
					}
					var b [1]byte
					if _, err := remote.Read(b[:]); err != io.EOF {
						t.Fatalf("read=%v, want EOF without answer", err)
					}
					<-mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, original).DispatchDone()
					if len(events) != 0 || observer.served.Load() != 0 {
						t.Fatal("duplicate event or ordinary dispatch")
					}
					logs := records.Records()
					wantLevel, wantMessage := slog.LevelWarn, "diam: malformed message; closing connection"
					if failure == "failed" {
						wantLevel, wantMessage = slog.LevelError, "diam: malformed message handler failed; closing connection"
					}
					if len(logs) != 2 || logs[0].Message != "diam: malformed message" || logs[0].Level != slog.LevelWarn || logs[1].Message != wantMessage || logs[1].Level != wantLevel {
						t.Fatalf("logs=%v", logs)
					}
				})
			}
		}
	}
}

func assertProtocolWireEvent(t *testing.T, event ProtocolErrorEvent, c Conn, wire []byte, kind ProtocolErrorKind, code uint32) {
	t.Helper()
	var header Header
	_ = header.DecodeFromBytes(wire)
	if event.Conn != c || !event.Message.HasHeader || event.Message.Header != header || event.Message.Stream != 0 {
		t.Fatalf("identity/metadata=%+v, want conn=%p header=%+v", event, c, header)
	}
	var protocolErr *ProtocolError
	if !errors.As(event.Err, &protocolErr) || !errors.Is(fmt.Errorf("wrapped: %w", event.Err), kind) || protocolErr.ResultCode() != code {
		t.Fatalf("classification=%v", event.Err)
	}
}

func TestProtocolErrorB16StrictAnswerDecodeWire(t *testing.T) {
	events := make(chan ProtocolErrorEvent, 2)
	records := logtest.New()
	handler := &protocolObserverHandler{onEvent: func(e ProtocolErrorEvent) { events <- e }}
	accepted := make(chan Conn, 1)
	dictionary := newTestDictionary(dict.Base())
	dictionary.SetStrict(true)
	addr := reportingTCPServer(t, &Server{Handler: handler, Dict: dictionary, Logger: records.Logger(), OnNewConnection: func(c Conn) { accepted <- c }})
	remote := reportingDial(t, addr)
	original := <-accepted
	wire := testFramedMessage(t, 0, rawAVP(avp.InbandSecurityID, []byte{1, 2}))
	if _, err := remote.Write(wire); err != nil {
		t.Fatal(err)
	}
	event := receiveProtocolEvent(t, events)
	assertProtocolWireEvent(t, event, original, wire, ProtocolMalformedMessage, InvalidAVPLength)
	if !event.Closing || event.Reply != ProtocolReplyNone {
		t.Fatalf("event=%+v", event)
	}
	var b [1]byte
	if _, err := remote.Read(b[:]); err != io.EOF {
		t.Fatalf("read=%v", err)
	}
	<-mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, original).DispatchDone()
	logs := records.Records()
	if len(logs) != 1 || logs[0].Message != "diam: read failed; closing connection" || logs[0].Level != slog.LevelWarn {
		t.Fatalf("logs=%v", logs)
	}
	if len(events) != 0 || handler.served.Load() != 0 {
		t.Fatal("duplicate event or ordinary dispatch")
	}
}

func TestProtocolErrorServerLeavesHandledNotificationToOwner(t *testing.T) {
	testDict := newTestDictionary(creditcontrol.Dictionary())

	for _, fatal := range []bool{false, true} {
		t.Run(fmt.Sprintf("fatal=%t", fatal), func(t *testing.T) {
			events := make(chan ProtocolErrorEvent, 3)
			observed := &protocolObserverHandler{onEvent: func(e ProtocolErrorEvent) { events <- e }}
			handler := &protocolErrorHandler{observed, func(c Conn, m *Message, e *MessageError) error {
				observed.HandleProtocolError(ProtocolErrorEvent{Conn: c, Message: protocolMessageMetadata(m), Err: NewProtocolError(ProtocolMalformedMessage, e.ResultCode), Closing: e.Fatal})
				return nil
			}}
			accepted := make(chan Conn, 1)
			records := logtest.New()
			addr := reportingTCPServer(t, &Server{Handler: handler, Logger: records.Logger(), OnNewConnection: func(c Conn) { accepted <- c }})
			remote := reportingDial(t, addr)
			original := <-accepted
			wire := testFramedMessage(t, RequestFlag, []byte{0, 0, 1, 2, avp.Mbit, 255, 255, 255})
			if fatal {
				wire = testMessageHeader(2, HeaderLength, RequestFlag)
			}
			if _, err := remote.Write(wire); err != nil {
				t.Fatal(err)
			}
			_ = receiveProtocolEvent(t, events)
			if !fatal {
				if _, err := NewRequest(DeviceWatchdog, 0, testDict).WriteTo(remote); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				for observed.served.Load() == 0 && ctx.Err() == nil {
					time.Sleep(time.Millisecond)
				}
				if observed.served.Load() != 1 {
					t.Fatal("handled nonfatal error stopped dispatch")
				}
				if err := remote.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				var b [1]byte
				if _, err := remote.Read(b[:]); err != io.EOF {
					t.Fatalf("read=%v", err)
				}
			}
			<-mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, original).DispatchDone()
			if len(events) != 0 {
				t.Fatal("Server duplicated owner notification")
			}
		})
	}
}

func TestServeMuxProtocolObserverRoutesSnapshot(t *testing.T) {
	testDict := newTestDictionary(dict.Base())

	for _, route := range []string{"index", "name", "fallback", "unknown header", "unknown command"} {
		t.Run(route, func(t *testing.T) {
			local, remote := net.Pipe()
			defer func() { _ = local.Close(); _ = remote.Close() }()
			c := (&Server{}).newConn(local).writer
			mux := NewServeMux()
			calls := 0
			handler := &protocolObserverHandler{onEvent: func(e ProtocolErrorEvent) {
				calls++
				if e.Conn != c {
					t.Error("connection identity lost")
				}
				mux.Handle("late", HandlerFunc(func(Conn, *Message) {}))
			}}
			m := NewRequest(CapabilitiesExchange, 0, testDict)
			e := ProtocolErrorEvent{Conn: c, Message: protocolMessageMetadata(m), Err: NewProtocolError(ProtocolMalformedMessage, 5004)}
			switch route {
			case "index":
				mux.HandleIdx(CommandIndex{AppID: 0, Code: CapabilitiesExchange, Request: true}, unwrapHandler{handler})
			case "name":
				mux.Handle("CER", unwrapHandler{handler})
			case "fallback":
				mux.Handle("CER", HandlerFunc(func(Conn, *Message) {}))
				mux.Handle("ALL", handler)
			case "unknown header":
				e.Message = ProtocolMessageMetadata{}
				mux.Handle("CER", &protocolObserverHandler{onEvent: func(ProtocolErrorEvent) { t.Error("unknown header reached CER") }})
				mux.Handle("ALL", handler)
			case "unknown command":
				e.Message.Header.CommandCode = 0x0badff
				mux.HandleIdx(CommandIndex{AppID: 0, Code: 0x0badff, Request: true}, handler)
			}
			mux.HandleProtocolError(e)
			if calls != 1 || handler.served.Load() != 0 {
				t.Fatalf("calls=%d ordinary dispatch=%d", calls, handler.served.Load())
			}
		})
	}
}

func TestProtocolErrorObserverPanicDoesNotEscapeServer(t *testing.T) {
	records := logtest.New()
	handler := &protocolObserverHandler{onEvent: func(ProtocolErrorEvent) { panic("synthetic protocol callback panic") }}
	accepted := make(chan Conn, 1)
	addr := reportingTCPServer(t, &Server{Handler: unwrapHandler{handler}, Logger: records.Logger(), OnNewConnection: func(c Conn) { accepted <- c }})
	remote := reportingDial(t, addr)
	original := <-accepted
	if _, err := remote.Write(testMessageHeader(2, HeaderLength, RequestFlag)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := remote.Read(b[:]); err != io.EOF {
		t.Fatalf("read=%v", err)
	}
	<-mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, original).DispatchDone()
	logs := records.Records()
	if len(logs) != 3 || logs[2].Message != "diam: protocol error callback panicked" || logs[2].Level != slog.LevelError {
		t.Fatalf("logs=%v", logs)
	}
	if logtest.Attr(logs[2], "panic").Any() != "synthetic protocol callback panic" || !bytes.Contains([]byte(logtest.Attr(logs[2], "stack").String()), []byte("HandleProtocolError")) {
		t.Fatal("panic diagnostic missing")
	}
}

func TestProtocolErrorA18BareMuxUnhandledWire(t *testing.T) {
	for _, flags := range []uint8{RequestFlag, 0} {
		t.Run(fmt.Sprintf("flags=%d", flags), func(t *testing.T) {
			events := make(chan ProtocolErrorEvent, 3)
			records := logtest.New()
			mux := NewServeMux()
			handler := &protocolObserverWrapper{Handler: mux, onEvent: func(e ProtocolErrorEvent) { events <- e }}
			accepted := make(chan Conn, 1)
			addr := reportingTCPServer(t, &Server{Handler: unwrapHandler{handler}, Logger: records.Logger(), OnNewConnection: func(c Conn) { accepted <- c }})
			remote := reportingDial(t, addr)
			original := <-accepted
			wire := testFramedMessage(t, flags, nil)
			for range 2 {
				if _, err := remote.Write(wire); err != nil {
					t.Fatal(err)
				}
				event := receiveProtocolEvent(t, events)
				assertProtocolWireEvent(t, event, original, wire, ProtocolUnexpectedMessage, 0)
				if event.Closing || event.Reply != ProtocolReplyNone || event.ReplyCode != 0 {
					t.Fatalf("event=%+v", event)
				}
			}
			if err := remote.Close(); err != nil {
				t.Fatal(err)
			}
			<-mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, original).DispatchDone()
			logs := records.Records()
			if len(logs) != 2 || len(events) != 0 {
				t.Fatalf("logs=%v duplicate events=%d", logs, len(events))
			}
			for _, record := range logs {
				if record.Level != slog.LevelWarn || record.Message != "diam: unhandled message" {
					t.Fatalf("record=%v", record)
				}
			}
		})
	}
}

func TestProtocolErrorServerCallbackBackpressure(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	observer := &protocolObserverHandler{onEvent: func(ProtocolErrorEvent) { close(entered); <-release }}
	records := logtest.New()
	addr := reportingTCPServer(t, &Server{Handler: observer, Logger: records.Logger()})
	remote := reportingDial(t, addr)
	if _, err := remote.Write(testMessageHeader(2, HeaderLength, RequestFlag)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("callback not entered")
	}
	if err := remote.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	_, err := remote.Read(b[:])
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("read while callback blocked=%v, want timeout", err)
	}
	if len(records.Records()) != 2 {
		t.Fatalf("handling/logging did not precede callback: %v", records.Records())
	}
	close(release)
	if err := remote.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := remote.Read(b[:]); err != io.EOF {
		t.Fatalf("read after callback returned=%v", err)
	}
}

func TestProtocolErrorA18ConcurrentDispatch(t *testing.T) {
	testDict := newTestDictionary(dict.Base())

	events := make(chan ProtocolErrorEvent, 2)
	release := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	handler := &protocolObserverWrapper{Handler: NewServeMux(), onEvent: func(event ProtocolErrorEvent) { events <- event; <-release }}
	accepted := make(chan Conn, 1)
	addr := reportingTCPServer(t, &Server{Handler: handler, Logger: logtest.New().Logger(), MaxConcurrentHandlers: -1, OnNewConnection: func(c Conn) { accepted <- c }})
	remote := reportingDial(t, addr)
	original := <-accepted
	first := NewRequest(DeviceWatchdog, 0, testDict)
	first.Header.HopByHopID = 11
	second := NewRequest(DeviceWatchdog, 0, testDict)
	second.Header.HopByHopID = 22
	if _, err := first.WriteTo(remote); err != nil {
		t.Fatal(err)
	}
	e1 := receiveProtocolEvent(t, events)
	if _, err := second.WriteTo(remote); err != nil {
		t.Fatal(err)
	}
	e2 := receiveProtocolEvent(t, events)
	if e1.Conn != original || e2.Conn != original || e1.Message.Header.HopByHopID != 11 || e2.Message.Header.HopByHopID != 22 {
		t.Fatalf("wrong concurrent events: %+v %+v", e1, e2)
	}
	e1.Message.Header.HopByHopID = 77
	if e2.Message.Header.HopByHopID != 22 {
		t.Fatal("retained metadata shares message storage")
	}
	close(release)
}

func TestProtocolErrorServerFirstObserverWins(t *testing.T) {
	events := make(chan ProtocolErrorEvent, 1)
	inner := &protocolObserverHandler{onEvent: func(ProtocolErrorEvent) { t.Error("inner observer bypassed outer interceptor") }}
	outer := &protocolObserverWrapper{Handler: unwrapHandler{inner}, onEvent: func(e ProtocolErrorEvent) { events <- e }}
	addr := reportingTCPServer(t, &Server{Handler: unwrapHandler{outer}, Logger: logtest.New().Logger()})
	remote := reportingDial(t, addr)
	if _, err := remote.Write(testMessageHeader(2, HeaderLength, RequestFlag)); err != nil {
		t.Fatal(err)
	}
	_ = receiveProtocolEvent(t, events)
	var b [1]byte
	if _, err := remote.Read(b[:]); err != io.EOF {
		t.Fatalf("read=%v", err)
	}
}

func TestProtocolErrorServerIgnoresTransportAndConfigurationErrors(t *testing.T) {
	testDict := newTestDictionary(dict.Base())

	for _, cause := range []error{io.EOF, io.ErrUnexpectedEOF, net.ErrClosed, bodyTimeout{}, errors.New("local dictionary has no AVPs")} {
		t.Run(cause.Error(), func(t *testing.T) {
			local, remote := net.Pipe()
			defer func() { _ = local.Close(); _ = remote.Close() }()
			events := 0
			h := &protocolObserverHandler{onEvent: func(ProtocolErrorEvent) { events++ }}
			c := (&Server{Handler: h, Logger: logtest.New().Logger()}).newConn(local)
			if c.handleReadError(NewRequest(DeviceWatchdog, 0, testDict), cause) || events != 0 {
				t.Fatalf("local error continued or notified: %v count=%d", cause, events)
			}
		})
	}
}

func TestProtocolErrorDecoderWrappingCloseStillNotifies(t *testing.T) {
	testDict := newTestDictionary(dict.Base())

	for _, cause := range []error{io.EOF, net.ErrClosed} {
		t.Run(cause.Error(), func(t *testing.T) {
			local, remote := net.Pipe()
			defer func() { _ = local.Close(); _ = remote.Close() }()
			events := make(chan ProtocolErrorEvent, 1)
			h := &protocolObserverHandler{onEvent: func(e ProtocolErrorEvent) { events <- e }}
			c := (&Server{Handler: h, Logger: logtest.New().Logger()}).newConn(local)
			cause := &avpDecodeError{resultCode: InvalidAVPValue, err: cause}
			if c.handleReadError(NewRequest(DeviceWatchdog, 0, testDict), cause) {
				t.Fatal("strict answer decode continued")
			}
			e := receiveProtocolEvent(t, events)
			if !e.Closing || !errors.Is(e.Err, ProtocolMalformedMessage) || e.Err.ResultCode() != InvalidAVPValue {
				t.Fatalf("event=%+v", e)
			}
		})
	}
}

func TestProtocolErrorFallbackSnapshotsBeforeHandlerMutation(t *testing.T) {
	testDict := newTestDictionary(dict.Base())

	local, remote := net.Pipe()
	defer func() { _ = local.Close(); _ = remote.Close() }()
	events := make(chan ProtocolErrorEvent, 1)
	observer := &protocolObserverHandler{onEvent: func(e ProtocolErrorEvent) { events <- e }}
	handler := &protocolErrorHandler{observer, func(_ Conn, m *Message, err *MessageError) error {
		m.Header.CommandCode = 0
		err.ResultCode = 0
		return errors.New("synthetic failure")
	}}
	c := (&Server{Handler: handler, Logger: logtest.New().Logger()}).newConn(local)
	m := NewRequest(DeviceWatchdog, 0, testDict)
	originalHeader := *m.Header
	if c.handleReadError(m, &MessageError{ResultCode: InvalidAVPValue, Err: errors.New("synthetic decode")}) {
		t.Fatal("failed handler continued")
	}
	event := receiveProtocolEvent(t, events)
	if event.Message.Header != originalHeader || event.Err.ResultCode() != InvalidAVPValue {
		t.Fatalf("mutable source leaked into snapshot: %+v", event)
	}
}
