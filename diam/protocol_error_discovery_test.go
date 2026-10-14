package diam

import (
	"bytes"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

const protocolDiscoveryPanic = "synthetic protocol discovery panic"

type protocolDiscoveryMessageHandler struct {
	Handler
	answered atomic.Int32
}

func (*protocolDiscoveryMessageHandler) HandleAccept(Conn) func()                  { return nil }
func (*protocolDiscoveryMessageHandler) HandleRetire(Conn, RetirementReason) error { return nil }

func (h *protocolDiscoveryMessageHandler) HandleMessageError(c Conn, m *Message, err *MessageError) error {
	answer := m.Answer(err.ResultCode)
	if err.FailedAVP != nil {
		answer.AddAVP(NewAVP(avp.FailedAVP, avp.Mbit, 0, &GroupedAVP{AVP: []*AVP{err.FailedAVP}}))
	}
	h.answered.Add(1)
	_, writeErr := answer.WriteTo(c)
	return writeErr
}

type protocolEnabledPanic struct {
	*protocolDiscoveryMessageHandler
	observer ProtocolErrorObserver
	panics   atomic.Bool
}

func (h *protocolEnabledPanic) ProtocolErrorEnabled() bool {
	if h.panics.Swap(false) {
		panic(protocolDiscoveryPanic)
	}
	return true
}

func (h *protocolEnabledPanic) HandleProtocolError(event ProtocolErrorEvent) {
	h.observer.HandleProtocolError(event)
}

type protocolUnwrapPanic struct {
	*protocolDiscoveryMessageHandler
	next   Handler
	panics atomic.Bool
}

func (h *protocolUnwrapPanic) Unwrap() Handler {
	if h.panics.Swap(false) {
		panic(protocolDiscoveryPanic)
	}
	return h.next
}

func protocolPanickingDiscovery(kind string, events chan ProtocolErrorEvent) (Handler, *protocolDiscoveryMessageHandler) {
	owner := &protocolDiscoveryMessageHandler{Handler: NewServeMux()}
	observer := &protocolObserverWrapper{Handler: owner.Handler, onEvent: func(event ProtocolErrorEvent) { events <- event }}
	if kind == "enabled" {
		h := &protocolEnabledPanic{protocolDiscoveryMessageHandler: owner, observer: observer}
		h.panics.Store(true)
		return h, owner
	}
	owner.Handler = observer
	h := &protocolUnwrapPanic{protocolDiscoveryMessageHandler: owner, next: observer}
	h.panics.Store(true)
	return h, owner
}

func protocolDiscoveryPanicRecord(t *testing.T, records *logtest.Recorder, preceding int) {
	t.Helper()
	logs := records.Records()
	if len(logs) != preceding+1 {
		t.Fatalf("logs=%v, want %d original records and one panic diagnostic", logs, preceding)
	}
	panicRecord := logs[preceding]
	if panicRecord.Level != slog.LevelError || panicRecord.Message != "diam: protocol error callback panicked" || logtest.Attr(panicRecord, "panic").Any() != protocolDiscoveryPanic {
		t.Fatalf("panic record=%v", panicRecord)
	}
	stack := logtest.Attr(panicRecord, "stack").String()
	if len(stack) == 0 || len(stack) > 64<<10 || !bytes.Contains([]byte(stack), []byte("protocolObserverFor")) {
		t.Fatalf("missing or unbounded discovery stack: %q", stack)
	}
}

func TestProtocolErrorDiscoveryPanicPreservesNonfatalHandling(t *testing.T) {
	testDict := newTestDictionary(dict.Base())

	for _, kind := range []string{"enabled", "unwrap"} {
		t.Run(kind, func(t *testing.T) {
			events := make(chan ProtocolErrorEvent, 2)
			handler, owner := protocolPanickingDiscovery(kind, events)
			dictionary := newTestDictionary(dict.Base())
			dictionary.SetStrict(true)
			records := logtest.New()
			accepted := make(chan Conn, 1)
			addr := reportingTCPServer(t, &Server{Handler: handler, Dict: dictionary, Logger: records.Logger(), OnNewConnection: func(c Conn) { accepted <- c }})
			remote := reportingDial(t, addr)
			original := <-accepted
			wire := testFramedMessage(t, RequestFlag, rawAVP(avp.InbandSecurityID, []byte{1, 2}))
			if _, err := remote.Write(wire); err != nil {
				t.Fatal(err)
			}
			answer, err := ReadMessage(remote, testDict)
			if err != nil {
				t.Fatalf("observer discovery changed nonfatal handling: error answer missing: %v", err)
			}
			header, err := DecodeHeader(wire)
			if err != nil {
				t.Fatal(err)
			}
			result, err := answer.FindAVP(avp.ResultCode, 0)
			if err != nil || result.Data != datatype.Unsigned32(InvalidAVPLength) || answer.Header.CommandFlags != 0 || answer.Header.HopByHopID != header.HopByHopID || answer.Header.EndToEndID != header.EndToEndID {
				t.Fatalf("error answer changed: %v, %v", answer, err)
			}
			failed, err := answer.FindAVP(avp.FailedAVP, 0)
			if err != nil || len(failed.Data.(*GroupedAVP).AVP) != 1 || failed.Data.(*GroupedAVP).AVP[0].Code != avp.InbandSecurityID {
				t.Fatalf("Failed-AVP changed: %v, %v", failed, err)
			}
			if original.Closed() || owner.answered.Load() != 1 || len(events) != 0 {
				t.Fatalf("closed=%t answered=%d events=%d", original.Closed(), owner.answered.Load(), len(events))
			}
			protocolDiscoveryPanicRecord(t, records, 1)
			if logs := records.Records(); logs[0].Level != slog.LevelWarn || logs[0].Message != "diam: malformed message" {
				t.Fatalf("original log changed: %v", logs)
			}
			// Later traffic must retain this connection and retry discovery.
			valid := testFramedMessage(t, RequestFlag, nil)
			if _, err := remote.Write(valid); err != nil {
				t.Fatal(err)
			}
			event := receiveProtocolEvent(t, events)
			assertProtocolWireEvent(t, event, original, valid, ProtocolUnexpectedMessage, 0)
			if event.Closing || event.Reply != ProtocolReplyNone || original.Closed() || len(events) != 0 {
				t.Fatalf("later traffic changed: %+v", event)
			}
			if logs := records.Records(); len(logs) != 3 || logs[2].Message != "diam: unhandled message" {
				t.Fatalf("later logs=%v", logs)
			}
		})
	}
}

func TestProtocolErrorServeMuxDiscoveryPanic(t *testing.T) {
	for _, kind := range []string{"enabled", "unwrap"} {
		t.Run(kind, func(t *testing.T) {
			events := make(chan ProtocolErrorEvent, 2)
			handler, _ := protocolPanickingDiscovery(kind, events)
			records := logtest.New()
			accepted := make(chan Conn, 1)
			addr := reportingTCPServer(t, &Server{Handler: HandlerFunc(func(Conn, *Message) {}), Logger: records.Logger(), OnNewConnection: func(c Conn) { accepted <- c }})
			remote := reportingDial(t, addr)
			defer func() { _ = remote.Close() }()
			original := <-accepted
			mux := NewServeMux()
			mux.HandleIdx(CommandIndex{Code: DeviceWatchdog}, handler)
			mux.Handle("ALL", &protocolObserverHandler{onEvent: func(ProtocolErrorEvent) { t.Error("panic fell through to ALL") }})
			event := ProtocolErrorEvent{Conn: original, Err: NewProtocolError(ProtocolMalformedMessage, InvalidAVPLength), Message: ProtocolMessageMetadata{HasHeader: true, Header: Header{Version: 1, CommandCode: DeviceWatchdog}}}
			func() {
				defer func() {
					if value := recover(); value != nil {
						t.Errorf("observer discovery panic escaped ServeMux: %v", value)
					}
				}()
				mux.HandleProtocolError(event)
			}()
			if original.Closed() || len(events) != 0 {
				t.Fatalf("closed=%t, events=%d", original.Closed(), len(events))
			}
			protocolDiscoveryPanicRecord(t, records, 0)
			mux.HandleProtocolError(event)
			if got := receiveProtocolEvent(t, events); got.Conn != original || got.Err != event.Err || got.Message != event.Message {
				t.Fatalf("later observation changed: %+v", got)
			}
		})
	}
}
