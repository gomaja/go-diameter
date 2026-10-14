package diam

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

type namedProtocolHandler struct {
	Handler
	name       string
	dispatched chan<- string
	malformed  chan<- string
	observers  chan<- string
	events     chan<- ProtocolErrorEvent
	afterServe func()
}

func (h *namedProtocolHandler) ServeDIAM(c Conn, m *Message) {
	h.dispatched <- h.name
	h.Handler.ServeDIAM(c, m)
	if h.afterServe != nil {
		h.afterServe()
	}
}

func (h *namedProtocolHandler) HandleMessageError(Conn, *Message, *MessageError) error {
	h.malformed <- h.name
	return errors.ErrUnsupported
}

func (h *namedProtocolHandler) HandleProtocolError(event ProtocolErrorEvent) {
	h.observers <- h.name
	h.events <- event
}

func receiveProtocolHandlerName(t *testing.T, names <-chan string) string {
	t.Helper()
	select {
	case name := <-names:
		return name
	case <-time.After(5 * time.Second):
		t.Fatal("handler callback missing")
		return ""
	}
}

func TestProtocolErrorCapturedHandler(t *testing.T) {
	for _, flags := range []uint8{RequestFlag, 0} {
		for _, malformed := range []bool{false, true} {
			for _, initiallyNil := range []bool{false, true} {
				t.Run(fmt.Sprintf("flags=%d/malformed=%t/initiallyNil=%t", flags, malformed, initiallyNil), func(t *testing.T) {
					dispatched := make(chan string, 3)
					messageErrors := make(chan string, 2)
					observers := make(chan string, 3)
					events := make(chan ProtocolErrorEvent, 3)
					accepted := make(chan Conn, 1)
					srv := &Server{Logger: logtest.New().Logger(), OnNewConnection: func(c Conn) { accepted <- c }}
					makeHandler := func(name string) *namedProtocolHandler {
						return &namedProtocolHandler{Handler: NewServeMux(), name: name, dispatched: dispatched, malformed: messageErrors, observers: observers, events: events}
					}
					a, b := makeHandler("A"), makeHandler("B")
					if !initiallyNil {
						srv.Handler = b
					}
					// Configuration changes before Serve must take effect, including
					// replacing an initially nil Handler without changing DefaultServeMux.
					srv.Handler = a
					// Sequential dispatch makes this assignment and the next dispatch
					// run on the same goroutine. It occurs after the first mux callback
					// has discarded its message and before ServeDIAM returns.
					a.afterServe = func() { srv.Handler = b }
					remote := reportingDial(t, reportingTCPServer(t, srv))
					original := <-accepted
					first := testFramedMessage(t, flags, nil)
					if _, err := remote.Write(first); err != nil {
						t.Fatal(err)
					}
					if got := receiveProtocolHandlerName(t, dispatched); got != "A" {
						t.Fatalf("before-Serve assignment: dispatched=%s, want A", got)
					}
					if got := receiveProtocolHandlerName(t, observers); got != "A" {
						t.Fatalf("before-Serve assignment: observer=%s, want A", got)
					}
					assertProtocolWireEvent(t, receiveProtocolEvent(t, events), original, first, ProtocolUnexpectedMessage, 0)
					second := testFramedMessage(t, flags, nil)
					if malformed {
						second = testFramedMessage(t, flags, []byte{0, 0, 1, 2, avp.Mbit, 255, 255, 255})
					}
					if _, err := remote.Write(second); err != nil {
						t.Fatal(err)
					}
					actual := dispatched
					kind, code := ProtocolUnexpectedMessage, uint32(0)
					if malformed {
						actual = messageErrors
						kind, code = ProtocolMalformedMessage, InvalidAVPLength
					}
					handlerName := receiveProtocolHandlerName(t, actual)
					observerName := receiveProtocolHandlerName(t, observers)
					if handlerName != observerName {
						t.Fatalf("second message: actual handler=%s, protocol observer=%s", handlerName, observerName)
					}
					if handlerName != "A" {
						t.Fatalf("connection changed handler: got %s, want captured A", handlerName)
					}
					assertProtocolWireEvent(t, receiveProtocolEvent(t, events), original, second, kind, code)
					if err := remote.Close(); err != nil {
						t.Fatal(err)
					}
					select {
					case <-mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, original).DispatchDone():
					case <-time.After(5 * time.Second):
						t.Fatal("dispatch did not finish")
					}
					if len(dispatched) != 0 || len(messageErrors) != 0 || len(events) != 0 || len(observers) != 0 {
						t.Fatal("unexpected additional handler or observer callback")
					}
				})
			}
		}
	}
}
