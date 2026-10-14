package diam

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/gomaja/go-diameter/diam/dict"
)

type disabledProtocolObserver struct {
	calls int
}

func (*disabledProtocolObserver) ServeDIAM(Conn, *Message)                 {}
func (*disabledProtocolObserver) ProtocolErrorEnabled() bool               { return false }
func (h *disabledProtocolObserver) HandleProtocolError(ProtocolErrorEvent) { h.calls++ }

func TestProtocolErrorServerDisabledObserverAllocations(t *testing.T) {
	testDict := newTestDictionary(dict.Base())

	observer := &disabledProtocolObserver{}
	local, remote := net.Pipe()
	defer func() { _ = local.Close() }()
	defer func() { _ = remote.Close() }()
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	message := NewMessage(DeviceWatchdog, 0, 0, 83, 86, testDict)
	decodeErr := &avpDecodeError{resultCode: InvalidAVPLength, err: errors.New("synthetic payload decoding failure")}
	measure := func(handler Handler) float64 {
		c := &conn{server: &Server{Handler: handler, Logger: logger}, rwc: local}
		c.writer = &response{conn: c}
		return testing.AllocsPerRun(100, func() {
			if c.handleReadError(message, decodeErr) {
				t.Fatal("strict malformed answer was retained")
			}
		})
	}
	withoutObserver := measure(HandlerFunc(func(Conn, *Message) {}))
	disabled := measure(observer)
	t.Logf("read-error allocations: absent observer=%g, disabled observer=%g", withoutObserver, disabled)
	if observer.calls != 0 {
		t.Errorf("disabled observer received %d Server events", observer.calls)
	}
	if disabled != withoutObserver {
		t.Errorf("disabled observer adds allocations: disabled=%g, absent=%g", disabled, withoutObserver)
	}
}

func TestProtocolErrorDisabledObserverOwnsMuxRoute(t *testing.T) {
	testDict := newTestDictionary(dict.Base())

	observer := &disabledProtocolObserver{}
	fallback := &protocolObserverHandler{onEvent: func(ProtocolErrorEvent) {
		t.Fatal("disabled route observer fell through to ALL")
	}}
	mux := NewServeMux()
	mux.HandleIdx(CommandIndex{Code: DeviceWatchdog}, observer)
	mux.Handle("ALL", fallback)
	if resolved, found := protocolObserverFor(nil, mux, NewMessage(DeviceWatchdog, 0, 0, 83, 86, testDict)); resolved != nil || !found {
		t.Fatalf("disabled route resolution=%T, %t", resolved, found)
	}
	if observer.calls != 0 {
		t.Fatal("disabled route observer was invoked")
	}
}
