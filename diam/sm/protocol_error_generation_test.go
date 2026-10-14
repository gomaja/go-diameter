package sm

import (
	"errors"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

type protocolGenerationWire struct {
	peer       net.Conn
	handshakes <-chan diam.Conn
	restarts   <-chan acceptedRestartPair
	logs       *logtest.Recorder
}

func newProtocolGenerationWire(t *testing.T, notify func(diam.ProtocolErrorEvent)) *protocolGenerationWire {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())
	serverSettings2 := cloneTestSettings(serverSettings2, testDict)

	t.Helper()
	handshakes := make(chan diam.Conn, 4)
	restarts := make(chan acceptedRestartPair, 4)
	cfg := *serverSettings2
	cfg.OnProtocolError = notify
	cfg.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { handshakes <- c }
	sm := mustNewStateMachine(t, &cfg, testDict)
	logs := logtest.New()
	server := diamtest.NewUnstartedServer(sm, testDict)
	server.Config.Logger = logs.Logger()
	server.Config.RenewAcceptedCER = true
	server.Config.MaxConcurrentHandlers = -1
	server.Config.OnConnectionRestart = func(old, next diam.Conn, reason diam.RetirementReason) {
		restarts <- acceptedRestartPair{old, next, reason}
	}
	server.Start()
	peer, err := net.DialTimeout("tcp", server.Addr, time.Second)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close(); server.Close() })
	return &protocolGenerationWire{peer: peer, handshakes: handshakes, restarts: restarts, logs: logs}
}

func protocolGenerationAwait[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for protocol generation observation")
		var zero T
		return zero
	}
}

func (w *protocolGenerationWire) handshake(t *testing.T, host string, app, state uint32) diam.Conn {
	t.Helper()
	protocolGenerationWrite(t, w.peer, acceptedRestartCER(t, host, app, state))
	acceptedRestartCEA(t, w.peer, diam.Success)
	return protocolGenerationAwait(t, w.handshakes)
}

func protocolGenerationWrite(t *testing.T, peer net.Conn, m *diam.Message) diam.Header {
	t.Helper()
	wire, err := m.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	writeSMErrorWire(t, peer, wire)
	header := *m.Header
	header.MessageLength = uint32(len(wire))
	return header
}

func protocolGenerationInvalidDWR(t *testing.T, id uint32) *diam.Message {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())
	clientSettings := cloneTestSettings(clientSettings, testDict)

	t.Helper()
	m := diam.NewRequest(diam.DeviceWatchdog, 0, testDict)
	m.Header.HopByHopID, m.Header.EndToEndID = id, id+1
	mustSMClientAVP(t, m, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
	return m
}

func assertProtocolGenerationDWR(t *testing.T, event diam.ProtocolErrorEvent, c diam.Conn, header diam.Header, stream uint) {
	t.Helper()
	var classified *diam.ProtocolError
	if event.Conn != c || !event.Message.HasHeader || event.Message.Header != header || event.Message.Stream != stream {
		t.Fatalf("notification metadata = %+v, want Conn %p header %+v stream %d", event, c, header, stream)
	}
	if !errors.As(event.Err, &classified) || !errors.Is(event.Err, diam.ProtocolInvalidDWR) || classified.Kind() != diam.ProtocolInvalidDWR || classified.ResultCode() != 0 {
		t.Fatalf("notification error = %v", event.Err)
	}
	if event.Closing || event.Reply != diam.ProtocolReplyNone || event.ReplyCode != 0 {
		t.Fatalf("notification disposition = %+v", event)
	}
}

func (w *protocolGenerationWire) validDWR(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	t.Helper()
	request := regressionDWR(t)
	protocolGenerationWrite(t, w.peer, request)
	_ = w.peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	answer, err := diam.ReadMessage(w.peer, testDict)
	if err != nil || answer.Header.CommandCode != diam.DeviceWatchdog || answer.Header.HopByHopID != request.Header.HopByHopID || !testResultCode(answer, diam.Success) {
		t.Fatalf("valid DWR answer = %v, %v", answer, err)
	}
}

func TestProtocolErrorGenerationRenewal(t *testing.T) {
	events := make(chan diam.ProtocolErrorEvent, 8)
	w := newProtocolGenerationWire(t, func(event diam.ProtocolErrorEvent) { events <- event })
	old := w.handshake(t, "first.example", 1001, 111)
	firstHeader := protocolGenerationWrite(t, w.peer, protocolGenerationInvalidDWR(t, 0x8601))
	first := protocolGenerationAwait(t, events)
	assertProtocolGenerationDWR(t, first, old, firstHeader, 0)
	w.validDWR(t)
	next := w.handshake(t, "second.example", 1002, 222)
	pair := protocolGenerationAwait(t, w.restarts)
	if pair.old != old || pair.next != next || next == old || pair.reason != diam.AcceptedCERRenewal || !old.Closed() || next.Closed() {
		t.Fatalf("renewal = %+v; old %p next %p", pair, old, next)
	}
	secondHeader := protocolGenerationWrite(t, w.peer, protocolGenerationInvalidDWR(t, 0x8602))
	second := protocolGenerationAwait(t, events)
	assertProtocolGenerationDWR(t, second, next, secondHeader, 0)
	assertProtocolGenerationDWR(t, first, old, firstHeader, 0)
	w.validDWR(t)
	select {
	case event := <-events:
		t.Fatalf("successful exchange emitted %+v", event)
	default:
	}
	logs := w.logs.RecordsWithMessage("sm: invalid DWR")
	if len(logs) != 2 || logs[0].Level != slog.LevelWarn || logs[1].Level != slog.LevelWarn {
		t.Fatalf("invalid DWR logs = %v", logs)
	}
	if records := w.logs.Records(); len(records) != 3 || records[0].Message != "sm: invalid DWR" || records[1].Message != "diam: accepted connection renewed" || records[1].Level != slog.LevelInfo || records[2].Message != "sm: invalid DWR" {
		t.Fatalf("unexpected records before close: %v", records)
	}
}

func TestProtocolErrorGenerationRetirementWhileCallbackBlocks(t *testing.T) {
	entered, returned := make(chan diam.ProtocolErrorEvent, 1), make(chan diam.ProtocolErrorEvent, 1)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	w := newProtocolGenerationWire(t, func(event diam.ProtocolErrorEvent) {
		entered <- event
		<-release
		returned <- event
	})
	// Unblock before closing the server even when an assertion fails.
	t.Cleanup(unblock)
	old := w.handshake(t, "first.example", 1001, 111)
	header := protocolGenerationWrite(t, w.peer, protocolGenerationInvalidDWR(t, 0x8610))
	initial := protocolGenerationAwait(t, entered)
	assertProtocolGenerationDWR(t, initial, old, header, 0)
	next := w.handshake(t, "second.example", 1002, 222)
	pair := protocolGenerationAwait(t, w.restarts)
	if pair.old != old || pair.next != next || old == next || !old.Closed() || next.Closed() {
		t.Fatalf("renewal while callback blocked = %+v", pair)
	}
	lifecycle, ok := diam.ConnAs[interface{ DispatchDone() <-chan struct{} }](old)
	if !ok {
		t.Fatal("old Conn has no lifecycle")
	}
	select {
	case <-lifecycle.DispatchDone():
		t.Fatal("old DispatchDone closed before callback returned")
	default:
	}
	unblock()
	completed := protocolGenerationAwait(t, returned)
	assertProtocolGenerationDWR(t, completed, old, header, 0)
	protocolGenerationAwait(t, lifecycle.DispatchDone())
	old.Close()
	w.validDWR(t)
	if next.Closed() {
		t.Fatal("callback completion/old Close closed replacement generation")
	}
}

func TestProtocolErrorGenerationMetadataRetention(t *testing.T) {
	events := make(chan diam.ProtocolErrorEvent, 4)
	w := newProtocolGenerationWire(t, func(event diam.ProtocolErrorEvent) { events <- event })
	c := w.handshake(t, "first.example", 1001, 111)
	m := protocolGenerationInvalidDWR(t, 0x8620)
	header := protocolGenerationWrite(t, w.peer, m)
	retained := protocolGenerationAwait(t, events)
	assertProtocolGenerationDWR(t, retained, c, header, 0)
	copy := retained
	copy.Message.Header.HopByHopID = 0
	copy.Message.Header.MessageLength = 0
	m.Header.HopByHopID = 0
	m.AVP[0].Code = 0
	otherHeader := protocolGenerationWrite(t, w.peer, protocolGenerationInvalidDWR(t, 0x8621))
	other := protocolGenerationAwait(t, events)
	assertProtocolGenerationDWR(t, other, c, otherHeader, 0)
	assertProtocolGenerationDWR(t, retained, c, header, 0)
	next := w.handshake(t, "second.example", 1002, 222)
	protocolGenerationAwait(t, w.restarts)
	assertProtocolGenerationDWR(t, retained, c, header, 0)
	if next == c || !c.Closed() || next.Closed() {
		t.Fatal("retained notification changed connection generation")
	}
	w.validDWR(t)
}

func TestProtocolErrorGenerationRejectedRenewal(t *testing.T) {
	events := make(chan diam.ProtocolErrorEvent, 4)
	w := newProtocolGenerationWire(t, func(event diam.ProtocolErrorEvent) { events <- event })
	old := w.handshake(t, "first.example", 1001, 111)
	header := protocolGenerationWrite(t, w.peer, acceptedRestartCER(t, "second.example", 9999, 222))
	acceptedRestartCEA(t, w.peer, diam.NoCommonApplication)
	pair := protocolGenerationAwait(t, w.restarts)
	event := protocolGenerationAwait(t, events)
	if pair.old != old || pair.next == old || event.Conn != pair.next || event.Message.Header != header || !event.Message.HasHeader || event.Message.Stream != 0 {
		t.Fatalf("rejected renewal notification = %+v, renewal = %+v", event, pair)
	}
	if !errors.Is(event.Err, diam.ProtocolCERRejected) || event.Err.ResultCode() != diam.NoCommonApplication || !event.Closing || event.Reply != diam.ProtocolReplyWritten || event.ReplyCode != diam.NoCommonApplication {
		t.Fatalf("rejected renewal disposition = %+v", event)
	}
	regressionClosed(t, w.peer)
	if !old.Closed() || !pair.next.Closed() {
		t.Fatal("rejected renewal left a generation open")
	}
	select {
	case c := <-w.handshakes:
		t.Fatalf("rejected renewal admitted %p", c)
	default:
	}
	select {
	case extra := <-events:
		t.Fatalf("rejected renewal duplicated notification: %+v", extra)
	default:
	}
	records := w.logs.RecordsWithMessage("sm: rejected CER; closing connection")
	if len(records) != 1 || records[0].Level != slog.LevelWarn {
		t.Fatalf("rejected CER logs = %v", records)
	}
}
