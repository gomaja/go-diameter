package sm

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

type protocolDuplicateConn struct {
	diam.Conn
	written chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (c *protocolDuplicateConn) Unwrap() diam.Conn { return c.Conn }

func (c *protocolDuplicateConn) WriteStream(wire []byte, stream uint) (int, error) {
	n, err := c.Conn.WriteStream(wire, stream)
	header, decodeErr := diam.DecodeHeader(wire)
	if err == nil && decodeErr == nil && header.CommandCode == diam.DisconnectPeer && header.CommandFlags&diam.RequestFlag != 0 {
		c.once.Do(func() { close(c.written) })
		<-c.release
	}
	return n, err
}

type protocolDuplicateHandler struct {
	*StateMachine
	once       sync.Once
	conn       *protocolDuplicateConn
	written    chan struct{}
	release    <-chan struct{}
	dispatched chan diam.Header
}

func (h *protocolDuplicateHandler) wrap(c diam.Conn) *protocolDuplicateConn {
	h.once.Do(func() { h.conn = &protocolDuplicateConn{Conn: c, written: h.written, release: h.release} })
	return h.conn
}

func (h *protocolDuplicateHandler) HandleAccept(c diam.Conn) func() {
	return h.StateMachine.HandleAccept(h.wrap(c))
}

func (h *protocolDuplicateHandler) ServeDIAM(c diam.Conn, m *diam.Message) {
	h.StateMachine.ServeDIAM(h.wrap(c), m)
	if m.Header.CommandCode == diam.DisconnectPeer && m.Header.CommandFlags&diam.RequestFlag == 0 {
		h.dispatched <- *m.Header
	}
}

func TestProtocolErrorDuplicateDPAWhileResultPending(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	events := make(chan diam.ProtocolErrorEvent, 4)
	handshake := make(chan diam.Conn, 1)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	cfg := testMessageErrorSettings(testDict)
	cfg.OnProtocolError = func(event diam.ProtocolErrorEvent) { events <- event }
	cfg.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { handshake <- c }
	machine := mustNewStateMachine(t, cfg, testDict)
	handler := &protocolDuplicateHandler{StateMachine: machine, written: make(chan struct{}), release: release, dispatched: make(chan diam.Header, 2)}
	logs := logtest.New()
	server := diamtest.NewUnstartedServer(handler, testDict)
	server.Config.Logger = logs.Logger()
	server.Start()
	t.Cleanup(server.Close)
	peer, err := net.DialTimeout("tcp", server.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	writeValidSMErrorCER(t, peer)
	cea, err := diam.ReadMessage(peer, testDict)
	if err != nil || !testResultCode(cea, diam.Success) {
		t.Fatalf("CEA = %v, %v", cea, err)
	}
	c := protocolGenerationAwait(t, handshake)
	disconnected := make(chan error, 1)
	go func() { disconnected <- machine.Disconnect(c, DisconnectRebooting, time.Hour) }()
	dpr, err := diam.ReadMessage(peer, testDict)
	if err != nil || dpr.Header.CommandCode != diam.DisconnectPeer || dpr.Header.CommandFlags&diam.RequestFlag == 0 {
		t.Fatalf("DPR = %v, %v", dpr, err)
	}
	protocolGenerationAwait(t, handler.written)
	first := protocolDPA(dpr, diam.Success)
	firstHeader := protocolGenerationWrite(t, peer, first)
	if dispatched := protocolGenerationAwait(t, handler.dispatched); dispatched != firstHeader {
		t.Fatalf("first DPA header = %+v, want %+v", dispatched, firstHeader)
	}
	select {
	case event := <-events:
		t.Fatalf("first success DPA emitted %+v", event)
	default:
	}
	select {
	case result := <-disconnected:
		t.Fatalf("Disconnect returned before DPR Write completed: %v", result)
	default:
	}
	if c.Closed() {
		t.Fatal("first DPA closed connection before write returned")
	}
	secondHeader := protocolGenerationWrite(t, peer, protocolDPA(dpr, diam.Success))
	if dispatched := protocolGenerationAwait(t, handler.dispatched); dispatched != secondHeader {
		t.Fatalf("duplicate DPA header = %+v, want %+v", dispatched, secondHeader)
	}
	event := protocolGenerationAwait(t, events)
	assertProtocolEvent(t, event, c, &secondHeader, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
	if records := logs.Records(); len(records) != 0 {
		t.Fatalf("DPA handling changed logs: %v", records)
	}
	unblock()
	if err := protocolGenerationAwait(t, disconnected); err != nil {
		t.Fatalf("Disconnect after original DPA = %v", err)
	}
	regressionClosed(t, peer)
	if !c.Closed() {
		t.Fatal("Disconnect did not close connection after result")
	}
	select {
	case extra := <-events:
		t.Fatalf("duplicate DPA produced extra notification %+v", extra)
	default:
	}
}
