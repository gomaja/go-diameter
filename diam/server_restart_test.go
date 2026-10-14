package diam

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/dict"
)

type restartRead struct {
	data []byte
	err  error
}
type restartTransport struct {
	net.Conn
	reads     chan restartRead
	remaining []byte
	closed    chan struct{}
	once      sync.Once
}

func (c *restartTransport) Read(b []byte) (int, error) {
	if len(c.remaining) == 0 {
		var event restartRead
		select {
		case value, ok := <-c.reads:
			if !ok {
				return 0, io.EOF
			}
			event = value
		case <-c.closed:
			return 0, net.ErrClosed
		}
		if event.err != nil {
			return 0, event.err
		}
		c.remaining = event.data
	}
	n := copy(b, c.remaining)
	c.remaining = c.remaining[n:]
	return n, nil
}

func (c *restartTransport) Close() error {
	if c.closed != nil {
		c.once.Do(func() { close(c.closed) })
	}
	return c.Conn.Close()
}

type restartHandler struct{ conns chan Conn }

func (h *restartHandler) ServeDIAM(c Conn, m *Message) {
	release := m.BeginDispatch()
	defer release()
	h.conns <- c
	_, _ = m.Answer(Success).WriteTo(c)
}
func (h *restartHandler) HandleRetire(Conn, RetirementReason) error { return nil }

func TestAcceptedRestartPreservesNextCER(t *testing.T) {
	testDict := newTestDictionary(dict.Base())

	for _, mode := range []int{0, 1, 2, -1} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			local, remote := net.Pipe()
			transport := &restartTransport{Conn: local, reads: make(chan restartRead, 4), closed: make(chan struct{})}
			h := &restartHandler{conns: make(chan Conn, 2)}
			srv := &Server{Handler: h, MaxConcurrentHandlers: mode}
			c := srv.newConn(transport)
			c.accepted = true
			finished := make(chan struct{})
			go func() { c.serve(); close(finished) }()
			defer func() { close(transport.reads); _ = remote.Close(); <-finished }()
			payload := cerPayload(t, testDict)
			transport.reads <- restartRead{data: payload}
			if err := remote.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadMessage(remote, testDict); err != nil {
				t.Fatalf("first CEA: %v", err)
			}
			old := <-h.conns
			transport.reads <- restartRead{err: &TransportRestartError{AssociationID: 42, InboundStreams: 4, OutboundStreams: 4}}
			transport.reads <- restartRead{data: payload}
			if _, err := ReadMessage(remote, testDict); err != nil {
				t.Fatalf("next CER lost after restart: %v", err)
			}
			next := <-h.conns
			if old == next {
				t.Fatal("restart retained old Conn identity")
			}
			if !old.Closed() || next.Closed() {
				t.Fatal("generation Closed state")
			}
			if _, err := old.Write(payload); !errors.Is(err, ErrConnectionRetired) || !errors.Is(err, net.ErrClosed) {
				t.Fatalf("old write: %v", err)
			}
			old.Close()
			if next.Closed() {
				t.Fatal("old Close closed replacement")
			}
			transport.reads <- restartRead{data: payload}
			if _, err := ReadMessage(remote, testDict); err != nil {
				t.Fatalf("old Close affected replacement transport: %v", err)
			}
			if third := <-h.conns; third != next {
				t.Fatal("unexpected third generation")
			}
		})
	}
}
