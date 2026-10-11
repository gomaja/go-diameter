package peer

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

type restartEvent struct {
	data []byte
	err  error
}
type restartScriptConn struct {
	net.Conn
	events  chan restartEvent
	pending []byte
	closed  chan struct{}
	once    sync.Once
}

func (c *restartScriptConn) Read(b []byte) (int, error) {
	if len(c.pending) == 0 {
		select {
		case event := <-c.events:
			if event.err != nil {
				return 0, event.err
			}
			c.pending = event.data
		case <-c.closed:
			return 0, net.ErrClosed
		}
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
func (c *restartScriptConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}
func (c *restartScriptConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3868}
}
func (c *restartScriptConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 43868}
}

type restartScriptListener struct {
	conn     net.Conn
	closed   chan struct{}
	accepted bool
	once     sync.Once
}

func (l *restartScriptListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		return l.conn, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}
func (l *restartScriptListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *restartScriptListener) Addr() net.Addr { return l.conn.LocalAddr() }

func TestManagerRestartClosesPhysicalConnection(t *testing.T) {
	for _, admitted := range []bool{false, true} {
		t.Run(map[bool]string{false: "before CER", true: "Open"}[admitted], func(t *testing.T) {
			records := logtest.New()
			manager, err := New(Config{Logger: records.Logger(), Settings: testSettings("local.example.net")})
			if err != nil {
				t.Fatal(err)
			}
			if err = manager.AddPeer(PeerConfig{Host: "known.example.net"}); err != nil {
				t.Fatal(err)
			}
			local, remote := net.Pipe()
			defer func() { _ = remote.Close() }()
			transport := &restartScriptConn{Conn: local, events: make(chan restartEvent, 2), closed: make(chan struct{})}
			listener := &restartScriptListener{conn: transport, closed: make(chan struct{})}
			accepted := make(chan diam.Conn, 1)
			srv := &diam.Server{Logger: records.Logger(), RenewAcceptedCER: true, OnNewConnection: func(c diam.Conn) { accepted <- c }}
			if err = manager.BindServer(srv); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- srv.Serve(listener) }()
			defer func() {
				closeManager(t, manager, srv)
				if err := <-done; !errors.Is(err, diam.ErrServerClosed) {
					t.Error(err)
				}
			}()
			c := <-accepted
			if _, ok := diam.HandlerAs[diam.RetireHandler](manager); ok {
				t.Fatal("Manager must remain outside renewal scope")
			}
			if admitted {
				b, err := reviewCER(t).Serialize()
				if err != nil {
					t.Fatal(err)
				}
				transport.events <- restartEvent{data: b}
				if a := read(t, remote); code(t, a) != diam.Success {
					t.Fatal(a)
				}
			}
			// Closure is expected; a peer that has already closed needs no deadline.
			if err := remote.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil && !errors.Is(err, io.ErrClosedPipe) {
				t.Fatal(err)
			}
			transport.events <- restartEvent{err: &diam.TransportRestartError{AssociationID: 81}}
			if _, err := remote.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("restart retained Manager socket: %v", err)
			}
			notifier, ok := diam.ConnAs[diam.CloseNotifier](c)
			if !ok {
				t.Fatal("CloseNotifier missing")
			}
			select {
			case <-notifier.CloseNotify():
			case <-time.After(time.Second):
				t.Fatal("Manager pending owners not notified")
			}
			if !c.Closed() {
				t.Fatal("Manager generation retained")
			}
			found := false
			for _, record := range records.Records() {
				if record.Message == "diam: transport restart without retirement handler; closing connection" {
					found = true
				}
			}
			if !found {
				t.Fatal("fallback close not logged")
			}
		})
	}
}

func TestManagerSecondCERPolicyStaysClosed(t *testing.T) {
	_, c := reviewPeerServer(t, false)
	write(t, c, reviewCER(t))
	if a := read(t, c); code(t, a) != diam.Success {
		t.Fatal(a)
	}
	write(t, c, reviewCER(t))
	if err := c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("second CER policy changed: %v", err)
	}
}
