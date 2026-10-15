package sm

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
)

// Keep the callback blocked even after transport closure: joining publication
// must be released by the disconnect deadline, not by cooperation of a writer.
type closingBlockedWriter struct {
	diam.Conn
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *closingBlockedWriter) Unwrap() diam.Conn { return c.Conn }
func (c *closingBlockedWriter) WriteStream(b []byte, stream uint) (int, error) {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return c.Conn.WriteStream(b, stream)
}

func TestClosingBlockedClientPublicationWire(t *testing.T) {
	for _, local := range []bool{false, true} {
		t.Run(fmt.Sprintf("local=%t", local), func(t *testing.T) {
			const deadline = 60 * time.Millisecond
			p := newProtocolClientWire(t, func(c *Client) {
				c.EnableWatchdog = true
				c.WatchdogInterval = time.Hour
				c.Handler.cfg.DPRCloseTimeout = deadline
			}, func(s *diam.Server) { s.WriteTimeout = 0 })
			p.send(t, protocolClientCEA(p.cer, diam.Success))
			if result := p.dialResult(t); result.err != nil {
				t.Fatal(result.err)
			}
			state := p.client.Handler.closingConnection(p.conn)
			state.mu.Lock()
			activity := state.client
			state.mu.Unlock()
			blocked := &closingBlockedWriter{Conn: p.conn, entered: make(chan struct{}), release: make(chan struct{})}
			finished := make(chan bool, 1)
			go func() { finished <- p.client.dwr(blocked, 0, &activity.watchdogSignals) }()
			<-blocked.entered
			defer func() { close(blocked.release); <-finished }()
			result := make(chan error, 1)
			if local {
				go func() { result <- p.client.Handler.Disconnect(p.conn, DisconnectBusy, deadline) }()
			} else {
				wire := &protocolWire{sm: p.client.Handler, conn: p.conn, peer: p.peer}
				p.send(t, closingContractDPR(t, wire, 500))
			}
			if err := p.peer.SetReadDeadline(time.Now().Add(5 * deadline)); err != nil {
				t.Fatal(err)
			}
			var b [1]byte
			if n, err := p.peer.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
				t.Errorf("blocked watchdog prevented disconnect deadline: bytes=%d error=%v", n, err)
			}
			if !activity.stopped.Load() {
				t.Error("Closing latch was not published")
			}
			if local {
				select {
				case err := <-result:
					if !errors.Is(err, ErrDisconnectTimeout) {
						t.Errorf("Disconnect=%v", err)
					}
				case <-time.After(deadline):
					t.Error("deadline/closure did not release publication join")
					p.conn.Close()
				}
			}
			if p.conn.Closed() {
				assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, nil, diam.ProtocolDisconnectTimeout, 0, true, diam.ProtocolReplyNone, 0)
			}
		})
	}
}
