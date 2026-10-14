package diam

import (
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

type retirementDeadlineConn struct {
	net.Conn
	setting, resume, interrupted chan struct{}
	once                         sync.Once
	mu                           sync.Mutex
	deadline                     time.Time
	written                      []byte
}

func (c *retirementDeadlineConn) SetWriteDeadline(deadline time.Time) error {
	if deadline.After(time.Now()) {
		c.once.Do(func() {
			close(c.setting)
			<-c.resume
		})
	}
	c.mu.Lock()
	c.deadline = deadline
	c.mu.Unlock()
	if !deadline.IsZero() && !deadline.After(time.Now()) {
		close(c.interrupted)
	}
	return nil
}

func (c *retirementDeadlineConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.deadline.IsZero() && !c.deadline.After(time.Now()) {
		return 0, os.ErrDeadlineExceeded
	}
	c.written = append(c.written, b...)
	return len(b), nil
}

type retirementDeadlineMultistream struct {
	*fencedMultistream
	deadlineConn *retirementDeadlineConn
}

func (c *retirementDeadlineMultistream) Write(b []byte) (int, error) {
	return c.deadlineConn.Write(b)
}

func (c *retirementDeadlineMultistream) WriteStream(b []byte, _ uint) (int, error) {
	return c.deadlineConn.Write(b)
}

func TestWriterDeadlineCannotUndoRetirement(t *testing.T) {
	for _, transportKind := range []string{"tcp", "multistream"} {
		for _, stream := range []bool{false, true} {
			t.Run(transportKind+map[bool]string{false: "/write", true: "/stream"}[stream], func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					local, remote := net.Pipe()
					defer func() { _ = local.Close(); _ = remote.Close() }()
					transport := &retirementDeadlineConn{Conn: local, setting: make(chan struct{}), resume: make(chan struct{}), interrupted: make(chan struct{})}
					var raw net.Conn = transport
					if transportKind == "multistream" {
						raw = &retirementDeadlineMultistream{fencedMultistream: &fencedMultistream{Conn: transport}, deadlineConn: transport}
					}
					srv := &Server{WriteTimeout: time.Minute, Handler: &generationHandler{}}
					c := srv.newConn(raw)
					c.accepted = true
					type result struct {
						n   int
						err error
					}
					written := make(chan result, 1)
					go func() {
						write := c.writer.Write
						if stream {
							write = func(b []byte) (int, error) { return c.writer.WriteStream(b, 3) }
						}
						n, err := write([]byte("stale"))
						written <- result{n, err}
					}()
					// The admitted writer pauses before applying its future deadline.
					<-transport.setting
					renewed := make(chan *conn, 1)
					go func() { renewed <- c.renew(SCTPAssociationRestart, &TransportRestartError{}) }()
					<-transport.interrupted
					if c.retirement.Load() == 0 {
						t.Error("interrupt deadline preceded retirement publication")
					}
					close(transport.resume)
					got := <-written
					if got.n != 0 || !errors.Is(got.err, ErrConnectionRetired) || !errors.Is(got.err, net.ErrClosed) {
						t.Errorf("writer replaced retirement deadline and sent after retirement = %d, %v; want zero bytes and ErrConnectionRetired", got.n, got.err)
					}
					if next := <-renewed; next == nil {
						t.Error("fenced writer prevented renewal")
					}
					transport.mu.Lock()
					if len(transport.written) != 0 {
						t.Errorf("retired writer reached physical socket: %q", transport.written)
					}
					transport.mu.Unlock()
				})
			})
		}
	}
}
