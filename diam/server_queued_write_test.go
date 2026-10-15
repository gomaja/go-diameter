package diam

import (
	"errors"
	"net"
	"sync"
	"testing"
	"testing/synctest"
)

type queuedWriteTransport struct {
	*fencedMultistream
	mu      sync.Mutex
	written []byte
}

func (c *queuedWriteTransport) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.written = append(c.written, b...)
	return len(b), nil
}

func (c *queuedWriteTransport) WriteStream(b []byte, _ uint) (int, error) {
	return c.Write(b)
}

func TestQueuedWriterRetirementFence(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{false: "write", true: "stream"}[stream], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				local, remote := net.Pipe()
				defer func() { _ = local.Close(); _ = remote.Close() }()
				transport := &queuedWriteTransport{fencedMultistream: &fencedMultistream{Conn: local}}
				srv := &Server{Handler: &generationHandler{}}
				c := srv.newConn(transport)
				c.accepted = true
				if err := c.writer.lockWrite(); err != nil {
					t.Fatal(err)
				}
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
				// The writer has passed its first ownership check and is queued
				// on the physical gate before retirement can acquire it.
				synctest.Wait()
				renewed := make(chan *conn, 1)
				go func() { renewed <- c.renew(SCTPAssociationRestart, &TransportRestartError{}) }()
				synctest.Wait()
				if c.retirement.Load() == 0 {
					t.Error("renewal did not fence the queued writer")
				}
				c.writer.unlockWrite()
				got := <-written
				if got.n != 0 || !errors.Is(got.err, ErrConnectionRetired) || !errors.Is(got.err, net.ErrClosed) {
					t.Errorf("queued old writer after retirement = %d, %v; want zero bytes and ErrConnectionRetired", got.n, got.err)
				}
				if next := <-renewed; next == nil {
					t.Error("queued writer prevented renewal")
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
