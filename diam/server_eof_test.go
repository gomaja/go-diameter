package diam

import (
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/gomaja/go-diameter/diam/dict"
)

type eofDispatchTransport struct {
	*fencedMultistream
	mu      sync.Mutex
	onError MutistreamConnErrorHandler
}

func (c *eofDispatchTransport) SetErrorHandler(h MutistreamConnErrorHandler) {
	c.mu.Lock()
	c.onError = h
	c.mu.Unlock()
}

func TestDecodedMessageBeforeEOFDispatches(t *testing.T) {
	testDict := newTestDictionary(dict.Base())

	for _, mode := range []int{0, 2, -1} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				local, remote := net.Pipe()
				raw := &restartTransport{Conn: local, reads: make(chan restartRead, 1), closed: make(chan struct{})}
				transport := &eofDispatchTransport{fencedMultistream: &fencedMultistream{Conn: raw}}
				entered, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				srv := &Server{MaxConcurrentHandlers: mode, Handler: HandlerFunc(func(Conn, *Message) {
					close(entered)
					<-release
				})}
				c := srv.newConn(transport)
				gone := c.writer.CloseNotify()
				served := make(chan struct{})
				go func() { c.serve(); close(served) }()
				defer func() { unblock(); _ = raw.Close(); _ = remote.Close(); <-served }()
				raw.reads <- restartRead{data: cerPayload(t, testDict)}
				<-entered
				transport.mu.Lock()
				onError := transport.onError
				transport.mu.Unlock()
				if onError == nil {
					t.Fatal("CloseNotify did not install the transport observer")
				}
				// A multistream receive loop can observe EOF while the Server
				// callback for an earlier decoded message is still running.
				onError(transport, io.EOF)
				if c.writer.Closed() {
					t.Error("ordinary EOF published Closed before decoded callback finished")
				}
				select {
				case <-gone:
				default:
					t.Error("physical EOF did not close CloseNotify")
				}
				select {
				case <-c.done:
					t.Error("ordinary EOF completed dispatch while callback was running")
				default:
				}
				unblock()
				<-served
				if !c.writer.Closed() {
					t.Error("reader exit did not publish Closed")
				}
				select {
				case <-c.done:
				default:
					t.Error("reader exit did not complete dispatch")
				}
			})
		})
	}
}
