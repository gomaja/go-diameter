package diam

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/transport"
)

func TestCloseNotifyFirstRegistrationDuringDispatch(t *testing.T) {
	for _, duringRead := range []bool{false, true} {
		t.Run(fmt.Sprint(duringRead), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				local, peer := net.Pipe()
				raw := &restartTransport{Conn: local, reads: make(chan restartRead), closed: make(chan struct{})}
				entered, release := make(chan struct{}), make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				c := (&Server{Handler: HandlerFunc(func(Conn, *Message) { close(entered); <-release })}).newConn(raw)
				done, _ := transport.ReadDone(c.writer)
				served := make(chan struct{})
				go func() { c.serve(); close(served) }()
				defer func() { unblock(); _ = raw.Close(); _ = peer.Close(); <-served }()
				synctest.Wait()
				if duringRead {
					c.writer.CloseNotify()
				}
				raw.reads <- restartRead{data: cerPayload(t, newTestDictionary(dict.Base()))}
				<-entered
				if !duringRead {
					c.writer.CloseNotify()
				}
				go func() {
					select {
					case raw.reads <- restartRead{err: io.EOF}:
					case <-raw.closed:
					}
				}()
				synctest.Wait()
				select {
				case <-done:
				default:
					t.Fatal("first public CloseNotify missed peer loss while the sequential handler ran")
				}
			})
		})
	}
}

func TestCloseNotifyDoesNotOverlapSocketRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, peer := net.Pipe()
		defer func() { _ = local.Close(); _ = peer.Close() }()
		entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
		overlapped := make(chan struct{}, 1)
		var active, calls atomic.Int32
		raw := signalReadTransport{Conn: local, read: func(b []byte) (int, error) {
			if active.Add(1) != 1 {
				overlapped <- struct{}{}
			}
			defer active.Add(-1)
			if calls.Add(1) == 1 {
				close(entered)
				<-release
				return copy(b, "abc"), nil
			}
			return 0, io.EOF
		}}
		c := (&Server{}).newConn(raw)
		defer close(c.owner.done)
		transport.ReadDone(c.writer)
		go func() { _, _ = c.sr.Read(make([]byte, 3)); close(returned) }()
		<-entered
		gone := c.writer.CloseNotify()
		synctest.Wait()
		select {
		case <-overlapped:
			t.Error("public monitor started a second socket read before ownership transferred")
		default:
		}
		close(release)
		<-returned
		synctest.Wait()
		select {
		case <-gone:
		default:
			t.Fatal("public monitor did not start after the active read returned")
		}
		if _, err := c.sr.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("terminal bridge event = %v", err)
		}
		if got := calls.Load(); got != 2 {
			t.Fatalf("socket reads = %d, want one direct read and one bridge read", got)
		}
	})
}
