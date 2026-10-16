package diam

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam/internal/transport"
)

func TestReadDeadlineWhileDispatchCapacityIsOccupied(t *testing.T) {
	for _, public := range []bool{false, true} {
		t.Run(fmt.Sprintf("public=%t", public), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				local, peer := net.Pipe()
				first, second := make(chan struct{}), make(chan struct{})
				enteredFirst, enteredSecond := make(chan struct{}), make(chan struct{})
				releaseFirst := sync.OnceFunc(func() { close(first) })
				releaseSecond := sync.OnceFunc(func() { close(second) })
				c := (&Server{ReadTimeout: time.Hour, MaxConcurrentHandlers: 1, Handler: HandlerFunc(func(_ Conn, m *Message) {
					switch m.Header.HopByHopID {
					case 1:
						close(enteredFirst)
						<-first
					case 2:
						close(enteredSecond)
						<-second
					}
				})}).newConn(local)
				gone, ok := transport.ReadDone(c.writer)
				if !ok {
					t.Fatal("native read signal unavailable")
				}
				if public {
					c.writer.CloseNotify()
				}
				served := make(chan struct{})
				go func() { c.serve(); close(served) }()
				defer func() { releaseFirst(); releaseSecond(); _ = peer.Close(); c.writer.Close(); <-served }()
				send := func(hop uint32) {
					t.Helper()
					frame, err := NewMessage(999, 0, 0, hop, 456, nil).Serialize()
					if err != nil {
						t.Fatal(err)
					}
					if len(frame) != 20 {
						t.Fatalf("header-only frame length=%d", len(frame))
					}
					if _, err := peer.Write(frame); err != nil {
						t.Fatal(err)
					}
				}
				send(1)
				<-enteredFirst
				send(2)
				// A complete pipe write and quiescence place the decoded second message
				// at the admission semaphore while the first callback owns its only slot.
				synctest.Wait()
				if err := local.SetReadDeadline(time.Now().Add(-time.Hour)); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				select {
				case <-gone:
					if !public {
						t.Fatal("deadline observed while dispatch admission owned the reader")
					}
				default:
					if public {
						t.Fatal("public read-ahead missed the expired deadline")
					}
				}
				if c.writer.Closed() {
					t.Fatal("deadline published Closed before callbacks drained")
				}
				releaseFirst()
				<-enteredSecond
				synctest.Wait()
				if !public {
					// The next message read replaces the expired deadline before touching
					// the socket, even though the second callback is still running.
					send(3)
					synctest.Wait()
					select {
					case <-gone:
						t.Fatal("refreshed read published transport loss")
					default:
					}
				}
				releaseSecond()
			})
		})
	}
}
