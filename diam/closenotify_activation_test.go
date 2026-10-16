package diam

import (
	"errors"
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

func registerReadObservers(c *conn, order string) <-chan struct{} {
	switch order {
	case "private-public":
		transport.ReadDone(c.writer)
		return c.writer.CloseNotify()
	case "public-private":
		gone := c.writer.CloseNotify()
		transport.ReadDone(c.writer)
		return gone
	case "concurrent":
		var wg sync.WaitGroup
		wg.Add(1)
		go func() { defer wg.Done(); transport.ReadDone(c.writer) }()
		gone := c.writer.CloseNotify()
		wg.Wait()
		return gone
	default:
		return c.writer.CloseNotify()
	}
}

func TestCloseNotifyActivationDuringCallback(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		for _, order := range []string{"public", "private-public", "public-private", "concurrent"} {
			for _, mode := range []int{0, 2} {
				if accepted && (mode != 0 || order != "public") {
					continue
				}
				t.Run(fmt.Sprintf("accepted=%t/%s/handlers=%d", accepted, order, mode), func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						local, peer := net.Pipe()
						raw := &restartTransport{Conn: local, reads: make(chan restartRead), closed: make(chan struct{})}
						entered, release := make(chan struct{}), make(chan struct{})
						unblock := sync.OnceFunc(func() { close(release) })
						var gone <-chan struct{}
						var c *conn
						c = (&Server{MaxConcurrentHandlers: mode, Handler: HandlerFunc(func(Conn, *Message) {
							gone = registerReadObservers(c, order)
							close(entered)
							<-release
						})}).newConn(raw)
						c.accepted = accepted
						served := make(chan struct{})
						go func() { c.serve(); close(served) }()
						defer func() { unblock(); _ = raw.Close(); _ = peer.Close(); <-served }()
						raw.reads <- restartRead{data: cerPayload(t, newTestDictionary(dict.Base()))}
						<-entered
						go func() {
							select {
							case raw.reads <- restartRead{err: io.EOF}:
							case <-raw.closed:
							}
						}()
						synctest.Wait()
						// Accepted callbacks leave the switch for the next read.
						wantGone := !accepted
						select {
						case <-gone:
							if !wantGone {
								t.Fatal("accepted sequential callback activated read-ahead")
							}
						default:
							if wantGone {
								t.Fatal("public subscriber missed EOF during dispatch")
							}
						}
						unblock()
						<-served
						select {
						case <-gone:
						default:
							t.Fatal("subscriber missed EOF after dispatch completed")
						}
					})
				})
			}
		}
	}
}

func TestCloseNotifyActivationAfterDirectRead(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		for _, order := range []string{"public", "private-public", "public-private", "concurrent"} {
			for _, firstErr := range []error{nil, io.EOF, &TransportRestartError{AssociationID: 42}} {
				t.Run(fmt.Sprintf("accepted=%t/%s/first=%v", accepted, order, firstErr), func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						local, peer := net.Pipe()
						defer func() { _ = local.Close(); _ = peer.Close() }()
						entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
						unblock := sync.OnceFunc(func() { close(release) })
						defer unblock()
						var active, calls atomic.Int32
						raw := signalReadTransport{Conn: local, read: func(b []byte) (int, error) {
							if active.Add(1) != 1 {
								t.Error("overlapping socket reads")
							}
							defer active.Add(-1)
							if calls.Add(1) == 1 {
								close(entered)
								<-release
								return copy(b, "abc"), firstErr
							}
							return 0, io.EOF
						}}
						c := (&Server{}).newConn(raw)
						c.accepted = accepted
						defer close(c.owner.done)
						go func() {
							n, err := c.sr.Read(make([]byte, 3))
							if n != 3 || err != firstErr {
								t.Errorf("direct read = %d,%v, want 3,%v", n, err, firstErr)
							}
							close(returned)
						}()
						<-entered
						gone := registerReadObservers(c, order)
						synctest.Wait()
						if calls.Load() != 1 {
							t.Fatal("bridge read before the direct read returned")
						}
						unblock()
						<-returned
						synctest.Wait()
						wantCalls := int32(2)
						if accepted {
							wantCalls = 1
						}
						if calls.Load() != wantCalls {
							t.Fatalf("socket reads after direct return = %d, want %d", calls.Load(), wantCalls)
						}
						if _, err := c.sr.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
							t.Fatalf("terminal bridge event = %v", err)
						}
						<-gone
						if calls.Load() != 2 {
							t.Fatalf("socket reads after terminal event = %d, want 2", calls.Load())
						}
					})
				})
			}
		}
	}
}

func TestCloseNotifyRegistrationAfterTerminalRead(t *testing.T) {
	for _, order := range []string{"public", "private-public", "public-private", "concurrent"} {
		t.Run(order, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				local, peer := net.Pipe()
				raw := &restartTransport{Conn: local, reads: make(chan restartRead, 1), closed: make(chan struct{})}
				c := (&Server{}).newConn(raw)
				defer func() { _ = raw.Close(); _ = peer.Close(); close(c.owner.done) }()
				raw.reads <- restartRead{err: io.EOF}
				if _, err := c.sr.Read(make([]byte, 1)); err != io.EOF {
					t.Fatalf("direct terminal read = %v", err)
				}
				gone := registerReadObservers(c, order)
				synctest.Wait()
				select {
				case <-gone:
				default:
					t.Fatal("public registration missed the completed terminal read")
				}
			})
		})
	}
}
