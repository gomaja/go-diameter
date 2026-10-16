package diam

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/transport"
)

func TestReadSignalLeavesSocketReaderInPlace(t *testing.T) {
	local, peer := net.Pipe()
	defer func() { _ = local.Close(); _ = peer.Close() }()
	c := (&Server{}).newConn(local)
	defer close(c.owner.done)
	done, ok := transport.ReadDone(c.writer)
	if !ok || done == nil {
		t.Fatal("native read signal unavailable")
	}
	if c.sr.r != local || c.sr.pr != nil || c.sr.pipeCopyF != nil {
		t.Fatal("read signal installed a reader bridge")
	}
	if next, _ := transport.ReadDone(c.writer); next != done {
		t.Fatal("read signal registration changed its channel")
	}
	if public := c.writer.CloseNotify(); public != done {
		t.Fatal("public CloseNotify did not install its early transport observer")
	}
	if _, bridged := c.sr.r.(*orderedReader); !bridged {
		t.Fatal("public CloseNotify did not transfer the idle reader to its bridge")
	}
}

func TestReadSignalHandlerOrdering(t *testing.T) {
	for _, mode := range []int{0, 2, -1} {
		for _, public := range []bool{false, true} {
			t.Run(fmt.Sprintf("handlers%d/public%t", mode, public), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					local, peer := net.Pipe()
					raw := &restartTransport{Conn: local, reads: make(chan restartRead), closed: make(chan struct{})}
					entered, release := make(chan struct{}), make(chan struct{})
					unblock := sync.OnceFunc(func() { close(release) })
					c := (&Server{MaxConcurrentHandlers: mode, Handler: HandlerFunc(func(Conn, *Message) {
						close(entered)
						<-release
					})}).newConn(raw)
					done, ok := transport.ReadDone(c.writer)
					if !ok {
						t.Fatal("native read signal unavailable")
					}
					if public {
						c.writer.CloseNotify()
					}
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
					wantGone := public || mode != 0
					select {
					case <-done:
						if !wantGone {
							t.Error("read signal overtook sequential dispatch")
						}
					default:
						if wantGone {
							t.Error("terminal read did not notify while callbacks drained")
						}
					}
					if c.writer.Closed() {
						t.Error("read signal published Closed before callback completion")
					}
					select {
					case <-c.done:
						t.Error("read signal completed dispatch before callback completion")
					default:
					}
					unblock()
					<-served
					select {
					case <-done:
					default:
						t.Error("reader completion lost terminal notification")
					}
				})
			})
		}
	}
}

func TestReadSignalWaitsForDispatchCapacity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, peer := net.Pipe()
		raw := &restartTransport{Conn: local, reads: make(chan restartRead), closed: make(chan struct{})}
		entered := make(chan struct{}, 2)
		first, second := make(chan struct{}), make(chan struct{})
		releaseFirst, releaseSecond := sync.OnceFunc(func() { close(first) }), sync.OnceFunc(func() { close(second) })
		index := 0
		c := (&Server{MaxConcurrentHandlers: 1, Handler: HandlerFunc(func(Conn, *Message) {
			index++
			gate := first
			if index == 2 {
				gate = second
			}
			entered <- struct{}{}
			<-gate
		})}).newConn(raw)
		done, _ := transport.ReadDone(c.writer)
		served := make(chan struct{})
		go func() { c.serve(); close(served) }()
		defer func() { releaseFirst(); releaseSecond(); _ = raw.Close(); _ = peer.Close(); <-served }()
		frame := cerPayload(t, newTestDictionary(dict.Base()))
		raw.reads <- restartRead{data: frame}
		<-entered
		raw.reads <- restartRead{data: frame}
		go func() {
			select {
			case raw.reads <- restartRead{err: io.EOF}:
			case <-raw.closed:
			}
		}()
		synctest.Wait()
		select {
		case <-done:
			t.Error("EOF overtook a reader waiting for dispatch capacity")
		default:
		}
		releaseFirst()
		<-entered
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Error("EOF notification waited for the remaining callback to drain")
		}
	})
}

type signalReadTransport struct {
	net.Conn
	read func([]byte) (int, error)
}

func (c signalReadTransport) Read(b []byte) (int, error) { return c.read(b) }

func TestReadSignalRetainsFinalDataAndRestart(t *testing.T) {
	local, peer := net.Pipe()
	defer func() { _ = local.Close(); _ = peer.Close() }()
	restart := &TransportRestartError{AssociationID: 42}
	for _, err := range []error{restart, io.EOF, io.ErrUnexpectedEOF} {
		t.Run(err.Error(), func(t *testing.T) {
			raw := signalReadTransport{Conn: local, read: func(b []byte) (int, error) { return copy(b, "abc"), err }}
			c := (&Server{}).newConn(raw)
			done, _ := transport.ReadDone(c.writer)
			b := make([]byte, 3)
			n, readErr := c.sr.Read(b)
			if n != 3 || string(b) != "abc" || !errors.Is(readErr, err) {
				t.Fatalf("final read = %d, %q, %v", n, b, readErr)
			}
			select {
			case <-done:
				if err == restart {
					t.Error("restart was reported as terminal transport loss")
				}
			default:
				if err != restart {
					t.Error("final bytes delayed terminal transport notification")
				}
			}
		})
	}
}

func TestReadSignalRegistrationDuringSocketRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, peer := net.Pipe()
		defer func() { _ = local.Close(); _ = peer.Close() }()
		entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
		raw := signalReadTransport{Conn: local, read: func([]byte) (int, error) {
			close(entered)
			<-release
			return 0, io.EOF
		}}
		c := (&Server{}).newConn(raw)
		go func() { _, _ = c.sr.Read(make([]byte, 1)); close(returned) }()
		<-entered
		done, _ := transport.ReadDone(c.writer)
		close(release)
		<-returned
		select {
		case <-done:
		default:
			t.Fatal("registration during a socket read missed terminal notification")
		}
	})
}

func TestReadSignalRegistrationAfterTerminalRead(t *testing.T) {
	local, peer := net.Pipe()
	defer func() { _ = local.Close(); _ = peer.Close() }()
	raw := signalReadTransport{Conn: local, read: func([]byte) (int, error) { return 0, io.EOF }}
	c := (&Server{}).newConn(raw)
	if _, err := c.sr.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal(err)
	}
	done, _ := transport.ReadDone(c.writer)
	select {
	case <-done:
	default:
		t.Fatal("registration after terminal read missed transport loss")
	}
	if c.writer.Closed() {
		t.Fatal("read notification published Closed before dispatch completion")
	}
}

func TestReadSignalKeepsMultistreamObserver(t *testing.T) {
	local, peer := net.Pipe()
	defer func() { _ = local.Close(); _ = peer.Close() }()
	raw := &restartTransport{Conn: local, reads: make(chan restartRead), closed: make(chan struct{})}
	multi := &eofDispatchTransport{fencedMultistream: &fencedMultistream{Conn: raw}}
	c := (&Server{}).newConn(multi)
	done, _ := transport.ReadDone(c.writer)
	multi.mu.Lock()
	onError := multi.onError
	multi.mu.Unlock()
	if onError == nil {
		t.Fatal("multistream read signal did not install the transport error observer")
	}
	onError(multi, &TransportRestartError{AssociationID: 42})
	select {
	case <-done:
		t.Fatal("multistream restart closed the transport loss signal")
	default:
	}
	onError(multi, io.EOF)
	select {
	case <-done:
	default:
		t.Fatal("multistream terminal error did not close the transport loss signal")
	}
}
