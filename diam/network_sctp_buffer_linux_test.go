//go:build linux && !386

package diam

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-sctp"
)

func TestSCTPBufferedReadDoesNotWaitForReceiveOnWire(t *testing.T) {
	requireSCTP(t)
	for _, accepted := range []bool{false, true} {
		t.Run(fmt.Sprintf("accepted=%v", accepted), func(t *testing.T) {
			listener, err := MultistreamListen("sctp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			incoming := make(chan net.Conn, 1)
			acceptErr := make(chan error, 1)
			go func() {
				c, err := listener.Accept()
				if err != nil {
					acceptErr <- err
					return
				}
				incoming <- c
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			dialed, err := (sctpDialer{}).DialContext(ctx, "sctp4", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = dialed.Close() })
			var peer net.Conn
			select {
			case peer = <-incoming:
			case err = <-acceptErr:
				t.Fatal(err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			t.Cleanup(func() { _ = peer.Close() })
			receiver, sender := dialed.(*SCTPConn), peer.(*SCTPConn)
			if accepted {
				receiver, sender = sender, receiver
			}
			if err := receiver.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			first := make(chan error, 1)
			second := make(chan error, 1)
			secondStarted, secondConsumed := false, false
			go func() {
				b := make([]byte, 64)
				n, err := receiver.ReadStream(b, 0)
				if err == nil && string(b[:n]) != "waiting-stream-zero" {
					err = fmt.Errorf("waiting stream data %q", b[:n])
				}
				first <- err
			}()
			t.Cleanup(func() {
				if _, err := sender.WriteStream([]byte("waiting-stream-zero"), 0); err != nil {
					t.Error(err)
				}
				select {
				case err := <-first:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(time.Second):
					t.Error("waiting SCTP reader did not finish after release")
				}
				if secondStarted && !secondConsumed {
					select {
					case <-second:
					case <-time.After(time.Second):
						t.Error("buffered SCTP reader did not finish after release")
					}
				}
			})
			if _, err := sender.WriteStream([]byte("buffered-stream-one"), 1); err != nil {
				t.Fatal(err)
			}
			for {
				receiver.streamBuffMu.Lock()
				sb := receiver.s.streamMap[1]
				buffered := sb != nil && sb.Len() == len("buffered-stream-one")
				receiver.streamBuffMu.Unlock()
				if buffered {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("stream 1 was not buffered by the stream 0 reader")
				case <-time.After(time.Millisecond):
				}
			}
			secondStarted = true
			go func() {
				b := make([]byte, 64)
				n, err := receiver.ReadStream(b, 1)
				if err == nil && string(b[:n]) != "buffered-stream-one" {
					err = fmt.Errorf("buffered stream data %q", b[:n])
				}
				second <- err
			}()
			select {
			case err := <-second:
				secondConsumed = true
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(250 * time.Millisecond):
				t.Fatal("buffered SCTP stream 1 read waited for stream 0 input")
			}
		})
	}
}

type queuedSCTPWireReceiver struct {
	sctpMessageReceiver
	entered, release, buffered chan struct{}
	calls                      atomic.Int32
	seen                       atomic.Bool
	once                       sync.Once
	releaseOnce                sync.Once
}

func (r *queuedSCTPWireReceiver) RecvMsg(b []byte) (int, sctp.MsgInfo, error) {
	if r.calls.Add(1) == 1 {
		close(r.entered)
		<-r.release
	}
	if r.seen.Load() {
		r.once.Do(func() { close(r.buffered) })
	}
	n, info, err := r.sctpMessageReceiver.RecvMsg(b)
	if n > 0 && !info.Notification && info.Rcv.Stream == 1 {
		r.seen.Store(true)
	}
	return n, info, err
}

func newSCTPBufferPair(t *testing.T, accepted bool) (*SCTPConn, *SCTPConn) {
	t.Helper()
	listener, err := MultistreamListen("sctp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	incoming := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		incoming <- c
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	dialed, err := (sctpDialer{}).DialContext(ctx, "sctp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dialed.Close() })
	var peer net.Conn
	select {
	case peer = <-incoming:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	t.Cleanup(func() { _ = peer.Close() })
	receiver, sender := dialed.(*SCTPConn), peer.(*SCTPConn)
	if accepted {
		receiver, sender = sender, receiver
	}
	if err := receiver.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return receiver, sender
}

func TestSCTPQueuedBufferedReadersWakeOnWire(t *testing.T) {
	requireSCTP(t)
	for _, accepted := range []bool{false, true} {
		for _, method := range []string{"ReadStream", "ReadAny"} {
			t.Run(fmt.Sprintf("%s/accepted=%v", method, accepted), func(t *testing.T) {
				receiver, sender := newSCTPBufferPair(t, accepted)
				r := &queuedSCTPWireReceiver{sctpMessageReceiver: receiver.receiver, entered: make(chan struct{}), release: make(chan struct{}), buffered: make(chan struct{})}
				receiver.receiver = r
				first := make(chan error, 1)
				second := make(chan bufferedSCTPRead, 1)
				consumed := false
				go func() {
					b := make([]byte, 64)
					n, err := receiver.ReadStream(b, 0)
					if err == nil && string(b[:n]) != "waiting-stream-zero" {
						err = fmt.Errorf("waiting stream data %q", b[:n])
					}
					first <- err
				}()
				t.Cleanup(func() {
					r.releaseOnce.Do(func() { close(r.release) })
					if _, err := sender.WriteStream([]byte("waiting-stream-zero"), 0); err != nil {
						t.Error(err)
					}
					select {
					case err := <-first:
						if err != nil {
							t.Error(err)
						}
					case <-time.After(time.Second):
						t.Error("wire receiver did not finish after stream 0 release")
					}
					if !consumed {
						_ = receiver.Close()
						select {
						case <-second:
						case <-time.After(time.Second):
							t.Error("queued wire reader did not finish after release")
						}
					}
				})
				<-r.entered
				id := make(chan string)
				go func() { id <- sctpReaderID(); second <- readQueuedSCTP(receiver, method) }()
				awaitSCTPQueuedReader(t, <-id)
				if _, err := sender.WriteStream([]byte("buffered-stream-one"), 1); err != nil {
					t.Fatal(err)
				}
				r.releaseOnce.Do(func() { close(r.release) })
				<-r.buffered
				select {
				case got := <-second:
					consumed = true
					if got.err != nil || got.data != "buffered-stream-one" || got.stream != 1 {
						t.Fatalf("queued SCTP wire read = %+v", got)
					}
				case <-time.After(250 * time.Millisecond):
					t.Fatal("already-queued SCTP reader did not wake for stream 1 DATA without stream 0 input")
				}
			})
		}
	}
}

func TestSCTPQueuedReadersObserveReceiveFailureOnWire(t *testing.T) {
	requireSCTP(t)
	for _, accepted := range []bool{false, true} {
		for _, failure := range []string{"deadline", "Close"} {
			t.Run(fmt.Sprintf("%s/accepted=%v", failure, accepted), func(t *testing.T) {
				receiver, _ := newSCTPBufferPair(t, accepted)
				r := &queuedSCTPWireReceiver{sctpMessageReceiver: receiver.receiver, entered: make(chan struct{}), release: make(chan struct{}), buffered: make(chan struct{})}
				receiver.receiver = r
				first, second := make(chan error, 1), make(chan bufferedSCTPRead, 1)
				firstConsumed, secondConsumed := false, false
				t.Cleanup(func() {
					r.releaseOnce.Do(func() { close(r.release) })
					_ = receiver.Close()
					if !firstConsumed {
						select {
						case <-first:
						case <-time.After(time.Second):
							t.Error("wire receiver did not finish after Close")
						}
					}
					if !secondConsumed {
						select {
						case <-second:
						case <-time.After(time.Second):
							t.Error("queued wire reader did not finish after Close")
						}
					}
				})
				go func() { _, err := receiver.ReadStream(make([]byte, 64), 0); first <- err }()
				<-r.entered
				id := make(chan string)
				go func() { id <- sctpReaderID(); second <- readQueuedSCTP(receiver, "ReadAny") }()
				awaitSCTPQueuedReader(t, <-id)
				want := error(net.ErrClosed)
				if failure == "deadline" {
					want = os.ErrDeadlineExceeded
					if err := receiver.SetReadDeadline(time.Now()); err != nil {
						t.Fatal(err)
					}
				} else if err := receiver.Close(); err != nil {
					t.Fatal(err)
				}
				r.releaseOnce.Do(func() { close(r.release) })
				err := <-first
				firstConsumed = true
				if !errors.Is(err, want) {
					t.Fatalf("wire receive failure = %v, want %v", err, want)
				}
				select {
				case got := <-second:
					secondConsumed = true
					if got.data != "" || !errors.Is(got.err, want) {
						t.Fatalf("queued wire receive failure = %+v, want %v", got, want)
					}
				case <-time.After(time.Second):
					t.Fatal("queued wire reader did not observe the connection-wide receive failure")
				}
				if calls := r.calls.Load(); calls != 1 {
					t.Fatalf("queued wire reader retried the failed receive: calls=%d", calls)
				}
			})
		}
	}
}
