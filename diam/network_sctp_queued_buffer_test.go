package diam

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-sctp"
)

type queuedSCTPReceiver struct {
	entered, buffered, data, zero chan struct{}
	dataOnce, zeroOnce            sync.Once
	calls, active                 atomic.Int32
	concurrent                    atomic.Bool
	failure                       error
	retry                         bool
	firstStream                   uint16
	dataWithError                 bool
}

func (r *queuedSCTPReceiver) release() {
	r.dataOnce.Do(func() { close(r.data) })
	r.zeroOnce.Do(func() { close(r.zero) })
}

func (r *queuedSCTPReceiver) RecvMsg(b []byte) (int, sctp.MsgInfo, error) {
	if r.active.Add(1) != 1 {
		r.concurrent.Store(true)
	}
	defer r.active.Add(-1)
	switch r.calls.Add(1) {
	case 1:
		close(r.entered)
		<-r.data
		if r.failure != nil && !r.dataWithError {
			return 0, sctp.MsgInfo{}, r.failure
		}
		return copy(b, "buffered-stream-one"), sctp.MsgInfo{Rcv: sctp.RcvInfo{Stream: r.firstStream}, EOR: true}, r.failure
	case 2:
		close(r.buffered)
		<-r.zero
		if r.retry {
			return copy(b, "buffered-stream-one"), sctp.MsgInfo{Rcv: sctp.RcvInfo{Stream: 1}, EOR: true}, nil
		}
		if r.failure != nil {
			return 0, sctp.MsgInfo{}, r.failure
		}
		return copy(b, "waiting-stream-zero"), sctp.MsgInfo{Rcv: sctp.RcvInfo{Stream: 0}, EOR: true}, nil
	default:
		return 0, sctp.MsgInfo{}, io.EOF
	}
}

func sctpReaderID() string {
	var stack [64]byte
	n := runtime.Stack(stack[:], false)
	return strings.Fields(string(stack[:n]))[1]
}

// Observe the wait before releasing input; a goroutine-start signal alone
// does not establish that the reader checked its empty buffer and queued.
func awaitSCTPQueuedReader(t *testing.T, id string) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()
	for {
		stack := make([]byte, 256<<10)
		n := runtime.Stack(stack, true)
		trace := string(stack[:n])
		if start := strings.Index(trace, "goroutine "+id+" ["); start >= 0 {
			trace = trace[start:]
			if end := strings.Index(trace, "\n\n"); end >= 0 {
				trace = trace[:end]
			}
			if strings.Contains(trace, "(*SCTPConn).Read") && !strings.Contains(trace, "(*SCTPConn).readBuffered") &&
				(strings.Contains(trace, "(*Mutex).lockSlow") || strings.Contains(trace, "(*Cond).Wait")) {
				return
			}
		}
		select {
		case <-ticker.C:
		case <-timeout.C:
			t.Fatal("second SCTP reader did not enter the receive wait path")
		}
	}
}

func readQueuedSCTP(c *SCTPConn, method string) bufferedSCTPRead {
	b := make([]byte, 64)
	var n int
	var err error
	stream := uint(1)
	switch method {
	case "ReadStream":
		n, err = c.ReadStream(b, 1)
	case "ReadAny":
		n, stream, err = c.ReadAny(b)
	case "ReadAtLeast":
		n, stream, err = c.ReadAtLeast(b, len("buffered-stream-one"), 1)
	case "ReadAtLeastAny":
		n, stream, err = c.ReadAtLeast(b, len("buffered-stream-one"), InvalidStreamID)
	case "Read":
		n, err = c.Read(b)
	}
	return bufferedSCTPRead{data: string(b[:n]), stream: stream, err: err}
}

func TestSCTPQueuedBufferedReadersWake(t *testing.T) {
	for _, aware := range []bool{false, true} {
		for _, method := range []string{"ReadStream", "ReadAny", "ReadAtLeast", "ReadAtLeastAny", "Read"} {
			t.Run(fmt.Sprintf("%s/restart=%v", method, aware), func(t *testing.T) {
				r := &queuedSCTPReceiver{entered: make(chan struct{}), buffered: make(chan struct{}), data: make(chan struct{}), zero: make(chan struct{}), firstStream: 1}
				c := newSCTPConn(nil)
				c.receiver, c.restartAware = r, aware
				c.SetCurrentStream(1)
				first, second := make(chan bufferedSCTPRead, 1), make(chan bufferedSCTPRead, 1)
				consumed := false
				go func() {
					b := make([]byte, 64)
					n, err := c.ReadStream(b, 0)
					first <- bufferedSCTPRead{data: string(b[:n]), err: err}
				}()
				t.Cleanup(func() {
					r.release()
					select {
					case got := <-first:
						if got.err != nil || got.data != "waiting-stream-zero" {
							t.Errorf("first SCTP reader = %+v", got)
						}
					case <-time.After(time.Second):
						t.Error("first SCTP reader did not finish after release")
					}
					if !consumed {
						select {
						case <-second:
						case <-time.After(time.Second):
							t.Error("queued SCTP reader did not finish after release")
						}
					}
				})
				<-r.entered
				id := make(chan string)
				go func() { id <- sctpReaderID(); second <- readQueuedSCTP(c, method) }()
				awaitSCTPQueuedReader(t, <-id)
				r.dataOnce.Do(func() { close(r.data) })
				<-r.buffered
				select {
				case got := <-second:
					consumed = true
					if got.err != nil || got.data != "buffered-stream-one" || got.stream != 1 {
						t.Fatalf("queued buffered read = %+v", got)
					}
				case <-time.After(250 * time.Millisecond):
					t.Fatal("already-queued stream 1 reader did not wake for buffered DATA without stream 0 input")
				}
				if r.concurrent.Load() || r.calls.Load() != 2 {
					t.Fatalf("wire receives: concurrent=%v calls=%d; want one receiver and two records", r.concurrent.Load(), r.calls.Load())
				}
			})
		}
	}
}

func TestSCTPQueuedReadersObserveReceiveFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"EOF", io.EOF},
		{"deadline", os.ErrDeadlineExceeded},
		{"Close", net.ErrClosed},
		{"malformed", sctp.ErrShortNotification},
		{"restart", &TransportRestartError{}},
	} {
		for _, method := range []string{"ReadStream", "ReadAny", "ReadAtLeast", "ReadAtLeastAny", "Read"} {
			t.Run(tc.name+"/"+method, func(t *testing.T) {
				r := &queuedSCTPReceiver{entered: make(chan struct{}), buffered: make(chan struct{}), data: make(chan struct{}), zero: make(chan struct{}), failure: tc.err}
				c := newRestartSCTPConn(nil)
				c.receiver = r
				c.SetCurrentStream(1)
				first, second := make(chan error, 1), make(chan bufferedSCTPRead, 1)
				consumed := false
				go func() { _, err := c.ReadStream(make([]byte, 64), 0); first <- err }()
				t.Cleanup(func() {
					r.release()
					if !consumed {
						select {
						case <-second:
						case <-time.After(time.Second):
							t.Error("queued failed reader did not finish after release")
						}
					}
				})
				<-r.entered
				id := make(chan string)
				go func() { id <- sctpReaderID(); second <- readQueuedSCTP(c, method) }()
				awaitSCTPQueuedReader(t, <-id)
				r.dataOnce.Do(func() { close(r.data) })
				if err := <-first; !errors.Is(err, tc.err) {
					t.Fatalf("receiver error = %v, want %v", err, tc.err)
				}
				select {
				case got := <-second:
					consumed = true
					if got.data != "" || !errors.Is(got.err, tc.err) {
						t.Fatalf("queued receive failure = %+v, want %v", got, tc.err)
					}
				case <-time.After(250 * time.Millisecond):
					t.Fatal("queued reader did not observe the connection-wide receive failure")
				}
				if r.calls.Load() != 1 || r.concurrent.Load() {
					t.Fatalf("queued reader retried failed receive: calls=%d concurrent=%v", r.calls.Load(), r.concurrent.Load())
				}
			})
		}
	}
}

func TestSCTPQueuedReadersReleaseReceiveToken(t *testing.T) {
	for _, method := range []string{"ReadStream", "ReadAny"} {
		t.Run(method, func(t *testing.T) {
			r := &queuedSCTPReceiver{entered: make(chan struct{}), buffered: make(chan struct{}), data: make(chan struct{}), zero: make(chan struct{}), retry: true}
			c := newSCTPConn(nil)
			c.receiver = r
			first, second := make(chan error, 1), make(chan bufferedSCTPRead, 1)
			go func() {
				b := make([]byte, 64)
				var err error
				if method == "ReadAny" {
					_, _, err = c.ReadAny(b)
				} else {
					_, err = c.ReadStream(b, 0)
				}
				first <- err
			}()
			<-r.entered
			id := make(chan string)
			go func() { id <- sctpReaderID(); second <- readQueuedSCTP(c, "ReadStream") }()
			awaitSCTPQueuedReader(t, <-id)
			r.release()
			if err := <-first; err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-second:
				if got.err != nil || got.data != "buffered-stream-one" {
					t.Fatalf("reader after receive-token handoff = %+v", got)
				}
			case <-time.After(time.Second):
				t.Fatal("queued reader did not wake when the successful receiver returned")
			}
			if r.concurrent.Load() || r.calls.Load() != 2 {
				t.Fatalf("receive-token handoff: calls=%d concurrent=%v", r.calls.Load(), r.concurrent.Load())
			}
		})
	}
}

func TestSCTPReceiveFailureAllowsLaterRetry(t *testing.T) {
	r := &queuedSCTPReceiver{entered: make(chan struct{}), buffered: make(chan struct{}), data: make(chan struct{}), zero: make(chan struct{}), failure: os.ErrDeadlineExceeded, retry: true}
	c := newSCTPConn(nil)
	c.receiver = r
	r.release()
	if _, err := c.ReadStream(make([]byte, 64), 0); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("initial receive failure = %v", err)
	}
	if got := readQueuedSCTP(c, "ReadAny"); got.err != nil || got.data != "buffered-stream-one" || got.stream != 1 {
		t.Fatalf("read after a temporary receive failure = %+v", got)
	}
	if r.calls.Load() != 2 {
		t.Fatalf("later read did not retry receive: calls=%d", r.calls.Load())
	}
}

func TestSCTPForeignStreamDataPrecedesReceiveFailure(t *testing.T) {
	r := &queuedSCTPReceiver{entered: make(chan struct{}), buffered: make(chan struct{}), data: make(chan struct{}), zero: make(chan struct{}), firstStream: 1, failure: io.EOF, dataWithError: true}
	c := newSCTPConn(nil)
	c.receiver = r
	r.release()
	if _, err := c.ReadStream(make([]byte, 64), 0); !errors.Is(err, io.EOF) {
		t.Fatalf("foreign-stream receive failure = %v", err)
	}
	if got := readQueuedSCTP(c, "ReadStream"); got.err != nil || got.data != "buffered-stream-one" {
		t.Fatalf("data buffered alongside EOF = %+v", got)
	}
	if r.calls.Load() != 1 {
		t.Fatalf("buffered data retried receive: calls=%d", r.calls.Load())
	}
}

func TestSCTPQueuedReaderWakesBeforeErrorHandlerReturns(t *testing.T) {
	r := &queuedSCTPReceiver{entered: make(chan struct{}), buffered: make(chan struct{}), data: make(chan struct{}), zero: make(chan struct{}), failure: io.EOF}
	c := newSCTPConn(nil)
	c.receiver = r
	handling, release := make(chan struct{}), make(chan struct{})
	c.SetErrorHandler(func(MultistreamConn, error) { close(handling); <-release })
	first, second := make(chan error, 1), make(chan bufferedSCTPRead, 1)
	consumed := false
	go func() { _, _, err := c.ReadAny(make([]byte, 64)); first <- err }()
	t.Cleanup(func() {
		close(release)
		r.release()
		if err := <-first; !errors.Is(err, io.EOF) {
			t.Errorf("error-handler owner = %v", err)
		}
		if !consumed {
			select {
			case <-second:
			case <-time.After(time.Second):
				t.Error("queued error reader did not finish after handler release")
			}
		}
	})
	<-r.entered
	id := make(chan string)
	go func() { id <- sctpReaderID(); second <- readQueuedSCTP(c, "ReadStream") }()
	awaitSCTPQueuedReader(t, <-id)
	r.dataOnce.Do(func() { close(r.data) })
	<-handling
	select {
	case got := <-second:
		consumed = true
		if got.data != "" || !errors.Is(got.err, io.EOF) {
			t.Fatalf("queued reader while error handler waits = %+v", got)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("queued reader waited for the receive error handler")
	}
}
