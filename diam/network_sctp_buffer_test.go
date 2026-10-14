package diam

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-sctp"
)

type parkedSCTPReceiver struct {
	calls   atomic.Int32
	parked  chan struct{}
	release chan struct{}
	once    sync.Once
	restart bool
}

func (r *parkedSCTPReceiver) resume() { r.once.Do(func() { close(r.release) }) }
func (r *parkedSCTPReceiver) RecvMsg(b []byte) (int, sctp.MsgInfo, error) {
	switch r.calls.Add(1) {
	case 1:
		return copy(b, "buffered-stream-one"), sctp.MsgInfo{Rcv: sctp.RcvInfo{Stream: 1}, EOR: true}, nil
	case 2:
		close(r.parked)
		<-r.release
		if r.restart {
			return copy(b, restartNotification(sctp.AssocRestart, 20)), sctp.MsgInfo{Notification: true, EOR: true}, nil
		}
		return copy(b, "waiting-stream-zero"), sctp.MsgInfo{Rcv: sctp.RcvInfo{Stream: 0}, EOR: true}, nil
	default:
		return 0, sctp.MsgInfo{}, io.EOF
	}
}

func TestSCTPRestartConcurrentReadersFenceBeforeReset(t *testing.T) {
	r := &parkedSCTPReceiver{parked: make(chan struct{}), release: make(chan struct{}), restart: true}
	c := newRestartSCTPConn(nil)
	c.receiver = r
	c.SetCurrentStream(3)
	c.SetWriterStream(6)
	results := make(chan error, 2)
	read := func(stream uint) {
		n, err := c.ReadStream(make([]byte, 64), stream)
		if n != 0 {
			err = fmt.Errorf("reader %d delivered %d bytes across restart", stream, n)
		}
		results <- err
	}
	go read(0)
	<-r.parked
	secondStarted := make(chan struct{})
	go func() { close(secondStarted); read(2) }()
	<-secondStarted
	r.resume()
	for range 2 {
		select {
		case err := <-results:
			var restart *TransportRestartError
			if !errors.As(err, &restart) {
				t.Errorf("concurrent reader lost the restart boundary: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent reader entered a receive beyond the restart marker")
		}
	}
	if calls := r.calls.Load(); calls != 2 {
		t.Fatalf("readers consumed %d records, want DATA and restart only", calls)
	}
	reset := make(chan struct{})
	go func() { c.ResetForRestart(); close(reset) }()
	select {
	case <-reset:
	case <-time.After(time.Second):
		t.Fatal("reset waited for a reader receiving beyond the restart boundary")
	}
	if c.s.Len() != 0 || c.CurrentStream() != InvalidStreamID || c.CurrentWriterStream() != InvalidStreamID {
		t.Fatal("concurrent restart reset retained retired stream state")
	}
}

type bufferedSCTPRead struct {
	data   string
	stream uint
	err    error
}

func TestSCTPBufferedReadsDoNotWaitForReceive(t *testing.T) {
	for _, aware := range []bool{false, true} {
		for _, method := range []string{"ReadStream", "ReadAny", "ReadAtLeast", "Read"} {
			t.Run(fmt.Sprintf("%s/restart=%v", method, aware), func(t *testing.T) {
				r := &parkedSCTPReceiver{parked: make(chan struct{}), release: make(chan struct{})}
				c := newSCTPConn(nil)
				c.receiver, c.restartAware = r, aware
				c.SetCurrentStream(1)
				first := make(chan bufferedSCTPRead, 1)
				second := make(chan bufferedSCTPRead, 1)
				secondConsumed := false
				go func() {
					b := make([]byte, 64)
					n, err := c.ReadStream(b, 0)
					first <- bufferedSCTPRead{data: string(b[:n]), err: err}
				}()
				<-r.parked // Stream 1 is buffered; stream 0 is inside its next receive.
				t.Cleanup(func() {
					r.resume()
					select {
					case got := <-first:
						if got.err != nil || got.data != "waiting-stream-zero" {
							t.Errorf("waiting stream read = %+v", got)
						}
					case <-time.After(time.Second):
						t.Error("waiting reader did not finish after release")
					}
					if !secondConsumed {
						select {
						case <-second:
						case <-time.After(time.Second):
							t.Error("buffered reader did not finish after release")
						}
					}
				})
				go func() {
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
					case "Read":
						n, err = c.Read(b)
					}
					second <- bufferedSCTPRead{data: string(b[:n]), stream: stream, err: err}
				}()
				select {
				case got := <-second:
					secondConsumed = true
					if got.err != nil || got.data != "buffered-stream-one" || got.stream != 1 {
						t.Fatalf("buffered read = %+v", got)
					}
					if r.calls.Load() != 2 {
						t.Fatalf("buffered read entered the receiver: %d calls", r.calls.Load())
					}
				case <-time.After(250 * time.Millisecond):
					t.Fatal("buffered stream 1 read waited for the blocked stream 0 receive")
				}
			})
		}
	}
}
