package diam

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/dict"
)

type pendingAdmissionConn struct {
	Conn
	entered chan struct{}
}

func (c pendingAdmissionConn) Unwrap() Conn { return c.Conn }
func (c pendingAdmissionConn) WriteStream(b []byte, stream uint) (int, error) {
	close(c.entered)
	return c.Conn.WriteStream(b, stream)
}

func TestPendingRequestHeldWriteGateWire(t *testing.T) {
	for _, retries := range []uint{0, 1} {
		t.Run(fmt.Sprintf("retries=%d", retries), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			dialed := make(chan net.Conn, 1)
			go func() { c, _ := net.Dial("tcp", listener.Addr().String()); dialed <- c }()
			raw, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			peer := <-dialed
			defer func() { _ = peer.Close() }()
			c := (&Server{}).newConn(raw)
			defer c.writer.Close()
			requests := c.writer.PendingRequests()
			if err := c.writer.lockWrite(); err != nil {
				t.Fatal(err)
			}
			wrapped := pendingAdmissionConn{c.writer, make(chan struct{})}
			request := NewRequest(999, 42, dict.Default)
			result := make(chan error, 1)
			go func() { _, err := request.WriteToWithRetry(wrapped, retries); result <- err }()
			<-wrapped.entered
			requests.CloseAdmission()
			if requests.HasPending() {
				t.Error("unsent retry reservation counted as in flight")
			}
			if requests.MatchAnswer(request.Answer(Success), false) {
				t.Error("unsent retry answer admitted during Closing")
			}
			c.writer.unlockWrite()
			if err := <-result; err == nil {
				t.Error("request published after Closing")
			}
			if err := peer.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			var b [1]byte
			if n, err := peer.Read(b[:]); n != 0 {
				t.Errorf("post-Closing request reached transport: bytes=%d error=%v", n, err)
			}
		})
	}
}
