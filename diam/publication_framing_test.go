package diam

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

type framingWriteResult struct {
	n   int64
	err error
}

// Pause outside the native writer after its first return. A competing frame
// can then expose a write gate released between a prefix and its retry.
type framingPausedConn struct {
	Conn
	first  chan framingWriteResult
	resume <-chan struct{}
	calls  int
}

func (c *framingPausedConn) Unwrap() Conn { return c.Conn }

func (c *framingPausedConn) WriteStream(b []byte, stream uint) (int, error) {
	n, err := c.Conn.WriteStream(b, stream)
	c.calls++
	if c.calls == 1 {
		c.first <- framingWriteResult{int64(n), err}
		<-c.resume
	}
	return n, err
}

func framingTCPPair(t *testing.T) (*response, *net.TCPConn, *Server) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	sender, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sender.Close() })
	peer, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	if err := sender.SetWriteBuffer(1024); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetReadBuffer(1024); err != nil {
		t.Fatal(err)
	}
	server := &Server{WriteTimeout: 30 * time.Millisecond}
	writer := server.newConn(sender).writer
	t.Cleanup(writer.Close)
	writer.PendingRequests()
	return writer, peer, server
}

func framingCompetingMessage(kind string) *Message {
	if kind == "application" {
		return NewMessage(998, RequestFlag, 42, 81, 82, dict.Default)
	}
	flags := uint8(0)
	if kind == "DPR" {
		flags = RequestFlag
	}
	m := NewMessage(DisconnectPeer, flags, 0, 81, 82, dict.Default)
	m.AddAVP(NewAVP(264, 0x40, 0, datatype.DiameterIdentity("sender.example")))
	m.AddAVP(NewAVP(296, 0x40, 0, datatype.DiameterIdentity("example")))
	if kind == "DPR" {
		m.AddAVP(NewAVP(273, 0x40, 0, datatype.Enumerated(1)))
	} else {
		m.AddAVP(NewAVP(268, 0x40, 0, datatype.Unsigned32(Success)))
	}
	return m
}

func framingReadPrefix(t *testing.T, peer *net.TCPConn) []byte {
	t.Helper()
	if err := peer.SetReadBuffer(1 << 20); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	prefix, err := io.ReadAll(peer)
	if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("drain transmitted prefix: %v", err)
	}
	return prefix
}

func TestNativeTCPPublicationFrameIntegrity(t *testing.T) {
	// The test needs a TCP write that stalls on a full send buffer. Windows
	// auto-tunes the send buffer and accepts the whole 1 MiB frame, so the
	// write never stalls there; frame integrity is platform independent and
	// this test exercises it on the other platforms.
	if runtime.GOOS == "windows" {
		t.Skip("cannot stall a TCP write on Windows: its send buffer grows to fit the frame")
	}
	for _, retries := range []uint{0, 1} {
		for _, competitor := range []string{"application", "DPR", "DPA"} {
			t.Run(fmt.Sprintf("retries=%d/competitor=%s", retries, competitor), func(t *testing.T) {
				writer, peer, server := framingTCPPair(t)
				request := NewMessage(999, RequestFlag, 42, 71, 72, dict.Default)
				request.AddAVP(NewAVP(0xffff, 0, 0, datatype.OctetString(bytes.Repeat([]byte{0x55}, 1<<20))))
				frame, err := request.Serialize()
				if err != nil {
					t.Fatal(err)
				}
				resume := make(chan struct{})
				var resumeOnce sync.Once
				unblock := func() { resumeOnce.Do(func() { close(resume) }) }
				t.Cleanup(unblock)
				paused := &framingPausedConn{Conn: writer, first: make(chan framingWriteResult, 1), resume: resume}
				result := make(chan framingWriteResult, 1)
				go func() {
					n, err := request.WriteToWithRetry(paused, retries)
					result <- framingWriteResult{n, err}
				}()
				select {
				case first := <-paused.first:
					if timeout, ok := first.err.(net.Error); !ok || !timeout.Timeout() {
						unblock()
						t.Fatalf("first stalled TCP write=%d,%v; want timeout", first.n, first.err)
					}
				case <-time.After(5 * time.Second):
					unblock()
					t.Fatal("stalled TCP write did not reach its deadline")
				}
				prefix := framingReadPrefix(t, peer)
				if len(prefix) == 0 || len(prefix) >= len(frame) || !bytes.Equal(prefix, frame[:len(prefix)]) {
					unblock()
					t.Fatalf("expected actual incomplete TCP frame, received %d of %d bytes", len(prefix), len(frame))
				}
				// The paused first call has finished using this configuration. Make
				// the now-draining TCP socket writable for either competing frame.
				server.WriteTimeout = 2 * time.Second
				if err := peer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					unblock()
					t.Fatal(err)
				}
				tail := make(chan []byte, 1)
				go func() { b, _ := io.ReadAll(peer); tail <- b }()
				other := framingCompetingMessage(competitor)
				otherFrame, err := other.Serialize()
				if err != nil {
					unblock()
					t.Fatal(err)
				}
				competingN, competingErr := other.WriteTo(writer)
				unblock()
				var completed framingWriteResult
				select {
				case completed = <-result:
				case <-time.After(5 * time.Second):
					t.Fatal("retried frame did not finish")
				}
				writer.Close()
				var wire []byte
				select {
				case remaining := <-tail:
					wire = append(prefix, remaining...)
				case <-time.After(5 * time.Second):
					t.Fatal("TCP receiver did not finish")
				}
				if len(wire) < len(frame) {
					// RFC 6733 §3: a failed prefix is not a boundary at which
					// another Diameter frame can begin on this byte stream.
					if !bytes.Equal(wire, frame[:len(wire)]) {
						t.Fatalf("unfinished native TCP frame followed by competing %s: prefix=%d wire=%d competing=%d,%v request=%d,%v", competitor, len(prefix), len(wire), competingN, competingErr, completed.n, completed.err)
					}
					if competingErr == nil || completed.err == nil {
						t.Fatalf("partial frame reported success: competing=%d,%v request=%d,%v", competingN, competingErr, completed.n, completed.err)
					}
					return
				}
				if !bytes.Equal(wire[:len(frame)], frame) {
					t.Fatalf("competing %s interleaved with native TCP retry: initial-prefix=%d frame=%d wire=%d", competitor, len(prefix), len(frame), len(wire))
				}
				remaining := wire[len(frame):]
				if competingErr == nil && !bytes.Equal(remaining, otherFrame) || competingErr != nil && len(remaining) != 0 {
					t.Fatalf("competing %s frame was truncated or lost after complete request", competitor)
				}
			})
		}
	}
}
