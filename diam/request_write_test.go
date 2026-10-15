package diam

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/dict"
)

func TestCompletedRequestWaitingForWriteGate(t *testing.T) {
	for _, retries := range []uint{0, 1} {
		t.Run(fmt.Sprintf("retries=%d", retries), func(t *testing.T) {
			local, peer := net.Pipe()
			defer func() { _ = peer.Close() }()
			c := (&Server{}).newConn(local)
			defer c.writer.Close()
			requests := c.writer.PendingRequests()
			request := NewRequest(999, 42, dict.Default)
			reservation := requests.PrepareWrite(request.Header)
			if err := c.writer.lockWrite(); err != nil {
				t.Fatal(err)
			}
			wrapped := pendingAdmissionConn{c.writer, make(chan struct{})}
			result := make(chan error, 1)
			go func() { _, err := request.WriteToWithRetry(wrapped, retries); result <- err }()
			<-wrapped.entered
			reservation.Cancel()
			select {
			case err := <-result:
				if !errors.Is(err, ErrRequestCompleted) {
					t.Errorf("completed gate waiter=%v", err)
				}
			case <-time.After(time.Second):
				c.writer.unlockWrite()
				t.Fatal("completion did not release the queued writer")
			}
			reservation.Release()
			c.writer.unlockWrite()
			requests.mu.Lock()
			pending, reserved := len(requests.pending), len(requests.reserved)
			requests.mu.Unlock()
			if pending != 0 || reserved != 0 {
				t.Fatalf("completed request leaked trackers: pending=%d reserved=%d", pending, reserved)
			}
			if err := peer.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			var b [1]byte
			if n, err := peer.Read(b[:]); n != 0 {
				t.Fatalf("completed request reached transport: n=%d error=%v", n, err)
			}
		})
	}
}

func TestRequestWriteCompletionAfterGateAcquisition(t *testing.T) {
	local, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	c := (&Server{}).newConn(local)
	defer c.writer.Close()
	p := c.writer.PendingRequests()
	request := NewRequest(999, 42, dict.Default)
	r := p.PrepareWrite(request.Header)
	frame, err := request.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.writer.lockWriteRequest(frame); err != nil {
		t.Fatal(err)
	}
	if !p.HasPending() {
		t.Error("gate acquisition failed to register answer ownership")
	}
	r.Release() // Writer completion must leave ownership available for the answer.
	if !p.HasPending() {
		t.Error("release removed live answer ownership")
	}
	r.Cancel()
	c.writer.unlockWrite()
	if p.HasPending() || len(p.reserved) != 0 {
		t.Fatal("completion after selection release leaked ownership")
	}
}

func TestRequestWriteCancelCannotBeRestoredByFailedOverlap(t *testing.T) {
	p := new(PendingRequests)
	request := NewRequest(999, 42, dict.Default)
	frame, err := request.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	selected := p.PrepareWrite(request.Header)
	p.BeginWrite(frame)(true)
	selected.Release()
	failed := p.BeginWrite(frame)
	selected.Cancel()
	failed(false)
	if p.HasPending() {
		t.Fatal("failed overlapping write restored completed request ownership")
	}
}
