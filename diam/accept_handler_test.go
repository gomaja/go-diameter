package diam_test

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
)

type acceptLifecycleHandler struct {
	accepted atomic.Int32
	closed   atomic.Int32
	opened   chan struct{}
	done     chan struct{}
}

func (h *acceptLifecycleHandler) ServeDIAM(diam.Conn, *diam.Message) {}
func (h *acceptLifecycleHandler) HandleAccept(diam.Conn) func() {
	h.accepted.Add(1)
	h.opened <- struct{}{}
	return func() { h.closed.Add(1); h.done <- struct{}{} }
}

func TestAcceptHandlerOnlyRunsForAcceptedConnections(t *testing.T) {
	h := &acceptLifecycleHandler{opened: make(chan struct{}, 2), done: make(chan struct{}, 2)}
	srv := diamtest.NewServer(h, dict.Default)
	defer srv.Close()
	client, err := diam.Dial(srv.Addr, h, dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case <-h.opened:
	case <-time.After(time.Second):
		t.Fatal("HandleAccept not called")
	}
	client.Close()
	select {
	case <-h.done:
	case <-time.After(time.Second):
		t.Fatal("accept cleanup not called")
	}
	done, ok := diam.ConnAs[interface{ DispatchDone() <-chan struct{} }](client)
	if !ok {
		t.Fatal("client does not expose DispatchDone")
	}
	select {
	case <-done.DispatchDone():
	case <-time.After(time.Second):
		t.Fatal("client did not close")
	}
	if got := h.accepted.Load(); got != 1 {
		t.Fatalf("HandleAccept calls = %d, want 1", got)
	}
	if got := h.closed.Load(); got != 1 {
		t.Fatalf("accept cleanup calls = %d, want 1", got)
	}
}
