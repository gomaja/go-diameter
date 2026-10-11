package diam

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type cerWithoutRenewalHandler struct {
	entered   chan Conn
	release   chan struct{}
	delivered chan Conn
	calls     atomic.Int32
}

func (h *cerWithoutRenewalHandler) ServeDIAM(c Conn, m *Message) {
	release := m.BeginDispatch()
	defer release()
	if h.calls.Add(1) == 1 {
		h.entered <- c
		<-h.release
	}
	h.delivered <- c
}

func TestAcceptedCERWithoutEligibilityDoesNotWaitForRetirement(t *testing.T) {
	for _, mode := range []int{1, 2, -1} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				local, remote := net.Pipe()
				transport := &restartTransport{Conn: local, reads: make(chan restartRead, 2), closed: make(chan struct{})}
				h := &cerWithoutRenewalHandler{entered: make(chan Conn, 1), release: make(chan struct{}), delivered: make(chan Conn, 2)}
				srv := &Server{Handler: h, RenewAcceptedCER: true, MaxConcurrentHandlers: mode}
				if _, ok := HandlerAs[AcceptedCERHandler](srv.handler()); ok {
					t.Fatal("test handler unexpectedly supports accepted CER renewal")
				}
				c := srv.newConn(transport)
				c.accepted = true
				finished := make(chan struct{})
				go func() { c.serve(); close(finished) }()
				var once sync.Once
				unblock := func() { once.Do(func() { close(h.release) }) }
				defer func() {
					unblock()
					close(transport.reads)
					_ = remote.Close()
					<-finished
				}()
				payload := cerPayload(t)
				transport.reads <- restartRead{data: payload}
				original := <-h.entered
				transport.reads <- restartRead{data: payload}
				synctest.Wait()
				// Unsupported renewal retains normal ordered dispatch even when
				// the previous callback takes longer than retirement permits.
				time.Sleep(retirementTimeout + time.Millisecond)
				synctest.Wait()
				select {
				case <-transport.closed:
					t.Fatal("CER without eligibility forced physical closure while prior callback held admission")
				default:
				}
				if original.Closed() {
					t.Fatal("CER without eligibility closed the active generation")
				}
				unblock()
				synctest.Wait()
				for range 2 {
					select {
					case delivered := <-h.delivered:
						if delivered != original || delivered.(ConnLifecycle).Generation() != 1 || delivered.(ConnLifecycle).RetirementReason() != 0 {
							t.Fatal("unsupported CER renewal changed callback generation")
						}
					default:
						t.Fatal("CER without eligibility lost an ordered callback")
					}
				}
				if h.calls.Load() != 2 {
					t.Fatalf("handler calls=%d, want 2", h.calls.Load())
				}
			})
		})
	}
}
