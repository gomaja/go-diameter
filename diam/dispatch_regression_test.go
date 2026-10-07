package diam

import (
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

type dispatchRegressionHandler struct {
	handle       func(Conn, *Message)
	messageError func(Conn, *Message, *MessageError) error
}

func (h dispatchRegressionHandler) ServeDIAM(c Conn, m *Message) { h.handle(c, m) }
func (h dispatchRegressionHandler) HandleMessageError(c Conn, m *Message, e *MessageError) error {
	return h.messageError(c, m, e)
}

func TestConcurrentReadErrorDoesNotBlockProxy(t *testing.T) {
	for _, limit := range []int{4, -1} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			answer := make(chan struct{})
			result := make(chan error, 1)
			h := dispatchRegressionHandler{handle: func(c Conn, m *Message) {
				if m.Header.CommandFlags&RequestFlag == 0 {
					close(answer)
					return
				}
				dwr := NewRequest(DeviceWatchdog, 0, dict.Default)
				dwr.AddAVP(NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("proxy.example")))
				dwr.AddAVP(NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
				if _, err := dwr.WriteTo(c); err != nil {
					result <- err
					return
				}
				select {
				case <-answer:
					result <- nil
				case <-time.After(500 * time.Millisecond):
					result <- fmt.Errorf("proxy timed out waiting for DWA")
				}
			}, messageError: func(Conn, *Message, *MessageError) error { return nil }}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			serveTestServer(t, &Server{Handler: h, MaxConcurrentHandlers: limit}, ln)
			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer closeTestConn(t, c)
			if err = c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err = c.Write(cerPayload(t)); err != nil {
				t.Fatal(err)
			}
			dwr, err := ReadMessage(c, dict.Default)
			if err != nil {
				t.Fatal(err)
			}
			bad := NewRequest(DeviceWatchdog, 0, dict.Default)
			bad.AddAVP(NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
			bad.AddAVP(NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
			bad.AddAVP(NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2}))
			start := time.Now()
			if _, err = bad.WriteTo(c); err != nil {
				t.Fatal(err)
			}
			dwa := dwr.Answer(Success)
			dwa.AddAVP(NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
			dwa.AddAVP(NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
			if _, err = dwa.WriteTo(c); err != nil {
				t.Fatal(err)
			}
			select {
			case err = <-result:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(time.Second):
				t.Fatal("reader stalled")
			}
			t.Logf("proxy round trip after malformed message: %v", time.Since(start))
		})
	}
}

func TestConcurrentDispatchDoesNotParkCompletedHandlers(t *testing.T) {
	for _, limit := range []int{4, -1} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			baseline := runtime.NumGoroutine()
			release := make(chan struct{})
			started := make(chan struct{})
			completed := make(chan struct{}, 200)
			c := &conn{server: &Server{MaxConcurrentHandlers: limit, Handler: HandlerFunc(func(_ Conn, m *Message) {
				if m.Header.HopByHopID == 1 {
					close(started)
					<-release
					return
				}
				completed <- struct{}{}
			})}}
			if limit > 0 {
				c.sem = make(chan struct{}, limit)
			}
			defer func() { close(release); c.hwg.Wait() }()
			c.dispatch(NewMessage(DeviceWatchdog, RequestFlag, 0, 1, 1, nil))
			<-started
			for i := 0; i < 200; i++ {
				c.dispatch(NewMessage(DeviceWatchdog, RequestFlag, 0, uint32(i+2), 1, nil))
				select {
				case <-completed:
				case <-time.After(time.Second):
					t.Fatal("fast handler stalled")
				}
			}
			deadline := time.Now().Add(250 * time.Millisecond)
			for runtime.NumGoroutine() > baseline+8 && time.Now().Before(deadline) {
				runtime.Gosched()
			}
			got := runtime.NumGoroutine()
			t.Logf("goroutines before=%d after=%d", baseline, got)
			if got > baseline+8 {
				t.Errorf("completed handlers retained %d goroutines", got-baseline)
			}
		})
	}
}

func TestBeginDispatchWaitsAllPredecessors(t *testing.T) {
	c := new(conn)
	first, middle, last := new(Message), new(Message), new(Message)
	c.prepareDispatch(first)
	c.prepareDispatch(middle)
	c.prepareDispatch(last)
	middleDone := make(chan struct{})
	go func() { middle.releaseDispatch(); close(middleDone) }()
	lastDone := make(chan struct{})
	go func() { release := last.BeginDispatch(); release(); close(lastDone) }()
	defer func() { first.releaseDispatch(); <-middleDone; <-lastDone }()
	select {
	case <-lastDone:
		t.Fatal("completed middle callback hid the unreleased first callback")
	case <-time.After(20 * time.Millisecond):
	}
}
