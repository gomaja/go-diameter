package peer

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

// Blocking this opaque TCP wrapper's answer Write holds the real native
// physical gate while a different, selected Manager request waits behind it.
type completionGateConn struct {
	net.Conn
	entered, release chan struct{}
	held, released   atomic.Bool
}

func (c *completionGateConn) unblock() {
	if c.released.CompareAndSwap(false, true) {
		close(c.release)
	}
}

func (c *completionGateConn) Close() error {
	c.unblock()
	return c.Conn.Close()
}

func (c *completionGateConn) Write(b []byte) (int, error) {
	var header diam.Header
	if header.DecodeFromBytes(b) == nil && header.CommandCode == diam.DeviceWatchdog &&
		header.CommandFlags&diam.RequestFlag == 0 && c.held.CompareAndSwap(false, true) {
		close(c.entered)
		<-c.release
	}
	return c.Conn.Write(b)
}

func completionHeldGatePeer(t *testing.T) (*Manager, net.Conn, *fakeClock, *completionGateConn, <-chan diam.ProtocolErrorEvent) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	clock := &fakeClock{}
	events := make(chan diam.ProtocolErrorEvent, 16)
	settings := testSettings("local.example.net")
	settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
	ready := make(chan *completionGateConn, 1)
	m, err := New(Config{Settings: settings, Clock: clock, Dial: func(ctx context.Context, endpoint Endpoint) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, endpoint.Network, endpoint.Address)
		if err != nil {
			return nil, err
		}
		gate := &completionGateConn{Conn: c, entered: make(chan struct{}), release: make(chan struct{})}
		ready <- gate
		return gate, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeManager(t, m, nil) })
	if err := m.AddPeer(PeerConfig{Host: "known.example.net", NoAutoReconnect: true, Endpoints: []Endpoint{{Network: "tcp", Address: l.Addr().String()}}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = l.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	write(t, c, correlationCEA(t, read(t, c), "known.example.net"))
	awaitState(t, m, IOpen)
	clock.waitTimers(t, 2)
	gate := <-ready
	t.Cleanup(gate.unblock)
	return m, c, clock, gate, events
}

func TestManagerCompletedRequestWaitingForNativeGateOnWire(t *testing.T) {
	for _, timer := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "request deadline"}[timer], func(t *testing.T) {
			m, c, clock, gate, events := completionHeldGatePeer(t)
			m.mu.RLock()
			s := m.peers["known.example.net"].activeSession.Load()
			m.mu.RUnlock()
			entered := make(chan struct{})
			s.beforePublication = func(msg *diam.Message) {
				if msg.Header.ApplicationID != 0 {
					close(entered)
				}
			}
			held, err := base.BuildDWA(reviewDWR(t), m.baseSettings(s.c))
			if err != nil {
				t.Fatal(err)
			}
			heldDone := make(chan error, 1)
			go func() { _, err := held.WriteTo(s.c); heldDone <- err }()
			select {
			case <-gate.entered:
			case <-time.After(time.Second):
				t.Fatal("answer writer did not hold the native physical gate")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			mark := clock.timerCount()
			result := sendAsync(m, ctx, outboundRequest("known.example.net", "example.net"))
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("request was not selected behind the occupied native gate")
			}
			wantErr := error(context.Canceled)
			if timer {
				wantErr = ErrRequestTimeout
				completionFireRequestTimer(t, clock, mark)
			} else {
				cancel()
			}
			if got := <-result; got.answer != nil || !errors.Is(got.err, wantErr) {
				t.Fatalf("gate-wait completion=%+v, want %v", got, wantErr)
			}
			deadline := time.Now().Add(time.Second)
			for {
				m.pendingMu.Lock()
				pending, controls := len(m.pending[s]), len(m.controls[s])
				m.pendingMu.Unlock()
				if pending == 0 && controls == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("completed request could not leave occupied gate: pending=%d controls=%d", pending, controls)
				}
				time.Sleep(time.Millisecond)
			}
			sentinel, err := base.BuildDWA(reviewDWR(t), m.baseSettings(s.c))
			if err != nil {
				t.Fatal(err)
			}
			if err := s.send(sentinel, false); err != nil {
				t.Fatal(err)
			}
			gate.unblock()
			if err := <-heldDone; err != nil {
				t.Fatal(err)
			}
			for {
				msg := read(t, c)
				if msg.Header.ApplicationID != 0 {
					t.Errorf("completed gate waiter reached transport: %+v", msg.Header)
				}
				if msg.Header.CommandCode == diam.DeviceWatchdog && msg.Header.HopByHopID == sentinel.Header.HopByHopID {
					break
				}
			}
			if s.requests.HasPending() {
				t.Fatal("completed gate waiter leaked native answer ownership")
			}
			select {
			case e := <-events:
				t.Fatalf("completed gate waiter invoked protocol hook: %+v", e)
			default:
			}
		})
	}
}
