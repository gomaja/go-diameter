package sm

import (
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type clientAlreadyClosedTransport struct {
	closed         chan struct{}
	once           sync.Once
	addressEntered chan struct{}
	addressRelease chan struct{}
	addressOnce    sync.Once
}

func (c *clientAlreadyClosedTransport) Read([]byte) (int, error) { return 0, io.EOF }
func (c *clientAlreadyClosedTransport) Write([]byte) (int, error) {
	return 0, net.ErrClosed
}
func (c *clientAlreadyClosedTransport) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}
func (c *clientAlreadyClosedTransport) LocalAddr() net.Addr {
	// Address discovery cannot finish before the native read loop closes the
	// transport. Thus closure precedes initiator construction, even on one P.
	<-c.closed
	if c.addressEntered != nil {
		c.addressOnce.Do(func() { close(c.addressEntered) })
		<-c.addressRelease
	}
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}
func (c *clientAlreadyClosedTransport) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 3868}
}
func (*clientAlreadyClosedTransport) SetDeadline(time.Time) error      { return nil }
func (*clientAlreadyClosedTransport) SetReadDeadline(time.Time) error  { return nil }
func (*clientAlreadyClosedTransport) SetWriteDeadline(time.Time) error { return nil }

// clientStartupCheckpointForTest waits until the real lifecycle watcher has
// consumed the closed signal, before the selected startup effects can run.
func clientStartupCheckpointForTest(state *acceptedHandshake) bool {
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, retained := state.sm.cores.Load(state.conn); !retained {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		runtime.Gosched()
	}
}

type clientStartupForTest struct {
	rw       *clientAlreadyClosedTransport
	state    atomic.Pointer[acceptedHandshake]
	consumed atomic.Bool
	reached  chan *acceptedHandshake
	result   chan error
	joined   chan struct{}
	unblock  func()
	restore  func()
	stopOnce sync.Once
}

func newClientStartupForTest(t *testing.T, delayAddress bool) *clientStartupForTest {
	t.Helper()
	cli := newLivenessClient(t)
	cli.EnableWatchdog = false
	cli.Handler.cfg.HostIPAddresses = nil
	cli.RetransmitInterval = time.Hour
	f := &clientStartupForTest{
		rw:      &clientAlreadyClosedTransport{closed: make(chan struct{})},
		reached: make(chan *acceptedHandshake, 1),
		result:  make(chan error, 1), joined: make(chan struct{}),
		unblock: func() {},
	}
	if delayAddress {
		f.rw.addressEntered = make(chan struct{})
		f.rw.addressRelease = make(chan struct{})
		f.unblock = sync.OnceFunc(func() { close(f.rw.addressRelease) })
	}
	previous := testHookClientBeforeStart
	f.restore = func() { testHookClientBeforeStart = previous }
	testHookClientBeforeStart = func(s *acceptedHandshake) {
		f.state.Store(s)
		f.reached <- s
		f.consumed.Store(clientStartupCheckpointForTest(s))
	}
	t.Cleanup(f.stop)
	go func() {
		defer close(f.joined)
		c, err := cli.NewConn(f.rw, "synthetic.example")
		if c != nil {
			c.Close()
		}
		f.result <- err
	}()
	return f
}

func (f *clientStartupForTest) stop() {
	f.stopOnce.Do(func() {
		// A failed assertion may run cleanup before construction reaches the hook.
		// Release address discovery first, then join the only hook reader before
		// restoring the package-level hook, including that early exit.
		f.unblock()
		select {
		case <-f.joined:
		case s := <-f.reached:
			// Complete the test waiter if a broken lifecycle path lost completion.
			s.finishHandshake(net.ErrClosed)
			<-f.joined
		}
		f.restore()
	})
}

func TestClientClosedBeforeStartupCompletes(t *testing.T) {
	f := newClientStartupForTest(t, false)
	select {
	case err := <-f.result:
		if !f.consumed.Load() {
			t.Fatal("lifecycle watcher did not consume closure before startup effects")
		}
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed-before-start NewConn error = %v; want native closed-connection error", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("closed-before-Start lifecycle event lost handshake completion")
	}
}

func TestClientStartupCleanupJoinsBeforeHookRestoration(t *testing.T) {
	f := newClientStartupForTest(t, true)
	// The fallback also joins a deliberately broken cleanup implementation.
	defer func() { f.unblock(); <-f.joined }()
	select {
	case <-f.rw.addressEntered:
	case <-time.After(15 * time.Second):
		t.Fatal("startup did not reach address discovery")
	}
	f.stop()
	select {
	case <-f.joined:
	default:
		t.Fatal("startup cleanup restored the hook before joining NewConn")
	}
	if !f.consumed.Load() {
		t.Fatal("startup cleanup restored the hook before its delayed reader ran")
	}
}
