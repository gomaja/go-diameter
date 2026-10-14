package sm

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/dict"
)

type eofDispatchGate struct {
	inner     *StateMachine
	entered   chan diam.Conn
	delivered chan *diam.Message
	release   chan struct{}
	once      sync.Once
}

func newEOFDispatchGate(t *testing.T) *eofDispatchGate {
	testDict := newSMTestDictionary(dict.Base())
	serverSettings2 :=
		cloneTestSettings(serverSettings2, testDict)

	t.Helper()
	cfg := *serverSettings2
	h := &eofDispatchGate{inner: mustNewStateMachine(t, &cfg, testDict), entered: make(chan diam.Conn, 1), delivered: make(chan *diam.Message, 1), release: make(chan struct{})}
	h.inner.Handle("ALL", diam.HandlerFunc(func(_ diam.Conn, m *diam.Message) { h.delivered <- m }))
	t.Cleanup(h.resume)
	return h
}

func (h *eofDispatchGate) Unwrap() diam.Handler { return h.inner }
func (h *eofDispatchGate) resume()              { h.once.Do(func() { close(h.release) }) }
func (h *eofDispatchGate) ServeDIAM(c diam.Conn, m *diam.Message) {
	if m.Header.CommandCode == 999 {
		h.entered <- c
		<-h.release
	}
	h.inner.ServeDIAM(c, m)
}

// This single-stream scripted association exercises the MultistreamConn error
// callback without an SCTP syscall. The error arrives only after the answer's
// complete body has been decoded and its callback has entered the wrapper.
type eofMultistreamTransport struct {
	*acceptedRestartTransport
	mu      sync.Mutex
	onError diam.MutistreamConnErrorHandler
}

var _ diam.MultistreamConn = (*eofMultistreamTransport)(nil)

func (c *eofMultistreamTransport) Read(b []byte) (int, error) {
	n, err := c.acceptedRestartTransport.Read(b)
	if err != nil {
		c.mu.Lock()
		h := c.onError
		c.mu.Unlock()
		if h != nil {
			h(c, err)
		}
	}
	return n, err
}
func (c *eofMultistreamTransport) ReadAny(b []byte) (int, uint, error) {
	n, err := c.Read(b)
	return n, 7, err
}
func (c *eofMultistreamTransport) ReadStream(b []byte, _ uint) (int, error) { return c.Read(b) }
func (c *eofMultistreamTransport) ReadAtLeast(b []byte, min int, _ uint) (int, uint, error) {
	n, err := io.ReadAtLeast(c, b, min)
	return n, 7, err
}
func (c *eofMultistreamTransport) CurrentStream() uint        { return 7 }
func (c *eofMultistreamTransport) ResetCurrentStream()        {}
func (c *eofMultistreamTransport) SetCurrentStream(uint) uint { return 7 }
func (c *eofMultistreamTransport) WriteStream(b []byte, _ uint) (int, error) {
	return c.Write(b)
}
func (c *eofMultistreamTransport) CurrentWriterStream() uint { return 7 }
func (c *eofMultistreamTransport) ResetWriterStream()        {}
func (c *eofMultistreamTransport) SetWriterStream(uint) uint { return 7 }
func (c *eofMultistreamTransport) SetErrorHandler(h diam.MutistreamConnErrorHandler) {
	c.mu.Lock()
	c.onError = h
	c.mu.Unlock()
}

func waitEOFProbe(t *testing.T, ch <-chan struct{}, event string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", event)
	}
}

func checkEOFDispatch(t *testing.T, h *eofDispatchGate, c diam.Conn, answer *diam.Message, closePeer func()) {
	t.Helper()
	defer h.resume()
	closePeer()
	waitEOFProbe(t, mustConnAs[diam.CloseNotifier](t, c).CloseNotify(), "EOF notification")
	if c.Closed() {
		t.Error("ordinary EOF published Closed before the decoded callback finished")
	}
	if lifecycle := mustConnAs[diam.ConnLifecycle](t, c); lifecycle.Generation() != 1 || lifecycle.RetirementReason() != 0 {
		t.Errorf("ordinary EOF changed generation: %d, reason %d", lifecycle.Generation(), lifecycle.RetirementReason())
	}
	h.resume()
	waitEOFProbe(t, mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, c).DispatchDone(), "decoded callback completion")
	if !c.Closed() {
		t.Error("ordinary EOF did not publish Closed after callback completion")
	}
	select {
	case got := <-h.delivered:
		if got.Header.HopByHopID != answer.Header.HopByHopID || got.Header.EndToEndID != answer.Header.EndToEndID || got.Header.CommandFlags != answer.Header.CommandFlags || got.MessageStream() != 7 {
			t.Fatalf("decoded answer changed before application delivery: %v", got)
		}
	default:
		t.Fatal("ordinary EOF dropped the already decoded business answer")
	}
}

func TestOrdinaryMultistreamEOFPreservesDecodedBusinessAnswer(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	for _, mode := range []int{1, 2, -1} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			h := newEOFDispatchGate(t)
			local, peer := net.Pipe()
			transport := &eofMultistreamTransport{acceptedRestartTransport: &acceptedRestartTransport{Conn: local, reads: make(chan acceptedRestartRead, 8), closed: make(chan struct{})}}
			listener := &watchdogPipeListener{accepted: make(chan net.Conn, 1), closed: make(chan struct{})}
			listener.accepted <- transport
			server := &diam.Server{Handler: h, Dict: testDict, MaxConcurrentHandlers: mode}
			done := make(chan error, 1)
			go func() { done <- server.Serve(listener) }()
			t.Cleanup(func() {
				h.resume()
				_ = transport.Close()
				_ = peer.Close()
				_ = server.Close()
				if err := <-done; err != nil && !errors.Is(err, diam.ErrServerClosed) {
					t.Error(err)
				}
			})
			transport.message(t, regressionCER(t, testDict, 1001))
			acceptedRestartCEA(t, peer, diam.Success)
			answer := diam.NewRequest(999, 1001, testDict).Answer(diam.Success)
			transport.message(t, answer)
			var c diam.Conn
			select {
			case c = <-h.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("business callback did not enter before EOF")
			}
			// Installing the notifier before EOF enables the real monitor path.
			_ = mustConnAs[diam.CloseNotifier](t, c).CloseNotify()
			checkEOFDispatch(t, h, c, answer, func() { transport.reads <- acceptedRestartRead{err: io.EOF} })
		})
	}
}
