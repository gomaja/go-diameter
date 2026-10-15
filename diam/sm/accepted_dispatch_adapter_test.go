package sm

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
)

type acceptedDispatchProbeConn struct {
	diam.Conn
	committed   atomic.Bool
	beforeReply func()
}

func (c *acceptedDispatchProbeConn) Unwrap() diam.Conn { return c.Conn }
func (c *acceptedDispatchProbeConn) markReply(b []byte, n int, err error) {
	if h, decodeErr := diam.DecodeHeader(b); decodeErr == nil && err == nil && n == len(b) && h.CommandCode == diam.DeviceWatchdog && h.CommandFlags&diam.RequestFlag == 0 {
		c.committed.Store(true)
	}
}
func (c *acceptedDispatchProbeConn) Write(b []byte) (int, error) {
	c.blockReply(b)
	n, err := c.Conn.Write(b)
	c.markReply(b, n, err)
	return n, err
}
func (c *acceptedDispatchProbeConn) WriteStream(b []byte, stream uint) (int, error) {
	c.blockReply(b)
	n, err := c.Conn.WriteStream(b, stream)
	c.markReply(b, n, err)
	return n, err
}

func (c *acceptedDispatchProbeConn) blockReply(b []byte) {
	if c.beforeReply == nil {
		return
	}
	if h, err := diam.DecodeHeader(b); err == nil && h.CommandCode == diam.DeviceWatchdog && h.CommandFlags&diam.RequestFlag == 0 {
		c.beforeReply()
	}
}

type acceptedDispatchProbeHandler struct {
	*StateMachine
	once        sync.Once
	conn        *acceptedDispatchProbeConn
	entered     chan struct{}
	returned    chan struct{}
	beforeReply func()
}

func (h *acceptedDispatchProbeHandler) wrap(c diam.Conn) *acceptedDispatchProbeConn {
	h.once.Do(func() { h.conn = &acceptedDispatchProbeConn{Conn: c, beforeReply: h.beforeReply} })
	return h.conn
}
func (h *acceptedDispatchProbeHandler) HandleAccept(c diam.Conn) func() {
	return h.StateMachine.HandleAccept(h.wrap(c))
}
func (h *acceptedDispatchProbeHandler) ServeDIAM(c diam.Conn, m *diam.Message) {
	marked := m.Header.CommandCode == 999
	if marked {
		h.entered <- struct{}{}
	}
	h.StateMachine.ServeDIAM(h.wrap(c), m)
	if marked {
		h.returned <- struct{}{}
	}
}

// RFC 6733 §§5.5.1,7.2: malformed DWR handling retains admission through
// its required error answer, then lets independent application dispatch run.
func TestAcceptedDispatchErrorReplyHoldsAdmission(t *testing.T) {
	for _, mode := range []int{2, -1} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			var handler *acceptedDispatchProbeHandler
			p := newProtocolDeliveryWire(t, mode, true, nil, func(server *diam.Server) {
				handler = &acceptedDispatchProbeHandler{StateMachine: server.Handler.(*StateMachine), entered: make(chan struct{}, 1), returned: make(chan struct{}, 1), beforeReply: func() { close(entered); <-release }}
				server.Handler = handler
			})
			t.Cleanup(unblock)
			admitted := make(chan bool, 1)
			p.sm.Handle("ALL", diam.HandlerFunc(func(c diam.Conn, _ *diam.Message) { admitted <- handler.wrap(c).committed.Load() }))
			header := p.send(t, protocolGenerationInvalidDWR(t, 0x91a0))
			protocolGenerationAwait(t, entered)
			p.send(t, diam.NewMessage(999, diam.RequestFlag, 4, 0x91a2, 0x91a3, p.conn.Dictionary()))
			protocolGenerationAwait(t, handler.entered) // The later native worker is running.
			select {
			case committed := <-admitted:
				t.Fatalf("application crossed blocked error reply: committed=%t", committed)
			case <-time.After(50 * time.Millisecond):
			}
			unblock()
			answer, err := diam.ReadMessage(p.peer, p.conn.Dictionary())
			if err != nil || !testResultCode(answer, diam.MissingAVP) || answer.Header.HopByHopID != header.HopByHopID || answer.Header.EndToEndID != header.EndToEndID {
				t.Fatalf("invalid DWR answer=%v error=%v", answer, err)
			}
			if !protocolGenerationAwait(t, admitted) {
				t.Fatal("application ran before the required reply writer committed")
			}
			protocolGenerationAwait(t, handler.returned)
			assertProtocolEvent(t, protocolEvent(t, p.events), handler.wrap(p.conn), &header, diam.ProtocolInvalidRequest, diam.MissingAVP, false, diam.ProtocolReplyWritten, diam.MissingAVP)
		})
	}
}

// RFC 6733 §5.6: DPR commits Closing before its callback, so subsequent
// Closing inputs can be discarded while an OnDPR observer remains blocked.
func TestAcceptedDispatchPeerDisconnectReleasesAdmission(t *testing.T) {
	for _, mode := range []int{2, -1} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			var handler *acceptedDispatchProbeHandler
			p := newProtocolDeliveryWire(t, mode, true, func(cfg *Settings) {
				cfg.DPRCloseTimeout = 3 * time.Second
				cfg.OnDPR = func(diam.Conn, DisconnectCause) { close(entered); <-release }
			}, func(server *diam.Server) {
				handler = &acceptedDispatchProbeHandler{StateMachine: server.Handler.(*StateMachine), entered: make(chan struct{}, 1), returned: make(chan struct{}, 1)}
				server.Handler = handler
			})
			t.Cleanup(unblock)
			admitted := make(chan struct{}, 1)
			p.sm.Handle("ALL", diam.HandlerFunc(func(diam.Conn, *diam.Message) { admitted <- struct{}{} }))
			header := p.send(t, closingContractDPR(t, p, 0x91b0))
			answer, err := diam.ReadMessage(p.peer, p.conn.Dictionary())
			if err != nil || !testResultCode(answer, diam.Success) || answer.Header.HopByHopID != header.HopByHopID || answer.Header.EndToEndID != header.EndToEndID {
				t.Fatalf("DPA=%v error=%v", answer, err)
			}
			protocolGenerationAwait(t, entered)
			p.send(t, diam.NewMessage(999, diam.RequestFlag, 4, 0x91b2, 0x91b3, p.conn.Dictionary()))
			protocolGenerationAwait(t, handler.entered)
			select {
			case <-handler.returned:
			case <-time.After(500 * time.Millisecond):
				t.Fatal("blocked OnDPR held later Closing input admission")
			}
			select {
			case <-admitted:
				t.Fatal("Closing input reached an application handler")
			default:
			}
			if p.conn.Closed() {
				t.Fatal("observer block caused premature closure")
			}
			unblock()
		})
	}
}
