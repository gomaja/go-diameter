package peer

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime"

	"github.com/gomaja/go-diameter/diam"
)

// HandleIdx registers handler for the requests a remote peer initiates with this
// application and command (RFC 6733 §1). diam.ALL_CMD_INDEX catches requests no
// other index matches, in any advertised application. A request with no route
// keeps its 3001 or 3007 answer (RFC 6733 §7.1.3).
//
// HandleIdx panics for a nil handler, a duplicate index, an answer index, code
// CER, DWR or DPR in any application, and an application this Manager does not
// advertise: such a route could never run. Registration is safe at any time and
// applies to later messages, so register before Start or Server.Serve.
//
// Handlers run on Manager's goroutines, concurrently up to
// Limits.HandlersPerConnection, whatever Server.MaxConcurrentHandlers is. A
// request reaches a handler only after protocol validation: one with an error
// gets its error answer, and one received while Closing or in the watchdog's
// REOPEN state is dropped. On a discovered peer, a request outside its live
// lease has no route. Like StateMachine, Manager does not check Destination-Host
// or Destination-Realm, forward requests or detect duplicates; the handler sees
// the T bit.
//
// smpeer.FromContext(c.Context()) identifies the peer. The handler answers by
// writing to c: Message.Answer supplies the identifiers, stream, Proxy-Info and
// Result-Code, and the handler adds Session-Id and the local Origin-Host and
// Origin-Realm (RFC 6733 §6.2, Verified Erratum 4887). c behaves like the native
// Conn, whose optional interfaces diam.ConnAs finds, except that:
//   - writing a request fails with ErrInvalidRequest and writes nothing; use Send;
//   - writing after a discovered peer's lease expires fails with ErrLeaseExpired;
//   - a failed write closes the connection, unless it is already closed or retired;
//   - Close ends the session at once and fails its pending requests over.
//
// An answer from a replaced connection generation fails with
// diam.ErrConnectionRetired.
//
// A panic is logged at Error with its stack. The request gets no answer and the
// connection stays open. Manager.Close waits for running handlers, so a handler
// must not call it synchronously.
func (m *Manager) HandleIdx(cmd diam.CommandIndex, handler diam.Handler) {
	if cmd != diam.ALL_CMD_INDEX {
		if !cmd.Request {
			panic(fmt.Sprintf("peer: cannot register answer handler %v", cmd))
		}
		switch cmd.Code {
		case diam.CapabilitiesExchange, diam.DeviceWatchdog, diam.DisconnectPeer:
			panic(fmt.Sprintf("peer: cannot overwrite reserved command %v", cmd))
		}
		if !m.supportsApplication(cmd.AppID) {
			panic(fmt.Sprintf("peer: application %d is not advertised", cmd.AppID))
		}
	}
	m.handlerMux.HandleIdx(cmd, handler)
	m.hasHandlers.Store(true)
}

func (s *session) hasRequestHandler(msg *diam.Message) bool {
	if msg == nil || msg.Header == nil || msg.Header.CommandFlags&diam.RequestFlag == 0 || !s.m.supportsApplication(msg.Header.ApplicationID) {
		return false
	}
	if a, _ := s.binding(); a != nil && a.discovery.Load() != nil {
		if !a.leaseLive() || msg.Header.ApplicationID != 0 && !a.discoveryAllows(msg.Header.ApplicationID) {
			return false
		}
	}
	_, found := s.m.handlerMux.Handler(msg)
	return found
}

// dispatchRequest runs only on a delivery consumer, after Server admission has
// been released. The actor accounts for the request but never waits for a slot.
func (s *session) dispatchRequest(msg *diam.Message) {
	drop := func() {
		s.m.logFailure(s, msg, "", slog.LevelWarn, "peer: request handler dropped; connection closed", net.ErrClosed)
		s.finishRequest()
	}
	select {
	case s.handlerSlots <- struct{}{}:
	case <-s.closed:
		drop()
		return
	}
	select {
	case <-s.closed:
		<-s.handlerSlots
		drop()
		return
	default:
	}
	go s.runRequestHandler(msg)
}

func (s *session) finishRequest() {
	s.handlersInFlight.Add(-1)
	s.m.wg.Done()
}

func (s *session) runRequestHandler(msg *diam.Message) {
	defer s.finishRequest()
	defer func() { <-s.handlerSlots }()
	defer func() {
		if value := recover(); value != nil {
			stack := make([]byte, panicStackSize)
			stack = stack[:runtime.Stack(stack, false)]
			host := ""
			if a, _ := s.binding(); a != nil {
				host = string(a.cfg.Host)
			}
			s.m.logger().LogAttrs(msg.Context(), slog.LevelError, "peer: panic in request handler",
				slog.String("peer_host", host), slog.Any("panic", value),
				slog.String("stack", string(stack)), slog.Any("message", msg))
		}
	}()
	if handler, found := s.m.handlerMux.Handler(msg); found {
		handler.ServeDIAM(s.handlerConn, msg)
	}
}

// requestHandlerConn leaves serialization, streams, the physical write gate and
// the generation fence with the native connection. Close closes its session,
// sealing admission and waking slot waiters. Its lifetime is one session.
type requestHandlerConn struct {
	diam.Conn
	s *session
}

func (c *requestHandlerConn) Unwrap() diam.Conn { return c.Conn }

// Close seals the session, so a request waiting for a slot wakes without waiting
// for the reader that DispatchDone would join. A native Close on a retired
// generation leaves the renewed transport alone.
func (c *requestHandlerConn) Close() { c.s.close() }

func (c *requestHandlerConn) checkWrite(b []byte) error {
	if len(b) > 4 && b[4]&diam.RequestFlag != 0 {
		return fmt.Errorf("%w: request handlers must send requests through Manager.Send", ErrInvalidRequest)
	}
	if a, _ := c.s.binding(); a != nil && !a.leaseLive() {
		return ErrLeaseExpired
	}
	return nil
}

func (c *requestHandlerConn) writeResult(n, length int, err error) (int, error) {
	if err == nil && n != length {
		err = io.ErrShortWrite
	}
	if err != nil && !errors.Is(err, diam.ErrConnectionRetired) && !errors.Is(err, net.ErrClosed) && !c.Closed() && !c.s.isRetired() {
		c.s.m.reportLocal(c.s, nil, "peer: write failed; closing connection", err)
		c.s.close()
	}
	return n, err
}

func (c *requestHandlerConn) Write(b []byte) (int, error) {
	if err := c.checkWrite(b); err != nil {
		return 0, err
	}
	n, err := c.Conn.Write(b)
	return c.writeResult(n, len(b), err)
}

func (c *requestHandlerConn) WriteStream(b []byte, stream uint) (int, error) {
	if err := c.checkWrite(b); err != nil {
		return 0, err
	}
	n, err := c.Conn.WriteStream(b, stream)
	return c.writeResult(n, len(b), err)
}
