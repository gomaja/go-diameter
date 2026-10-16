// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Diameter server, based on net/http.

package diam

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/observe"
	"github.com/gomaja/go-diameter/diam/internal/transport"
	"github.com/gomaja/go-sctp"
)

// The Handler interface allow arbitrary objects to be
// registered to serve particular messages like CER, DWR.
//
// Concurrent plain handlers are independent: returning releases their callback
// without waiting for older handlers. Protocol handlers may use BeginDispatch
// to order admission, and must release admission before waiting for later traffic.
// Wrappers around an ordered handler must forward ServeDIAM synchronously, before
// returning. A wrapper should expose Unwrap() Handler so HandlerAs can discover optional
// AcceptHandler, RetireHandler, AcceptedCERHandler, MessageErrorHandler and
// ProtocolErrorObserver methods. These calls bypass an Unwrap-only
// wrapper. A wrapper intercepting MessageErrorHandler must delegate synchronously
// or take responsibility itself; consuming a callback leaves no dispatch gap.
// Successive Unwrap calls must terminate.
type Handler interface {
	// ServeDIAM should write messages to the Conn and then return.
	// Returning signals that the request is finished.
	//
	// If Server.MaxConcurrentHandlers != 0, ServeDIAM may be invoked
	// concurrently on the same connection from multiple goroutines;
	// handlers that maintain per-connection state must synchronize
	// access themselves. By default (MaxConcurrentHandlers == 0) the
	// server dispatches messages on a connection sequentially.
	ServeDIAM(Conn, *Message)
}

// Conn interface is used by a handler to send diameter messages.
//
// A wrapper should expose Unwrap() Conn so ConnAs can discover optional
// interfaces such as ConnLifecycle, CloseNotifier and DispatchDone() <-chan struct{}.
// These calls bypass an Unwrap-only wrapper. A wrapper implementing an optional
// interface intercepts it and can delegate with ConnAs on its wrapped connection.
// A wrapper without Unwrap hides its wrapped connection's optional interfaces.
// Successive Unwrap calls must terminate.
type Conn interface {
	// Logger returns the owning Server or Client logger, with network,
	// local_addr and remote_addr attributes. A nil configured logger resolves
	// slog.Default on every call, including after a later slog.SetDefault.
	Logger() *slog.Logger
	Write(b []byte) (int, error)                    // Writes a msg to the connection
	WriteStream(b []byte, stream uint) (int, error) // Writes a msg to the connection's stream
	Close()                                         // Close the connection
	// Closed reports whether Close has been called, or the server has finished
	// with the connection. It is safe to call concurrently and requires no read.
	// On read-loop exit the server waits for pending handlers before setting it.
	// Close publishes it before closing the transport, without waiting for handlers;
	// use DispatchDone to wait for them. Retirement publishes Closed immediately
	// while old callbacks finish. Closing Connection() directly bypasses it.
	Closed() bool
	LocalAddr() net.Addr            // Returns the local IP
	RemoteAddr() net.Addr           // Returns the remote IP
	TLS() *tls.ConnectionState      // TLS or nil when not using TLS
	Dictionary() *dict.Parser       // Dictionary parser of the connection
	Context() context.Context       // Returns the internal context
	SetContext(ctx context.Context) // Stores a new context
	// Connection returns the originally supplied transport. Renewal users must
	// use Conn for writes/Close and keep one Server reader: raw operations can
	// bypass generation fences and affect a replacement.
	Connection() net.Conn
}

// The CloseNotifier interface is implemented by Conns which
// allow detecting when the underlying connection has gone away.
//
// This mechanism can be used to detect if a peer has disconnected.
type CloseNotifier interface {
	// CloseNotify returns a channel that is closed
	// when the client connection has gone away.
	//
	// On TCP and TLS, the first call makes the connection read the socket
	// one chunk ahead of message dispatch, so that peer loss is seen while a
	// callback runs unless data received before it still awaits dispatch;
	// this adds a goroutine handoff to every socket read. A dialed connection
	// starts reading ahead once any socket read in progress returns, also
	// when the call comes from a callback; TLS waits for the handshake to
	// finish. An accepted connection starts at its next read. A
	// MultistreamConn reports loss through its transport instead.
	CloseNotify() <-chan struct{}
}

// AcceptHandler observes connections accepted by Server.Serve before any
// Diameter message is read (RFC 6733 §5.6.1). HandleAccept runs after the
// transport handshake, once per accepted generation on its reader goroutine, and must
// not block. Its returned function runs once on closure or retirement.
// The hook runs after TLS because Server.TLSHandshakeTimeout separately bounds
// the TLS handshake. Server uses HandlerAs on Server.Handler, so Unwrap wrappers need not forward
// this method. An intercepting wrapper must delegate to retain inner admission.
type AcceptHandler interface {
	HandleAccept(c Conn) (onClose func())
}

// A liveSwitchReader is a switchReader that's safe for concurrent
// reads and switches, if its mutex is held.
type liveSwitchReader struct {
	sync.Mutex
	r             io.Reader
	accepted      *bool // The initial generation's role is fixed before serving.
	pr            io.Reader
	pipeCopyF     func()
	onReadGone    func()
	readGone      bool
	reading       atomic.Bool
	switchPending atomic.Bool
}

func (sr *liveSwitchReader) Read(p []byte) (n int, err error) {
	sr.Lock()
	sr.startPending()
	if sr.accepted != nil && *sr.accepted {
		r := sr.r
		sr.Unlock()
		return r.Read(p)
	}
	sr.reading.Store(true)
	r := sr.r
	sr.Unlock()
	n, err = r.Read(p)
	sr.reading.Store(false)
	if sr.switchPending.Load() {
		sr.Lock()
		sr.startPending()
		sr.Unlock()
	}
	if err != nil {
		var restart *TransportRestartError
		if !errors.As(err, &restart) {
			// Registration can occur while the socket read is in progress.
			sr.Lock()
			sr.readGone = true
			gone := sr.onReadGone
			sr.Unlock()
			if gone != nil {
				gone()
			}
		}
	}
	return n, err
}

// startPending transfers reader ownership only after the direct read returns.
// The caller holds the mutex and no socket read is in progress.
func (sr *liveSwitchReader) startPending() {
	if sr.pr != nil && sr.pipeCopyF != nil {
		go sr.pipeCopyF()
		sr.r = sr.pr
		sr.pr = nil
		sr.pipeCopyF = nil
		sr.switchPending.Store(false)
	}
}

// conn represents the server side of a diameter connection.
type conn struct {
	owner       *physicalConn
	generation  uint64
	retirement  atomic.Uint32
	onClose     func()
	cleanupOnce sync.Once
	cleanupErr  error
	doneOnce    sync.Once
	server      *Server              // the Server on which the connection arrived
	rwc         net.Conn             // i/o connection
	sr          liveSwitchReader     // reads from rwc
	buf         *bufio.ReadWriter    // buffered(sr, rwc)
	tlsState    *tls.ConnectionState // or nil when not using TLS
	writer      *response            // the diam.Conn exposed to handlers

	// handshakeDone is closed after the TLS handshake and its deadline reset.
	// It is nil for non-TLS connections and is set before trackConn.
	handshakeDone chan struct{}
	// accepted marks a connection taken from a listener by Serve. Dialed
	// connections share serve but run the client side of the handshake.
	accepted bool
	closed   atomic.Bool

	hwg           sync.WaitGroup // tracks in-flight handler goroutines
	sem           chan struct{}  // bounds concurrent handlers; nil = unbounded/sequential
	dispatchOrder dispatchQueue  // pending reader callbacks

	drainMu       sync.Mutex
	draining      bool
	active        int
	dispatchEnded bool
	idle          chan struct{}
	done          chan struct{}

	mu           sync.Mutex // guards the following
	closeNotifyc chan struct{}
	clientGone   bool
}

func (c *conn) closeNotify() <-chan struct{} {
	return c.closeSignal(true)
}

// readDone observes terminal transport reads without reading ahead of dispatch.
// MultistreamConn retains its transport-owned asynchronous error observer.
func (c *conn) readDone() <-chan struct{} {
	return c.closeSignal(false)
}

func (c *conn) closeSignal(monitor bool) <-chan struct{} {
	c.mu.Lock()
	if c.closeNotifyc == nil {
		c.closeNotifyc = make(chan struct{})
		if c.clientGone {
			close(c.closeNotifyc)
		}
	}
	result := c.closeNotifyc
	gone := c.clientGone
	c.mu.Unlock()
	if !gone {
		_, multi := c.rwc.(MultistreamConn)
		if monitor || multi {
			c.owner.monitor(c)
		} else {
			c.owner.sr.Lock()
			c.owner.sr.onReadGone = c.owner.notifyReadGone
			readGone := c.owner.sr.readGone
			c.owner.sr.Unlock()
			if readGone {
				c.owner.notifyReadGone()
			}
		}
	}
	return result
}

func (c *conn) notifyClientGone() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closeNotifyc != nil && !c.clientGone {
		close(c.closeNotifyc) // unblock readers
	}
	// Latch the gone state even when nothing has registered yet, so a
	// CloseNotify call that races the read loop's exit still observes it.
	c.clientGone = true
}

// newConn wraps rwc in a connection served by srv.
func (srv *Server) newConn(rwc net.Conn) *conn {
	p := &physicalConn{server: srv, rwc: rwc, original: rwc, done: make(chan struct{}), shutdownDone: make(chan struct{})}
	c := p.newGeneration(nil)
	p.current = c
	if _, ok := rwc.(*tls.Conn); ok {
		c.handshakeDone = make(chan struct{})
	}
	return c
}

// Read next message from connection.
func (c *conn) readMessage() (m *Message, err error) {
	if c.server.ReadTimeout > 0 {
		if err := c.rwc.SetReadDeadline(time.Now().Add(c.server.ReadTimeout)); err != nil {
			return nil, err
		}
	}
	if msc, isMulti := c.rwc.(MultistreamConn); isMulti {
		// If it's a multi-stream association - reset the stream to "undefined" prior to reading next message
		msc.ResetCurrentStream()
		m, err = ReadMessage(msc, c.dictionary()) // MultistreamConn has it's own buffering
	} else {
		m, err = ReadMessage(c.buf.Reader, c.dictionary())
	}
	return m, err
}

// Serve a new connection.
func (c *conn) serve() {
	p := c.owner
	defer func() {
		if v := recover(); v != nil {
			c.logPanic(v)
			_ = p.close()
			p.mu.Lock()
			c = p.current
			p.mu.Unlock()
		}
		// Finish already received messages before normal EOF closure.
		c.hwg.Wait()
		if err := p.close(); err != nil && !errors.Is(err, net.ErrClosed) {
			c.log(slog.LevelDebug, "diam: close connection", slog.Any(logKeyError, err))
		}
		if err := c.cleanup(); err != nil {
			_ = p.close()
		}
		c.notifyClientGone()
		c.finishGeneration()
		p.mu.Lock()
		retired := p.retired
		p.mu.Unlock()
		if retired != nil {
			<-retired.done
		}
		c.server.untrackConn(c)
		close(p.done)
	}()
	if tlsConn, ok := c.rwc.(*tls.Conn); ok {
		err := c.handshakeTLS(tlsConn)
		close(c.handshakeDone)
		if err != nil {
			return
		}
		c.tlsState = new(tls.ConnectionState)
		*c.tlsState = tlsConn.ConnectionState()
	}
	c.accept()
	if cb := c.server.OnNewConnection; cb != nil {
		cb(c.writer)
	}
	for {
		m, err := c.readMessage()
		if err != nil {
			var restart *TransportRestartError
			if c.accepted && errors.As(err, &restart) {
				next := c.renew(SCTPAssociationRestart, restart)
				if next == nil {
					break
				}
				c = next
				continue
			}
			if c.handleReadError(m, err) {
				continue
			}
			break
		}
		if c.accepted && c.server.RenewAcceptedCER && isAcceptedCER(m) {
			if h, ok := HandlerAs[AcceptedCERHandler](c.server.handler()); ok {
				if !c.waitAdmission(time.Now().Add(retirementTimeout)) {
					c.log(slog.LevelWarn, "diam: CER renewal admission timeout; closing connection")
					_ = p.close()
					break
				}
				if h.CanRenewAcceptedCER(c.writer) {
					next := c.renew(AcceptedCERRenewal, nil)
					if next == nil {
						break
					}
					c = next
				}
			}
		}
		c.dispatch(m)
	}
}

// handshakeTLS bounds only the handshake of an accepted connection. RFC 6733
// §2.1 and §13 require TLS before Diameter messages, so the normal message
// read deadline starts later.
func (c *conn) handshakeTLS(tlsConn *tls.Conn) error {
	var limit time.Duration
	if c.accepted {
		limit = c.server.tlsHandshakeTimeout()
	}
	if limit > 0 {
		if err := tlsConn.SetDeadline(time.Now().Add(limit)); err != nil {
			return err
		}
	}
	err := tlsConn.Handshake()
	if limit > 0 {
		if clearErr := tlsConn.SetDeadline(time.Time{}); err == nil {
			err = clearErr
		}
	}
	return err
}

// tlsHandshakeTimeout follows net/http.Server.tlsHandshakeTimeout's minimum
// positive ReadTimeout/WriteTimeout rule (Go net/http/server.go). A negative
// explicit handshake timeout disables the handshake deadline.
func (srv *Server) tlsHandshakeTimeout() time.Duration {
	if srv.TLSHandshakeTimeout < 0 {
		return 0
	}
	limit := srv.TLSHandshakeTimeout
	if limit == 0 {
		limit = 10 * time.Second
	}
	for _, d := range [...]time.Duration{srv.ReadTimeout, srv.WriteTimeout} {
		if d > 0 && d < limit {
			limit = d
		}
	}
	return limit
}

// handleReadError reports err and gives handlers with Diameter message-error
// support an opportunity to answer malformed messages. It returns true only
// when the message boundary is still reliable and the handler succeeded.
func (c *conn) handleReadError(m *Message, err error) bool {
	var me *MessageError
	// RFC 6733 §§5.3.2, 5.4.2, 5.5.2 and 7: let an owning base
	// adapter discard a payload-invalid answer without consuming its pending
	// exchange. Plain readers and handlers retain their decoding-error policy.
	if m != nil && m.Header != nil && m.Header.CommandFlags&RequestFlag == 0 &&
		(m.Header.CommandCode == CapabilitiesExchange || m.Header.CommandCode == DeviceWatchdog || m.Header.CommandCode == DisconnectPeer) {
		var decodeErr *avpDecodeError
		if !errors.As(err, &me) && errors.As(err, &decodeErr) {
			if _, ownsErrors := HandlerAs[MessageErrorHandler](c.dispatchHandler()); ownsErrors {
				err = &MessageError{ResultCode: decodeErr.resultCode, FailedAVP: decodeErr.failedAVP, Err: err}
			}
		}
	}
	if !errors.As(err, &me) {
		var decodeErr *avpDecodeError
		isDecodeFailure := errors.As(err, &decodeErr)
		// Local closes include net.OpError wrappers. MessageError takes
		// precedence above: a decoder can wrap either close sentinel. Only
		// bare EOF is quiet; wrapped EOF can identify a truncated body.
		if err == io.EOF || errors.Is(err, net.ErrClosed) {
			if isDecodeFailure {
				if observer := c.readProtocolObserver(m); observer != nil {
					c.notifyReadProtocolError(observer, protocolMessageMetadata(m), decodeErr.resultCode, ProtocolReplyNone)
				}
			}
			return false
		}
		level := slog.LevelWarn
		var ne net.Error
		if errors.As(err, &ne) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.ErrClosedPipe) {
			level = slog.LevelDebug
		}
		c.log(level, "diam: read failed; closing connection", slog.Any("error", err), slog.Any("message", m))
		// RFC 6733 §§4 and 7: a known AVP payload decoder failure is a
		// protocol condition; transport and local dictionary failures are not.
		if isDecodeFailure {
			if observer := c.readProtocolObserver(m); observer != nil {
				c.notifyReadProtocolError(observer, protocolMessageMetadata(m), decodeErr.resultCode, ProtocolReplyNone)
			}
		}
		return false
	}
	// RFC 6733 §7: record the decoding failure before the handler can answer
	// or close. A handler may take responsibility asynchronously.
	attrs := []slog.Attr{slog.Any("error", err), slog.Any("message", m), slog.Uint64("result_code", uint64(me.ResultCode)), slog.Bool("fatal", me.Fatal)}
	c.log(slog.LevelWarn, "diam: malformed message", attrs...)
	h := c.dispatchHandler()
	c.prepareDispatch(m)
	defer m.releaseDispatch()
	observer := c.readProtocolObserver(m)
	var metadata ProtocolMessageMetadata
	if observer != nil {
		metadata = protocolMessageMetadata(m)
	}
	resultCode := me.ResultCode
	handleErr := fmt.Errorf("no handler supports Diameter message errors: %w", errors.ErrUnsupported)
	if mh, ok := HandlerAs[MessageErrorHandler](h); ok {
		handleErr = mh.HandleMessageError(c.writer, m, me)
	}
	if handleErr == nil && !me.Fatal {
		return true
	}
	level := slog.LevelWarn
	msg := "diam: malformed message; closing connection"
	if handleErr != nil {
		attrs[0] = slog.Any("error", errors.Join(err, handleErr))
		if !errors.Is(handleErr, errors.ErrUnsupported) {
			level = slog.LevelError
			msg = "diam: malformed message handler failed; closing connection"
		}
	}
	c.log(level, msg, attrs...)
	if handleErr != nil {
		reply := ProtocolReplyNone
		if !errors.Is(handleErr, errors.ErrUnsupported) {
			reply = ProtocolReplyUnknown
		}
		c.notifyReadProtocolError(observer, metadata, resultCode, reply)
	}
	return false
}

// dispatch invokes the handler for m either in the current goroutine
// (sequential, default) or in a new goroutine (concurrent), depending
// on Server.MaxConcurrentHandlers. A positive value bounds concurrency
// via a per-connection semaphore; a negative value is unbounded.
func (c *conn) dispatch(m *Message) {
	if c.retirement.Load() != 0 {
		return
	}
	c.drainMu.Lock()
	isDPA := m.Header.ApplicationID == 0 && m.Header.CommandCode == DisconnectPeer && m.Header.CommandFlags&RequestFlag == 0
	if c.draining && !isDPA {
		c.drainMu.Unlock()
		return
	}
	c.prepareDispatch(m)
	c.active++
	c.drainMu.Unlock()
	if c.server.MaxConcurrentHandlers == 0 {
		// Sequential dispatch preserves the historical Handler contract.
		defer c.finishDispatch()
		defer m.releaseDispatch()
		serverHandler{c.server}.ServeDIAM(c.writer, m)
		return
	}
	if c.sem != nil {
		c.sem <- struct{}{} // blocks when MaxConcurrentHandlers reached
	}
	c.hwg.Add(1)
	go func() {
		defer c.hwg.Done()
		defer c.finishDispatch()
		defer m.releaseDispatch()
		defer func() {
			if c.sem != nil {
				<-c.sem
			}
		}()
		defer func() {
			if v := recover(); v != nil {
				c.logPanic(v)
			}
		}()
		serverHandler{c.server}.ServeDIAM(c.writer, m)
	}()
}

// RFC 6733 §§5.6 and 7: admission observes reader order even when a wrapper
// consumes a callback instead of forwarding it to the protocol handler.
func (c *conn) prepareDispatch(m *Message) {
	if m == nil {
		return
	}
	queue := &c.dispatchOrder
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if queue.handler == nil && c.server != nil {
		queue.handler = c.server.handler()
	}
	queue.sequence++
	barrier := &dispatchBarrier{queue: queue, sequence: queue.sequence, previous: queue.tail, done: make(chan struct{})}
	if queue.tail == nil {
		queue.head = barrier
	} else {
		queue.tail.next = barrier
	}
	queue.tail = barrier
	m.dispatch = barrier
}

// dispatchHandler captures one root for message handling and observations.
// The queue's handler is immutable after capture, including across callbacks.
func (c *conn) dispatchHandler() Handler {
	queue := &c.dispatchOrder
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if queue.handler == nil {
		queue.handler = c.server.handler()
	}
	return queue.handler
}

func (c *conn) finishDispatch() {
	c.drainMu.Lock()
	c.active--
	if c.active == 0 && c.dispatchEnded {
		c.finishGeneration()
	}
	if c.active == 0 && c.draining {
		select {
		case c.idle <- struct{}{}:
		default:
		}
	}
	c.drainMu.Unlock()
}

// endDispatch publishes completion from the exact callback count. No more
// callbacks can be admitted once the reader has retired this generation.
func (c *conn) endDispatch() {
	c.drainMu.Lock()
	c.dispatchEnded = true
	if c.active == 0 {
		c.finishGeneration()
	}
	c.drainMu.Unlock()
}

// dictionary returns the dictionary parser associated to the Server instance
// or the shared, initially base-only dict.Default.
func (c *conn) dictionary() *dict.Parser {
	if c.server.Dict == nil {
		return dict.Default
	}
	return c.server.Dict
}

// A response represents the server side of a diameter response.
// It implements the Conn and CloseNotifier interfaces.
type response struct {
	transport.Signal
	conn     *conn           // socket, reader and writer
	xmu      sync.Mutex      // guards ctx
	ctx      context.Context // context for this Conn
	requests atomic.Pointer[PendingRequests]
}

// Write writes the message m to the connection.
func (w *response) Write(b []byte) (int, error) {
	if err := w.lockWriteRequest(b); err != nil {
		return 0, err
	}
	defer w.unlockWrite()
	return w.writeLocked(b, 0, false)
}

// writeLocked writes a complete frame while owning the physical write gate.
// bufio caches transport failures: no later frame may follow a partial prefix
// on a byte stream (RFC 6733 §3).
func (w *response) writeLocked(b []byte, stream uint, explicitStream bool) (int, error) {
	if w.conn.server.WriteTimeout > 0 {
		if err := w.conn.rwc.SetWriteDeadline(time.Now().Add(w.conn.server.WriteTimeout)); err != nil {
			return 0, err
		}
	}
	// Deadline setup can race with retirement's interrupt deadline.
	if err := w.writeError(); err != nil {
		return 0, err
	}
	if msc, ok := w.conn.rwc.(MultistreamConn); ok {
		if explicitStream {
			return msc.WriteStream(b, stream)
		}
		return msc.Write(b)
	}
	n, err := w.conn.buf.Write(b)
	if err == nil {
		err = w.conn.buf.Flush()
	}
	if err != nil {
		w.conn.owner.writeFailed.Store(true)
		return 0, err
	}
	return n, nil
}

// WriteStream of MultistreamWriter interface.
func (w *response) WriteStream(b []byte, stream uint) (int, error) {
	if err := w.lockWriteRequest(b); err != nil {
		return 0, err
	}
	defer w.unlockWrite()
	return w.writeLocked(b, stream, true)
}

// CurrentWriterStream of MultistreamWriter interface
func (w *response) CurrentWriterStream() uint {
	if err := w.lockWrite(); err != nil {
		return 0
	}
	defer w.unlockWrite()
	if msc, ok := w.conn.rwc.(MultistreamConn); ok {
		return msc.CurrentWriterStream()
	}
	return 0
}

func (w *response) ResetWriterStream() {
	if err := w.lockWrite(); err != nil {
		return
	}
	defer w.unlockWrite()
	if msc, ok := w.conn.rwc.(MultistreamConn); ok {
		msc.ResetWriterStream()
	}
}

func (w *response) SetWriterStream(stream uint) uint {
	if err := w.lockWrite(); err != nil {
		return 0
	}
	defer w.unlockWrite()
	if msc, ok := w.conn.rwc.(MultistreamConn); ok {
		return msc.SetWriterStream(stream)
	}
	return 0
}

// Close closes the connection. A failure to close a connection that is not
// already closed is logged to Server.Logger at Debug level.
func (w *response) Close() {
	if err := w.conn.close(); err != nil && !errors.Is(err, net.ErrClosed) {
		w.conn.log(slog.LevelDebug, "diam: close connection", slog.Any(logKeyError, err))
	}
}

// close publishes the local close decision before touching the transport.
func (c *conn) close() error {
	c.owner.mu.Lock()
	if c.owner.current != c || c.retirement.Load() != 0 {
		c.owner.mu.Unlock()
		return nil
	}
	c.closed.Store(true)
	if c.owner.closed {
		c.owner.mu.Unlock()
		return net.ErrClosed
	}
	c.owner.closed = true
	c.owner.mu.Unlock()
	c.notifyClientGone()
	return c.owner.closeTransport()
}

// Closed implements Conn.Closed.
func (w *response) Closed() bool { return w.conn.closed.Load() }

// LocalAddr returns the local address of the connection.
func (w *response) LocalAddr() net.Addr {
	return w.conn.rwc.LocalAddr()
}

// RemoteAddr returns the peer address of the connection.
func (w *response) RemoteAddr() net.Addr {
	return w.conn.rwc.RemoteAddr()
}

// TLS returns the TLS connection state, or nil.
func (w *response) TLS() *tls.ConnectionState {
	return w.conn.tlsState
}

// Dictionary returns the dictionary parser associated to this connection.
// If none was provided, it returns the shared, initially base-only dict.Default.
func (w *response) Dictionary() *dict.Parser {
	return w.conn.dictionary()
}

// CloseNotify implements the CloseNotifier interface.
func (w *response) CloseNotify() <-chan struct{} {
	return w.conn.closeNotify()
}

// DispatchDone closes after the read loop and all handlers for this
// generation have finished, including after retirement. It excludes goroutines
// the application or a watchdog observer starts. It can order connection teardown
// after messages already read from the transport.
func (w *response) DispatchDone() <-chan struct{} {
	return w.conn.done
}

// Context returns the internal context or a new context.Background.
func (w *response) Context() context.Context {
	w.xmu.Lock()
	defer w.xmu.Unlock()
	if w.ctx == nil {
		w.ctx = context.Background()
	}
	return w.ctx
}

// SetContext replaces the internal context with the given one.
func (w *response) SetContext(ctx context.Context) {
	w.xmu.Lock()
	w.ctx = ctx
	w.xmu.Unlock()
}

func (w *response) Connection() net.Conn {
	return w.conn.owner.original
}

// The HandlerFunc type is an adapter to allow the use of
// ordinary functions as diameter handlers.  If f is a function
// with the appropriate signature, HandlerFunc(f) is a
// Handler object that calls f.
type HandlerFunc func(Conn, *Message)

// ServeDIAM calls f(c, m).
func (f HandlerFunc) ServeDIAM(c Conn, m *Message) {
	f(c, m)
}

// MessageErrorHandler takes responsibility for malformed messages (RFC 6733 §7).
// Server discovers it with HandlerAs and calls it synchronously on the reader,
// never through ServeDIAM. Nil means the handler takes responsibility to answer,
// discard an answer, or close, possibly asynchronously. The component performing
// that work logs any later failure. An error matching errors.ErrUnsupported
// declines responsibility; any other error means taking responsibility failed.
// The callback must not wait for subsequent input on this connection. Ordered
// handlers may call Message.BeginDispatch. An Unwrap-only wrapper is bypassed;
// a wrapper intercepting this method must delegate synchronously or take
// responsibility itself before returning.
type MessageErrorHandler interface {
	HandleMessageError(Conn, *Message, *MessageError) error
}

// ServeMux is a diameter message multiplexer. It matches the
// command from the incoming message against a list of
// registered commands and calls the handler.
type ServeMux struct {
	mu     sync.RWMutex // Guards m.
	m      map[string]muxEntry
	idxMap map[CommandIndex]muxEntry
}

type muxEntry struct {
	h      Handler
	cmd    string
	cmdIdx CommandIndex
}

type CommandIndex struct {
	AppID   uint32
	Code    uint32
	Request bool
}

var ALL_CMD_INDEX = CommandIndex{^uint32(0), ^uint32(0), false}

// NewServeMux allocates and returns a new ServeMux.
func NewServeMux() *ServeMux {
	return &ServeMux{
		m:      make(map[string]muxEntry),
		idxMap: make(map[CommandIndex]muxEntry),
	}
}

// DefaultServeMux is the default ServeMux used by Serve.
var DefaultServeMux = NewServeMux()

// Handler returns the handler for m: its CommandIndex registration, then its
// dictionary short-name registration, then ALL. It returns nil, false if none
// matches. Index routes work even when the dictionary does not know the command.
func (mux *ServeMux) Handler(m *Message) (Handler, bool) {
	mux.mu.RLock()
	defer mux.mu.RUnlock()
	if m != nil && m.Header != nil {
		h := m.Header
		idx := CommandIndex{h.ApplicationID, h.CommandCode, h.CommandFlags&RequestFlag != 0}
		if e, ok := mux.idxMap[idx]; ok {
			return e.h, true
		}
		if cmd, err := m.Dictionary().FindCommand(h.ApplicationID, h.CommandCode); err == nil {
			name := cmd.Short + "A"
			if idx.Request {
				name = cmd.Short + "R"
			}
			if e, ok := mux.m[name]; ok {
				return e.h, true
			}
		}
	}
	e, ok := mux.idxMap[ALL_CMD_INDEX]
	return e.h, ok
}

// ServeDIAM calls the handler returned by Handler. If no route matches, it
// drops m and writes a synchronous Warn record using m.Context(). A bare mux
// cannot answer without a local identity; sm.StateMachine answers unsupported
// requests (RFC 6733 §7.1.3).
func (mux *ServeMux) ServeDIAM(c Conn, m *Message) {
	if h, ok := mux.Handler(m); ok {
		h.ServeDIAM(c, m)
		return
	}
	c.Logger().LogAttrs(m.Context(), slog.LevelWarn, "diam: unhandled message", slog.Any("message", m))
	// RFC 6733 §§6.2.1 and 7.1.3: preserve a wrapper's observer for a bare
	// mux discard. Calling this mux again would find no route or ALL.
	if m.dispatch != nil {
		queue := m.dispatch.queue
		queue.mu.Lock()
		handler := queue.handler
		queue.mu.Unlock()
		if observer, _ := protocolObserverFor(c, handler, m); observer != nil {
			event := ProtocolErrorEvent{Conn: c, Message: protocolMessageMetadata(m), Err: NewProtocolError(ProtocolUnexpectedMessage, 0)}
			observe.Call(c.Logger(), func() { observer.HandleProtocolError(event) })
		}
	}
}

// HandleMessageError delegates to the MessageErrorHandler found through
// HandlerAs on the matching route, falling back to ALL if the route has no such
// interface. It returns an error matching errors.ErrUnsupported when neither
// supports malformed messages. It never invokes a route's ServeDIAM.
func (mux *ServeMux) HandleMessageError(c Conn, m *Message, messageErr *MessageError) error {
	if h, ok := mux.Handler(m); ok {
		if mh, ok := HandlerAs[MessageErrorHandler](h); ok {
			return mh.HandleMessageError(c, m, messageErr)
		}
	}
	mux.mu.RLock()
	fallback := mux.idxMap[ALL_CMD_INDEX].h
	mux.mu.RUnlock()
	if mh, ok := HandlerAs[MessageErrorHandler](fallback); ok {
		return mh.HandleMessageError(c, m, messageErr)
	}
	return fmt.Errorf("no registered handler supports Diameter message errors: %w", errors.ErrUnsupported)
}

// HandleProtocolError delegates to the first ProtocolErrorObserver found by
// HandlerAs on the matching route, then ALL. Header metadata is resolved using
// the original connection's dictionary. An unknown header uses ALL only.
// It never invokes a route's ServeDIAM and contains third-party observer panics.
func (mux *ServeMux) HandleProtocolError(event ProtocolErrorEvent) {
	defer func() {
		if value := recover(); value != nil {
			observe.LogPanic(event.Conn.Logger(), value)
		}
	}()
	var message *Message
	if event.Message.HasHeader {
		header := event.Message.Header
		message = &Message{Header: &header, dictionary: event.Conn.Dictionary()}
	}
	if observer, _ := protocolObserverFor(event.Conn, mux, message); observer != nil {
		observe.Call(event.Conn.Logger(), func() { observer.HandleProtocolError(event) })
	}
}

func (mux *ServeMux) protocolObserver(c Conn, message *Message) ProtocolErrorObserver {
	if handler, ok := mux.Handler(message); ok {
		if observer, found := protocolObserverFor(c, handler, message); found {
			return observer
		}
	}
	mux.mu.RLock()
	fallback := mux.idxMap[ALL_CMD_INDEX].h
	mux.mu.RUnlock()
	observer, _ := protocolObserverFor(c, fallback, message)
	return observer
}

// Handle registers a command short name, such as CER, or ALL as a fallback.
// Short names are application-agnostic: PUR matches both S6a and Sh PUR.
// Use HandleIdx with an AppID to bind one application. Handle panics for an
// empty name, a nil handler, or a duplicate registration.
func (mux *ServeMux) Handle(shortCmd string, handler Handler) {
	mux.mu.Lock()
	defer mux.mu.Unlock()
	if handler == nil {
		panic("diam: nil handler")
	}
	if f, ok := handler.(HandlerFunc); ok && f == nil {
		panic("diam: nil handler")
	}
	if shortCmd == "" {
		panic("diam: empty command name")
	}
	if shortCmd == "ALL" {
		if _, ok := mux.idxMap[ALL_CMD_INDEX]; ok {
			panic("diam: duplicate ALL handler")
		}
		mux.idxMap[ALL_CMD_INDEX] = muxEntry{h: handler, cmd: shortCmd}
		return
	}
	if _, ok := mux.m[shortCmd]; ok {
		panic("diam: duplicate handler for " + shortCmd)
	}
	mux.m[shortCmd] = muxEntry{h: handler, cmd: shortCmd}
}

// HandleIdx registers an application-specific command index; ALL_CMD_INDEX
// is the same fallback as Handle("ALL", handler). It panics for nil handlers
// or duplicate indexes.
func (mux *ServeMux) HandleIdx(cmd CommandIndex, handler Handler) {
	mux.mu.Lock()
	defer mux.mu.Unlock()
	if handler == nil {
		panic("diam: nil handler")
	}
	if f, ok := handler.(HandlerFunc); ok && f == nil {
		panic("diam: nil handler")
	}
	if _, ok := mux.idxMap[cmd]; ok {
		panic(fmt.Sprintf("diam: duplicate handler for %v", cmd))
	}
	mux.idxMap[cmd] = muxEntry{h: handler, cmdIdx: cmd}
}

// HandleFunc registers the handler function for the given command.
// Special cmd "ALL" may be used as a catch all.
func (mux *ServeMux) HandleFunc(cmd string, handler func(Conn, *Message)) {
	if handler == nil {
		panic("diam: nil handler")
	}
	mux.Handle(cmd, HandlerFunc(handler))
}

// Handle registers the handler object for the given command
// in the DefaultServeMux.
func Handle(cmd string, handler Handler) {
	DefaultServeMux.Handle(cmd, handler)
}

// HandleFunc registers the handler function for the given command
// in the DefaultServeMux.
func HandleFunc(cmd string, handler func(Conn, *Message)) {
	DefaultServeMux.HandleFunc(cmd, handler)
}

// Serve accepts incoming diameter connections on the listener l,
// creating a new service goroutine for each.  The service goroutines
// read messages and then call handler to reply to them.
// Handler is typically nil, in which case the DefaultServeMux is used.
func Serve(l net.Listener, handler Handler) error {
	srv := &Server{Handler: handler}
	return srv.Serve(l)
}

// A Server defines parameters for running a diameter server.
// Shutdown takes precedence over accepted connection renewal: a renewal in
// progress is abandoned and its physical connection closes.
type Server struct {
	Network string // network of the address - empty string defaults to tcp
	Addr    string // address to listen on; blank uses :3868, or :5868 with TLS
	// Handler invokes message handlers; nil uses DefaultServeMux. Set it before
	// serving or dialing starts and do not replace it while Server is in use.
	// Each connection captures one root for dispatch and protocol notification.
	Handler      Handler
	Dict         *dict.Parser  // Selected parser; nil uses the shared, initially base-only dict.Default
	ReadTimeout  time.Duration // maximum duration before timing out read of the request
	WriteTimeout time.Duration // maximum duration before timing out write of the response
	// TLSHandshakeTimeout limits the TLS handshake of connections accepted by
	// Serve; dialed connections are not affected. Zero defaults to 10 seconds;
	// a negative value disables the handshake deadline. Positive ReadTimeout
	// or WriteTimeout values can shorten this limit.
	TLSHandshakeTimeout time.Duration
	TLSConfig           *tls.Config // optional TLS config, used by ListenAndServeTLS
	LocalAddr           net.Addr    // optional Local Address to bind dailer's (Dail...) socket to

	// MaxConcurrentHandlers controls per-connection handler dispatch.
	//   0 (default) - sequential dispatch: each message is handled to
	//                 completion before the next is read. Preserves the
	//                 historical Handler contract.
	//   >0          - concurrent dispatch bounded by this many in-flight
	//                 handlers per connection; once reached, the read
	//                 loop blocks until a slot frees.
	//   <0          - unbounded concurrent dispatch (not recommended for
	//                 untrusted peers).
	//
	// Why enable concurrent dispatch:
	// Sequential dispatch caps per-connection throughput at
	// 1 / handler_latency, regardless of network or CPU headroom. Real
	// handlers typically do I/O (DB lookups, auth, logging, remote calls)
	// in the 1-10ms range, which caps a connection at 100-1000 msg/s.
	// Concurrent dispatch lets independent requests proceed in parallel,
	// hiding handler latency and raising throughput to roughly
	// MaxConcurrentHandlers / handler_latency until CPU saturates.
	// Measured locally with a 1ms handler: ~810 msg/s sequential vs
	// ~39,900 msg/s with MaxConcurrentHandlers=256 (~49x).
	//
	// Concurrent callbacks can finish out of order; Diameter correlates answers
	// by Hop-by-Hop ID. Plain callbacks never wait for older callbacks on return.
	// Stateful protocol handlers may call Message.BeginDispatch to order admission;
	// release before waiting for later messages. BeginDispatch waits for earlier
	// callbacks to return, so a callback that waits for a later message on its
	// connection must not be followed by one that calls BeginDispatch while every
	// slot is taken. sm.StateMachine and peer.Manager
	// do this internally. Their wrappers must forward ServeDIAM synchronously.
	// Unwrap-only wrappers are bypassed for MessageErrorHandler; wrappers that
	// intercept it must delegate synchronously or take responsibility themselves.
	// Shared application state still needs its own synchronization.
	MaxConcurrentHandlers int

	// OnNewConnection, if non-nil, is invoked once per accepted connection
	// after the transport is fully established (TLS handshake complete, if
	// applicable) and before the read loop starts. It runs in the
	// connection's serve goroutine, so long-running work will delay message
	// processing on that connection. Use ConnAs[CloseNotifier] to detect
	// disconnection:
	//
	//	srv.OnNewConnection = func(c diam.Conn) {
	//		slog.Info("peer connected", "remote_addr", c.RemoteAddr())
	//		notifier, ok := diam.ConnAs[diam.CloseNotifier](c)
	//		if !ok {
	//			return
	//		}
	//		go func() {
	//			<-notifier.CloseNotify()
	//			slog.Info("peer disconnected", "remote_addr", c.RemoteAddr())
	//		}()
	//	}
	OnNewConnection func(Conn)

	// RenewAcceptedCER interprets a subsequent admitted base CER as a fresh
	// accepted generation when the handler implements AcceptedCERHandler and
	// RetireHandler. Default false preserves the handler's Open-state CER policy.
	// Prefer SCTP restart notifications; this policy cannot distinguish a retry
	// from a peer restart (RFC 6733 §§1.1.3, 5.6).
	RenewAcceptedCER bool

	// OnConnectionRestart runs after HandleAccept on the fresh generation, before
	// its CER. Context starts from Background; applications may rebuild values
	// here. The hook must return promptly and is invoked once per renewal.
	OnConnectionRestart func(oldConn, newConn Conn, reason RetirementReason)

	// OnShutdownConnection runs once per open connection after its active
	// handlers finish and before the transport closes. The read loop remains
	// available for a DPR/DPA exchange. The callback must honor ctx and
	// return promptly when it is canceled. A generation already retired when
	// Shutdown begins does not receive this callback.
	OnShutdownConnection func(ctx context.Context, c Conn)

	// Logger receives synchronous records about accepted and dialed connections
	// through Conn.Logger. Error records describe recovered panics (value and stack)
	// and failures taking responsibility for malformed messages. Warn records
	// describe malformed messages (RFC 6733 §7), unhandled messages, undecodable
	// input, and accept failures Serve retries. Transport read failures other than
	// bare EOF and errors wrapping net.ErrClosed, and close failures, are Debug.
	// StateMachine logs answered unsupported requests at Info and unmatched answers
	// at Warn; protocol faults are Warn and local failures are Error.
	// A malformed-input record precedes the optional error handler. If Server
	// decides to close, it records that decision before closing. Handlers that
	// close or fail asynchronously log their own decisions before acting.
	// The error attribute retains the error value for errors.As. Connection
	// records include network, local_addr and remote_addr. Slow slog handlers
	// slow the detecting goroutine; buffering and sampling are application choices.
	// Nil uses slog.Default for each record, honoring later slog.SetDefault calls.
	// Use slog.New(slog.DiscardHandler) to discard records.
	Logger *slog.Logger

	mu        sync.Mutex
	listeners map[net.Listener]struct{}
	conns     map[*physicalConn]struct{}
	closed    bool
}

// ConfigureHandlerBeforeServe atomically installs a handler and chains connection
// hooks while the server is idle. It is used by opt-in connection owners.
func (srv *Server) ConfigureHandlerBeforeServe(handler Handler, onNew func(Conn), onShutdown func(context.Context, Conn)) error {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.closed || len(srv.listeners) != 0 || len(srv.conns) != 0 {
		return fmt.Errorf("diam: server is already serving or closed")
	}
	if srv.Handler != nil {
		return fmt.Errorf("diam: server already has a handler")
	}
	previousNew, previousShutdown := srv.OnNewConnection, srv.OnShutdownConnection
	srv.Handler = handler
	srv.OnNewConnection = func(c Conn) {
		if previousNew != nil {
			previousNew(c)
		}
		if onNew != nil {
			onNew(c)
		}
	}
	srv.OnShutdownConnection = func(ctx context.Context, c Conn) {
		if onShutdown != nil {
			onShutdown(ctx, c)
		}
		if previousShutdown != nil {
			previousShutdown(ctx, c)
		}
	}
	return nil
}

// ErrServerClosed is returned by Server.Serve and Server.ListenAndServe(TLS)
// after a call to Server.Close.
var ErrServerClosed = fmt.Errorf("diam: Server closed")

// Close immediately closes all listeners registered with the server and
// closes accepted connections still in a TLS handshake. Established
// connections and in-flight handlers continue until their read loop exits
// naturally or their underlying connection is closed by the peer. After Close,
// Server.Serve returns ErrServerClosed and no new connections are accepted.
// The error joins every failure to close a listener or a connection.
func (srv *Server) Close() error {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.closed = true
	var errs []error
	for l := range srv.listeners {
		if err := l.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	for c := range srv.conns {
		c.mu.Lock()
		handshakeDone := c.current.handshakeDone
		c.mu.Unlock()
		if handshakeDone != nil {
			select {
			case <-handshakeDone:
			default:
				if err := c.close(); err != nil && !errors.Is(err, net.ErrClosed) {
					errs = append(errs, err)
				}
			}
		}
	}
	srv.listeners = nil
	return errors.Join(errs...)
}

// Shutdown stops accepting connections, waits for active handlers, runs
// OnShutdownConnection for each live generation, and closes their transports.
// When ctx expires, remaining transports are closed and ctx.Err is returned.
// A caller can use the hook to send a DPR before each transport closes.
// Shutdown abandons any renewal in progress and closes its physical connection.
// A retired generation does not receive the hook: after an association restart
// it cannot send a DPR to the old peer (RFC 9260 §5.2.4; RFC 6733 §5.4).
func (srv *Server) Shutdown(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("diam: nil shutdown context")
	}
	srv.mu.Lock()
	srv.closed = true
	conns := make([]*physicalConn, 0, len(srv.conns))
	for p := range srv.conns {
		conns = append(conns, p)
		p.mu.Lock()
		p.draining = true
		c := p.current
		c.drainMu.Lock()
		c.draining = true
		c.drainMu.Unlock()
		p.mu.Unlock()
	}
	srv.mu.Unlock()
	closeErr := srv.Close()
	for _, p := range conns {
		p.shutdownOnce.Do(func() { go srv.shutdownConn(ctx, p) })
	}
	for _, p := range conns {
		for _, done := range []<-chan struct{}{p.shutdownDone, p.done} {
			select {
			case <-done:
			case <-ctx.Done():
				for _, pending := range conns {
					_ = pending.close()
				}
				return ctx.Err()
			}
		}
	}
	return closeErr
}

func (srv *Server) shutdownConn(ctx context.Context, p *physicalConn) {
	defer close(p.shutdownDone)
	defer func() { _ = p.close() }()
	p.mu.Lock()
	c, retired := p.current, p.retired
	if p.closed || c.retirement.Load() != 0 {
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()
	if retired != nil {
		select {
		case <-retired.done:
		case <-ctx.Done():
			return
		}
	}
	for {
		c.drainMu.Lock()
		active := c.active
		c.drainMu.Unlock()
		if active == 0 {
			break
		}
		select {
		case <-c.idle:
		case <-c.done:
			return
		case <-ctx.Done():
			return
		}
	}
	select {
	case <-c.done:
		return
	case <-ctx.Done():
		return
	default:
	}
	if srv.OnShutdownConnection != nil {
		srv.OnShutdownConnection(ctx, c.writer)
	}
}

func (srv *Server) trackConn(c *conn) bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.closed {
		return false
	}
	if srv.conns == nil {
		srv.conns = make(map[*physicalConn]struct{})
	}
	srv.conns[c.owner] = struct{}{}
	return true
}

func (srv *Server) untrackConn(c *conn) {
	srv.mu.Lock()
	delete(srv.conns, c.owner)
	srv.mu.Unlock()
}

func (srv *Server) trackListener(l net.Listener, add bool) bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if add {
		if srv.closed {
			return false
		}
		if srv.listeners == nil {
			srv.listeners = make(map[net.Listener]struct{})
		}
		srv.listeners[l] = struct{}{}
		return true
	}
	delete(srv.listeners, l)
	return true
}

func (srv *Server) isClosed() bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return srv.closed
}

// onceCloseListener wraps a net.Listener so that Close is idempotent.
// Used internally by ListenAndServe(TLS) so the defer l.Close() and
// Server.Close do not both close the underlying listener, which triggers
// file-descriptor reuse races on SCTP (see 29cbaef). Only the first Close
// reports the outcome of closing the listener; later calls return
// net.ErrClosed, as a second Close of a net listener does, so a close
// failure reaches exactly one caller.
type onceCloseListener struct {
	net.Listener
	once sync.Once
}

func (oc *onceCloseListener) Close() error {
	err := net.ErrClosed
	oc.once.Do(func() { err = oc.Listener.Close() })
	return err
}

// closeOwnedListener closes a listener ListenAndServe(TLS) opened, after
// Serve returned *err, and joins a close failure to *err. When Server.Close
// closed the listener first, Close reports net.ErrClosed here, and the
// failure, if any, was returned by Server.Close.
func closeOwnedListener(l net.Listener, err *error) {
	if closeErr := l.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
		*err = errors.Join(*err, fmt.Errorf("diam: close listener: %w", closeErr))
	}
}

// serverHandler uses the root captured at dispatch admission. Calls outside
// Server admission use the configured Handler or DefaultServeMux.
type serverHandler struct {
	srv *Server
}

func (sh serverHandler) ServeDIAM(w Conn, m *Message) {
	var handler Handler
	if m != nil && m.dispatch != nil {
		handler = m.dispatch.queue.handler
	}
	if handler == nil {
		handler = sh.srv.handler()
	}
	handler.ServeDIAM(w, m)
}

// ListenAndServe listens on the network address srv.Addr and then
// calls Serve to handle requests on incoming connections. It closes the
// listener when Serve returns; a failure to close it is joined to the error
// Serve returned.
//
// If srv.Network is blank, "tcp" is used
// If srv.Addr is blank, ":3868" is used.
func (srv *Server) ListenAndServe() (err error) {
	network := srv.Network
	if len(network) == 0 {
		network = "tcp"
	}
	addr := srv.Addr
	if len(addr) == 0 {
		addr = ":3868"
	}
	l, e := MultistreamListen(network, addr)
	if e != nil {
		return e
	}
	l = &onceCloseListener{Listener: l}
	defer closeOwnedListener(l, &err)
	return srv.Serve(l)
}

// Serve accepts incoming connections on the Listener l, creating a
// new service goroutine for each. The service goroutines read requests and
// then call srv.Handler to reply to them.
// The caller is responsible for closing l when Serve returns.
// Serve retries transient accept errors with a capped exponential backoff.
// Serve returns ErrServerClosed after srv.Close is called.
func (srv *Server) Serve(l net.Listener) error {
	if !srv.trackListener(l, true) {
		return ErrServerClosed
	}
	defer srv.trackListener(l, false)
	var tempDelay time.Duration // how long to sleep on accept failure
	for {
		rw, e := l.Accept()
		if e != nil {
			if srv.isClosed() {
				return ErrServerClosed
			}
			if retryAcceptError(e) {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				attrs := append(addrAttrs(l.Addr(), nil),
					slog.Any(logKeyError, e), slog.Duration(logKeyRetryIn, tempDelay))
				srv.logger().LogAttrs(context.Background(), slog.LevelWarn,
					"diam: accept failed; retrying", attrs...)
				time.Sleep(tempDelay)
				continue
			}
			// Returned, not logged: the caller decides how to report it,
			// and a listener's error already names its network and address.
			return e
		}
		tempDelay = 0
		original := rw
		if raw, ok := rw.(*sctp.Conn); ok {
			adapter, err := NewSCTPConn(raw)
			if err != nil {
				srv.logger().Warn("diam: subscribe accepted SCTP connection; closing connection", "error", err)
				_ = rw.Close()
				continue
			}
			rw = adapter
		}
		c := srv.newConn(rw)
		c.owner.original = original
		c.accepted = true
		if !srv.trackConn(c) {
			_ = rw.Close()
			return ErrServerClosed
		}
		go c.serve()
	}
}

// ListenAndServeNetwork listens on the network & addr
// and then calls Serve with handler to handle requests
// on incoming connections.
//
// If handler is nil, DefaultServeMux is used.
//
// If dict is nil, the shared, initially base-only dict.Default is used.
// Pass an explicitly selected parser for application dictionaries.
func ListenAndServeNetwork(network, addr string, handler Handler, dp *dict.Parser) error {
	server := &Server{Network: network, Addr: addr, Handler: handler, Dict: dp}
	return server.ListenAndServe()
}

// ListenAndServe listens on the TCP network address addr
// and then calls Serve with handler to handle requests
// on incoming connections.
//
// If handler is nil, DefaultServeMux is used.
//
// If dict is nil, the shared, initially base-only dict.Default is used.
// Pass an explicitly selected parser for application dictionaries.
func ListenAndServe(addr string, handler Handler, dp *dict.Parser) error {
	return ListenAndServeNetwork("tcp", addr, handler, dp)
}

// ListenAndServeTLS listens on the network address srv.Addr and
// then calls Serve to handle requests on incoming TLS connections.
//
// Either filenames containing a certificate and matching private key
// for the server must be provided either the callback
// srv.TLSConfig.GetCertificate should be filled in advance.
// If the certificate is signed by a
// certificate authority, the certFile should be the concatenation
// of the server's certificate followed by the CA's certificate.
//
// It closes the listener when Serve returns; a failure to close it is joined
// to the error Serve returned.
//
// If srv.Network is blank, "tcp" is used
// If srv.Addr is blank, ":5868" is used (RFC 6733 §2.1, Verified Erratum 3997).
func (srv *Server) ListenAndServeTLS(certFile, keyFile string) (err error) {
	network := srv.Network
	if len(network) == 0 {
		network = "tcp"
	}
	addr := defaultTransportAddress(srv.Addr, true)
	var config *tls.Config
	if srv.TLSConfig == nil {
		config = new(tls.Config)
	} else {
		config = TLSConfigClone(srv.TLSConfig)
	}
	if config.GetCertificate == nil {
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return err
		}
	}
	conn, err := MultistreamListen(network, addr)
	if err != nil {
		return err
	}
	tlsListener := tls.NewListener(conn, config)
	tlsListener = &onceCloseListener{Listener: tlsListener}
	defer closeOwnedListener(tlsListener, &err)
	return srv.Serve(tlsListener)
}

// ListenAndServeNetworkTLS acts identically to ListenAndServeNetwork, except that it
// expects SSL connections. Additionally, files containing a certificate and
// matching private key for the server must be provided. If the certificate
// is signed by a certificate authority, the certFile should be the concatenation
// of the server's certificate followed by the CA's certificate.
//
// One can use generate_cert.go in crypto/tls to generate cert.pem and key.pem.
func ListenAndServeNetworkTLS(network, addr string, certFile string, keyFile string, handler Handler, dp *dict.Parser) error {
	server := &Server{Network: network, Addr: addr, Handler: handler, Dict: dp}
	return server.ListenAndServeTLS(certFile, keyFile)
}

// ListenAndServeTLS acts identically to ListenAndServe, except that it
// expects SSL connections. Additionally, files containing a certificate and
// matching private key for the server must be provided. If the certificate
// is signed by a certificate authority, the certFile should be the concatenation
// of the server's certificate followed by the CA's certificate.
//
// One can use generate_cert.go in crypto/tls to generate cert.pem and key.pem.
func ListenAndServeTLS(addr string, certFile string, keyFile string, handler Handler, dp *dict.Parser) error {
	return ListenAndServeNetworkTLS("tcp", addr, certFile, keyFile, handler, dp)
}
