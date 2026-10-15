package diam

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const retirementTimeout = time.Second

// physicalConn owns transport operations across handler-visible generations.
// Its single reader retains TCP read-ahead during an opt-in CER renewal.
type physicalConn struct {
	server             *Server
	rwc, original      net.Conn
	reader             *bufio.Reader
	sr                 *liveSwitchReader
	writeGate          writeGate
	writeFailed        atomic.Bool
	tlsRestart         atomic.Bool
	mu                 sync.Mutex
	current, retired   *conn
	closed, draining   bool
	readGone           bool
	monitorOnce        sync.Once
	done, shutdownDone chan struct{}
	shutdownOnce       sync.Once
}

func (srv *Server) handler() Handler {
	if srv.Handler != nil {
		return srv.Handler
	}
	return DefaultServeMux
}

func (p *physicalConn) newGeneration(old *conn) *conn {
	c := &conn{owner: p, server: p.server, rwc: p.rwc, generation: 1,
		idle: make(chan struct{}, 1), done: make(chan struct{}), clientGone: p.readGone}
	if old != nil {
		c.generation = old.generation + 1
		c.accepted = old.accepted
		c.tlsState = old.tlsState
	}
	c.writer = &response{conn: c}
	if _, multi := p.rwc.(MultistreamConn); !multi {
		if p.reader == nil {
			p.sr = &c.sr
			p.sr.r = p.rwc
			p.reader = bufio.NewReader(p.sr)
		}
		c.buf = bufio.NewReadWriter(p.reader, bufio.NewWriter(p.rwc))
	}
	if n := p.server.MaxConcurrentHandlers; n > 0 {
		c.sem = make(chan struct{}, n)
	}
	return c
}

func (p *physicalConn) close() error {
	return p.closePhysical(true)
}

// RFC 6733 §5.6: transport loss must not publish Closed before callbacks for
// already decoded messages finish. Their reader publishes it on exit.
func (p *physicalConn) closeAfterReadError() error {
	return p.closePhysical(false)
}

func (p *physicalConn) closePhysical(closeGeneration bool) error {
	p.mu.Lock()
	c := p.current
	if closeGeneration {
		c.closed.Store(true)
	}
	if p.closed {
		p.mu.Unlock()
		return net.ErrClosed
	}
	p.closed = true
	p.mu.Unlock()
	c.notifyClientGone()
	return p.closeTransport()
}

func (p *physicalConn) closeTransport() error {
	if secure, ok := p.rwc.(*tls.Conn); ok && p.tlsRestart.Load() {
		// Abort the failed TLS session (RFC 9846 §6.2); the restarted
		// peer cannot consume its old close_notify record.
		return secure.NetConn().Close()
	}
	return p.rwc.Close()
}

func (c *conn) accept() {
	if c.accepted {
		if h, ok := HandlerAs[AcceptHandler](c.server.handler()); ok {
			c.onClose = h.HandleAccept(c.writer)
		}
	}
}

func (c *conn) cleanup() error {
	c.cleanupOnce.Do(func() {
		defer func() {
			if v := recover(); v != nil {
				c.logPanic(v)
				c.cleanupErr = fmt.Errorf("accept cleanup panicked: %v", v)
			}
		}()
		if c.onClose != nil {
			c.onClose()
		}
	})
	return c.cleanupErr
}
func (c *conn) finishGeneration() { c.doneOnce.Do(func() { close(c.done) }) }

func (w *response) Generation() uint64 { return w.conn.generation }
func (w *response) RetirementReason() RetirementReason {
	return RetirementReason(w.conn.retirement.Load())
}

func (w *response) writeError() error {
	c, p := w.conn, w.conn.owner
	p.mu.Lock()
	defer p.mu.Unlock()
	if c.retirement.Load() != 0 || p.current != c {
		return errors.Join(net.ErrClosed, ErrConnectionRetired)
	}
	if p.closed || c.closed.Load() {
		return net.ErrClosed
	}
	return nil
}
func (w *response) lockWrite() error { return w.lockWriteRequest(nil) }

func (w *response) lockWriteRequest(b []byte) error {
	// Check ownership again after acquiring the common lock: a writer queued
	// before retirement cannot publish into a new generation.
	if err := w.writeError(); err != nil {
		return err
	}
	if err := w.conn.owner.writeGate.lock(w.requestPublication(b)); err != nil {
		return err
	}
	if err := w.writeError(); err != nil {
		w.unlockWrite()
		return err
	}
	return nil
}
func (w *response) unlockWrite() { w.conn.owner.writeGate.unlock() }

func (c *conn) waitAdmission(until time.Time) bool {
	for {
		c.dispatchOrder.mu.Lock()
		head := c.dispatchOrder.head
		if head == nil {
			c.dispatchOrder.mu.Unlock()
			return true
		}
		done := head.done
		c.dispatchOrder.mu.Unlock()
		timer := time.NewTimer(time.Until(until))
		select {
		case <-done:
			timer.Stop()
		case <-timer.C:
			return false
		}
	}
}

func isAcceptedCER(m *Message) bool {
	return m != nil && m.Header != nil && m.DecodeErr == nil && m.Header.ApplicationID == 0 &&
		m.Header.CommandCode == CapabilitiesExchange && m.Header.CommandFlags&RequestFlag != 0 &&
		m.Header.CommandFlags&(ProxiableFlag|ErrorFlag|0x0f) == 0
}

func (c *conn) renew(reason RetirementReason, restart *TransportRestartError) *conn {
	p := c.owner
	if reason == SCTPAssociationRestart && c.tlsState != nil {
		// Record this before fallback paths: the old TLS session cannot
		// send close_notify even when the handler cannot retire.
		p.tlsRestart.Store(true)
	}
	h, ok := HandlerAs[RetireHandler](c.server.handler())
	if !ok {
		c.log(slog.LevelWarn, "diam: transport restart without retirement handler; closing connection", slog.Any("reason", reason), slog.Any("restart", restart))
		_ = p.close()
		return nil
	}
	until := time.Now().Add(retirementTimeout)
	p.mu.Lock()
	if p.closed || p.draining || c.closed.Load() || p.current != c {
		p.mu.Unlock()
		_ = p.close()
		return nil
	}
	if p.retired != nil {
		select {
		case <-p.retired.done:
			p.retired = nil
		default:
			p.mu.Unlock()
			c.log(slog.LevelWarn, "diam: previous generation still dispatching; closing connection")
			_ = p.close()
			return nil
		}
	}
	// RFC 9260 §5.2.4 restarts the association. Map it to transport loss of
	// this Diameter generation and fresh admission (RFC 6733 §§5.6–5.6.1).
	c.retirement.Store(uint32(reason))
	c.closed.Store(true)
	p.mu.Unlock()
	c.notifyClientGone()
	fail := func(err error) *conn {
		c.log(slog.LevelWarn, "diam: connection retirement failed; closing connection", slog.Any("reason", reason), slog.Any("error", err))
		_ = p.close()
		return nil
	}
	// Quiesce previously started writes. Deadlines are internal transport
	// operations; no optional ConnWriteDeadline API is needed by this owner.
	if acquired, _, _ := p.writeGate.attempt(nil); !acquired {
		if err := p.rwc.SetWriteDeadline(time.Now()); err != nil {
			return fail(err)
		}
		if !p.writeGate.lockUntil(until) {
			return fail(fmt.Errorf("write quiescence timeout"))
		}
	}
	locked := true
	defer func() {
		if locked {
			p.writeGate.unlock()
		}
	}()
	if _, multi := p.rwc.(MultistreamConn); !multi && p.writeFailed.Load() {
		return fail(fmt.Errorf("interrupted write may contain a partial frame"))
	}
	if err := p.rwc.SetWriteDeadline(time.Time{}); err != nil {
		return fail(err)
	}
	if !c.waitAdmission(until) {
		return fail(fmt.Errorf("protocol admission timeout"))
	}
	retired := make(chan error, 1)
	go func() {
		defer func() {
			if v := recover(); v != nil {
				c.logPanic(v)
				retired <- fmt.Errorf("retirement handler panicked: %v", v)
			}
		}()
		err := h.HandleRetire(c.writer, reason)
		if err == nil {
			err = c.cleanup()
		}
		retired <- err
	}()
	timer := time.NewTimer(time.Until(until))
	select {
	case err := <-retired:
		timer.Stop()
		if err != nil {
			return fail(err)
		}
	case <-timer.C:
		return fail(fmt.Errorf("protocol retirement timeout"))
	}
	if reason == SCTPAssociationRestart && c.tlsState != nil {
		// Go 1.27.2 crypto/tls/conn.go, readRecordOrCCS, latches a
		// non-temporary transport error. This TLS reader cannot resume.
		return fail(fmt.Errorf("TLS reader cannot resume after SCTP restart"))
	}
	if reason == SCTPAssociationRestart {
		if reset, ok := p.rwc.(interface{ ResetForRestart() }); ok {
			reset.ResetForRestart()
		}
		if p.reader != nil {
			p.reader.Reset(p.sr)
		}
	}
	p.mu.Lock()
	if p.closed || p.draining {
		p.mu.Unlock()
		_ = p.close()
		return nil
	}
	next := p.newGeneration(c)
	p.current = next
	p.retired = c
	p.mu.Unlock()
	c.endDispatch()
	// Release the writer before hooks: HandleAccept/OnConnectionRestart may
	// perform immediate connection operations, including Close.
	p.writeGate.unlock()
	locked = false
	next.accept()
	if hook := c.server.OnConnectionRestart; hook != nil {
		hook(c.writer, next.writer, reason)
	}
	attrs := []slog.Attr{slog.Any("reason", reason), slog.String("physical_connection", fmt.Sprintf("%p", p)), slog.Uint64("old_generation", c.generation), slog.Uint64("new_generation", next.generation)}
	if restart != nil {
		attrs = append(attrs, slog.Uint64("association_id", uint64(restart.AssociationID)), slog.Uint64("inbound_streams", uint64(restart.InboundStreams)), slog.Uint64("outbound_streams", uint64(restart.OutboundStreams)))
	}
	next.log(slog.LevelInfo, "diam: accepted connection renewed", attrs...)
	return next
}

// monitor is installed once per transport. The reader bridge forwards restart
// as an ordered event, since io.Pipe.CloseWithError cannot represent a renewal.
func (p *physicalConn) monitor(c *conn) {
	p.monitorOnce.Do(func() {
		if multi, ok := p.rwc.(MultistreamConn); ok {
			multi.SetErrorHandler(func(_ MultistreamConn, err error) {
				var restart *TransportRestartError
				if errors.As(err, &restart) {
					return
				}
				if closeErr := p.closeAfterReadError(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
					p.mu.Lock()
					current := p.current
					p.mu.Unlock()
					current.log(slog.LevelDebug, "diam: close connection after read error", slog.Any(logKeyError, closeErr), slog.Any(logKeyReadError, err))
				}
			})
			return
		}
		p.sr.Lock()
		source := p.sr.r
		bridge := &orderedReader{events: make(chan restartReadEvent), closed: p.done}
		p.sr.pr = bridge
		p.sr.pipeCopyF = func() {
			bridge.copy(source, func() {
				p.mu.Lock()
				p.readGone = true
				current := p.current
				p.mu.Unlock()
				current.notifyClientGone()
			})
		}
		p.sr.Unlock()
	})
}

type restartReadEvent struct {
	data []byte
	err  error
}
type orderedReader struct {
	events  chan restartReadEvent
	closed  <-chan struct{}
	pending restartReadEvent
}

func (r *orderedReader) Read(b []byte) (int, error) {
	if len(r.pending.data) == 0 && r.pending.err == nil {
		select {
		case r.pending = <-r.events:
		case <-r.closed:
			return 0, net.ErrClosed
		}
	}
	n := copy(b, r.pending.data)
	r.pending.data = r.pending.data[n:]
	if len(r.pending.data) > 0 {
		return n, nil
	}
	err := r.pending.err
	r.pending = restartReadEvent{}
	return n, err
}
func (r *orderedReader) copy(source io.Reader, gone func()) {
	for {
		b := make([]byte, 32<<10)
		n, err := source.Read(b)
		var restart *TransportRestartError
		terminal := err != nil && !errors.As(err, &restart)
		if terminal {
			gone()
		}
		if n > 0 || err != nil {
			select {
			case r.events <- restartReadEvent{b[:n], err}:
			case <-r.closed:
				return
			}
		}
		if terminal {
			return
		}
	}
}
