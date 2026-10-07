package peer

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/gomaja/go-diameter/diam"
)

var errQueueFull = errors.New("peer: queue full")

type writeRequest struct {
	msg        *diam.Message
	closeAfter bool
	pending    *pendingRequest
}
type incoming struct {
	msg *diam.Message
	err *diam.MessageError
}
type session struct {
	m               *Manager
	c               diam.Conn
	actor           *actor
	gen             uint64
	inbound         bool
	firstMu         sync.Mutex
	first           bool
	rejectingFirst  bool
	preTimer        Timer
	writes          chan writeRequest
	beforeAdmission func()
	ingressMu       sync.Mutex
	ingressClosed   bool
	ingress         chan incoming
	closed          chan struct{}
	closeOnce       sync.Once
	cerRequest      *diam.Message
	cerHop, cerEnd  uint32
}

func (m *Manager) newSession(c diam.Conn, a *actor, gen uint64, inbound bool) *session {
	s := &session{m: m, c: c, actor: a, gen: gen, inbound: inbound, writes: make(chan writeRequest, m.cfg.Limits.Events), ingress: make(chan incoming, m.cfg.Limits.Events), closed: make(chan struct{})}
	// Close sets closing under this lock before it waits for session workers.
	m.mu.Lock()
	if m.closing {
		m.mu.Unlock()
		c.Close()
		return nil
	}
	m.sessions[c] = s
	m.wg.Add(3)
	m.mu.Unlock()
	go s.writer()
	go s.watch()
	go s.dispatch()
	return s
}
func (s *session) enqueue(msg *diam.Message) error {
	return s.enqueueIncoming(incoming{msg: msg})
}
func (s *session) enqueueIncoming(in incoming) error {
	s.ingressMu.Lock()
	defer s.ingressMu.Unlock()
	if s.ingressClosed {
		return net.ErrClosed
	}
	select {
	case s.ingress <- in:
		return nil
	default:
		return errQueueFull
	}
}
func (s *session) dispatch() {
	defer s.m.wg.Done()
	defer func() {
		a, gen := s.binding()
		if a != nil {
			// RFC 6733 §5.5.4: answers read on this connection reach the
			// actor before its disconnect can fail their pending requests over.
			a.post(event{kind: connGone, s: s, gen: gen})
		}
	}()
	dispatch := func(in incoming) {
		if in.err != nil {
			if a, _ := s.binding(); a != nil {
				a.post(event{kind: wireEvent, s: s, msg: in.msg, messageErr: in.err})
			} else if err := s.m.answerMessageError(s, in.msg, in.err); err != nil {
				s.m.reportLocal(s, in.msg, "peer: error answer failed; closing connection", err)
				s.close()
			}
		} else {
			s.m.processDIAM(s, in.msg)
		}
	}

	for {
		select {
		case <-s.closed:
			// Closure seals admission. Drain every message admitted before it;
			// the actor receives connGone only after those wire events.
			for {
				select {
				case in := <-s.ingress:
					dispatch(in)
				default:
					return
				}
			}
		case in := <-s.ingress:
			dispatch(in)
		}
	}
}
func (s *session) binding() (*actor, uint64) {
	s.firstMu.Lock()
	defer s.firstMu.Unlock()
	return s.actor, s.gen
}
func (s *session) bind(a *actor, gen uint64) {
	s.firstMu.Lock()
	s.actor = a
	s.gen = gen
	s.firstMu.Unlock()
}
func (s *session) send(msg *diam.Message, closeAfter bool) error {
	return s.sendWrite(writeRequest{msg: msg, closeAfter: closeAfter})
}
func (s *session) sendWrite(w writeRequest) error {
	if w.msg == nil {
		return ErrInvalidRequest
	}
	if s.beforeAdmission != nil {
		s.beforeAdmission()
	}
	s.ingressMu.Lock()
	defer s.ingressMu.Unlock()
	select {
	case <-s.closed:
		return net.ErrClosed
	default:
	}
	select {
	case s.writes <- w:
		return nil
	default:
		return errQueueFull
	}
}
func (s *session) sendControl(msg *diam.Message) error {
	if msg == nil || msg.Header == nil || msg.Header.CommandFlags&diam.RequestFlag == 0 {
		return ErrInvalidRequest
	}
	m := s.m
	m.pendingMu.Lock()
	hop := m.nextHopIDLocked(s, 0, false)
	msg.Header.HopByHopID = hop
	if m.controls[s] == nil {
		m.controls[s] = make(map[uint32]struct{})
	}
	m.controls[s][hop] = struct{}{}
	m.pendingMu.Unlock()
	if err := s.send(msg, false); err != nil {
		s.releaseControl(hop)
		return err
	}
	return nil
}
func (s *session) releaseControl(hop uint32) {
	s.m.pendingMu.Lock()
	delete(s.m.controls[s], hop)
	if len(s.m.controls[s]) == 0 {
		delete(s.m.controls, s)
	}
	s.m.pendingMu.Unlock()
}
func (s *session) close() {
	s.closeWithFailover(true)
}
func (s *session) closeObserved() {
	s.closeWithFailover(false)
}
func (s *session) closeWithFailover(immediate bool) {
	s.closeOnce.Do(func() {
		s.firstMu.Lock()
		if s.preTimer != nil {
			s.preTimer.Stop()
		}
		s.firstMu.Unlock()
		s.ingressMu.Lock()
		s.ingressClosed = true
		close(s.closed)
		s.ingressMu.Unlock()
		s.m.pendingMu.Lock()
		delete(s.m.controls, s)
		s.m.pendingMu.Unlock()
		if immediate {
			s.m.failoverSession(s)
		}
		s.c.Close()
	})
}
func (s *session) writer() {
	defer s.m.wg.Done()
	for {
		select {
		case <-s.closed:
			return
		case w := <-s.writes:
			// RFC 6733 §§5.3–5.6: a stalled transport cannot hold a managed control write forever.
			deadline := s.m.cfg.Timers.Closing
			if deadline <= 0 {
				deadline = 5 * time.Second
			}
			if err := s.c.Connection().SetWriteDeadline(time.Now().Add(deadline)); err != nil {
				s.m.reportLocal(s, w.msg, "peer: write deadline failed; closing connection", err)
				s.close()
				return
			}
			if w.pending != nil {
				s.m.pendingMu.Lock()
				if w.pending.done || w.pending.current != s {
					s.m.pendingMu.Unlock()
					continue
				}
				// The write begins here. A later completion cannot retract bytes
				// already submitted to the transport (RFC 6733 §5.5.4).
				attempt := w.pending.entries[s]
				attempt.writing = true
				w.pending.entries[s] = attempt
				s.m.pendingMu.Unlock()
			}
			_, err := w.msg.WriteTo(s.c)
			if err != nil {
				s.m.reportLocal(s, w.msg, "peer: write failed; closing connection", err)
				s.close()
				return
			}
			if w.closeAfter {
				s.close()
				return
			}
		}
	}
}
func (s *session) watch() {
	defer s.m.wg.Done()
	// Server's DispatchDone waits for its read loop and concurrent handlers.
	// CloseNotify alone can race a handler that has decoded but not queued an
	// answer. Other transports fall back to CloseNotify.
	if n, ok := s.c.(interface{ DispatchDone() <-chan struct{} }); ok {
		select {
		case <-n.DispatchDone():
		case <-s.closed:
		}
	} else if n, ok := s.c.(diam.CloseNotifier); ok {
		select {
		case <-n.CloseNotify():
		case <-s.closed:
		}
	} else {
		<-s.closed
	}
	s.closeObserved()
	s.m.unregister(s)
}
