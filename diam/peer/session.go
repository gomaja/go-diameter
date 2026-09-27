package peer

import (
	"errors"
	"sync"
	"time"

	"github.com/gomaja/go-diameter/diam"
)

type writeRequest struct {
	msg        *diam.Message
	closeAfter bool
	pending    *pendingRequest
}
type incoming struct {
	msg *diam.Message
	seq uint64
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
func (s *session) enqueue(msg *diam.Message) bool {
	s.ingressMu.Lock()
	defer s.ingressMu.Unlock()
	if s.ingressClosed {
		return false
	}
	select {
	case s.ingress <- incoming{msg: msg, seq: msg.DispatchSequence()}:
		return true
	default:
		return false
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
	next := uint64(1)
	pending := make(map[uint64]*diam.Message)
	process := func(in incoming) bool {
		if in.seq == 0 {
			s.m.processDIAM(s, in.msg)
			return true
		}
		if in.seq < next {
			return true
		}
		if in.seq > next {
			if _, exists := pending[in.seq]; !exists && len(pending) >= s.m.cfg.Limits.Events {
				s.m.report(s, in.msg, errors.New("peer: ordered ingress queue full"))
				s.close()
				return false
			}
			pending[in.seq] = in.msg
			return true
		}
		s.m.processDIAM(s, in.msg)
		next++
		for msg := pending[next]; msg != nil; msg = pending[next] {
			delete(pending, next)
			next++
			s.m.processDIAM(s, msg)
		}
		return true
	}
	for {
		select {
		case <-s.closed:
			// Closure seals admission. Drain every message admitted before it;
			// the actor receives connGone only after those wire events.
			for {
				select {
				case in := <-s.ingress:
					if !process(in) {
						return
					}
				default:
					return
				}
			}
		case in := <-s.ingress:
			if !process(in) {
				return
			}
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
func (s *session) send(msg *diam.Message, closeAfter bool) bool {
	return s.sendWrite(writeRequest{msg: msg, closeAfter: closeAfter})
}
func (s *session) sendWrite(w writeRequest) bool {
	msg := w.msg
	if msg == nil {
		return false
	}
	select {
	case <-s.closed:
		return false
	default:
	}
	if s.beforeAdmission != nil {
		s.beforeAdmission()
	}
	select {
	case <-s.closed:
		return false
	case s.writes <- w:
		return true
	default:
		return false
	}
}
func (s *session) sendControl(msg *diam.Message) bool {
	if msg == nil || msg.Header == nil || msg.Header.CommandFlags&diam.RequestFlag == 0 {
		return false
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
	if s.send(msg, false) {
		return true
	}
	s.releaseControl(hop)
	return false
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
				s.m.report(s, w.msg, err)
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
				s.m.report(s, w.msg, err)
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
