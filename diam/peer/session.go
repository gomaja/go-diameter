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
}
type incoming struct {
	msg *diam.Message
	seq uint64
}
type session struct {
	m              *Manager
	c              diam.Conn
	actor          *actor
	gen            uint64
	inbound        bool
	firstMu        sync.Mutex
	first          bool
	rejectingFirst bool
	preTimer       Timer
	writes         chan writeRequest
	ingress        chan incoming
	closed         chan struct{}
	closeOnce      sync.Once
	cerRequest     *diam.Message
	cerHop, cerEnd uint32
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
	select {
	case <-s.closed:
		return false
	case s.ingress <- incoming{msg: msg, seq: msg.DispatchSequence()}:
		return true
	default:
		return false
	}
}
func (s *session) dispatch() {
	defer s.m.wg.Done()
	next := uint64(1)
	pending := make(map[uint64]*diam.Message)
	for {
		select {
		case <-s.closed:
			return
		case in := <-s.ingress:
			if in.seq == 0 {
				s.m.processDIAM(s, in.msg)
				continue
			}
			if in.seq < next {
				continue
			}
			if in.seq > next {
				if _, exists := pending[in.seq]; !exists && len(pending) >= s.m.cfg.Limits.Events {
					s.m.report(s, in.msg, errors.New("peer: ordered ingress queue full"))
					s.close()
					return
				}
				pending[in.seq] = in.msg
				continue
			}
			s.m.processDIAM(s, in.msg)
			next++
			for msg := pending[next]; msg != nil; msg = pending[next] {
				select {
				case <-s.closed:
					return
				default:
				}
				delete(pending, next)
				next++
				s.m.processDIAM(s, msg)
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
	if msg == nil {
		return false
	}
	select {
	case <-s.closed:
		return false
	default:
	}
	select {
	case <-s.closed:
		return false
	case s.writes <- writeRequest{msg: msg, closeAfter: closeAfter}:
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
	s.closeOnce.Do(func() {
		s.firstMu.Lock()
		if s.preTimer != nil {
			s.preTimer.Stop()
		}
		s.firstMu.Unlock()
		close(s.closed)
		s.m.pendingMu.Lock()
		delete(s.m.controls, s)
		s.m.pendingMu.Unlock()
		s.m.failoverSession(s)
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
	if n, ok := s.c.(diam.CloseNotifier); ok {
		select {
		case <-n.CloseNotify():
		case <-s.closed:
		}
	} else {
		<-s.closed
	}
	s.close()
	s.m.unregister(s)
	a, gen := s.binding()
	if a != nil {
		a.post(event{kind: connGone, s: s, gen: gen})
	}
}
