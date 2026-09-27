package peer

import (
	"sync"
	"time"

	"github.com/gomaja/go-diameter/diam"
)

type writeRequest struct {
	msg        *diam.Message
	closeAfter bool
}
type session struct {
	m              *Manager
	c              diam.Conn
	actor          *actor
	gen            uint64
	inbound        bool
	firstMu        sync.Mutex
	first          bool
	preTimer       Timer
	writes         chan writeRequest
	closed         chan struct{}
	closeOnce      sync.Once
	cerRequest     *diam.Message
	cerHop, cerEnd uint32
}

func (m *Manager) newSession(c diam.Conn, a *actor, gen uint64, inbound bool) *session {
	s := &session{m: m, c: c, actor: a, gen: gen, inbound: inbound, writes: make(chan writeRequest, m.cfg.Limits.Events), closed: make(chan struct{})}
	m.register(s)
	m.wg.Add(2)
	go s.writer()
	go s.watch()
	if m.isClosing() {
		s.close()
	}
	return s
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
	case s.writes <- writeRequest{msg: msg, closeAfter: closeAfter}:
		return true
	default:
		return false
	}
}
func (s *session) close() {
	s.closeOnce.Do(func() {
		s.firstMu.Lock()
		if s.preTimer != nil {
			s.preTimer.Stop()
		}
		s.firstMu.Unlock()
		close(s.closed)
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
