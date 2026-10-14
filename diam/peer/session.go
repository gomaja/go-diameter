package peer

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

var errQueueFull = errors.New("peer: queue full")

type writeRequest struct {
	msg        *diam.Message
	closeAfter bool
	pending    *pendingRequest
}
type incoming struct {
	msg      *diam.Message
	err      *diam.MessageError
	delivery *protocolDelivery
}
type session struct {
	retired         atomic.Bool
	terminal        atomic.Bool // committed rejection or local close, before transport completion
	retireErr       error
	acceptCleaned   bool // guarded by Manager.mu
	admitted        atomic.Bool
	retireOnce      sync.Once
	meta            *smpeer.Metadata
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
	if m.closing || c.Closed() || a != nil && (a.retiring.Load() || !a.leaseLive()) {
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
	if s.ingressClosed || s.isRetired() {
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
		if a != nil && !s.isRetired() {
			// RFC 6733 §5.5.4: answers read on this connection reach the
			// actor before its disconnect can fail their pending requests over.
			a.post(event{kind: connGone, s: s, gen: gen})
		}
	}()
	dispatch := func(in incoming) {
		if s.isRetired() {
			if in.delivery != nil {
				in.delivery.finish()
			}
			return
		}
		if in.delivery == nil {
			if in.err != nil {
				if a, _ := s.binding(); a != nil {
					a.post(event{kind: wireEvent, s: s, msg: in.msg, messageErr: in.err})
				} else {
					_ = s.m.answerMessageError(s, in.msg, in.err)
				}
			} else {
				s.m.processDIAM(s, in.msg)
			}
			return
		}
		d := in.delivery
		if in.err != nil {
			if a, _ := s.binding(); a != nil {
				a.commit(event{kind: wireEvent, s: s, msg: in.msg, messageErr: in.err}, d)
			} else {
				_ = s.m.answerMessageError(s, in.msg, in.err, d)
			}
		} else {
			s.m.processDIAM(s, in.msg, d)
		}
		d.finish()
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
func (s *session) bind(a *actor, gen uint64) bool {
	s.firstMu.Lock()
	if a.retiring.Load() || !a.leaseLive() {
		s.firstMu.Unlock()
		s.close()
		return false
	}
	if s.isRetired() {
		s.firstMu.Unlock()
		return false
	}
	s.actor = a
	s.gen = gen
	s.firstMu.Unlock()
	return true
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
	if !s.leaseAllowsWrite(w) {
		return ErrLeaseExpired
	}
	s.ingressMu.Lock()
	defer s.ingressMu.Unlock()
	if s.isRetired() {
		return errors.Join(net.ErrClosed, diam.ErrConnectionRetired)
	}
	select {
	case <-s.closed:
		return net.ErrClosed
	default:
	}
	if w.closeAfter {
		// A queued terminal answer must veto renewal even while its writer
		// is stalled (RFC 6733 §§2.5, 5.3, 7.1.3).
		s.terminal.Store(true)
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
		if immediate && !s.isRetired() {
			s.terminal.Store(true)
		}
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
			if s.isRetired() {
				return
			}
			if w.pending != nil {
				s.m.pendingMu.Lock()
				if w.pending.done || w.pending.current != s || s.isRetired() {
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
			if !s.leaseAllowsWrite(w) {
				s.close()
				return
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
	select {
	case <-connectionDone(s.c):
	case <-s.closed:
	}
	if !s.isRetired() {
		s.closeObserved()
	}
	// A local close seals s.closed before Conn.Close finishes. That Close
	// can be fenced by Server retirement while this watcher joins closeOnce.
	// Recheck afterward so unregister cannot bypass the actor acknowledgement.
	if s.isRetired() {
		_ = s.m.HandleRetire(s.c, func() diam.RetirementReason {
			if l, ok := diam.ConnAs[diam.ConnLifecycle](s.c); ok {
				return l.RetirementReason()
			}
			return diam.SCTPAssociationRestart
		}())
	} else {
		s.m.unregister(s)
	}
}

// connectionDone honors the first wrapper exposing either lifecycle interface.
// At the same layer DispatchDone takes precedence: it waits for already-decoded
// answers to reach handlers before peer failover. An outer CloseNotifier still
// intercepts closure instead of being bypassed for an inner DispatchDone.
func connectionDone(c diam.Conn) <-chan struct{} {
	for c != nil {
		switch n := c.(type) {
		case interface{ DispatchDone() <-chan struct{} }:
			return n.DispatchDone()
		case diam.CloseNotifier:
			return n.CloseNotify()
		case interface{ Unwrap() diam.Conn }:
			c = n.Unwrap()
		default:
			return nil
		}
	}
	return nil
}

// Expiry permits only disconnect and terminal rejection, never application traffic.
func (s *session) leaseAllowsWrite(w writeRequest) bool {
	msg := w.msg
	a, _ := s.binding()
	if a == nil {
		return true
	}
	if a.leaseLive() {
		if msg == nil || msg.Header == nil || msg.Header.ApplicationID == 0 || a.discovery.Load() == nil {
			return true
		}
		realm, err := destination(msg, avp.DestinationRealm)
		return err == nil && a.discoveryMessageIdentities(msg) && a.discoveryRealm(realm) && a.discoveryAllows(msg.Header.ApplicationID)
	}
	if msg == nil || msg.Header == nil || msg.Header.ApplicationID != 0 {
		return false
	}
	return msg.Header.CommandCode == diam.DisconnectPeer || w.closeAfter && msg.Header.CommandCode == diam.CapabilitiesExchange && msg.Header.CommandFlags&diam.RequestFlag == 0
}
