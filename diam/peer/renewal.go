package peer

import (
	"fmt"
	"sync"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/watchdog"
)

// protocolDelivery reserves completion storage with the admitted work. The
// actor commits without calling an observer; the reporting worker delivers
// synchronously after releasing Server admission (RFC 6733 §§5.6, 5.6.1).
type protocolDelivery struct {
	done          chan struct{}
	once          sync.Once
	notifications []diam.ProtocolErrorEvent
}

func newProtocolDelivery() *protocolDelivery { return &protocolDelivery{done: make(chan struct{})} }
func (d *protocolDelivery) finish()          { d.once.Do(func() { close(d.done) }) }
func (d *protocolDelivery) deliver(m *Manager) {
	for _, notification := range d.notifications {
		m.HandleProtocolError(notification)
	}
}

type retirementCommand struct {
	s      *session
	reason diam.RetirementReason
	done   chan struct{}
}

func (a *actor) retirementMailbox() chan retirementCommand {
	a.controlOnce.Do(func() { a.control = make(chan retirementCommand, 1) })
	return a.control
}

func (a *actor) commit(e event, d *protocolDelivery) {
	e.delivery = d
	select {
	case a.events <- e:
	case <-a.done:
		d.finish()
		return
	}
	select {
	case <-d.done:
	case <-a.done:
		d.finish()
	}
}

// HandleAccept creates admission once per accepted generation. SCTP restart
// notifications preserve the physical socket (RFC 9260 §5.2.4; RFC 6458 §6.1.1).
func (m *Manager) HandleAccept(c diam.Conn) func() {
	s := m.acceptConnection(c)
	return func() {
		if s != nil {
			s.closeObserved()
			m.mu.Lock()
			s.acceptCleaned = true
			delete(m.retiredSessions, c)
			m.mu.Unlock()
		}
	}
}

func retiredConnection(c diam.Conn) bool {
	l, ok := diam.ConnAs[diam.ConnLifecycle](c)
	return ok && l.RetirementReason() != 0
}
func (s *session) isRetired() bool { return s.retired.Load() || retiredConnection(s.c) }

// CanRenewAcceptedCER is a pure eligibility check. Ordered actor admission
// commits a preceding DPR before this check (RFC 6733 §§5.4, 5.6).
func (m *Manager) CanRenewAcceptedCER(c diam.Conn) bool {
	s := m.getSession(c)
	if s == nil || !s.inbound || s.isRetired() || s.terminal.Load() || c.Closed() || !s.admitted.Load() || m.isClosing() {
		return false
	}
	a, _ := s.binding()
	return a != nil && a.leaseLive() && a.snapshot().State == ROpen && a.activeSession.Load() == s
}

// HandleRetire stops this generation without joining its writers or observers.
// The reserved mailbox is independent of ordinary peer event capacity. Server
// owns the write gate here; waiting for a writer would deadlock renewal.
func (m *Manager) HandleRetire(c diam.Conn, reason diam.RetirementReason) error {
	m.mu.RLock()
	s := m.sessions[c]
	if s == nil {
		s = m.retiredSessions[c]
	}
	m.mu.RUnlock()
	if s == nil {
		return nil
	}
	s.retireOnce.Do(func() {
		// Serialize the latch with answer completion and request reservations.
		m.pendingMu.Lock()
		s.retired.Store(true)
		m.pendingMu.Unlock()
		s.closeObserved()
		// Closing seals ingress and joins any local close already in flight.
		// Read the veto afterward: that close or a queued terminal answer may
		// have committed while retirement was waiting for the admission lock.
		if s.terminal.Load() {
			s.retireErr = fmt.Errorf("peer: terminal session decision cannot renew")
		}
		requests := m.claimRetiredRequests(s)
		a, _ := s.binding()
		if a != nil {
			cmd := retirementCommand{s: s, reason: reason, done: make(chan struct{})}
			select {
			case a.retirementMailbox() <- cmd:
			case <-a.done:
			}
			select {
			case <-cmd.done:
			case <-a.done:
			}
		}
		m.mu.Lock()
		if m.sessions[c] == s {
			delete(m.sessions, c)
		}
		if m.retiredSessions == nil {
			m.retiredSessions = make(map[diam.Conn]*session)
		}
		if !s.acceptCleaned {
			m.retiredSessions[c] = s
		}
		m.mu.Unlock()
		m.retryRetiredRequests(requests)
	})
	return s.retireErr
}

// retireResponder maps only the current R leg to transport loss. In election
// states the I leg and its dial remain intact (RFC 6733 §§5.6, 5.6.4).
func (a *actor) retireResponder(cmd retirementCommand) {
	s := cmd.s
	_, gen := s.binding()
	wasActive := a.active == s
	current := a.r == s
	if current {
		a.r = nil
		a.step(rDisc, s, nil)
		if !wasActive {
			a.meta = nil
			if a.active != nil && a.active.meta != nil {
				a.meta = a.active.meta.Clone()
			}
		}
	}
	if wasActive {
		a.stopWatchdog()
		a.pendingWatchdog = false
		a.watchdogHop, a.watchdogEnd, a.watchdogGen = 0, 0, 0
		a.numDWA = 0
		a.pendingDPR, a.pendingDPREnd = 0, 0
		a.pendingDPRGen, a.pendingDPRCommand = 0, 0
		if a.everOpen {
			next, _ := a.watchdogCore().Step(watchdog.ConnectionDown)
			a.watchdog = WatchdogState(next.State)
		}
		a.scheduleReconnect()
	}
	s.cerRequest = nil
	s.cerHop, s.cerEnd = 0, 0
	s.meta = nil
	a.publish(fmt.Errorf("peer: accepted session generation %d retired (%v): %w", gen, cmd.reason, diam.ErrConnectionRetired))
	close(cmd.done)
}

// RFC 6733 §5.5.4: claim each current attempt once, retaining other live legs
// and the logical request's deadline, End-to-End ID and attempted-peer set.
func (m *Manager) claimRetiredRequests(s *session) []*pendingRequest {
	m.pendingMu.Lock()
	defer m.pendingMu.Unlock()
	var requests []*pendingRequest
	for _, p := range m.pending[s] {
		delete(p.entries, s)
		if !p.done && !p.failovering && p.current == s {
			p.failovering = true
			requests = append(requests, p)
		}
	}
	delete(m.pending, s)
	delete(m.controls, s)
	return requests
}

func (m *Manager) retryRetiredRequests(requests []*pendingRequest) {
	if len(requests) == 0 {
		return
	}
	m.mu.Lock()
	closing := m.closing
	if !closing {
		m.wg.Add(1)
	}
	m.mu.Unlock()
	if closing {
		for _, p := range requests {
			m.complete(p, nil, ErrFailover)
		}
		return
	}
	go func() {
		defer m.wg.Done()
		for _, p := range requests {
			m.retry(p)
		}
	}()
}

var _ diam.AcceptHandler = (*Manager)(nil)
var _ diam.RetireHandler = (*Manager)(nil)
var _ diam.AcceptedCERHandler = (*Manager)(nil)
