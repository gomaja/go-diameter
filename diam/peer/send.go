package peer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
)

var (
	ErrNoRoute         = errors.New("peer: no route")
	ErrUnableToDeliver = errors.New("peer: unable to deliver")
	ErrRequestTimeout  = errors.New("peer: request timeout")
	ErrFailover        = errors.New("peer: failover exhausted")
	ErrPendingFull     = errors.New("peer: pending limit reached")
	ErrInvalidRequest  = errors.New("peer: invalid outbound request")
)

type sendResult struct {
	answer *diam.Message
	err    error
}
type pendingAttempt struct {
	hop        uint32
	generation uint64
	writing    bool
}
type pendingRequest struct {
	msg               *diam.Message
	attempted         map[*actor]bool
	entries           map[*session]pendingAttempt
	result            chan sendResult
	done, failovering bool
	lastHop           uint32
	current           *session
}

func destination(msg *diam.Message, code uint32) (string, error) {
	var value string
	for _, field := range msg.AVP {
		if field == nil || field.Code != code || field.VendorID != 0 {
			continue
		}
		if value != "" {
			return "", fmt.Errorf("peer: duplicate destination AVP %d", code)
		}
		id, ok := field.Data.(datatype.DiameterIdentity)
		if !ok || len(id) == 0 {
			return "", fmt.Errorf("peer: malformed destination AVP %d", code)
		}
		value = identity(id)
	}
	return value, nil
}

func (m *Manager) usable(a *actor, app uint32) *session {
	if a == nil {
		return nil
	}
	p := a.snapshot()
	if !p.Eligible {
		return nil
	}
	remote := false
	for _, id := range p.Applications {
		if id == app || id == 0xffffffff {
			remote = true
			break
		}
	}
	if !remote {
		return nil
	}
	// RFC 6733 §2.4: a negotiated Relay application ID covers all apps;
	// otherwise both endpoints must advertise the request's application.
	_, local := m.localApps[app]
	_, relay := m.localApps[0xffffffff]
	if !local && !relay {
		return nil
	}
	s := a.activeSession.Load()
	if s == nil || s.gen != p.Generation {
		return nil
	}
	select {
	case <-s.closed:
		return nil
	default:
		return s
	}
}

// selectPeer applies RFC 6733 §§6.1.1–6.1.6 for a request originating here.
// A configured Destination-Host is the final destination and cannot fail over.
// An unconfigured Destination-Host can be carried through a routed agent.
func (m *Manager) selectPeer(msg *diam.Message, excluded map[*actor]bool) (*actor, *session, error) {
	if msg == nil || msg.Header == nil {
		return nil, nil, ErrInvalidRequest
	}
	realm, err := destination(msg, avp.DestinationRealm)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if realm == "" {
		return nil, nil, fmt.Errorf("%w: missing Destination-Realm (RFC 6733 §6.1)", ErrNoRoute)
	}
	host, err := destination(msg, avp.DestinationHost)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closing {
		return nil, nil, ErrFailover
	}
	if a := m.peers[host]; a != nil {
		// RFC 6733 §5.5.4: no alternate peer can deliver to an unavailable
		// configured final destination.
		if !excluded[a] {
			if s := m.usable(a, msg.Header.ApplicationID); s != nil {
				return a, s, nil
			}
		}
		return nil, nil, ErrUnableToDeliver
	}
	peers, ok := m.routes.Load().entries[routeKey{realm: realm, app: msg.Header.ApplicationID}]
	if !ok {
		if host != "" {
			return nil, nil, ErrUnableToDeliver
		}
		return nil, nil, ErrNoRoute
	}
	for _, name := range peers {
		a := m.peers[name]
		if excluded[a] {
			continue
		}
		if s := m.usable(a, msg.Header.ApplicationID); s != nil {
			return a, s, nil
		}
	}
	return nil, nil, ErrUnableToDeliver
}

func cloneRequest(msg *diam.Message) (*diam.Message, error) {
	wire, err := msg.Serialize()
	if err != nil {
		return nil, err
	}
	return diam.ReadMessage(bytes.NewReader(wire), msg.Dictionary())
}

func ensureOrigin(msg *diam.Message, code uint32, local datatype.DiameterIdentity, name string) error {
	value, err := destination(msg, code)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrInvalidRequest, name, err)
	}
	if value == "" {
		if _, err := msg.NewAVP(code, avp.Mbit, 0, local); err != nil {
			return fmt.Errorf("%w: %s: %v", ErrInvalidRequest, name, err)
		}
		return nil
	}
	if value != identity(local) {
		return fmt.Errorf("%w: %s does not match local identity", ErrInvalidRequest, name)
	}
	return nil
}

// Send copies and sends a locally originated request. Cancellation after the
// writer accepts bytes leaves the remote outcome ambiguous (RFC 6733 §5.5.4).
// A failover retransmission keeps the End-to-End ID and payload but sets T.
func (m *Manager) Send(ctx context.Context, msg *diam.Message) (*diam.Message, error) {
	if ctx == nil {
		return nil, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if msg == nil || msg.Header == nil || msg.Header.CommandFlags&diam.RequestFlag == 0 || msg.Header.CommandFlags&diam.ErrorFlag != 0 || msg.Header.ApplicationID == 0 || msg.Header.CommandCode == diam.CapabilitiesExchange || msg.Header.CommandCode == diam.DeviceWatchdog || msg.Header.CommandCode == diam.DisconnectPeer {
		return nil, ErrInvalidRequest
	}
	copy, err := cloneRequest(msg)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	// RFC 6733 §6.1.1 requires the local Origin-Host and Origin-Realm on
	// every locally created request; §3 forbids the E bit on requests.
	if err := ensureOrigin(copy, avp.OriginHost, m.cfg.Settings.OriginHost, "Origin-Host"); err != nil {
		return nil, err
	}
	if err := ensureOrigin(copy, avp.OriginRealm, m.cfg.Settings.OriginRealm, "Origin-Realm"); err != nil {
		return nil, err
	}
	// RFC 6733 §3: this is a first transmission regardless of the caller's
	// header; only retransmission after failover carries T.
	copy.Header.CommandFlags &^= diam.RetransmittedFlag
	// RFC 6733 §6.1.4: a request addressed to this node is for local
	// consumption. Local request dispatch is not available in this manager.
	host, err := destination(copy, avp.DestinationHost)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if host == identity(m.cfg.Settings.OriginHost) {
		return nil, fmt.Errorf("%w: local Destination-Host requires local dispatch", ErrInvalidRequest)
	}
	a, s, err := m.selectPeer(copy, nil)
	if err != nil {
		return nil, err
	}
	if m.cfg.EndToEnd != nil {
		copy.Header.EndToEndID = m.cfg.EndToEnd()
	} else {
		copy.Header.EndToEndID = m.endToEnd.allocate()
	}
	p := &pendingRequest{msg: copy, attempted: make(map[*actor]bool), entries: make(map[*session]pendingAttempt), result: make(chan sendResult, 1)}
	// Arm the logical deadline before any reservation: a closing session can
	// hand the request to another peer before queue admission returns.
	timer := m.cfg.Clock.AfterFunc(m.cfg.Timers.Request, func() { m.complete(p, nil, ErrRequestTimeout) })
	defer timer.Stop()
	for {
		if err := ctx.Err(); err != nil {
			m.complete(p, nil, err)
			break
		}
		m.pendingMu.Lock()
		done := p.done
		m.pendingMu.Unlock()
		if done {
			break
		}
		err = m.reserveAndSend(p, a, s, false)
		if err == nil {
			break
		}
		if !errors.Is(err, ErrFailover) {
			m.complete(p, nil, err)
			break
		}
		p.attempted[a] = true
		a, s, err = m.selectPeer(copy, p.attempted)
		if err != nil {
			m.complete(p, nil, ErrFailover)
			break
		}
	}
	select {
	case out := <-p.result:
		return out.answer, out.err
	case <-ctx.Done():
		m.complete(p, nil, ctx.Err())
	}
	out := <-p.result
	return out.answer, out.err
}

func (m *Manager) reserveAndSend(p *pendingRequest, a *actor, s *session, retransmission bool) error {
	m.pendingMu.Lock()
	if p.done {
		m.pendingMu.Unlock()
		return ErrFailover
	}
	if m.usable(a, p.msg.Header.ApplicationID) != s {
		m.pendingMu.Unlock()
		return ErrFailover
	}
	entries := m.pending[s]
	peerPending := 0
	for leg, requests := range m.pending {
		if leg.actor == a {
			peerPending += len(requests)
		}
	}
	if peerPending >= m.cfg.Limits.PendingPerPeer {
		m.pendingMu.Unlock()
		return ErrPendingFull
	}
	if entries == nil {
		entries = make(map[uint32]*pendingRequest)
		m.pending[s] = entries
	}
	// RFC 6733 §3: Hop-by-Hop is unique among outstanding requests on this
	// connection. Scanning skips occupied IDs after uint32 wrap.
	hop := m.nextHopIDLocked(s, p.lastHop, retransmission)
	attempt := *p.msg
	header := *p.msg.Header
	header.HopByHopID = hop
	if retransmission {
		header.CommandFlags |= diam.RetransmittedFlag
	}
	attempt.Header = &header
	entries[hop] = p
	p.entries[s] = pendingAttempt{hop: hop, generation: s.gen}
	p.lastHop = hop
	p.current = s
	p.attempted[a] = true
	m.pendingMu.Unlock()
	if !s.sendWrite(writeRequest{msg: &attempt, pending: p}) {
		// Closing the session transfers ownership to failover. Close may have
		// raced ahead of this reservation, so check pending again afterwards.
		s.close()
		m.failoverSession(s)
		return nil
	}
	return nil
}

func (m *Manager) nextHopIDLocked(s *session, avoid uint32, skipAvoid bool) uint32 {
	for {
		hop := atomic.AddUint32(&m.nextHop, 1)
		_, business := m.pending[s][hop]
		_, control := m.controls[s][hop]
		if !business && !control && (!skipAvoid || hop != avoid) {
			return hop
		}
	}
}

func (m *Manager) complete(p *pendingRequest, answer *diam.Message, err error) {
	m.pendingMu.Lock()
	if p.done {
		m.pendingMu.Unlock()
		return
	}
	p.done = true
	for s, attempt := range p.entries {
		delete(m.pending[s], attempt.hop)
		if len(m.pending[s]) == 0 {
			delete(m.pending, s)
		}
	}
	m.pendingMu.Unlock()
	p.result <- sendResult{answer: answer, err: err}
}

func (m *Manager) receiveAnswer(s *session, answer *diam.Message) {
	if answer == nil || answer.Header == nil {
		return
	}
	m.pendingMu.Lock()
	p := m.pending[s][answer.Header.HopByHopID]
	if p == nil || p.done {
		m.pendingMu.Unlock()
		m.report(s, answer, errors.New("peer: unmatched answer (RFC 6733 §6.2.1)"))
		return
	}
	_, generation := s.binding()
	attempt, present := p.entries[s]
	if !present || attempt.generation != generation || !answerMatches(p, answer) {
		m.pendingMu.Unlock()
		m.report(s, answer, errors.New("peer: unmatched or mismatched answer (RFC 6733 §6.2.1)"))
		return
	}
	p.done = true
	for leg, attempt := range p.entries {
		delete(m.pending[leg], attempt.hop)
		if len(m.pending[leg]) == 0 {
			delete(m.pending, leg)
		}
	}
	m.pendingMu.Unlock()
	p.result <- sendResult{answer: answer}
}

func answerMatches(p *pendingRequest, answer *diam.Message) bool {
	return p.msg.Header.EndToEndID == answer.Header.EndToEndID &&
		p.msg.Header.CommandCode == answer.Header.CommandCode &&
		p.msg.Header.ApplicationID == answer.Header.ApplicationID &&
		answer.Header.CommandFlags&(diam.RequestFlag|diam.RetransmittedFlag) == 0
}

func (m *Manager) failoverSession(s *session) {
	if s == nil {
		return
	}
	m.pendingMu.Lock()
	var requests []*pendingRequest
	for _, p := range m.pending[s] {
		if !p.done && !p.failovering && p.current == s {
			p.failovering = true
			requests = append(requests, p)
		}
	}
	m.pendingMu.Unlock()
	for _, p := range requests {
		m.retry(p)
	}
}

func (m *Manager) retry(p *pendingRequest) {
	m.pendingMu.Lock()
	if p.done {
		m.pendingMu.Unlock()
		return
	}
	excluded := make(map[*actor]bool, len(p.attempted))
	for a := range p.attempted {
		excluded[a] = true
	}
	m.pendingMu.Unlock()
	for {
		a, s, err := m.selectPeer(p.msg, excluded)
		if err != nil {
			m.complete(p, nil, ErrFailover)
			return
		}
		if err := m.reserveAndSend(p, a, s, true); err != nil {
			if errors.Is(err, ErrPendingFull) {
				m.complete(p, nil, err)
				return
			}
			excluded[a] = true
			continue
		}
		m.pendingMu.Lock()
		p.failovering = false
		m.pendingMu.Unlock()
		// A writer can close the newly queued leg before failovering clears.
		// Recheck after clearing it so that close cannot be lost.
		select {
		case <-s.closed:
			m.failoverSession(s)
		default:
		}
		return
	}
}
