package peer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/sm"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

type event struct {
	// testHook observes actor-owned state at an event boundary; nil in use.
	testHook        func()
	receivedAt      time.Time
	receiveSequence uint64
	afterReceive    uint64
	delivery        *protocolDelivery
	messageErr      *diam.MessageError
	kind            psmEvent
	s               *session
	msg             *diam.Message
	meta            *smpeer.Metadata
	gen, token      uint64
	err             error
	cause           sm.DisconnectCause
	discovery       *discoveryCommand
	leaseState      *discoveryState
	input           protocol.Input
	replyDelivery   *protocolDelivery
}

const (
	discoveryStart   psmEvent = "discovery-start"
	discoveryStop    psmEvent = "discovery-stop"
	discoveryExpire  psmEvent = "discovery-expire"
	discoveryRefresh psmEvent = "discovery-refresh"
	coreEvent        psmEvent = "core"
	wireEvent        psmEvent = "wire"
	dialDone         psmEvent = "dial-done"
	connGone         psmEvent = "conn-gone"
	watchdogTimeout  psmEvent = "watchdog-timeout"
	reconnectTimeout psmEvent = "reconnect-timeout"
)

type actor struct {
	discovery         atomic.Pointer[discoveryState]
	retiring          atomic.Bool
	ready             *discoveryReady
	leaseTimer        Timer
	leaseStop         chan struct{}
	dialCancel        context.CancelFunc
	controlOnce       sync.Once
	control           chan retirementCommand
	delivery          *protocolDelivery
	m                 *Manager
	cfg               PeerConfig
	events            chan event
	done              chan struct{}
	state             PeerState
	i, r              *session
	pendingGen        uint64
	nextGen           uint64
	token             uint64
	timer             Timer
	meta              *smpeer.Metadata
	active            *session
	pendingDPR        uint32
	pendingDPREnd     uint32
	pendingDPRGen     uint64
	pendingDPRCommand uint32
	closeCause        sm.DisconnectCause
	closingWatchdog   bool // unanswered pre-Closing DWR, after watchdog invalidation
	snapshotValue     atomic.Value
	activeSession     atomic.Pointer[session]

	watchdog          WatchdogState
	wdTimer, tcTimer  Timer
	wdToken, tcToken  uint64
	deferredWatchdog  *event
	pendingWatchdog   bool
	watchdogAnswered  bool // response ownership, separate from watchdog credit
	watchdogHop       uint32
	watchdogEnd       uint32
	watchdogGen       uint64
	numDWA            int
	everOpen          bool
	dialing           bool
	ownStop           bool
	suppressReconnect bool
	failures          int
}

func (a *actor) snapshot() PeerSnapshot {
	v := a.snapshotValue.Load().(PeerSnapshot)
	if d := a.discovery.Load(); d != nil {
		v.Dynamic = true
		v.ExpiresAt = d.expires
		v.Eligible = v.Eligible && a.leaseLive()
	}
	v.Applications = append([]uint32(nil), v.Applications...)
	return v
}
func (a *actor) publish(err error) {
	p := PeerSnapshot{Host: a.cfg.Host, State: a.state, Generation: a.nextGen, Watchdog: a.watchdog}
	p.Eligible = (a.state == IOpen || a.state == ROpen) && a.watchdog == WatchdogOkay && a.leaseLive() && !a.ownStop
	if d := a.discovery.Load(); d != nil {
		p.Dynamic = true
		p.ExpiresAt = d.expires
	}
	if a.meta != nil && (a.state == IOpen || a.state == ROpen || a.state == Closing) {
		p.Realm = a.meta.OriginRealm
		p.Applications = append([]uint32(nil), a.meta.Applications...)
	}
	if a.active != nil {
		p.Generation = a.active.gen
	}
	a.snapshotValue.Store(p)
	a.activeSession.Store(a.active)
	if p.Eligible && p.Dynamic {
		a.publishDiscoveryRoutes()
		a.signalReady(nil)
	} else if err != nil {
		a.signalReady(err)
	}
	if err != nil || a.state == IOpen || a.state == ROpen || a.state == Closed {
		a.m.notify(PeerEvent{Peer: p, Reason: err})
	}
}
func (a *actor) notify(err error) { a.m.notify(PeerEvent{Peer: a.snapshot(), Reason: err}) }
func (a *actor) post(e event) {
	select {
	case a.events <- e:
	case <-a.done:
	}
}
func (a *actor) run() {
	control := a.retirementMailbox()
	leaseStop := a.leaseStop
	defer a.m.wg.Done()
	defer close(a.done)
	defer a.m.forgetRetiredActor(a)
	defer a.closeOwnedSessions()
	for {
		select {
		case cmd := <-control:
			a.retireResponder(cmd)
		default:
			select {
			case cmd := <-control:
				a.retireResponder(cmd)
			case <-leaseStop:
				a.handleEvent(event{kind: discoveryStop})
				leaseStop = nil
			case e := <-a.events:
				a.handleEvent(e)
			}
		}
		if (a.m.isClosing() || a.discovery.Load() != nil && a.ownStop) && a.state == Closed {
			if a.dialCancel != nil {
				a.dialCancel()
			}
			if a.leaseTimer != nil {
				a.leaseTimer.Stop()
			}
			a.signalReady(ErrLeaseExpired)
			a.stopTimer()
			a.stopWatchdog()
			a.stopReconnect()
			if a.i != nil {
				a.i.close()
			}
			if a.r != nil {
				a.r.close()
			}
			return
		}
	}
}

// A writer can report failure after an event accepted its reply without any
// admission notices. Finalize that delivery too, with observers off the actor.
func (a *actor) handleEvent(e event) {
	d := e.delivery
	if d == nil {
		d = newProtocolDelivery()
	}
	a.delivery = d
	d.priorReply = e.replyDelivery
	a.handle(e)
	a.delivery = nil
	d.finish()
	if e.delivery == nil {
		a.m.wg.Add(1)
		go func() { defer a.m.wg.Done(); d.deliver(a.m) }()
	}
}

func (m *Manager) isClosing() bool { m.mu.RLock(); v := m.closing; m.mu.RUnlock(); return v }
func (a *actor) stopTimer() {
	a.token++
	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
}
func (a *actor) arm(d time.Duration) {
	a.stopTimer()
	token := a.token
	a.timer = a.m.cfg.Clock.AfterFunc(d, func() { a.post(event{kind: timeout, token: token}) })
}
func (a *actor) setState(s PeerState, err error) { a.state = s; a.publish(err) }
func (a *actor) fail(err error) {
	a.failWithLog(slog.LevelWarn, "peer: protocol error", err)
}
func (a *actor) failLocal(operation string, err error) {
	a.failWithLog(slog.LevelError, "peer: "+operation+" failed; closing connection", fmt.Errorf("peer: %s: %w", operation, err))
}
func (a *actor) failWithLog(level slog.Level, text string, err error) {
	s := a.active
	if s == nil {
		s = a.i
	}
	if s == nil {
		s = a.r
	}
	a.m.logFailure(s, nil, string(a.cfg.Host), level, text, fmt.Errorf("peer: closing connection: %w", err))
	a.stopTimer()
	if a.i != nil {
		a.i.close()
		a.i = nil
	}
	if a.r != nil {
		a.r.close()
		a.r = nil
	}
	a.active = nil
	a.meta = nil
	a.pendingDPRGen, a.pendingDPRCommand = 0, 0
	a.setState(Closed, err)
	a.lostConnection(err)
}
func (a *actor) handle(e event) {
	if e.testHook != nil {
		e.testHook()
		return
	}
	defer func() {
		if e.s != nil && e.receiveSequence != 0 {
			e.s.receivedSequence = e.receiveSequence
		}
		if pending := a.deferredWatchdog; pending != nil &&
			(pending.s == nil || pending.s.receivedSequence >= pending.afterReceive) {
			a.deferredWatchdog = nil
			a.handle(*pending)
		}
	}()
	if a.handleDiscovery(e) {
		return
	}
	// Dial completion releases worker ownership even if its transport retired
	// while queued. Other events from that transport remain stale.
	if e.kind == dialDone {
		if e.s != nil && e.s.isRetired() {
			e.s.close()
			e.s = nil
			e.err = diam.ErrConnectionRetired
		}
		a.onDial(e)
		return
	}
	if e.kind == coreEvent {
		if e.s != nil {
			e.s.applyProtocol(e.input, a.delivery)
		}
		return
	}
	if e.s != nil && e.s.isRetired() {
		return
	}

	if e.kind == reconnectTimeout {
		if e.token == a.tcToken {
			a.tcTimer = nil
			a.reconnectTick()
		}
		return
	}
	if e.kind == timeout {
		if e.token != a.token && e.token != 0 {
			return
		}
		if a.state == Closed || (a.active != nil && a.active.isRetired()) {
			return
		}
		a.step(timeout, nil, nil)
		return
	}
	if e.kind == start {
		// RFC 6733 §5.4.3: a BUSY or DO_NOT_WANT_TO_TALK_TO_YOU DPR received
		// before Start also suppresses the first dial.
		if a.state == Closed && !a.m.isClosing() && !a.suppressReconnect && a.leaseLive() && !a.ownStop {
			a.setState(WaitConnAck, nil)
			a.arm(a.m.cfg.Timers.Connect)
			a.dial()
		}
		return
	}
	if e.kind == stop {
		a.stop(e.cause)
		return
	}
	if e.kind == connGone {
		if e.s != nil && e.s.core != nil {
			e.s.applyProtocol(protocol.Input{Kind: protocol.TransportLost}, a.delivery)
		}
		a.onGone(e.s)
		a.m.failoverSession(e.s)
		return
	}
	if e.kind == rConnCER {
		a.onCER(e)
		return
	}
	if e.kind == wireEvent {
		a.onWire(e)
		return
	}
}
func (a *actor) dial() {
	if a.dialing || !a.leaseLive() || a.ownStop {
		return
	}
	a.dialing = true
	a.nextGen++
	gen := a.nextGen
	a.pendingGen = gen
	endpoints := a.cfg.Endpoints
	m := a.m
	ctx, cancel := context.WithTimeout(m.startContext(), m.cfg.Timers.Connect)
	a.dialCancel = cancel
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer cancel()
		var lastErr error
		for _, e := range endpoints {
			if err := ctx.Err(); err != nil {
				lastErr = err
				break
			}
			if s, err := m.dialEndpoint(ctx, e, a, gen); err == nil {
				a.finishDial(ctx, s, gen)
				return
			} else {
				lastErr = errors.Join(lastErr, err)
			}
		}
		a.post(event{kind: dialDone, gen: gen, err: lastErr})
	}()
}

// finishDial transfers a successful dial to the actor, or closes it if its
// authorization ended before delivery.
func (a *actor) finishDial(ctx context.Context, s *session, gen uint64) {
	err := ctx.Err()
	if !a.leaseLive() {
		err = ErrLeaseExpired
	}
	if err != nil {
		s.close()
		// Completion owns the pending generation even when the successful
		// transport became unusable before the actor could receive it.
		a.post(event{kind: dialDone, gen: gen, err: err})
		return
	}
	select {
	case a.events <- event{kind: dialDone, s: s, gen: gen}:
	case <-a.done:
		s.close()
	}
}

func (m *Manager) dialEndpoint(ctx context.Context, e Endpoint, a *actor, gen uint64) (*session, error) {
	network := e.Network
	if network == "" {
		network = "tcp"
	}
	ready := make(chan *session, 1)
	srv := &diam.Server{Network: network, Addr: e.Address, Handler: m, Dict: m.cfg.Settings.Dict, WriteTimeout: m.cfg.Timers.Closing, Logger: m.cfg.Logger, OnNewConnection: func(c diam.Conn) { ready <- m.newSession(c, a, gen, false) }}
	var c diam.Conn
	var err error
	if m.cfg.Dial != nil {
		var raw net.Conn
		raw, err = m.cfg.Dial(ctx, e)
		if err == nil {
			if e.TLSConfig != nil {
				cfg := e.TLSConfig.Clone()
				if cfg.ServerName == "" {
					cfg.ServerName, _, _ = net.SplitHostPort(e.Address)
				}
				client := tls.Client(raw, cfg)
				if err = client.HandshakeContext(ctx); err != nil {
					_ = raw.Close()
					return nil, err
				}
				raw = client
			}
			if err = ctx.Err(); err != nil {
				_ = raw.Close()
				return nil, err
			}
			c, err = srv.NewConn(raw)
			if err != nil {
				_ = raw.Close()
			}
		}
	} else if e.TLSConfig != nil {
		srv.TLSConfig = e.TLSConfig.Clone()
		c, err = srv.DialTLSContext(ctx, "", "")
	} else {
		c, err = srv.DialContext(ctx)
	}
	if err != nil {
		return nil, err
	}
	select {
	case s := <-ready:
		if s == nil {
			c.Close()
			return nil, errors.New("peer: manager closing")
		}
		return s, nil
	case <-ctx.Done():
		c.Close()
		return nil, ctx.Err()
	}
}
func (a *actor) onDial(e event) {
	if e.gen == a.pendingGen {
		a.dialing = false
	}
	if !a.leaseLive() || a.ownStop || e.gen != a.pendingGen || (a.state != WaitConnAck && a.state != WaitConnAckElect) {
		if e.s != nil {
			e.s.close()
		}
		if a.state == Closed && a.tcTimer == nil {
			a.scheduleReconnect()
		}
		return
	}
	if e.err != nil {
		if a.state == WaitConnAck {
			a.failLocal("dial", e.err)
		} else {
			a.m.logFailure(nil, nil, string(a.cfg.Host), slog.LevelError, "peer: dial failed", e.err)
			a.step(iNack, nil, nil)
			if a.state != Closed {
				a.notify(e.err)
			}
		}
		return
	}
	if e.s.c.Closed() || e.s.protocolSnapshot().Phase() >= protocol.Closed {
		a.failLocal("send CER", net.ErrClosed)
		return
	}
	a.i = e.s
	a.step(iAck, e.s, nil)
	if a.state == WaitReturns {
		a.elect()
	}
}
func (a *actor) onCER(e event) {
	if e.s == nil || e.meta == nil {
		return
	}
	if !a.leaseLive() || a.state == Closing || a.m.isClosing() || a.ownStop {
		a.m.report(e.s, e.msg, errors.New("peer: CER while closing; closing connection"))
		e.s.close()
		a.protocolError(e.s.c, e.msg, diam.ProtocolHandshakeState, 0, true, diam.ProtocolReplyNone, 0)
		return
	}
	if compareIdentity(e.meta.OriginHost, a.cfg.Host) != 0 {
		a.m.report(e.s, e.msg, errors.New("peer: configured Origin-Host mismatch; closing connection"))
		e.s.close()
		a.protocolError(e.s.c, e.msg, diam.ProtocolCERRejected, 0, true, diam.ProtocolReplyNone, 0)
		return
	}
	if err := a.admitDiscovery(e.s, e.meta); err != nil {
		a.signalReady(err)
		a.m.report(e.s, e.msg, err)
		e.s.applyProtocol(protocol.Input{Kind: protocol.RejectCandidate, Token: e.s.candidate, ResultCode: diam.UnknownPeer, Message: e.msg}, a.delivery)
		return
	}
	if a.state != Closed && a.state != WaitConnAck && a.state != WaitICEA && a.state != WaitConnAckElect && a.state != WaitReturns && a.state != IOpen && a.state != ROpen {
		a.m.report(e.s, e.msg, fmt.Errorf("peer: CER in state %s; closing connection", a.state))
		e.s.close()
		a.protocolError(e.s.c, e.msg, diam.ProtocolHandshakeState, 0, true, diam.ProtocolReplyNone, 0)
		return
	}
	if a.state == WaitConnAckElect || a.state == WaitReturns || a.state == IOpen || a.state == ROpen {
		a.step(rConnCER, e.s, e.msg)
		return
	}
	a.nextGen++
	if !e.s.bind(a, a.nextGen) {
		return
	}
	a.r = e.s
	e.s.cerRequest = e.msg
	e.s.meta = e.meta.Clone()
	a.meta = e.meta.Clone()
	a.step(rConnCER, e.s, e.msg)
	if a.state == WaitReturns {
		a.elect()
	}
}
func (a *actor) elect() {
	if a.r == nil || a.r.isRetired() {
		return
	}
	// RFC 6733 §5.6.4: compare ASCII case-folded octets; the winner discards I.
	switch compareIdentity(a.m.cfg.Settings.OriginHost, a.cfg.Host) {
	case 0:
		s := a.r
		a.fail(errors.New("peer: Origin-Host identity collision"))
		if s != nil {
			a.protocolError(s.c, s.cerRequest, diam.ProtocolHandshakeState, 0, true, diam.ProtocolReplyNone, 0)
		}
	case 1:
		if a.state == WaitReturns {
			a.step(winElection, a.r, nil)
		}
	}
}
func (a *actor) onWire(e event) {
	s := e.s
	if s == nil || s.isRetired() {
		return
	}
	if s != a.i && s != a.r || s.gen == 0 {
		msg := e.msg
		if msg != nil && msg.Header != nil && msg.Header.CommandFlags&diam.RequestFlag == 0 && msg.Header.ApplicationID != 0 {
			a.m.report(s, msg, errors.New("peer: answer on retired connection generation (RFC 6733 §6.2.1)"))
			a.protocolError(s.c, msg, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
		}
		return
	}
	s.applyProtocol(protocol.Input{Kind: protocol.Receive, Message: e.msg, Error: e.messageErr, ErrorInput: e.messageErr != nil, At: e.receivedAt, Sequence: e.receiveSequence}, a.delivery)
}

func (a *actor) onGone(s *session) {
	if s == nil {
		return
	}
	if s == a.i {
		old := a.state
		wasActive := s == a.active
		a.i = nil
		a.step(iDisc, s, nil)
		if a.state == Closed && (wasActive || old == WaitICEA) {
			a.lostConnection(errors.New("peer: initiator transport closed"))
		}
		return
	}
	if s == a.r {
		wasActive := s == a.active
		a.r = nil
		a.step(rDisc, s, nil)
		if wasActive && a.state == Closed {
			a.lostConnection(errors.New("peer: responder transport closed"))
		}
		return
	}
}
func (a *actor) stop(cause sm.DisconnectCause) {
	a.ownStop = true
	a.retiring.Store(true)
	if a.dialCancel != nil {
		a.dialCancel()
	}
	a.stopReconnect()
	if a.state == IOpen || a.state == ROpen {
		a.closingWatchdog = a.active != nil && a.pendingWatchdog && !a.watchdogAnswered && a.watchdogGen == a.active.gen
	}
	a.stopWatchdog()
	if a.state == Closed {
		return
	}
	if a.state == IOpen || a.state == ROpen {
		a.closeCause = cause
		a.step(stop, a.active, nil)
		return
	}
	if a.state == Closing {
		return
	}
	a.failWithLog(slog.LevelInfo, "peer: shutdown during handshake; closing connection", errors.New("peer: shutdown during handshake"))
}
func (a *actor) step(ev psmEvent, s *session, msg *diam.Message) {
	row, ok := transition(a.state, ev)
	if !ok {
		return
	}
	old := a.state
	a.state = row.next

	if old == Closing && a.state != Closing {
		a.pendingDPRGen, a.pendingDPRCommand = 0, 0
	}
	switch ev {
	case iAck:
		a.stopTimer()
		if a.i != nil {
			a.i.runProtocol(protocol.Input{Kind: protocol.Start}, a.i.takeStartup(), a.delivery)
		}

	case iNack:
		if old == WaitConnAckElect {
			a.active = a.r
			a.stopTimer()
			if !a.sendCEA(a.r) {
				return
			}
		} else {
			a.failLocal("dial", errors.New("connection attempt failed"))
			return
		}
	case rConnCER:
		switch old {
		case Closed:
			a.active = a.r
			a.stopTimer()
			if !a.sendCEA(a.r) {
				return
			}
		case WaitConnAckElect, WaitReturns, IOpen, ROpen:
			a.m.report(s, msg, errors.New("peer: duplicate CER candidate; closing connection"))
			s.close()
			a.protocolError(s.c, msg, diam.ProtocolUnexpectedMessage, 0, true, diam.ProtocolReplyNone, 0)
		}
	case winElection, iDisc:
		switch old {
		case WaitReturns:
			if a.i != nil {
				a.i.close()
				a.i = nil
			}
			a.active = a.r
			a.stopTimer()
			if !a.sendCEA(a.r) {
				return
			}
		case IOpen, Closing:
			a.stopTimer()
			a.active = nil
			a.meta = nil
		}
	case iCEA:
		a.stopTimer()
		if old == WaitReturns && a.r != nil {
			a.r.close()
			a.r = nil
		}
		a.active = a.i
	case rDisc:
		switch old {
		case ROpen, Closing:
			a.stopTimer()
			a.active = nil
			a.meta = nil
		case WaitReturns:
			// The surviving initiator retains its core CER deadline.
		}
	case iNonCEA:
		a.fail(errors.New("peer: non-CEA before handshake"))
		return
	case timeout:
		connection := a.active
		if connection == nil {
			connection = a.i
		}
		if connection == nil {
			connection = a.r
		}
		kind := diam.ProtocolHandshakeTimeout
		if old == Closing {
			kind = diam.ProtocolDisconnectTimeout
		}
		a.fail(errors.New("peer: state timeout"))
		if connection != nil {
			a.protocolError(connection.c, nil, kind, 0, true, diam.ProtocolReplyNone, 0)
		}
		return
	case stop:
		a.stopTimer()
		if s != nil {
			s.applyProtocol(protocol.Input{Kind: protocol.Disconnect, Cause: uint32(a.closeCause)}, a.delivery)
		}
		if a.state == Closed {
			return
		}
	case iDPA, rDPA:
		a.stopTimer()
		s.close()
		a.active, a.meta = nil, nil

	}
	if a.active != nil && a.active.inbound && (a.state == ROpen) && !a.active.isRetired() {
		a.active.admitted.Store(true)
	}
	if old != IOpen && old != ROpen && (a.state == IOpen || a.state == ROpen) {
		a.closingWatchdog = false
		a.stopReconnect()
		if a.active != nil {
			a.syncProtocol(a.active, protocol.Input{Kind: protocol.ReleaseAdmission})
		}
		a.everOpen = true
		if a.state == Closed {
			return
		}
	}
	a.publish(nil)
}
func (a *actor) sendCEA(s *session) bool {
	if s == nil {
		a.failLocal("send CEA", errors.New("missing responder"))
		return false
	}
	if s.candidate == 0 {
		a.failLocal("send CEA", errors.New("missing CER"))
		return false
	}
	s.applyProtocol(protocol.Input{Kind: protocol.Activate, Token: s.candidate, Message: s.cerRequest, Recovery: a.watchdog == WatchdogDown}, a.delivery)
	return !s.c.Closed() && !s.isRetired()
}

// Core admission selects this event; peer election decides which leg survives.
func (a *actor) openInitiator(s *session) {
	row, ok := transition(a.state, iCEA)
	if !ok {
		return
	}
	old := a.state
	a.state = row.next
	a.stopTimer()
	a.stopReconnect()
	if old == WaitReturns && a.r != nil {
		a.r.close()
		a.r = nil
	}
	a.active = s
	a.meta = s.meta.Clone()
}

// dictionary preserves the configured parser identity; its nil fallback is
// the shared, initially base-only dict.Default.
func (m *Manager) dictionary() *dict.Parser {
	if m.cfg.Settings.Dict != nil {
		return m.cfg.Settings.Dict
	}
	return dict.Default
}
