package peer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/sm"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

type event struct {
	messageErr *diam.MessageError
	kind       psmEvent
	s          *session
	msg        *diam.Message
	meta       *smpeer.Metadata
	gen, token uint64
	err        error
	cause      sm.DisconnectCause
}

const (
	wireEvent        psmEvent = "wire"
	dialDone         psmEvent = "dial-done"
	connGone         psmEvent = "conn-gone"
	watchdogTimeout  psmEvent = "watchdog-timeout"
	reconnectTimeout psmEvent = "reconnect-timeout"
)

type actor struct {
	m             *Manager
	cfg           PeerConfig
	events        chan event
	done          chan struct{}
	state         PeerState
	i, r          *session
	pendingGen    uint64
	nextGen       uint64
	token         uint64
	timer         Timer
	meta          *smpeer.Metadata
	active        *session
	pendingDPR    uint32
	pendingDPREnd uint32
	closeCause    sm.DisconnectCause
	snapshotValue atomic.Value
	activeSession atomic.Pointer[session]

	watchdog          WatchdogState
	wdTimer, tcTimer  Timer
	wdToken, tcToken  uint64
	pendingWatchdog   bool
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
	v.Applications = append([]uint32(nil), v.Applications...)
	return v
}
func (a *actor) publish(err error) {
	p := PeerSnapshot{Host: a.cfg.Host, State: a.state, Generation: a.nextGen, Watchdog: a.watchdog}
	p.Eligible = (a.state == IOpen || a.state == ROpen) && a.watchdog == WatchdogOkay
	if a.meta != nil && (a.state == IOpen || a.state == ROpen || a.state == Closing) {
		p.Realm = a.meta.OriginRealm
		p.Applications = append([]uint32(nil), a.meta.Applications...)
	}
	if a.active != nil {
		p.Generation = a.active.gen
	}
	a.snapshotValue.Store(p)
	a.activeSession.Store(a.active)
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
	defer a.m.wg.Done()
	defer close(a.done)
	for {
		e := <-a.events
		a.handle(e)
		if a.m.isClosing() && a.state == Closed {
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
	a.setState(Closed, err)
	a.lostConnection(err)
}
func (a *actor) handle(e event) {
	if e.kind == watchdogTimeout {
		if e.token == a.wdToken && a.active != nil && e.gen == a.active.gen {
			a.watchdogTick()
		}
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
		if a.state == Closed {
			return
		}
		a.step(timeout, nil, nil)
		return
	}
	if e.kind == start {
		// RFC 6733 §5.4.3: a BUSY or DO_NOT_WANT_TO_TALK_TO_YOU DPR received
		// before Start also suppresses the first dial.
		if a.state == Closed && !a.m.isClosing() && !a.suppressReconnect {
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
	if e.kind == dialDone {
		a.onDial(e)
		return
	}
	if e.kind == connGone {
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
	if a.dialing {
		return
	}
	a.dialing = true
	a.nextGen++
	gen := a.nextGen
	a.pendingGen = gen
	endpoints := a.cfg.Endpoints
	m := a.m
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ctx, cancel := context.WithTimeout(m.startContext(), m.cfg.Timers.Connect)
		defer cancel()
		var lastErr error
		for _, e := range endpoints {
			if err := ctx.Err(); err != nil {
				lastErr = err
				break
			}
			if s, err := m.dialEndpoint(ctx, e, a, gen); err == nil {
				a.post(event{kind: dialDone, s: s, gen: gen})
				return
			} else {
				lastErr = errors.Join(lastErr, err)
			}
		}
		a.post(event{kind: dialDone, gen: gen, err: lastErr})
	}()
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
				raw = tls.Client(raw, cfg)
			}
			c, err = srv.NewConn(raw)
			if err != nil {
				_ = raw.Close()
			}
		}
	} else if e.TLSConfig != nil {
		srv.TLSConfig = e.TLSConfig.Clone()
		c, err = srv.DialTLS("", "", time.Until(deadline(ctx)))
	} else {
		c, err = srv.Dial(time.Until(deadline(ctx)))
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
func deadline(ctx context.Context) time.Time { d, _ := ctx.Deadline(); return d }
func (a *actor) onDial(e event) {
	if e.gen == a.pendingGen {
		a.dialing = false
	}
	if e.gen != a.pendingGen || (a.state != WaitConnAck && a.state != WaitConnAckElect) {
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
	if a.state == Closing || a.m.isClosing() {
		a.m.report(e.s, e.msg, errors.New("peer: CER while closing; closing connection"))
		e.s.close()
		return
	}
	if compareIdentity(e.meta.OriginHost, a.cfg.Host) != 0 {
		a.m.report(e.s, e.msg, errors.New("peer: configured Origin-Host mismatch; closing connection"))
		e.s.close()
		return
	}
	if a.state != Closed && a.state != WaitConnAck && a.state != WaitICEA && a.state != WaitConnAckElect && a.state != WaitReturns && a.state != IOpen && a.state != ROpen {
		a.m.report(e.s, e.msg, fmt.Errorf("peer: CER in state %s; closing connection", a.state))
		e.s.close()
		return
	}
	if a.state == WaitConnAckElect || a.state == WaitReturns || a.state == IOpen || a.state == ROpen {
		a.step(rConnCER, e.s, e.msg)
		return
	}
	a.nextGen++
	e.s.bind(a, a.nextGen)
	a.r = e.s
	e.s.cerRequest = e.msg
	a.meta = e.meta.Clone()
	a.step(rConnCER, e.s, e.msg)
	if a.state == WaitReturns {
		a.elect()
	}
}
func (a *actor) elect() {
	// RFC 6733 §5.6.4: compare ASCII case-folded octets; the winner discards I.
	switch compareIdentity(a.m.cfg.Settings.OriginHost, a.cfg.Host) {
	case 0:
		a.fail(errors.New("peer: Origin-Host identity collision"))
	case 1:
		if a.state == WaitReturns {
			a.step(winElection, a.r, nil)
		}
	}
}
func (a *actor) onWire(e event) {
	s := e.s
	msg := e.msg
	if s == nil || msg == nil || msg.Header == nil {
		return
	}
	if (s != a.i && s != a.r) || s.gen == 0 {
		if msg.Header.CommandFlags&diam.RequestFlag == 0 && msg.Header.ApplicationID != 0 {
			a.m.report(s, msg, errors.New("peer: answer on retired connection generation (RFC 6733 §6.2.1)"))
		}
		return
	} // RFC 6733 §5.6: ignore retired candidate generations.
	isI := s == a.i
	cmd := msg.Header.CommandCode
	req := msg.Header.CommandFlags&diam.RequestFlag != 0
	if a.state == WaitICEA || a.state == WaitReturns {
		if isI && e.messageErr == nil && cmd == diam.CapabilitiesExchange && !req && msg.Header.ApplicationID == 0 {
			if s.cerHop != msg.Header.HopByHopID || s.cerEnd != msg.Header.EndToEndID {
				a.fail(errors.New("peer: CEA identifiers mismatch"))
				return
			}
			cea := new(smparser.CEA)
			if err := cea.Parse(msg, smparser.ParseOptions{Role: smparser.Client, LocalApplications: base.AdvertisedApplicationIDs(a.m.baseSettings(s.c))}); err != nil {
				a.fail(fmt.Errorf("peer: invalid CEA: %w", err))
				return
			}
			if compareIdentity(cea.OriginHost, a.cfg.Host) != 0 {
				a.fail(errors.New("peer: CEA Origin-Host mismatch"))
				return
			}
			a.meta = smpeer.FromCEA(cea).Clone()
			s.releaseControl(s.cerHop)
			a.step(iCEA, s, msg)
			return
		}
		if isI {
			a.step(iNonCEA, s, msg)
		} else {
			// RFC 6733 §5.6 has no R-Rcv-Message action in Wait-Returns.
			// As in Wait-Conn-Ack/Elect, close all pre-CEA traffic on R.
			reason := error(e.messageErr)
			if e.messageErr == nil {
				reason = errors.New("peer: message before answering connection handshake")
			}
			a.m.report(s, msg, reason)
			s.close()
		}
		return
	}
	if a.state != IOpen && a.state != ROpen && a.state != Closing {
		a.m.report(s, msg, errors.New("peer: message before handshake"))
		s.close()
		return
	}
	if headerErr := base.ValidateHeader(msg); headerErr != nil {
		a.m.report(s, msg, headerErr)
		if !req {
			return
		} // RFC 6733 §§2.5 and 7: invalid DWA/DPA is discarded.
		e.messageErr = headerErr
	}
	if e.messageErr != nil {
		// The actor queued CEA before this error answer (RFC 6733 §§5.6, 7).
		if err := a.m.answerMessageError(s, msg, e.messageErr); err != nil {
			a.m.reportLocal(s, msg, "peer: error answer failed; closing connection", err)
			s.close()
		}
		return
	}

	if s != a.active {
		return
	}
	if a.state == Closing {
		if cmd == diam.DisconnectPeer && !req && msg.Header.ApplicationID == 0 {
			// RFC 6733 §5.4.2 and §5.6 Closing: only the matching peer's
			// successful DPA completes this disconnect exchange.
			if msg.Header.HopByHopID != a.pendingDPR || msg.Header.EndToEndID != a.pendingDPREnd {
				a.m.report(s, msg, errors.New("peer: DPA identifiers mismatch"))
				return
			}
			result, err := base.ValidateDPA(msg)
			if err != nil {
				a.m.report(s, msg, err)
				return
			}
			if result != diam.Success {
				a.m.report(s, msg, fmt.Errorf("peer: DPA Result-Code %d", result))
				return
			}
			host, err := msg.FindAVP(avp.OriginHost, 0)
			if err != nil || compareIdentity(host.Data.(datatype.DiameterIdentity), a.cfg.Host) != 0 {
				a.m.report(s, msg, errors.New("peer: DPA Origin-Host mismatch"))
				return
			}
			if isI {
				s.releaseControl(a.pendingDPR)
				a.step(iDPA, s, msg)
			} else {
				s.releaseControl(a.pendingDPR)
				a.step(rDPA, s, msg)
			}
		} else if cmd == diam.DisconnectPeer && req && a.validDPR(s, msg) {
			a.answerDPR(s, msg)
		}
		return
	}
	if !a.watchdogReceive(msg) {
		return
	}
	switch {
	case cmd == diam.DeviceWatchdog && req && msg.Header.ApplicationID == 0:
		var dwr base.DWR
		if err := dwr.Parse(msg); err != nil {
			a.m.report(s, msg, err)
			return
		}
		if compareIdentity(dwr.OriginHost, a.cfg.Host) != 0 {
			a.m.report(s, msg, errors.New("peer: DWR Origin-Host mismatch"))
			return
		}
		if isI {
			a.step(iDWR, s, msg)
		} else {
			a.step(rDWR, s, msg)
		}
	case cmd == diam.DeviceWatchdog && !req && msg.Header.ApplicationID == 0:
		if isI {
			a.step(iDWA, s, msg)
		} else {
			a.step(rDWA, s, msg)
		}
	case cmd == diam.DisconnectPeer && req && msg.Header.ApplicationID == 0:
		if !a.validDPR(s, msg) {
			return
		}
		if isI {
			a.step(iDPR, s, msg)
		} else {
			a.step(rDPR, s, msg)
		}
	case cmd == diam.CapabilitiesExchange && req && msg.Header.ApplicationID == 0:
		// RFC 6733 §5.6 Open/R-Conn-CER rejects a duplicate candidate.
		a.m.report(s, msg, errors.New("peer: duplicate CER on open connection; closing connection"))
		s.close()
	default:
		if a.watchdog == WatchdogReopen {
			return
		} // RFC 3539 Appendix A: Throwaway(non-DWA).
		if isI {
			a.step(iMessage, s, msg)
		} else {
			a.step(rMessage, s, msg)
		}
	}
}
func (a *actor) validDPR(s *session, msg *diam.Message) bool {
	if _, err := base.ValidateDPR(msg); err != nil {
		a.m.report(s, msg, err)
		return false
	}
	// RFC 6733 §§5.1, 5.4.1: accept a DPR only from this connection's peer.
	host, err := msg.FindAVP(avp.OriginHost, 0)
	if err != nil || compareIdentity(host.Data.(datatype.DiameterIdentity), a.cfg.Host) != 0 {
		a.m.report(s, msg, errors.New("peer: DPR Origin-Host mismatch"))
		return false
	}
	return true
}
func (a *actor) answerDPR(s *session, msg *diam.Message) {
	if _, err := base.ValidateDPR(msg); err != nil {
		a.m.report(s, msg, err)
		return
	}
	dpa, err := base.BuildDPA(msg, a.m.baseSettings(s.c))
	if err == nil {
		err = s.send(dpa, false)
	}
	if err != nil {
		a.m.reportLocal(s, msg, "peer: DPA answer failed; closing connection", err)
		s.close()
	}
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
	a.stopReconnect()
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
	switch ev {
	case iAck:
		a.stopTimer()
		a.arm(a.m.cfg.Timers.CER)
		if a.i != nil {
			m, err := base.BuildCER(a.m.dictionary(), a.m.baseSettings(a.i.c))
			if err != nil {
				a.failLocal("build CER", err)
				return
			}
			if err := a.i.sendControl(m); err != nil {
				a.failLocal("send CER", err)
				return
			}
			a.i.cerHop = m.Header.HopByHopID
			a.i.cerEnd = m.Header.EndToEndID
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
			a.arm(a.m.cfg.Timers.CER)
		}
	case iNonCEA:
		a.fail(errors.New("peer: non-CEA before handshake"))
		return
	case timeout:
		a.fail(errors.New("peer: state timeout"))
		return
	case iDWR, rDWR:
		dwa, err := base.BuildDWA(msg, a.m.baseSettings(s.c))
		if err != nil {
			a.failLocal("build DWA", err)
			return
		}
		if err := s.send(dwa, false); err != nil {
			a.failLocal("send DWA", err)
			return
		}
	case iDPR, rDPR:
		a.stopTimer()
		a.stopWatchdog()
		cause, _ := base.ValidateDPR(msg)
		// RFC 6733 §5.4.3: only REBOOTING permits periodic reconnection.
		a.suppressReconnect = cause == uint32(sm.DisconnectBusy) || cause == uint32(sm.DisconnectDoNotWantToTalkToYou)
		a.answerDPR(s, msg)
		a.arm(a.m.cfg.Timers.Closing)
	case stop:
		a.stopTimer()
		dpr, err := base.BuildDPR(a.m.dictionary(), a.m.baseSettings(s.c), uint32(a.closeCause))
		if err != nil {
			a.failLocal("build DPR", err)
			return
		}
		if err := s.sendControl(dpr); err != nil {
			a.failLocal("send DPR", err)
			return
		}
		a.pendingDPR = dpr.Header.HopByHopID
		a.pendingDPREnd = dpr.Header.EndToEndID
		a.arm(a.m.cfg.Timers.Closing)
	case iDPA, rDPA:
		a.stopTimer()
		s.close()
		a.active = nil
		a.meta = nil
	case iMessage, rMessage:
		if msg.Header.CommandFlags&diam.RequestFlag == 0 {
			a.m.receiveAnswer(s, msg)
		} else {
			a.m.unsupported(s, msg)
		}
	}
	if old != IOpen && old != ROpen && (a.state == IOpen || a.state == ROpen) {
		a.onOpen()
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
	} // RFC 6733 §§5.3.2, 5.6.
	msg := s.cerRequest
	if msg == nil {
		a.failLocal("send CEA", errors.New("missing CER"))
		return false
	}
	answer, err := base.BuildCEA(msg, a.m.baseSettings(s.c), diam.Success)
	if err != nil {
		a.failLocal("build CEA", err)
		return false
	}
	if err := s.send(answer, false); err != nil {
		a.failLocal("send CEA", err)
		return false
	}
	return true
}
func (m *Manager) dictionary() *dict.Parser {
	if m.cfg.Settings.Dict != nil {
		return m.cfg.Settings.Dict
	}
	return dict.Default
}
