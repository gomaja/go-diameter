package protocol

import (
	"errors"
	"sort"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/watchdog"
)

// Core is exclusively owned by its caller's serialization domain.
type Core struct {
	handshakePending, callbackReady bool
	continuations                   map[uint64]Input
	closeOutcome                    Outcome
	handshake                       HandshakeResult

	wdNext           *watchdog.Machine
	receivedSequence uint64
	deferredExpiry   *Input

	closeLocal, disconnectWaiting bool
	peerDisconnectSelected        bool
	peerCause                     uint32
	peerDPR                       bool
	disconnectToken, fenceToken   uint64
	closeRequest                  Input

	cfg                              Config
	phase                            Phase
	serial                           uint64
	started, ready, terminal, frozen bool
	candidateToken, admission        uint64
	caps                             Capabilities
	cer                              *diam.Message
	hookToken                        uint64
	timers                           [timerCount]TimerSnapshot
	reservations                     map[uint64]uint32
	controls                         map[uint32]*control
	operations                       map[uint64]*operation
	closeCause                       uint32
	wd                               watchdog.Machine
}

func New(cfg Config) (*Core, error) {
	if cfg.Connection.Instance == 0 || cfg.Role != Responder && cfg.Role != Initiator {
		return nil, errors.New("protocol: invalid connection or role")
	}
	if cfg.Local.ResolveHostIPAddresses != nil {
		return nil, errors.New("protocol: resolve addresses before New")
	}
	if cfg.HandshakeTimeout < 0 || cfg.CERInterval < 0 || cfg.ClosingTimeout < 0 {
		return nil, errors.New("protocol: negative timeout")
	}
	if cfg.Watchdog && cfg.WatchdogInterval < watchdog.MinimumTw {
		return nil, errors.New("protocol: watchdog interval below minimum")
	}
	if err := base.ValidateCapabilities(cfg.Local); err != nil {
		return nil, err
	}
	if cfg.Dictionary == nil {
		cfg.Dictionary = dict.Default
	}
	cfg.Local = copySettings(cfg.Local)
	c := &Core{cfg: cfg, reservations: make(map[uint64]uint32), controls: make(map[uint32]*control), operations: make(map[uint64]*operation), continuations: make(map[uint64]Input), closeOutcome: ConnectionClosed, wd: watchdog.Machine{State: watchdog.Initial}}
	c.caps = Capabilities{Local: copySettings(cfg.Local), LocalApplications: base.AdvertisedApplicationIDs(cfg.Local), TLS: cfg.TLS}
	if cfg.Recovery {
		c.wd.State = watchdog.Down
	}
	return c, nil
}
func (c *Core) Snapshot() Snapshot {
	s := Snapshot{phase: c.phase, connection: c.cfg.Connection, role: c.cfg.Role, timers: c.timers, candidate: c.candidateToken, admission: c.admission, ready: c.ready, frozen: c.frozen, capabilities: copyCapabilities(c.caps), wd: c.wd}
	s.peerCause, s.peerDPR = c.peerCause, c.peerDPR
	s.handshake = c.handshake
	for _, cmd := range []uint32{diam.CapabilitiesExchange, diam.DeviceWatchdog, diam.DisconnectPeer} {
		if r := c.controls[cmd]; r != nil {
			s.controls = append(s.controls, ControlSnapshot{Command: cmd, Reservation: r.reservation, Logical: r.logical, Answered: r.answered, Writers: r.writers})
		}
	}
	return s
}

func (c *Core) token() uint64              { c.serial++; return c.serial }
func (c *Core) effect(k EffectKind) Effect { return Effect{Kind: k, Connection: c.cfg.Connection} }
func (c *Core) arm(k TimerKind, at time.Time, d time.Duration) []Effect {
	if d <= 0 {
		return nil
	}
	e := c.effect(ArmTimer)
	e.Timer = k
	e.Token = c.token()
	e.Deadline = at.Add(d)
	c.timers[k] = TimerSnapshot{e.Token, e.Deadline}
	return []Effect{e}
}
func (c *Core) stop(k TimerKind) []Effect {
	if c.timers[k].Token == 0 {
		return nil
	}
	e := c.effect(StopTimer)
	e.Timer = k
	e.Token = c.timers[k].Token
	c.timers[k] = TimerSnapshot{}
	return []Effect{e}
}
func (c *Core) terminate(phase Phase) []Effect {
	c.phase = phase
	c.candidateToken, c.hookToken, c.admission = 0, 0, 0
	c.ready = false
	c.callbackReady = false
	c.continuations = make(map[uint64]Input)
	c.cer = nil
	c.wdNext = nil
	c.deferredExpiry = nil
	if c.cfg.Watchdog && c.wd.State != watchdog.Initial {
		c.wd, _ = c.wd.Step(watchdog.ConnectionDown)
		c.wd.Pending = false
	}
	var es []Effect
	for k := HandshakeTimer; k < timerCount; k++ {
		es = append(es, c.stop(k)...)
	}
	for _, cmd := range []uint32{diam.CapabilitiesExchange, diam.DeviceWatchdog, diam.DisconnectPeer} {
		if r := c.controls[cmd]; r != nil {
			r.logical = false
			es = append(es, c.release(r)...)
		}
	}
	var tokens []uint64
	for token := range c.operations {
		tokens = append(tokens, token)
	}
	sort.Slice(tokens, func(i, j int) bool { return tokens[i] < tokens[j] })
	for _, token := range tokens {
		e := c.effect(CancelSend)
		e.Token = token
		es = append(es, e)
	}
	if phase == Closed {
		es = append(es, c.effect(Close))
	}
	if c.handshakePending {
		c.handshakePending = false
		es = append(es, c.notify(Notification{Kind: HandshakeNotice, Outcome: c.closeOutcome}))
	}
	if c.disconnectWaiting {
		c.disconnectWaiting = false
		e := c.notify(Notification{Kind: DisconnectNotice, Outcome: c.closeOutcome})
		e.Token = c.disconnectToken
		es = append(es, e)
	}
	return es
}
func (c *Core) Handle(in Input) []Effect {
	if in.Connection != c.cfg.Connection {
		return nil
	}
	if in.Kind == ReserveResult {
		return c.reserved(in)
	}
	if in.Kind == WriteResult {
		return c.writeResult(in)
	}
	if c.phase >= Closed {
		return nil
	}
	switch in.Kind {
	case Start:
		if c.started || c.phase != PreCER {
			return nil
		}
		c.started = true
		es := c.arm(HandshakeTimer, in.At, c.cfg.HandshakeTimeout)
		if c.cfg.Role == Initiator {
			c.phase = WaitCEA
			c.handshakePending = true
			es = append(es, c.reserve(diam.CapabilitiesExchange)...)
		}
		return es
	case Retire:
		return c.terminate(Retired)
	case Abort:
		c.closeOutcome = Cancelled
		return c.terminate(Closed)
	case TransportLost:
		return c.terminate(Closed)
	case Receive:
		es := c.receive(in)
		if len(es) == 1 && es[0].Kind == Hold {
			return es
		}
		if in.Sequence > c.receivedSequence {
			c.receivedSequence = in.Sequence
		}
		if c.deferredExpiry != nil && c.deferredExpiry.AfterReceive <= c.receivedSequence {
			pending := *c.deferredExpiry
			c.deferredExpiry = nil
			es = append(es, c.expire(pending)...)
		}
		return es
	case Continue:
		saved, ok := c.continuations[in.Token]
		if !ok {
			return nil
		}
		delete(c.continuations, in.Token)
		if c.hookToken == in.Token {
			c.hookToken = 0
		}
		if in.TransportClosed {
			return c.terminate(Closed)
		}
		original := *saved.Message.Header
		if in.Message != nil {
			saved.Message = in.Message
		}
		if saved.Message == nil || saved.Message.Header == nil {
			return c.fail(in, diam.ProtocolMalformedMessage, 0)
		}
		h := saved.Message.Header
		// Hooks may change AVPs, but cannot turn their continuation into a
		// different base exchange or replace its reply identifiers (#108).
		if h.CommandCode != original.CommandCode || h.ApplicationID != original.ApplicationID || h.CommandFlags&diam.RequestFlag != original.CommandFlags&diam.RequestFlag || h.HopByHopID != original.HopByHopID || h.EndToEndID != original.EndToEndID {
			return c.fail(saved, diam.ProtocolInvalidHeader, diam.InvalidHDRBits)
		}
		if err := base.ValidateMessage(saved.Message); err != nil {
			if original.CommandCode == diam.CapabilitiesExchange {
				return c.reject(saved, diam.ProtocolCERRejected, err)
			}
			return c.discard(saved, diam.ProtocolInvalidDWR, err.ResultCode)
		}
		if original.CommandCode == diam.DeviceWatchdog {
			return c.dwr(saved)
		}
		return c.candidate(saved)
	case Activate:
		return c.activate(in)
	case RejectCandidate:
		if c.candidateToken == 0 || in.Token != c.candidateToken {
			return nil
		}
		if in.ResultCode == 0 {
			return c.terminate(Closed)
		}
		c.candidateToken = 0
		c.terminal = true
		answer, err := base.BuildCEA(c.cer, c.cfg.Local, in.ResultCode)
		if err != nil {
			in.Message = c.cer
			return c.failedRejection(in, diam.ProtocolCERRejected, in.ResultCode)
		}
		notice := Notification{Protocol: diam.ProtocolCERRejected, ResultCode: in.ResultCode, Closing: true, Message: metadata(c.cer)}
		return c.send(answer, nil, true, true, false, &notice)
	case ReleaseAdmission:
		if c.phase != Open || in.Token == 0 || in.Token != c.admission || c.ready || !c.callbackReady {
			return nil
		}
		c.ready = true
		c.handshakePending = false
		return append([]Effect{c.notify(Notification{Kind: HandshakeNotice})}, c.watchdogUp(in)...)
	case Disconnect:
		return c.disconnect(in)
	case Frozen:
		return c.freeze(in)
	case Unhandled:
		return c.unhandled(in)
	case TimerExpired:
		return c.expire(in)
	}
	return nil
}
func (c *Core) expire(in Input) []Effect {
	if in.Timer >= timerCount {
		return nil
	}
	t := c.timers[in.Timer]
	if t.Token == 0 || t.Token != in.Token || in.At.Before(t.Deadline) {
		return nil
	}
	if in.Timer == WatchdogTimer {
		return c.watchdogExpired(in)
	}
	if in.Timer == RetryTimer {
		r := c.controls[diam.CapabilitiesExchange]
		if r != nil && r.logical && r.attempts <= c.cfg.MaxRetransmits {
			es := c.stop(RetryTimer)
			return append(es, c.send(copyMessage(r.frame), r, false, false, false, nil)...)
		}
	}
	kind := diam.ProtocolHandshakeTimeout
	if in.Timer == ClosingTimer {
		kind = diam.ProtocolDisconnectTimeout
	}
	return c.fail(in, kind, 0)
}
func (c *Core) notify(n Notification) Effect {
	if n.Kind == HandshakeNotice {
		n.Handshake = c.handshake
	}
	e := c.effect(Notify)
	e.Notification = n
	return e
}
func (c *Core) discard(in Input, kind diam.ProtocolErrorKind, code uint32) []Effect {
	e := c.effect(Discard)
	es := []Effect{e}
	if kind != "" {
		es = append(es, c.notify(Notification{Protocol: kind, ResultCode: code, Message: metadata(in.Message)}))
	}
	return es
}
func (c *Core) fail(in Input, kind diam.ProtocolErrorKind, code uint32) []Effect {
	if kind == diam.ProtocolHandshakeTimeout || kind == diam.ProtocolDisconnectTimeout || kind == diam.ProtocolWatchdogTimeout {
		c.closeOutcome = TimedOut
	}
	es := c.terminate(Closed)
	n := Notification{Protocol: kind, ResultCode: code, Closing: true, Message: metadata(in.Message)}
	if kind == diam.ProtocolReplyFailure {
		n.ResultCode, n.ReplyCode, n.Reply = 0, code, diam.ProtocolReplyFailed
	}
	return append(es, c.notify(n))
}
func (c *Core) reject(in Input, kind diam.ProtocolErrorKind, me *diam.MessageError) []Effect {
	if c.phase == Closing {
		return c.discard(in, kind, me.ResultCode)
	}
	var failed []*diam.AVP
	if me.FailedAVP != nil {
		failed = []*diam.AVP{me.FailedAVP}
	}
	answer, err := base.BuildErrorAnswer(in.Message, c.cfg.Local, me.ResultCode, failed, me.ResultCode >= 3000 && me.ResultCode < 4000)
	if err != nil {
		return c.failedRejection(in, kind, me.ResultCode)
	}
	terminal := c.phase == PreCER || me.Fatal
	if terminal {
		c.terminal = true
	}
	n := Notification{Protocol: kind, ResultCode: me.ResultCode, Closing: terminal, Message: metadata(in.Message)}
	return c.send(answer, nil, true, terminal, false, &n)
}

// #108 required replies preserve the detected condition when construction
// fails before any Queued/Written report. A later queued failure is separate.
func (c *Core) failedRejection(in Input, kind diam.ProtocolErrorKind, code uint32) []Effect {
	es := c.terminate(Closed)
	n := Notification{Protocol: kind, ResultCode: code, Reply: diam.ProtocolReplyFailed, ReplyCode: code, Closing: true, Message: metadata(in.Message)}
	return append(es, c.notify(n))
}
