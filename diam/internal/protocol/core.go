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

type continuation struct {
	Input
	repeatedCER bool
}

// Core is exclusively owned by its caller's serialization domain.
type Core struct {
	handshakePending, callbackReady bool
	continuations                   map[uint64]continuation
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
	earlyDPA                      *Input

	lateCERToken                     uint64
	lateCER                          Input
	cfg                              Config
	phase                            Phase
	serial                           uint64
	started, ready, terminal, frozen bool
	cerDeferred                      bool
	passiveResponder, passiveCER     bool
	passiveWatchdog                  bool
	passivePresent                   bool
	candidateToken, admission        uint64
	caps                             Capabilities
	cer                              *diam.Message
	completedCEA                     *diam.Header
	hookToken                        uint64
	timers                           [timerCount]TimerSnapshot
	reservations                     map[uint64]uint32
	controls                         map[uint32]*control
	operations                       map[uint64]*operation
	spareOperation                   *operation
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
	c := &Core{cfg: cfg, reservations: make(map[uint64]uint32), controls: make(map[uint32]*control), operations: make(map[uint64]*operation), continuations: make(map[uint64]continuation), closeOutcome: ConnectionClosed, wd: watchdog.Machine{State: watchdog.Initial}}
	c.caps = Capabilities{Local: copySettings(cfg.Local), LocalApplications: base.AdvertisedApplicationIDs(cfg.Local), TLS: cfg.TLS}
	// Initiators have a completion obligation from construction, including a
	// lifecycle event received before Start (RFC 6733 §5.3).
	c.handshakePending = cfg.Role == Initiator
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
func (c *Core) arm(es []Effect, k TimerKind, at time.Time, d time.Duration) []Effect {
	if d <= 0 {
		return es
	}
	e := c.effect(ArmTimer)
	e.Timer = k
	e.Token = c.token()
	e.Deadline = at.Add(d)
	c.timers[k] = TimerSnapshot{e.Token, e.Deadline}
	return append(es, e)
}

func (c *Core) stop(es []Effect, k TimerKind) []Effect {
	if c.timers[k].Token == 0 {
		return es
	}
	e := c.effect(StopTimer)
	e.Timer = k
	e.Token = c.timers[k].Token
	c.timers[k] = TimerSnapshot{}
	return append(es, e)
}

func (c *Core) terminate(es []Effect, phase Phase) []Effect {
	c.phase = phase
	c.earlyDPA = nil
	c.candidateToken, c.hookToken, c.admission = 0, 0, 0
	c.ready = false
	c.callbackReady = false
	c.continuations = make(map[uint64]continuation)
	c.cer = nil
	c.wdNext = nil
	c.deferredExpiry = nil
	if c.cfg.Watchdog && c.wd.State != watchdog.Initial {
		c.wd, _ = c.wd.Step(watchdog.ConnectionDown)
		c.wd.Pending = false
	}

	for k := HandshakeTimer; k < timerCount; k++ {
		es = c.stop(es, k)
	}
	for _, cmd := range []uint32{diam.CapabilitiesExchange, diam.DeviceWatchdog, diam.DisconnectPeer} {
		if r := c.controls[cmd]; r != nil {
			r.logical = false
			es = c.release(es, r)
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

// Handle returns a batch whose storage is independent of later calls.
func (c *Core) Handle(in Input) []Effect {
	return c.HandleInto(in, nil)
}

// HandleInto appends obligations to dst in execution order. The caller owns dst
// and must finish consuming a batch before reusing its storage. Core never
// retains the output slice; concurrent calls still require caller serialization.
func (c *Core) HandleInto(in Input, dst []Effect) []Effect {
	es := dst
	if in.Connection != c.cfg.Connection {
		return es
	}
	if in.Kind == ReserveResult {
		return c.reserved(es, in)
	}
	if in.Kind == WriteResult {
		return c.writeResult(es, in)
	}
	if c.phase == Closed && in.Kind == Continue && in.Token == c.lateCERToken && c.lateCERToken != 0 {
		c.lateCERToken = 0
		saved := c.lateCER
		c.lateCER = Input{}
		if in.TransportClosed {
			return es
		}
		n := Notification{Protocol: diam.ProtocolHandshakeState, Closing: true, Message: metadata(saved.Message), Diagnostic: "late-cer"}
		return append(es, c.effect(Close), c.notify(n))
	}
	if c.phase >= Closed {
		return es
	}
	if in.RefreshLocalAddresses && (c.phase == PreCER || c.passiveResponder && in.ErrorInput) {
		c.cfg.Local.HostIPAddresses = base.CloneAddresses(in.LocalAddresses)
		c.caps.Local.HostIPAddresses = base.CloneAddresses(in.LocalAddresses)
	}
	switch in.Kind {
	case Start:
		if c.started || c.phase != PreCER {
			return es
		}
		c.started = true
		if c.cfg.Role == Initiator && in.DeferCER {
			c.phase = WaitCEA
			c.cerDeferred = true
			return es
		}
		es = c.arm(es, HandshakeTimer, in.At, c.cfg.HandshakeTimeout)
		if c.cfg.Role == Initiator {
			c.phase = WaitCEA
			c.handshakePending = true
			es = c.reserve(es, diam.CapabilitiesExchange)
		}
		return es
	case BeginCER:
		if !c.cerDeferred || c.phase != WaitCEA {
			return es
		}
		c.cerDeferred = false
		return c.reserve(c.arm(es, HandshakeTimer, in.At, c.cfg.HandshakeTimeout), diam.CapabilitiesExchange)
	case StopSupervision:
		c.cfg.Watchdog = false
		c.wd.Pending = false
		c.wdNext = nil
		return c.stop(es, WatchdogTimer)
	case Retire:
		return c.terminate(es, Retired)
	case Abort:
		c.closeOutcome = Cancelled
		return c.terminate(es, Closed)
	case TransportLost:
		if c.cfg.KeepCERDeadlineAfterTransportLoss && c.phase == WaitCEA {
			// EOF preserves the CER response window. Its deadline selects a
			// retry or completes the handshake with timeout.
			return es
		}
		return c.terminate(es, Closed)
	case Receive:
		start := len(es)
		es = c.receive(es, in)
		if len(es) == start+1 && es[start].Kind == Hold {
			return es
		}
		if in.Sequence > c.receivedSequence {
			c.receivedSequence = in.Sequence
		}
		if c.deferredExpiry != nil && c.deferredExpiry.AfterReceive <= c.receivedSequence {
			pending := *c.deferredExpiry
			c.deferredExpiry = nil
			es = c.expire(es, pending)
		}
		return es
	case Continue:
		pending, ok := c.continuations[in.Token]
		if !ok {
			return es
		}
		saved := pending.Input
		delete(c.continuations, in.Token)
		if c.hookToken == in.Token {
			c.hookToken = 0
		}
		if in.TransportClosed {
			return c.terminate(es, Closed)
		}
		original := *saved.Message.Header
		if in.Message != nil {
			saved.Message = in.Message
		}
		if saved.Message == nil || saved.Message.Header == nil {
			return c.fail(es, in, diam.ProtocolMalformedMessage, 0)
		}
		h := saved.Message.Header
		// Hooks may change AVPs, but cannot turn their continuation into a
		// different base exchange or replace its reply identifiers (#108).
		if h.CommandCode != original.CommandCode || h.ApplicationID != original.ApplicationID || h.CommandFlags&diam.RequestFlag != original.CommandFlags&diam.RequestFlag || h.HopByHopID != original.HopByHopID || h.EndToEndID != original.EndToEndID {
			return c.fail(es, saved, diam.ProtocolInvalidHeader, diam.InvalidHDRBits)
		}
		// A hook cannot reclassify a repeated CER as a fresh admission when
		// frontend metadata is revoked meanwhile (RFC 6733 §5.6).
		if pending.repeatedCER {
			return c.discard(es, saved, diam.ProtocolUnexpectedMessage, 0)
		}
		if original.CommandCode == diam.DeviceWatchdog && c.cfg.SkipDWRGrammarAfterHook {
			return c.dwr(es, saved)
		}
		if err := base.ValidateMessage(saved.Message); err != nil {
			if original.CommandCode == diam.CapabilitiesExchange {
				return c.reject(es, saved, diam.ProtocolCERRejected, err)
			}
			return c.discard(es, saved, diam.ProtocolInvalidDWR, err.ResultCode)
		}
		if original.CommandCode == diam.DeviceWatchdog {
			return c.dwr(es, saved)
		}
		return c.candidate(es, saved)
	case Activate:
		return c.activate(es, in)
	case RejectCandidate:
		if c.candidateToken == 0 || in.Token != c.candidateToken {
			return es
		}
		if in.ResultCode == 0 {
			return c.terminate(es, Closed)
		}
		c.candidateToken = 0
		c.terminal = true
		answer, err := base.BuildCEA(c.cer, c.cfg.Local, in.ResultCode)
		if err != nil {
			in.Message = c.cer
			return c.failedRejection(es, in, diam.ProtocolCERRejected, in.ResultCode, err)
		}
		notice := Notification{Protocol: diam.ProtocolCERRejected, ResultCode: in.ResultCode, Closing: true, Message: metadata(c.cer)}
		return c.send(es, answer, nil, true, true, false, &notice)
	case ReleaseAdmission:
		if c.phase != Open || in.Token == 0 || in.Token != c.admission || c.ready || !c.callbackReady {
			return es
		}
		c.ready = true
		c.handshakePending = false
		return c.watchdogUp(append(es, c.notify(Notification{Kind: HandshakeNotice})), in)
	case Disconnect:
		return c.disconnect(es, in)
	case Frozen:
		return c.freeze(es, in)
	case Unhandled:
		return c.unhandled(es, in)
	case TimerExpired:
		return c.expire(es, in)
	}
	return es
}

func (c *Core) expire(es []Effect, in Input) []Effect {
	if in.Timer >= timerCount {
		return es
	}
	t := c.timers[in.Timer]
	if t.Token == 0 || t.Token != in.Token || in.At.Before(t.Deadline) {
		return es
	}
	if in.Timer == WatchdogTimer {
		return c.watchdogExpired(es, in)
	}
	if in.Timer == RetryTimer {
		r := c.controls[diam.CapabilitiesExchange]
		if r != nil && r.logical && r.attempts <= c.cfg.MaxRetransmits {
			es = c.stop(es, RetryTimer)
			return c.send(es, copyMessage(r.frame), r, false, false, false, nil)
		}
	}
	kind := diam.ProtocolHandshakeTimeout
	if in.Timer == ClosingTimer || in.Timer == ReceiverDisconnectTimer {
		kind = diam.ProtocolDisconnectTimeout
	}
	if in.Timer == ClosingTimer && c.disconnectWaiting && !c.closeLocal && c.timers[ReceiverDisconnectTimer].Token != 0 {
		// The peer-initiated Closing deadline is transport closure to the
		// later local caller, not expiry of that caller's own timeout (§5.6).
		return append(c.terminate(es, Closed), c.notify(Notification{Protocol: kind, Closing: true}))
	}
	return c.fail(es, in, kind, 0)
}

func (c *Core) notify(n Notification) Effect {
	if n.Kind == HandshakeNotice {
		n.Handshake = c.handshake
	}
	e := c.effect(Notify)
	e.Notification = n
	return e
}

func (c *Core) discard(es []Effect, in Input, kind diam.ProtocolErrorKind, code uint32) []Effect {
	e := c.effect(Discard)
	es = append(es, e)
	if kind != "" {
		es = append(es, c.notify(Notification{Protocol: kind, ResultCode: code, Message: metadata(in.Message), CauseError: copyHandshakeError(in.Error)}))
	}
	return es
}

func (c *Core) fail(es []Effect, in Input, kind diam.ProtocolErrorKind, code uint32) []Effect {
	var localDPR *diam.Message
	localTimeout := kind == diam.ProtocolDisconnectTimeout && (c.closeLocal || in.Timer == ReceiverDisconnectTimer)
	if localTimeout {
		if r := c.controls[diam.DisconnectPeer]; r != nil {
			localDPR = copyMessage(r.frame)
		}
	}
	if kind == diam.ProtocolHandshakeTimeout && c.hookToken != 0 {
		if saved, ok := c.continuations[c.hookToken]; ok && saved.Message.Header.CommandCode == diam.CapabilitiesExchange {
			c.lateCERToken = c.hookToken
			c.lateCER = saved.Input
		}
	}

	if kind == diam.ProtocolHandshakeTimeout || kind == diam.ProtocolDisconnectTimeout || kind == diam.ProtocolWatchdogTimeout {
		c.closeOutcome = TimedOut
	}
	es = c.terminate(es, Closed)
	n := Notification{Protocol: kind, ResultCode: code, Closing: true, Message: metadata(in.Message), CauseError: copyHandshakeError(in.Error)}
	if in.Error == nil {
		n.CauseError = copyHandshakeError(in.Err)
	}
	if localTimeout {
		n.Diagnostic = "local-disconnect"
	}
	if kind == diam.ProtocolReplyFailure {
		n.ResultCode, n.ReplyCode, n.Reply = 0, code, diam.ProtocolReplyFailed
	}
	e := c.notify(n)
	e.Message = localDPR // log source only; public timeout metadata remains empty
	return append(es, e)
}

func (c *Core) reject(es []Effect, in Input, kind diam.ProtocolErrorKind, me *diam.MessageError) []Effect {
	if c.phase == Closing {
		es = c.discard(es, in, kind, me.ResultCode)
		es[len(es)-1].Notification.CauseError = copyHandshakeError(me)
		return es
	}
	var failed []*diam.AVP
	if me.FailedAVP != nil {
		failed = []*diam.AVP{me.FailedAVP}
	}
	answer, err := base.BuildErrorAnswer(in.Message, c.cfg.Local, me.ResultCode, failed, me.ResultCode >= 3000 && me.ResultCode < 4000)
	if err != nil {
		es = c.failedRejection(es, in, kind, me.ResultCode, err)
		es[len(es)-1].Notification.CauseError = copyHandshakeError(me)
		return es
	}
	terminal := c.phase == PreCER || me.Fatal || in.Message.Header.CommandCode == diam.CapabilitiesExchange && base.ValidateHeader(in.Message) != nil
	if terminal {
		c.terminal = true
	}
	n := Notification{Protocol: kind, ResultCode: me.ResultCode, Closing: terminal, Message: metadata(in.Message), CauseError: copyHandshakeError(me)}
	if in.Message.Header.CommandCode == diam.CapabilitiesExchange && (c.phase == PreCER || base.ValidateHeader(in.Message) != nil) {
		n.Diagnostic = "reject-cer"
	}

	return c.send(es, answer, nil, true, terminal, false, &n)
}

// #108 required replies preserve the detected condition when construction
// fails before any Queued/Written report. A later queued failure is separate.
func (c *Core) failedRejection(es []Effect, in Input, kind diam.ProtocolErrorKind, code uint32, err error) []Effect {
	initialCER := c.phase == PreCER && in.Message != nil && in.Message.Header.CommandCode == diam.CapabilitiesExchange
	es = c.terminate(es, Closed)
	n := Notification{Protocol: kind, ResultCode: code, Reply: diam.ProtocolReplyFailed, ReplyCode: code, Closing: true, Message: metadata(in.Message), ReplyError: copyHandshakeError(err, true)}
	if initialCER {
		n.Diagnostic = "reject-cer"
	}
	return append(es, c.notify(n))
}
