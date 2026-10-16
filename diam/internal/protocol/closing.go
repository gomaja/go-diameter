package protocol

import (
	"errors"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

// beginClosing latches before DPR/DPA effects. Frozen acknowledges the native
// write-gate boundary before selecting disconnect control.
func (c *Core) beginClosing(es []Effect, in Input, local bool) []Effect {
	c.phase = Closing
	c.ready = false
	c.closeLocal = local
	c.closeRequest = in
	c.closeCause = in.Cause
	c.fenceToken = c.token()
	if local {
		c.disconnectWaiting = true
		c.disconnectToken = in.Token
	}
	es = c.stop(es, WatchdogTimer)
	duration := in.Timeout
	if duration <= 0 {
		duration = c.cfg.ClosingTimeout
	}
	es = c.arm(es, ClosingTimer, in.At, duration)
	e := c.effect(FreezeAdmission)
	e.Token = c.fenceToken
	return append(es, e)
}
func (c *Core) freeze(es []Effect, in Input) []Effect {
	if c.phase != Closing || c.frozen || in.Token != c.fenceToken {
		return es
	}
	c.frozen = true
	c.fenceToken = 0
	if c.closeLocal {
		return c.reserve(es, diam.DisconnectPeer)
	}
	saved := c.closeRequest
	c.closeRequest = Input{}
	saved.InFlight = in.InFlight
	return c.answerDPR(es, saved, true)
}
func (c *Core) disconnect(es []Effect, in Input) []Effect {
	if c.disconnectWaiting {
		return append(es, c.notify(Notification{Kind: DisconnectNotice, Outcome: AlreadyPending}))
	}
	// Preserve StateMachine's local API after a received DPR (RFC 6733
	// §§5.4.1,5.6). Neither the original receiver deadline nor admission changes.
	if c.cfg.LocalDisconnectInClosing && c.phase == Closing && c.frozen && !c.closeLocal && in.Cause <= 2 {
		c.disconnectWaiting, c.disconnectToken, c.closeCause = true, in.Token, in.Cause
		es = c.arm(es, ReceiverDisconnectTimer, in.At, in.Timeout)
		return c.reserve(es, diam.DisconnectPeer)
	}
	if c.phase != Open || in.Cause > 2 {
		return append(es, c.notify(Notification{Kind: DisconnectNotice, Outcome: NotOpen}))
	}
	return c.beginClosing(es, in, true)
}
func (c *Core) bound(m *diam.Message, realm bool) bool {
	var identity base.DWR
	if identity.Parse(m) != nil {
		return false
	}
	return equalIdentity(string(identity.OriginHost), c.caps.Host) && (!realm || equalIdentity(string(identity.OriginRealm), c.caps.Realm))
}
func (c *Core) dpr(es []Effect, in Input) (out []Effect) {
	cause, err := base.ValidateDPR(in.Message)
	if err == nil && !c.bound(in.Message, false) {
		err = errors.New("DPR Origin-Host does not match the admitted peer (RFC 6733 §6.3)")
	}
	if err != nil {
		return c.discardCause(es, in, diam.ProtocolInvalidDPR, err)
	}
	in.Cause = cause
	start := len(es)
	defer func() {
		if len(out) > start {
			out[start].ReleaseDispatch = true
		}
	}()
	// RFC 6733 §5.4.3: reconnect suppression is decided by the validated
	// request, independently of whether a DPA can be queued or written.
	if !c.peerDPR {
		c.peerDPR, c.peerCause = true, cause
		e := c.effect(PeerDisconnectDecision)
		e.Cause = cause
		es = append(es, e)
	}
	if c.phase != Closing {
		es = c.validActivity(es)
		return c.beginClosing(es, in, false)
	}
	if !c.frozen {
		return c.discard(es, in, "", 0)
	}
	return c.answerDPR(es, in, !c.peerDisconnectSelected)
}
func (c *Core) answerDPR(es []Effect, in Input, first bool) []Effect {
	result := uint32(diam.Success)
	if in.InFlight {
		result = diam.UnableToComply
	}
	answer, err := base.BuildDPAResult(in.Message, c.cfg.Local, result)
	if err != nil {
		return c.fail(es, in, diam.ProtocolReplyFailure, result)
	}
	var notice *Notification
	if first {
		c.peerDisconnectSelected = true
		notice = &Notification{Kind: PeerDisconnectNotice, Cause: c.peerCause, ReplyCode: result, Message: metadata(in.Message)}
	}
	return c.send(es, answer, nil, true, false, false, notice, in.Message)
}
func (c *Core) dpa(es []Effect, in Input) []Effect {
	r := c.controls[diam.DisconnectPeer]
	if !c.matches(r, in.Message) {
		es = c.discard(es, in, diam.ProtocolUnexpectedMessage, 0)
		if r != nil && r.logical {
			es[len(es)-1].Notification.Diagnostic = "dpa-correlation"
		}
		return es
	}
	result, err := base.ValidateDPA(in.Message)
	if err != nil {
		return c.discardCause(es, in, diam.ProtocolInvalidDPA, err)
	}
	if !c.bound(in.Message, false) {
		es = c.discard(es, in, diam.ProtocolUnexpectedMessage, 0)
		es[len(es)-1].Notification.Diagnostic = "dpa-host"
		return es
	}
	es = c.settle(es, r)
	// Synchronous frontends complete their DPR send before publishing the
	// disconnect result. An early answer settles ownership without cancelling
	// the original Closing deadline or the selected writer (#110 API boundary).
	if !c.cfg.QueueWrites && !r.written && r.writers != 0 {
		saved := in
		saved.Message = copyMessage(in.Message)
		saved.ResultCode = result
		c.earlyDPA = &saved
		return es
	}
	return c.completeDPA(es, in, result)
}

func (c *Core) completeDPA(es []Effect, in Input, result uint32) []Effect {
	c.earlyDPA = nil

	c.disconnectWaiting = false
	es = c.terminate(es, Closed)
	n := Notification{Kind: DisconnectNotice, ResultCode: result, Outcome: Completed}
	e := c.notify(n)
	e.Token = c.disconnectToken
	es = append(es, e)
	if result != diam.Success {
		es = append(es, c.notify(Notification{Protocol: diam.ProtocolPeerRejected, ResultCode: result, Closing: true, Message: metadata(in.Message)}))
	}
	return es
}

func (c *Core) closingAllowed(in Input) bool {
	m := in.Message
	if m == nil || m.Header == nil {
		return false
	}
	h := m.Header
	if h.ApplicationID == 0 {
		switch h.CommandCode {
		case diam.DisconnectPeer:
			return true
		case diam.CapabilitiesExchange, diam.DeviceWatchdog:
			return false
		}
	}
	return h.CommandFlags&diam.RequestFlag == 0 && in.Ownership != 0
}
