package protocol

import (
	"errors"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

// beginClosing latches before DPR/DPA effects. Frozen acknowledges the #125
// native write-gate boundary, not queue selection (RFC 6733 §§5.4,5.6).
func (c *Core) beginClosing(in Input, local bool) []Effect {
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
	es := c.stop(WatchdogTimer)
	duration := in.Timeout
	if duration <= 0 {
		duration = c.cfg.ClosingTimeout
	}
	es = append(es, c.arm(ClosingTimer, in.At, duration)...)
	e := c.effect(FreezeAdmission)
	e.Token = c.fenceToken
	return append(es, e)
}
func (c *Core) freeze(in Input) []Effect {
	if c.phase != Closing || c.frozen || in.Token != c.fenceToken {
		return nil
	}
	c.frozen = true
	c.fenceToken = 0
	if c.closeLocal {
		return c.reserve(diam.DisconnectPeer)
	}
	saved := c.closeRequest
	c.closeRequest = Input{}
	saved.InFlight = in.InFlight
	return c.answerDPR(saved, true)
}
func (c *Core) disconnect(in Input) []Effect {
	if c.disconnectWaiting {
		return []Effect{c.notify(Notification{Kind: DisconnectNotice, Outcome: AlreadyPending})}
	}
	// Preserve StateMachine's local API after a received DPR (RFC 6733
	// §§5.4.1,5.6). Neither the original receiver deadline nor admission changes.
	if c.cfg.LocalDisconnectInClosing && c.phase == Closing && c.frozen && !c.closeLocal && in.Cause <= 2 {
		c.disconnectWaiting, c.disconnectToken, c.closeCause = true, in.Token, in.Cause
		es := c.arm(ReceiverDisconnectTimer, in.At, in.Timeout)
		return append(es, c.reserve(diam.DisconnectPeer)...)
	}
	if c.phase != Open || in.Cause > 2 {
		return []Effect{c.notify(Notification{Kind: DisconnectNotice, Outcome: NotOpen})}
	}
	return c.beginClosing(in, true)
}
func (c *Core) bound(m *diam.Message, realm bool) bool {
	var identity base.DWR
	if identity.Parse(m) != nil {
		return false
	}
	return equalIdentity(string(identity.OriginHost), c.caps.Host) && (!realm || equalIdentity(string(identity.OriginRealm), c.caps.Realm))
}
func (c *Core) dpr(in Input) (es []Effect) {
	cause, err := base.ValidateDPR(in.Message)
	if err == nil && !c.bound(in.Message, false) {
		err = errors.New("DPR Origin-Host does not match the admitted peer (RFC 6733 §6.3)")
	}
	if err != nil {
		return c.discardCause(in, diam.ProtocolInvalidDPR, err)
	}
	in.Cause = cause
	defer func() {
		if len(es) != 0 {
			es[0].ReleaseDispatch = true
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
		es = append(es, c.validActivity()...)
		return append(es, c.beginClosing(in, false)...)
	}
	if !c.frozen {
		return append(es, c.discard(in, "", 0)...)
	}
	return append(es, c.answerDPR(in, !c.peerDisconnectSelected)...)
}
func (c *Core) answerDPR(in Input, first bool) []Effect {
	result := uint32(diam.Success)
	if in.InFlight {
		result = diam.UnableToComply
	}
	answer, err := base.BuildDPAResult(in.Message, c.cfg.Local, result)
	if err != nil {
		return c.fail(in, diam.ProtocolReplyFailure, result)
	}
	var notice *Notification
	if first {
		c.peerDisconnectSelected = true
		notice = &Notification{Kind: PeerDisconnectNotice, Cause: c.peerCause, ReplyCode: result, Message: metadata(in.Message)}
	}
	return c.send(answer, nil, true, false, false, notice, in.Message)
}
func (c *Core) dpa(in Input) []Effect {
	r := c.controls[diam.DisconnectPeer]
	if !c.matches(r, in.Message) {
		es := c.discard(in, diam.ProtocolUnexpectedMessage, 0)
		if r != nil && r.logical {
			es[len(es)-1].Notification.Diagnostic = "dpa-correlation"
		}
		return es
	}
	result, err := base.ValidateDPA(in.Message)
	if err != nil {
		return c.discardCause(in, diam.ProtocolInvalidDPA, err)
	}
	if !c.bound(in.Message, false) {
		es := c.discard(in, diam.ProtocolUnexpectedMessage, 0)
		es[len(es)-1].Notification.Diagnostic = "dpa-host"
		return es
	}
	es := c.settle(r)
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
	return append(es, c.completeDPA(in, result)...)
}

func (c *Core) completeDPA(in Input, result uint32) []Effect {
	c.earlyDPA = nil
	var es []Effect
	c.disconnectWaiting = false
	es = append(es, c.terminate(Closed)...)
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
