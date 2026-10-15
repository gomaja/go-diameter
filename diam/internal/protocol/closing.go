package protocol

import (
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
func (c *Core) dpr(in Input) []Effect {
	cause, err := base.ValidateDPR(in.Message)
	if err != nil || !c.bound(in.Message, false) {
		return c.discard(in, diam.ProtocolInvalidDPR, 0)
	}
	in.Cause = cause
	var es []Effect
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
		return c.discard(in, diam.ProtocolInvalidDPA, 0)
	}
	result, err := base.ValidateDPA(in.Message)
	if err != nil || !c.bound(in.Message, false) {
		return c.discard(in, diam.ProtocolInvalidDPA, 0)
	}
	es := c.settle(r)
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
