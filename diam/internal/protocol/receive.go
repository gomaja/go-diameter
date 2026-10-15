package protocol

import (
	"errors"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

func (c *Core) receive(in Input) (es []Effect) {
	if c.terminal || c.phase == Closing && !c.closingAllowed(in) {
		return c.discard(in, "", 0)
	}
	if c.hookToken != 0 || c.phase == Open && !c.ready {
		e := c.effect(Hold)
		e.Input = in
		e.Input.Message = copyMessage(in.Message)
		return []Effect{e}
	}
	m := in.Message
	if m == nil || m.Header == nil {
		return c.fail(in, diam.ProtocolMalformedMessage, 0)
	}
	isCERRequest := m.Header.CommandCode == diam.CapabilitiesExchange && m.Header.CommandFlags&diam.RequestFlag != 0
	isCER := isCERRequest && m.Header.ApplicationID == 0
	if c.phase == WaitCEA || c.phase == PreCER && c.cfg.Role == Initiator {
		if m.Header.CommandCode == diam.CapabilitiesExchange && m.Header.ApplicationID == 0 && m.Header.CommandFlags&diam.RequestFlag == 0 {
			return c.cea(in)
		}
		return c.fail(in, diam.ProtocolHandshakeState, 0)
	}
	if c.phase == PreCER && (!isCERRequest || c.candidateToken != 0) {
		var code uint32
		if in.Error != nil {
			code = in.Error.ResultCode
		} else if headerErr := base.ValidateHeader(m); headerErr != nil {
			code = headerErr.ResultCode
		}
		return c.fail(in, diam.ProtocolHandshakeState, code)
	}
	activity := c.activity(in)
	releaseDispatch := false
	defer func() {
		es = append(activity, es...)
		if releaseDispatch && len(es) != 0 {
			es[0].ReleaseDispatch = true
		}
	}()
	// #108: repeated CER disposition precedes optional body revalidation.
	if c.phase == Open && isCER && !base.FatalHeaderError(in.Error) {
		if in.Error == nil && base.ValidateMessage(m) == nil && base.ValidateRequest(m, c.caps.LocalApplications, c.cfg.ValidateRequests, c.cfg.RejectUnknownMandatoryAVPs) == nil && c.bound(m, true) {
			activity = append(activity, c.validActivity()...)
		}
		if c.cfg.Hooks && in.Error == nil {
			return c.pauseHook(in)
		}
		return c.discard(in, diam.ProtocolUnexpectedMessage, 0)
	}
	if err := base.ValidateHeader(m); err != nil && !base.FatalHeaderError(in.Error) {
		in.Error = err
	}
	if in.Error != nil {
		return c.messageError(in)
	}
	if c.phase == Open && c.cfg.Watchdog && m.Header.CommandCode == diam.DeviceWatchdog && m.Header.CommandFlags&diam.RequestFlag == 0 {
		releaseDispatch = true
		return c.dwa(in)
	}
	if err := base.ValidateMessage(m); err != nil {
		if m.Header.CommandFlags&diam.RequestFlag == 0 {
			in.Error = err
			return c.discard(in, base.AnswerErrorKind(m), err.ResultCode)
		}
		return c.reject(in, diam.ProtocolInvalidRequest, err)
	}
	if rejection := base.ValidateRequest(m, c.caps.LocalApplications, c.cfg.ValidateRequests, c.cfg.RejectUnknownMandatoryAVPs); rejection != nil {
		return c.requestError(in, rejection)
	}
	if c.phase == PreCER {
		if c.cfg.Hooks {
			return c.pauseHook(in)
		}
		return c.candidate(in)
	}
	baseDPR := m.Header.ApplicationID == 0 && m.Header.CommandCode == diam.DisconnectPeer && m.Header.CommandFlags&diam.RequestFlag != 0
	releaseDispatch = m.Header.CommandCode != diam.CapabilitiesExchange && !baseDPR
	if m.Header.ApplicationID == 0 {
		switch m.Header.CommandCode {
		case diam.DeviceWatchdog:
			if m.Header.CommandFlags&diam.RequestFlag != 0 {
				if c.cfg.Hooks {
					return c.pauseHook(in)
				}
				return c.dwr(in)
			}
			if !in.HasHandler {
				return c.discard(in, diam.ProtocolUnexpectedMessage, 0)
			}
			e := c.effect(Admit)
			e.Message = m
			return []Effect{e}
		case diam.DisconnectPeer:
			if m.Header.CommandFlags&diam.RequestFlag != 0 {
				return c.dpr(in)
			}
			return c.dpa(in)
		case diam.CapabilitiesExchange:
			if !in.HasHandler {
				return c.discard(in, diam.ProtocolUnexpectedMessage, 0)
			}
			e := c.effect(Admit)
			e.Message = m
			return []Effect{e}
		}
	}
	if in.Unhandled && m.Header.CommandFlags&diam.RequestFlag != 0 {
		if base.SupportsApplication(c.caps.LocalApplications, m.Header.ApplicationID) {
			activity = append(activity, c.validActivity()...)
		}
		return c.unhandled(in)
	}
	activity = append(activity, c.validActivity()...)
	if c.cfg.Watchdog && c.wd.State == "REOPEN" {
		return c.discard(in, "", 0)
	}
	e := c.effect(Admit)
	e.Message = m
	e.Ownership = in.Ownership
	return []Effect{e}
}
func (c *Core) pauseHook(in Input) []Effect {
	token := c.token()
	saved := in
	saved.Message = copyMessage(in.Message)
	c.continuations[token] = saved
	if c.phase == PreCER {
		c.hookToken = token
	}
	e := c.effect(RunHook)
	e.Token = token
	e.Message = copyMessage(in.Message)
	return []Effect{e}
}
func (c *Core) dwr(in Input) []Effect {
	var parsed base.DWR
	err := parsed.Parse(in.Message)
	if err == nil && !c.bound(in.Message, false) {
		err = errors.New("DWR Origin-Host does not match the admitted peer (RFC 6733 §6.3)")
	}
	if err != nil {
		return c.discardCause(in, diam.ProtocolInvalidDWR, err)
	}
	answer, err := base.BuildDWA(in.Message, c.cfg.Local)
	if err != nil {
		return c.fail(in, diam.ProtocolReplyFailure, diam.Success)
	}
	reply := c.send(answer, nil, true, false, false, nil, in.Message)
	reply[0].AnswerHook = true
	return append(c.validActivity(), reply...)
}

func (c *Core) discardCause(in Input, kind diam.ProtocolErrorKind, err error) []Effect {
	es := c.discard(in, kind, 0)
	es[len(es)-1].Notification.CauseError = copyHandshakeError(err)
	return es
}
func (c *Core) messageError(in Input) []Effect {
	m, me := in.Message, in.Error
	kind := diam.ProtocolMalformedMessage
	if base.ValidateHeader(m) != nil && !base.FatalHeaderError(me) {
		kind = diam.ProtocolInvalidHeader
	}
	if c.phase == Closing {
		return c.discard(in, kind, me.ResultCode)
	}
	if m.Header.CommandFlags&diam.RequestFlag == 0 {
		if me.Fatal {
			return c.fail(in, kind, me.ResultCode)
		}
		return c.discard(in, kind, me.ResultCode)
	}
	if rejection := base.ValidateRequest(m, c.caps.LocalApplications, c.cfg.ValidateRequests, c.cfg.RejectUnknownMandatoryAVPs, me); rejection != nil && !base.IsCommand(m) && !me.Fatal {
		return c.requestError(in, rejection)
	}
	return c.reject(in, kind, me)
}
func (c *Core) requestError(in Input, r *base.RequestError) []Effect {
	answer, err := base.BuildErrorAnswer(in.Message, c.cfg.Local, r.Code, r.Failed, r.Code >= 3000 && r.Code < 4000)
	if err != nil {
		return c.failedRejection(in, r.Kind, r.Code)
	}
	if c.phase == Closing {
		return c.discard(in, r.Kind, r.Code)
	}
	terminal := c.phase == PreCER
	if terminal {
		c.terminal = true
	}
	n := Notification{Protocol: r.Kind, ResultCode: r.Code, Closing: terminal, Message: metadata(in.Message)}
	if terminal && in.Message.Header.CommandCode == diam.CapabilitiesExchange {
		n.Diagnostic = "reject-cer"
	}
	return c.send(answer, nil, true, terminal, false, &n)
}
func (c *Core) unhandled(in Input) []Effect {
	if c.phase != Open || !c.ready {
		return c.discard(in, "", 0)
	}
	if in.Message == nil || in.Message.Header == nil {
		return c.discard(in, "", 0)
	}
	if in.Message.Header.CommandFlags&diam.RequestFlag == 0 {
		return c.discard(in, diam.ProtocolUnexpectedMessage, 0)
	}
	kind, code := diam.ProtocolUnsupportedCommand, uint32(diam.CommandUnsupported)
	if !base.SupportsApplication(c.caps.LocalApplications, in.Message.Header.ApplicationID) {
		kind, code = diam.ProtocolUnsupportedApplication, diam.ApplicationUnsupported
	}
	return c.requestError(in, &base.RequestError{Kind: kind, Code: code})
}
