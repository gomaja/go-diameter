package protocol

import (
	"errors"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

func (c *Core) receive(es []Effect, in Input) (out []Effect) {
	if c.passiveResponder && in.ErrorInput {
		if in.TransportClosed {
			return c.discard(es, in, "", 0)
		}
		// Nil message reports have no retained external admission. Preserve
		// their framing-failure obligation even while Closing.
		if in.Message == nil && c.phase == Closing {
			return c.fail(es, in, diam.ProtocolMalformedMessage, 0)
		}
	}
	if c.terminal || c.phase == Closing && !c.closingAllowed(in) {
		return c.discard(es, in, "", 0)
	}
	if c.hookToken != 0 || c.phase == Open && !c.ready {
		e := c.effect(Hold)
		saved := in
		e.Input = &saved
		e.Input.Message = copyMessage(in.Message)
		return append(es, e)
	}
	m := in.Message
	if m == nil || m.Header == nil {
		if c.cfg.IgnoreBoundHeaderlessInput {
			if c.phase != PreCER || c.cfg.Role == Initiator || c.candidateToken != 0 {
				return es
			}
			var code uint32
			if in.Error != nil {
				code = in.Error.ResultCode
			}
			return c.fail(es, in, diam.ProtocolHandshakeState, code)
		}
		if c.passiveResponder && c.passivePresent && in.ErrorInput && m != nil {
			return c.externalMessageError(es, in, diam.ProtocolMalformedMessage, in.Error != nil && in.Error.Fatal)
		}
		return c.fail(es, in, diam.ProtocolMalformedMessage, 0)
	}
	isCERRequest := m.Header.CommandCode == diam.CapabilitiesExchange && m.Header.CommandFlags&diam.RequestFlag != 0
	isCER := isCERRequest && m.Header.ApplicationID == 0
	if c.phase == WaitCEA || c.phase == PreCER && c.cfg.Role == Initiator {
		if m.Header.CommandCode == diam.CapabilitiesExchange && m.Header.ApplicationID == 0 && m.Header.CommandFlags&diam.RequestFlag == 0 {
			return c.cea(es, in)
		}
		var code uint32
		if in.Error != nil {
			code = in.Error.ResultCode
		}
		return c.fail(es, in, diam.ProtocolHandshakeState, code)
	}
	// Removing external metadata restores admission gating during Closing too,
	// including decoder-error inputs eligible for that phase.
	preAdmission := c.phase == PreCER || c.phase == Closing && c.passiveResponder && !c.passivePresent
	if preAdmission && (!isCERRequest || c.candidateToken != 0) {
		var code uint32
		if in.Error != nil {
			code = in.Error.ResultCode
		} else if headerErr := base.ValidateHeader(m); headerErr != nil {
			code = headerErr.ResultCode
		}
		return c.fail(es, in, diam.ProtocolHandshakeState, code)
	}
	start := len(es)
	es = c.activity(es, in)
	releaseDispatch := false
	defer func() {
		if releaseDispatch && len(out) > start {
			out[start].ReleaseDispatch = true
		}
	}()
	// RFC 6733 §3: discard duplicate or unowned completed answers before body
	// semantics. Receipt activity receives no health credit; decoder failures
	// retain the separate message-error path below.
	if !in.ErrorInput && c.phase == Open && c.cfg.Role == Initiator && m.Header.CommandCode == diam.CapabilitiesExchange && m.Header.ApplicationID == 0 && m.Header.CommandFlags&diam.RequestFlag == 0 && in.Error == nil {
		es = c.discard(es, in, diam.ProtocolUnexpectedMessage, 0)
		es[len(es)-1].Notification.Diagnostic = "cea-correlation"
		if h := c.completedCEA; h != nil && h.HopByHopID == m.Header.HopByHopID && h.EndToEndID == m.Header.EndToEndID {
			es[len(es)-1].Notification.Diagnostic = "duplicate-cea"
		}
		return es
	}
	originalFatal := in.Error != nil && in.Error.Fatal
	// RFC 6733 §§3, 5.3.1, 7.1.3: reject inconsistent CER flags before
	// applying the Open-state repeated-CER policy.
	headerErr := base.ValidateHeader(m)
	if headerErr != nil && !base.FatalHeaderError(in.Error) {
		// Fatality is independent of which diagnosis wins header precedence.
		headerErr.Fatal = originalFatal
		in.Error = headerErr
	}
	// RFC 6733 §7, §7.1.5: a detected fatal request error retains its
	// required answer. Decodable repeated CERs keep their ordinary disposition.
	fatalCER := in.Error != nil && in.Error.Fatal
	if c.phase == Open && isCER && headerErr == nil && !base.FatalHeaderError(in.Error) && !fatalCER {
		if c.passiveResponder && c.passiveCER && in.Error == nil && !in.ErrorInput {
			return c.discard(es, in, "", 0)
		}
		if in.Error == nil && base.ValidateMessage(m) == nil && base.ValidateRequest(m, c.caps.LocalApplications, c.cfg.ValidateRequests, c.cfg.RejectUnknownMandatoryAVPs) == nil && c.bound(m, true) {
			es = c.validActivity(es)
		}
		if c.cfg.Hooks && in.Error == nil && !in.ErrorInput {
			return c.pauseHook(es, in)
		}
		return c.discard(es, in, diam.ProtocolUnexpectedMessage, 0)
	}
	if in.Error != nil {
		return c.messageError(es, in, originalFatal)
	}
	if in.ErrorInput {
		return c.discard(es, in, diam.ProtocolMalformedMessage, 0)
	}
	if c.phase == Open && c.cfg.Watchdog && m.Header.CommandCode == diam.DeviceWatchdog && m.Header.CommandFlags&diam.RequestFlag == 0 {
		releaseDispatch = true
		return c.dwa(es, in)
	}
	if err := base.ValidateMessage(m); err != nil {
		if m.Header.CommandFlags&diam.RequestFlag == 0 {
			in.Error = err
			es = c.discard(es, in, base.AnswerErrorKind(m), err.ResultCode)
			if c.passiveResponder {
				es[len(es)-1].Notification.Diagnostic = "external-invalid-base"
			}
			return es
		}
		return c.reject(es, in, diam.ProtocolInvalidRequest, err)
	}
	if rejection := base.ValidateRequest(m, c.caps.LocalApplications, c.cfg.ValidateRequests, c.cfg.RejectUnknownMandatoryAVPs); rejection != nil {
		return c.requestError(es, in, rejection)
	}
	if c.phase == PreCER {
		if c.cfg.Hooks {
			return c.pauseHook(es, in)
		}
		return c.candidate(es, in)
	}
	baseDPR := m.Header.ApplicationID == 0 && m.Header.CommandCode == diam.DisconnectPeer && m.Header.CommandFlags&diam.RequestFlag != 0
	releaseDispatch = m.Header.CommandCode != diam.CapabilitiesExchange && !baseDPR
	if m.Header.ApplicationID == 0 {
		switch m.Header.CommandCode {
		case diam.DeviceWatchdog:
			if m.Header.CommandFlags&diam.RequestFlag != 0 {
				if c.cfg.Hooks {
					return c.pauseHook(es, in)
				}
				return c.dwr(es, in)
			}
			if !in.HasHandler {
				return c.discard(es, in, diam.ProtocolUnexpectedMessage, 0)
			}
			e := c.effect(Admit)
			e.Message = m
			return append(es, e)
		case diam.DisconnectPeer:
			if m.Header.CommandFlags&diam.RequestFlag != 0 {
				return c.dpr(es, in)
			}
			return c.dpa(es, in)
		case diam.CapabilitiesExchange:
			if !in.HasHandler {
				return c.discard(es, in, diam.ProtocolUnexpectedMessage, 0)
			}
			e := c.effect(Admit)
			e.Message = m
			return append(es, e)
		}
	}
	if c.cfg.Watchdog && c.wd.State == "REOPEN" {
		return c.discard(es, in, "", 0)
	}
	if in.Unhandled && m.Header.CommandFlags&diam.RequestFlag != 0 {
		if base.SupportsApplication(c.caps.LocalApplications, m.Header.ApplicationID) {
			es = c.validActivity(es)
		}
		return c.unhandled(es, in)
	}
	es = c.validActivity(es)
	if c.cfg.Watchdog && c.wd.State == "REOPEN" {
		return c.discard(es, in, "", 0)
	}
	e := c.effect(Admit)
	e.Message = m
	e.Ownership = in.Ownership
	return append(es, e)
}

func (c *Core) pauseHook(es []Effect, in Input) []Effect {
	token := c.token()
	saved := in
	saved.Message = copyMessage(in.Message)
	c.continuations[token] = continuation{Input: saved, repeatedCER: c.phase == Open && in.Message.Header.CommandCode == diam.CapabilitiesExchange}
	if c.phase == PreCER {
		// A genuine exchange owns admission before its hook; later metadata
		// cannot bypass pending CER validation (RFC 6733 §§5.3, 5.6).
		c.passiveResponder = false
		c.hookToken = token
	}
	e := c.effect(RunHook)
	e.Token = token
	e.Message = copyMessage(in.Message)
	return append(es, e)
}

func (c *Core) dwr(es []Effect, in Input) []Effect {
	var parsed base.DWR
	err := parsed.Parse(in.Message)
	if err == nil && !c.bound(in.Message, false) {
		err = errors.New("DWR Origin-Host does not match the admitted peer (RFC 6733 §6.3)")
	}
	if err != nil {
		return c.discardCause(es, in, diam.ProtocolInvalidDWR, err)
	}
	answer, err := base.BuildDWA(in.Message, c.cfg.Local)
	if err != nil {
		return c.fail(es, in, diam.ProtocolReplyFailure, diam.Success)
	}
	es = c.validActivity(es)
	es = c.send(es, answer, nil, true, false, false, nil, in.Message)
	es[len(es)-1].AnswerHook = true
	return es
}

func (c *Core) discardCause(es []Effect, in Input, kind diam.ProtocolErrorKind, err error) []Effect {
	es = c.discard(es, in, kind, 0)
	es[len(es)-1].Notification.CauseError = copyHandshakeError(err)
	return es
}

func (c *Core) messageError(es []Effect, in Input, originalFatal bool) []Effect {
	m, me := in.Message, in.Error
	kind := diam.ProtocolMalformedMessage
	if base.ValidateHeader(m) != nil && !base.FatalHeaderError(me) {
		kind = diam.ProtocolInvalidHeader
	}
	if c.passiveResponder && in.ErrorInput || c.cfg.ReaderOwnsMessageErrorClosure && (c.phase == Open || c.phase == Closing) {
		return c.externalMessageError(es, in, kind, originalFatal)
	}
	if c.phase == Closing {
		// Closing selects no new reply or termination for message errors.
		// Preserve fatality in the report; the reader and Closing deadline
		// retain responsibility for closing the connection.
		es = c.discard(es, in, kind, me.ResultCode)
		es[len(es)-1].Notification.Closing = originalFatal
		return es
	}
	if m.Header.CommandFlags&diam.RequestFlag == 0 {
		if me.Fatal {
			return c.fail(es, in, kind, me.ResultCode)
		}
		return c.discard(es, in, kind, me.ResultCode)
	}
	if rejection := base.ValidateRequest(m, c.caps.LocalApplications, c.cfg.ValidateRequests, c.cfg.RejectUnknownMandatoryAVPs, me); rejection != nil && !base.IsCommand(m) && !me.Fatal {
		return c.requestError(es, in, rejection)
	}
	return c.reject(es, in, kind, me)
}

// externalMessageError retains the frontend's error-reporting contract for
// externally admitted peers. Closing in a report and closing the transport are
// separate: framing ownership remains with the frontend that supplied the error.
func (c *Core) externalMessageError(es []Effect, in Input, kind diam.ProtocolErrorKind, originalFatal bool) []Effect {
	me := in.Error
	n := Notification{Protocol: kind, Message: metadata(in.Message), Closing: originalFatal, Diagnostic: "external-message-error"}
	if me != nil {
		n.ResultCode, n.CauseError = me.ResultCode, copyHandshakeError(me)
	}
	if c.phase == Closing || in.Message.Header == nil || in.Message.Header.CommandFlags&diam.RequestFlag == 0 {
		return append(es, c.effect(Discard), c.notify(n))
	}
	var failed []*diam.AVP
	if me.FailedAVP != nil {
		failed = []*diam.AVP{me.FailedAVP}
	}
	if rejection := base.ValidateRequest(in.Message, c.caps.LocalApplications, c.cfg.ValidateRequests, c.cfg.RejectUnknownMandatoryAVPs, me); rejection != nil && !base.IsCommand(in.Message) && !me.Fatal {
		n.Protocol, n.ResultCode = rejection.Kind, rejection.Code
		me = &diam.MessageError{ResultCode: rejection.Code, Err: me}
		failed = rejection.Failed
	}
	answer, err := base.BuildErrorAnswer(in.Message, c.cfg.Local, me.ResultCode, failed, me.ResultCode >= 3000 && me.ResultCode < 4000)
	if err != nil {
		es = c.failedRejection(es, in, n.Protocol, me.ResultCode, err)
		failure := &es[len(es)-1].Notification
		failure.CauseError = copyHandshakeError(err)
		failure.Diagnostic = "external-message-error"
		return es
	}
	terminal := in.Message.Header.CommandCode == diam.CapabilitiesExchange && base.ValidateHeader(in.Message) != nil
	if c.cfg.CloseCEROnInvalidHeaderBitsOnly {
		terminal = in.Message.Header.CommandCode == diam.CapabilitiesExchange && me.ResultCode == diam.InvalidHDRBits
	}
	if terminal {
		c.terminal, n.Closing, n.Diagnostic = true, true, "external-reject-cer"
	}
	return c.send(es, answer, nil, true, terminal, false, &n)
}

func (c *Core) requestError(es []Effect, in Input, r *base.RequestError, diagnostic ...string) []Effect {
	if c.phase == Closing {
		return c.discard(es, in, r.Kind, r.Code)
	}
	answer, err := base.BuildErrorAnswer(in.Message, c.cfg.Local, r.Code, r.Failed, r.Code >= 3000 && r.Code < 4000)
	if err != nil {
		es = c.failedRejection(es, in, r.Kind, r.Code, err)
		if len(diagnostic) != 0 {
			es[len(es)-1].Notification.Diagnostic = diagnostic[0]
		}
		return es
	}
	terminal := c.phase == PreCER
	if terminal {
		c.terminal = true
	}
	n := Notification{Protocol: r.Kind, ResultCode: r.Code, Closing: terminal, Message: metadata(in.Message)}
	if len(diagnostic) != 0 {
		n.Diagnostic = diagnostic[0]
	}
	if terminal && in.Message.Header.CommandCode == diam.CapabilitiesExchange {
		n.Diagnostic = "reject-cer"
	}
	return c.send(es, answer, nil, true, terminal, false, &n)
}

func (c *Core) unhandled(es []Effect, in Input) []Effect {
	if c.phase != Open || !c.ready {
		return c.discard(es, in, "", 0)
	}
	if in.Message == nil || in.Message.Header == nil {
		return c.discard(es, in, "", 0)
	}
	if in.Message.Header.CommandFlags&diam.RequestFlag == 0 {
		return c.discard(es, in, diam.ProtocolUnexpectedMessage, 0)
	}
	kind, code := diam.ProtocolUnsupportedCommand, uint32(diam.CommandUnsupported)
	if !base.SupportsApplication(c.caps.LocalApplications, in.Message.Header.ApplicationID) {
		kind, code = diam.ProtocolUnsupportedApplication, diam.ApplicationUnsupported
	}
	return c.requestError(es, in, &base.RequestError{Kind: kind, Code: code}, "unhandled")
}
