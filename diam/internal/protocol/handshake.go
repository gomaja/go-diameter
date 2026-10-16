package protocol

import (
	"errors"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

// ErrUnexpectedPeer identifies configured-host rejection after CEA parsing.
var ErrUnexpectedPeer = errors.New("protocol: unexpected peer identity")

func (c *Core) candidate(in Input) []Effect {
	// A genuine CER owns all later admission decisions (RFC 6733 §§5.3, 5.6).
	c.passiveResponder = false
	var parsed base.CER
	_, err := parsed.Parse(in.Message, base.ParseOptions{Role: base.Server, TLS: c.cfg.TLS, Dictionary: c.cfg.Dictionary, LocalApplications: c.caps.LocalApplications})
	if err != nil {
		return c.rejectCER(in, err)
	}
	if c.cfg.ExpectedHost != "" && !equalIdentity(c.cfg.ExpectedHost, string(parsed.OriginHost)) {
		return c.rejectCER(in, errors.New("unexpected remote host"))
	}
	c.caps.CER = copyCER(&parsed)
	c.caps.ParsedApplications = parsed.Applications()
	c.negotiate(string(parsed.OriginHost), string(parsed.OriginRealm), base.AdvertisedApplicationIDs(base.Settings{AuthApplicationID: parsed.AuthApplicationID, AcctApplicationID: parsed.AcctApplicationID, VendorSpecificApplicationID: parsed.VendorSpecificApplicationID}))
	c.candidateToken = c.token()
	c.cer = copyMessage(in.Message)
	e := c.effect(ValidatedCER)
	e.Token = c.candidateToken
	e.Snapshot = c.Snapshot()
	return []Effect{e}
}
func (c *Core) activate(in Input) []Effect {
	if c.phase != PreCER || c.candidateToken == 0 || in.Token != c.candidateToken {
		return nil
	}
	c.candidateToken = 0
	c.phase = Open
	c.handshakePending = true
	c.admission = c.token()
	es := c.stop(HandshakeTimer)
	e := c.effect(Publish)
	e.Token = c.admission
	e.Snapshot = c.Snapshot()
	es = append(es, e)
	answer, err := base.BuildCEA(c.cer, c.cfg.Local, diam.Success)
	if err != nil {
		in.Message = c.cer
		return append(es, c.fail(in, diam.ProtocolReplyFailure, diam.Success)...)
	}
	return append(es, c.send(answer, nil, true, false, true, nil, c.cer)...)
}
func (c *Core) handshakeReady() Effect {
	c.callbackReady = true
	e := c.effect(HandshakeReady)
	e.Token = c.admission
	e.Snapshot = c.Snapshot()
	return e
}
func (c *Core) cea(in Input) []Effect {
	r := c.controls[diam.CapabilitiesExchange]
	if !base.FatalHeaderError(in.Error) && !c.matches(r, in.Message) {
		return c.discard(in, diam.ProtocolUnexpectedMessage, 0)
	}
	if in.Error != nil {
		c.handshake = newHandshakeResult(in.Error, nil)
		return c.fail(in, diam.ProtocolCEARejected, in.Error.ResultCode)
	}
	if err := base.ValidateMessage(in.Message); err != nil {
		c.handshake = newHandshakeResult(err, nil)
		kind := base.AnswerErrorKind(in.Message)
		if base.ValidateHeader(in.Message) != nil {
			kind = diam.ProtocolInvalidHeader
		}
		return c.fail(in, kind, err.ResultCode)
	}
	var parsed base.CEA
	err := parsed.Parse(in.Message, base.ParseOptions{Role: base.Client, Dictionary: c.cfg.Dictionary, LocalApplications: c.caps.LocalApplications})
	c.handshake = newHandshakeResult(err, &parsed)
	if err != nil {
		var code uint32
		var failed *base.ErrFailedResultCode
		var malformed *diam.MessageError
		if errors.As(err, &failed) {
			code = failed.ResultCode
		} else if errors.As(err, &malformed) {
			code = malformed.ResultCode
		}
		return c.fail(in, diam.ProtocolCEARejected, code)
	}
	if c.cfg.ExpectedHost != "" && !equalIdentity(c.cfg.ExpectedHost, string(parsed.OriginHost)) {
		c.handshake = newHandshakeResult(ErrUnexpectedPeer, &parsed)
		return c.fail(in, diam.ProtocolCEARejected, 0)
	}
	es := []Effect{c.consumed(in.Message)}
	es = append(es, c.settle(r)...)
	es = append(es, c.stop(HandshakeTimer)...)
	es = append(es, c.stop(RetryTimer)...)
	c.caps.CEA = copyCEA(&parsed)
	header := *in.Message.Header
	c.completedCEA = &header
	c.caps.ParsedApplications = parsed.Applications()
	c.negotiate(string(parsed.OriginHost), string(parsed.OriginRealm), base.AdvertisedApplicationIDs(base.Settings{AuthApplicationID: parsed.AuthApplicationID, AcctApplicationID: parsed.AcctApplicationID, VendorSpecificApplicationID: parsed.VendorSpecificApplicationID}))
	c.phase = Open
	c.handshakePending = true
	c.admission = c.token()
	e := c.effect(Publish)
	e.Token = c.admission
	e.Snapshot = c.Snapshot()
	return append(es, e, c.handshakeReady())
}
func (c *Core) rejectCER(in Input, err error) []Effect {
	code := uint32(diam.UnableToComply)
	if errors.Is(err, base.ErrNoCommonApplication) {
		code = diam.NoCommonApplication
	}
	if errors.Is(err, base.ErrNoCommonSecurity) {
		code = diam.NoCommonSecurity
	}
	var me *diam.MessageError
	if errors.As(err, &me) {
		return c.reject(in, diam.ProtocolCERRejected, me)
	}
	answer, buildErr := base.BuildCEA(in.Message, c.cfg.Local, code)
	if buildErr != nil {
		return c.failedRejection(in, diam.ProtocolCERRejected, code)
	}
	c.terminal = true
	n := Notification{Protocol: diam.ProtocolCERRejected, ResultCode: code, ReplyCode: code, Closing: true, Message: metadata(in.Message), CauseError: copyHandshakeError(err)}
	return c.send(answer, nil, true, true, false, &n)
}
