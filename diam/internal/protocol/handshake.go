package protocol

import (
	"errors"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/watchdog"
)

// ErrUnexpectedPeer identifies configured-host rejection after CEA parsing.
var ErrUnexpectedPeer = errors.New("protocol: unexpected peer identity")

func (c *Core) candidate(es []Effect, in Input) []Effect {
	// A genuine CER owns all later admission decisions (RFC 6733 §§5.3, 5.6).
	c.passiveResponder = false
	var parsed base.CER
	_, err := parsed.Parse(in.Message, base.ParseOptions{Role: base.Server, TLS: c.cfg.TLS, Dictionary: c.cfg.Dictionary, LocalApplications: c.caps.LocalApplications})
	if err != nil {
		return c.rejectCER(es, in, err)
	}
	if c.cfg.ExpectedHost != "" && !equalIdentity(c.cfg.ExpectedHost, string(parsed.OriginHost)) {
		return c.rejectCER(es, in, errors.New("unexpected remote host"))
	}
	c.caps.CER = copyCER(&parsed)
	c.caps.ParsedApplications = parsed.Applications()
	c.negotiate(string(parsed.OriginHost), string(parsed.OriginRealm), base.AdvertisedApplicationIDs(base.Settings{AuthApplicationID: parsed.AuthApplicationID, AcctApplicationID: parsed.AcctApplicationID, VendorSpecificApplicationID: parsed.VendorSpecificApplicationID}))
	c.candidateToken = c.token()
	c.cer = copyMessage(in.Message)
	e := c.effect(ValidatedCER)
	e.Token = c.candidateToken
	snapshot := c.Snapshot()
	e.Snapshot = &snapshot
	if c.cfg.CandidateDeadlineOwnedByPeer {
		return append(c.stop(es, HandshakeTimer), e)
	}
	return append(es, e)
}
func (c *Core) activate(es []Effect, in Input) []Effect {
	if c.phase != PreCER || c.candidateToken == 0 || in.Token != c.candidateToken {
		return es
	}
	c.candidateToken = 0
	if in.Recovery {
		c.wd.State = watchdog.Down
	}
	c.phase = Open
	c.handshakePending = true
	c.admission = c.token()
	es = c.stop(es, HandshakeTimer)
	e := c.effect(Publish)
	e.Token = c.admission
	snapshot := c.Snapshot()
	e.Snapshot = &snapshot
	es = append(es, e)
	answer, err := base.BuildCEA(c.cer, c.cfg.Local, diam.Success)
	if err != nil {
		in.Message = c.cer
		in.Err = err
		return c.fail(es, in, diam.ProtocolReplyFailure, diam.Success)
	}
	return c.send(es, answer, nil, true, false, true, nil, c.cer)
}
func (c *Core) handshakeReady() Effect {
	c.callbackReady = true
	e := c.effect(HandshakeReady)
	e.Token = c.admission
	snapshot := c.Snapshot()
	e.Snapshot = &snapshot
	return e
}
func (c *Core) cea(es []Effect, in Input) []Effect {
	r := c.controls[diam.CapabilitiesExchange]
	// RFC 6733 §3: an uncorrelated body report cannot reject a pending CER.
	// Framing failure still terminates independently of exchange ownership.
	fatal := base.FatalHeaderError(in.Error)
	if !fatal && !c.matches(r, in.Message) {
		// Discarding the answer does not make a fatal decoder report recoverable.
		// The selected closure owner still ends the connection.
		fatalInput := in.Error != nil && in.Error.Fatal
		if fatalInput && !c.cfg.ReaderOwnsMessageErrorClosure {
			return c.fail(es, in, diam.ProtocolUnexpectedMessage, 0)
		}
		es = c.discard(es, in, diam.ProtocolUnexpectedMessage, 0)
		es[len(es)-1].Notification.Closing = fatalInput
		return es
	}
	if in.Error != nil {
		c.handshake = newHandshakeResult(in.Error, nil)
		return c.fail(es, in, diam.ProtocolCEARejected, in.Error.ResultCode)
	}
	if err := base.ValidateMessage(in.Message); err != nil {
		c.handshake = newHandshakeResult(err, nil)
		kind := base.AnswerErrorKind(in.Message)
		if base.ValidateHeader(in.Message) != nil {
			kind = diam.ProtocolInvalidHeader
		}
		return c.fail(es, in, kind, err.ResultCode)
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
		return c.fail(es, in, diam.ProtocolCEARejected, code)
	}
	if c.cfg.ExpectedHost != "" && !equalIdentity(c.cfg.ExpectedHost, string(parsed.OriginHost)) {
		c.handshake = newHandshakeResult(ErrUnexpectedPeer, &parsed)
		return c.fail(es, in, diam.ProtocolCEARejected, 0)
	}
	es = append(es, c.consumed(in.Message))
	es = c.settle(es, r)
	es = c.stop(es, HandshakeTimer)
	es = c.stop(es, RetryTimer)
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
	snapshot := c.Snapshot()
	e.Snapshot = &snapshot
	return append(es, e, c.handshakeReady())
}
func (c *Core) rejectCER(es []Effect, in Input, err error) []Effect {
	code := uint32(diam.UnableToComply)
	if errors.Is(err, base.ErrNoCommonApplication) {
		code = diam.NoCommonApplication
	}
	if errors.Is(err, base.ErrNoCommonSecurity) {
		code = diam.NoCommonSecurity
	}
	var me *diam.MessageError
	if errors.As(err, &me) {
		return c.reject(es, in, diam.ProtocolCERRejected, me)
	}
	answer, buildErr := base.BuildCEA(in.Message, c.cfg.Local, code)
	if buildErr != nil {
		return c.failedRejection(es, in, diam.ProtocolCERRejected, code, buildErr)
	}
	c.terminal = true
	n := Notification{Protocol: diam.ProtocolCERRejected, ResultCode: code, ReplyCode: code, Closing: true, Message: metadata(in.Message), CauseError: copyHandshakeError(err)}
	return c.send(es, answer, nil, true, true, false, &n)
}
