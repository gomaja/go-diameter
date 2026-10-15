// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"fmt"
	"log/slog"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// handleUnsupportedCommand handles messages with no registered route.
func (sm *StateMachine) handleUnsupportedCommand(c diam.Conn, request *diam.Message) {
	// RFC 6733 §§7.1.3, 7.2: answer requests with 3001/3007 and E;
	// answers never receive another answer.
	if request.Header.CommandFlags&diam.RequestFlag == 0 {
		logMessage(c, request, slog.LevelWarn, "sm: unhandled answer discarded", nil)
		sm.protocolError(c, request, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
		return
	}
	resultCode := uint32(diam.CommandUnsupported)
	if !sm.supportsApplicationOn(c, request.Header.ApplicationID) {
		resultCode = diam.ApplicationUnsupported
	}
	kind := diam.ProtocolUnsupportedCommand
	if resultCode == diam.ApplicationUnsupported {
		kind = diam.ProtocolUnsupportedApplication
	}
	outcome, err := sm.handleMessageError(c, request, &diam.MessageError{ResultCode: resultCode}, kind)
	if outcome.reply == diam.ProtocolReplyWritten {
		c.Logger().LogAttrs(request.Context(), slog.LevelInfo, "sm: unsupported command answered", slog.Any("message", request), slog.Uint64("result_code", uint64(resultCode)))
	}
	if err == nil {
		sm.reportMessageError(c, request, outcome)
	}
}

type advertisedAppsKey struct{}

// supportsApplicationOn uses the local CER or CEA offer saved at admission.
// The snapshot follows this connection's advertised capabilities throughout its
// lifetime, including overrides (RFC 6733 §§5.3, 5.6).
func (sm *StateMachine) supportsApplicationOn(c diam.Conn, appID uint32) bool {
	return base.SupportsApplication(sm.applicationsOn(c, nil), appID)
}

func (sm *StateMachine) applicationsOn(c diam.Conn, m *diam.Message) []uint32 {
	if c != nil && c.Context() != nil {
		if local, ok := c.Context().Value(advertisedAppsKey{}).([]uint32); ok {
			return local
		}
	}
	if m != nil && m.Header.CommandCode == diam.CapabilitiesExchange {
		return base.AdvertisedApplicationIDs(sm.capabilities(c, m))
	}
	return nil
}

func (sm *StateMachine) rejectRequest(c diam.Conn, m *diam.Message, rejection *base.RequestError) {
	release := m.BeginDispatch()
	defer release()
	switch rejection.Kind {
	case diam.ProtocolUnsupportedAVP:
		logMessage(c, m, slog.LevelWarn, "sm: unsupported mandatory AVP", diam.NewProtocolError(rejection.Kind, rejection.Code))
	case diam.ProtocolInvalidRequest:
		logMessage(c, m, slog.LevelWarn, "sm: invalid request", diam.NewProtocolError(rejection.Kind, rejection.Code))
	}
	if sm.isClosing(c) {
		release()
		sm.protocolError(c, m, rejection.Kind, rejection.Code, false, diam.ProtocolReplyNone, 0)
		return
	}
	replyCode, err := sm.writeErrorAnswer(c, m, rejection.Code, rejection.Failed, rejection.Code >= 3000 && rejection.Code < 4000)
	if err == nil && rejection.Kind == diam.ProtocolUnsupportedApplication {
		c.Logger().LogAttrs(m.Context(), slog.LevelInfo, "sm: unsupported command answered", slog.Any("message", m), slog.Uint64("result_code", uint64(rejection.Code)))
	}
	closing := sm.closeRejectedCER(c, m, diam.NewProtocolError(rejection.Kind, rejection.Code))
	if err != nil {
		sm.closeRequiredReply(c)
		closing = true
	}
	// The rejection is committed before the observer, which may block or
	// retire this generation (RFC 6733 §§5.5.4, 5.6).
	release()
	sm.protocolError(c, m, rejection.Kind, rejection.Code, closing, protocolReply(err), replyCode)
}

func (sm *StateMachine) rejectBaseMessage(c diam.Conn, m *diam.Message, err *diam.MessageError) {
	if m.Header.CommandFlags&diam.RequestFlag == 0 {
		logMessage(c, m, slog.LevelWarn, "sm: invalid base message", err)
		release := m.BeginDispatch()
		release()
		sm.protocolError(c, m, base.AnswerErrorKind(m), err.ResultCode, false, diam.ProtocolReplyNone, 0)
		return
	}
	rejection := &base.RequestError{Kind: diam.ProtocolInvalidRequest, Code: err.ResultCode}
	if err.FailedAVP != nil {
		rejection.Failed = []*diam.AVP{err.FailedAVP}
	}
	sm.rejectRequest(c, m, rejection)
}

// HandleMessageError implements diam.MessageErrorHandler. RFC 6733 §§7.1-7.2
// reserve E for protocol errors; answers never receive answers. A local answer
// failure is logged here and closes the connection; returning nil means the
// state machine took responsibility. Invalid error descriptions are returned.
func (sm *StateMachine) HandleMessageError(c diam.Conn, request *diam.Message, messageErr *diam.MessageError) error {
	outcome, err := sm.handleMessageError(c, request, messageErr, diam.ProtocolMalformedMessage)
	if err == nil {
		sm.reportMessageError(c, request, outcome)
	}
	return err
}

type messageErrorOutcome struct {
	kind      diam.ProtocolErrorKind
	code      uint32
	closing   bool
	reply     diam.ProtocolReplyStatus
	replyCode uint32
}

func (sm *StateMachine) reportMessageError(c diam.Conn, m *diam.Message, outcome messageErrorOutcome) {
	if outcome.kind != "" {
		replyCode := uint32(0)
		if outcome.reply != diam.ProtocolReplyNone {
			replyCode = outcome.replyCode
		}
		sm.protocolError(c, m, outcome.kind, outcome.code, outcome.closing, outcome.reply, replyCode)
	}
}

// handleMessageError returns the owned decision without notifying, so the
// unsupported-command path can finish its existing post-write log first.
func (sm *StateMachine) handleMessageError(c diam.Conn, request *diam.Message, messageErr *diam.MessageError, kind diam.ProtocolErrorKind) (outcome messageErrorOutcome, err error) {
	release := request.BeginDispatch()
	defer release()
	if c.Closed() {
		return outcome, nil
	}
	if !sm.closingAllowed(c, request) {
		return outcome, nil
	}
	if (messageErr == nil || !messageErr.Fatal) && request != nil && request.Header != nil && request.Header.ApplicationID == 0 && request.Header.CommandCode == diam.CapabilitiesExchange && request.Header.CommandFlags&diam.RequestFlag != 0 && admittedPeer(c) {
		handleCER(sm)(c, request)
		return outcome, nil
	}
	outcome = messageErrorOutcome{kind: kind, closing: messageErr != nil && messageErr.Fatal}
	if headerErr := base.ValidateHeader(request); headerErr != nil && !base.FatalHeaderError(messageErr) {
		messageErr = headerErr
		outcome.kind = diam.ProtocolInvalidHeader
	}
	if messageErr != nil {
		outcome.code = messageErr.ResultCode
	}
	if sm.isClosing(c) {
		// An eligible but malformed disconnect retains its diagnostics;
		// only a valid DPR receives a DPA while Closing (RFC 6733 §5.6).
		outcome.closing = false
		return outcome, nil
	}
	if !sm.preCERMessageAllowed(c, request) {
		logMessage(c, request, slog.LevelWarn, "sm: message before CER; closing connection", messageErr)
		c.Close()
		outcome.kind = diam.ProtocolHandshakeState
		outcome.closing = true
		return outcome, nil
	}
	if request == nil || request.Header == nil || request.Header.CommandFlags&diam.RequestFlag == 0 {
		return outcome, nil
	}
	if messageErr == nil {
		return outcome, fmt.Errorf("cannot answer a nil Diameter message error")
	}
	var requestRejection *base.RequestError
	if kind == diam.ProtocolMalformedMessage && !messageErr.Fatal && !base.IsCommand(request) {
		requestRejection = base.ValidateRequest(request, sm.applicationsOn(c, request), sm.cfg.ValidateRequests, sm.cfg.RejectUnknownMandatoryAVPs, messageErr)
		if requestRejection != nil {
			outcome.kind, outcome.code = requestRejection.Kind, requestRejection.Code
			messageErr = &diam.MessageError{ResultCode: requestRejection.Code, FailedAVP: messageErr.FailedAVP, Err: messageErr}
		}
	}
	if messageErr.ResultCode == diam.InvalidAVPLength && messageErr.FailedAVP == nil {
		return outcome, fmt.Errorf("diameter result code %d requires Failed-AVP", messageErr.ResultCode)
	}
	protocolError := messageErr.ResultCode >= 3000 && messageErr.ResultCode < 4000
	var failedAVPs []*diam.AVP
	if messageErr.FailedAVP != nil {
		failedAVPs = []*diam.AVP{messageErr.FailedAVP}
	}
	if requestRejection != nil {
		failedAVPs = requestRejection.Failed
	}
	replyCode, err := sm.writeErrorAnswer(c, request, messageErr.ResultCode, failedAVPs, protocolError)
	outcome.replyCode = replyCode
	if err != nil {
		// writeErrorAnswer records the failure before this close. Do not return
		// it to Server, which would mistake it for a failure to take ownership.
		sm.closeRequiredReply(c)
		outcome.closing = true
		outcome.reply = diam.ProtocolReplyFailed
		return outcome, nil
	}
	outcome.reply = diam.ProtocolReplyWritten
	if sm.closeRejectedCER(c, request, messageErr) {
		outcome.closing = true
	}
	return outcome, nil
}

// closeRejectedCER shares the post-answer rejection policy with request
// validation. RFC 6733 §§5.3, 5.6.1: a rejected initial CER admits no peer.
// An admitted connection keeps its existing validation policy.
func (sm *StateMachine) closeRejectedCER(c diam.Conn, request *diam.Message, messageErr error) bool {
	if request.Header.CommandCode == diam.CapabilitiesExchange && (base.ValidateHeader(request) != nil || !admittedPeer(c)) {
		logMessage(c, request, slog.LevelWarn, "sm: rejected CER; closing connection", messageErr)
		sm.closeRequiredReply(c)
		return true
	}
	return false
}

func (sm *StateMachine) writeErrorAnswer(c diam.Conn, request *diam.Message, resultCode uint32, failedAVPs []*diam.AVP, protocolError bool) (replyCode uint32, err error) {
	replyCode = resultCode
	defer func() {
		if err != nil {
			logMessage(c, request, slog.LevelError, "sm: error answer failed", err)
		}
	}()
	cfg := baseSettings(sm.cfg)
	cfg.ResolveHostIPAddresses = func() ([]datatype.Address, error) { return getLocalAddresses(c) }
	answer, err := base.BuildErrorAnswer(request, cfg, resultCode, failedAVPs, protocolError)
	if err != nil {
		return replyCode, err
	}
	if request.Header.CommandCode == diam.CapabilitiesExchange && sm.cfg.OnCEA != nil {
		sm.cfg.OnCEA(c, answer)
	}
	if sm.cfg.OnProtocolError != nil {
		replyCode = protocolAnswerCode(answer)
	}
	if err := writeRequiredReply(c, answer); err != nil {
		return replyCode, fmt.Errorf("write Diameter error answer: %w", err)
	}
	return replyCode, nil
}

// admittedPeer reports whether a successful CER/CEA stored peer metadata on c.
func admittedPeer(c diam.Conn) bool {
	ctx := c.Context()
	if ctx == nil {
		return false
	}
	_, ok := smpeer.FromContext(ctx)
	return ok
}
