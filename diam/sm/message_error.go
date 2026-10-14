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
	if appID == 0 {
		return true
	}
	if c != nil && c.Context() != nil {
		if local, ok := c.Context().Value(advertisedAppsKey{}).([]uint32); ok {
			for _, advertised := range local {
				if advertised == appID || advertised == relayApplicationID {
					return true
				}
			}
			return false
		}
	}

	return false
}

// relayApplicationID is the Relay Application-Id (RFC 6733 §2.4).
const relayApplicationID = 0xffffffff

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
	kind    diam.ProtocolErrorKind
	code    uint32
	closing bool
	reply   diam.ProtocolReplyStatus
}

func (sm *StateMachine) reportMessageError(c diam.Conn, m *diam.Message, outcome messageErrorOutcome) {
	if outcome.kind != "" {
		replyCode := uint32(0)
		if outcome.reply != diam.ProtocolReplyNone {
			replyCode = outcome.code
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
	outcome = messageErrorOutcome{kind: kind, closing: messageErr != nil && messageErr.Fatal}
	if headerErr := base.ValidateHeader(request); headerErr != nil {
		messageErr = headerErr
		outcome.kind = diam.ProtocolInvalidHeader
	}
	if messageErr != nil {
		outcome.code = messageErr.ResultCode
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
	if messageErr.ResultCode == diam.InvalidAVPLength && messageErr.FailedAVP == nil {
		return outcome, fmt.Errorf("diameter result code %d requires Failed-AVP", messageErr.ResultCode)
	}
	protocolError := messageErr.ResultCode >= 3000 && messageErr.ResultCode < 4000
	var failedAVPs []*diam.AVP
	if messageErr.FailedAVP != nil {
		failedAVPs = []*diam.AVP{messageErr.FailedAVP}
	}
	if err := sm.writeErrorAnswer(c, request, messageErr.ResultCode, failedAVPs, protocolError); err != nil {
		// writeErrorAnswer records the failure before this close. Do not return
		// it to Server, which would mistake it for a failure to take ownership.
		c.Close()
		outcome.closing = true
		outcome.reply = diam.ProtocolReplyFailed
		return outcome, nil
	}
	outcome.reply = diam.ProtocolReplyWritten
	if request.Header.CommandCode == diam.CapabilitiesExchange && (base.ValidateHeader(request) != nil || !admittedPeer(c)) {
		// RFC 6733 §§5.3 and 5.6.1: a rejected CER admits no peer, and the
		// transport connection is closed, as handleCER does.
		logMessage(c, request, slog.LevelWarn, "sm: rejected CER; closing connection", messageErr)
		c.Close()
		outcome.closing = true
	}
	return outcome, nil
}

func (sm *StateMachine) writeErrorAnswer(c diam.Conn, request *diam.Message, resultCode uint32, failedAVPs []*diam.AVP, protocolError bool) (err error) {
	defer func() {
		if err != nil {
			logMessage(c, request, slog.LevelError, "sm: error answer failed", err)
		}
	}()
	cfg := baseSettings(sm.cfg)
	cfg.ResolveHostIPAddresses = func() ([]datatype.Address, error) { return getLocalAddresses(c) }
	answer, err := base.BuildErrorAnswer(request, cfg, resultCode, failedAVPs, protocolError)
	if err != nil {
		return err
	}
	if _, err := answer.WriteTo(c); err != nil {
		return fmt.Errorf("write Diameter error answer: %w", err)
	}
	return nil
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
