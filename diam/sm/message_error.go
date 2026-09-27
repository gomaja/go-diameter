// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"fmt"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
)

// handleUnsupportedCommand is the default ALL handler. A caller's ALL
// registration replaces it, preserving ServeMux dispatch precedence.
func (sm *StateMachine) handleUnsupportedCommand(c diam.Conn, request *diam.Message) {
	isRequest := request.Header.CommandFlags&diam.RequestFlag != 0
	// RFC 6733 §§7.1.3 and 7.2: 3001 is a protocol error on a request;
	// an answer must never cause another answer.
	if isRequest {
		if err := sm.HandleMessageError(c, request, &diam.MessageError{ResultCode: diam.CommandUnsupported}); err != nil {
			sm.Error(&diam.ErrorReport{Conn: c, Message: request, Error: err})
		}
	}
	// Report every unhandled message, as ServeMux did before this fallback
	// existed, so an unhandled answer is not dropped without a trace.
	sm.Error(&diam.ErrorReport{Conn: c, Message: request, Error: fmt.Errorf(
		"unhandled message for index: %+v", diam.CommandIndex{
			AppID:   request.Header.ApplicationID,
			Code:    request.Header.CommandCode,
			Request: isRequest,
		})})
}

// HandleMessageError implements diam.MessageErrorHandler. RFC 6733 Sections
// 7.1.5 and 7.2 permit the generic error grammar when malformed framing makes
// an application-specific answer impractical. Answers never receive answers.
func (sm *StateMachine) HandleMessageError(c diam.Conn, request *diam.Message, messageErr *diam.MessageError) error {
	if request == nil || request.Header == nil || request.Header.CommandFlags&diam.RequestFlag == 0 {
		return nil
	}
	if messageErr == nil {
		return fmt.Errorf("cannot answer a nil Diameter message error")
	}
	if messageErr.ResultCode == diam.InvalidAVPLength && messageErr.FailedAVP == nil {
		return fmt.Errorf("diameter result code %d requires Failed-AVP", messageErr.ResultCode)
	}
	if messageErr.FailedAVP != nil {
		return sm.writeErrorAnswer(c, request, messageErr.ResultCode, []*diam.AVP{messageErr.FailedAVP}, true)
	}
	return sm.writeErrorAnswer(c, request, messageErr.ResultCode, nil, true)
}

func (sm *StateMachine) writeErrorAnswer(c diam.Conn, request *diam.Message, resultCode uint32, failedAVPs []*diam.AVP, protocolError bool) error {
	answer := request.Answer(0)
	// RFC 6733 §§7 and 7.2: application errors such as 5001 clear R and T
	// without E; protocol errors such as 3001 set E. Both copy only P.
	answer.Header.CommandFlags = request.Header.CommandFlags & diam.ProxiableFlag
	if protocolError {
		answer.Header.CommandFlags |= diam.ErrorFlag
	} else if sessionID, err := request.FindAVP(avp.SessionID, 0); err == nil &&
		answer.Len()+sessionID.Len() <= diam.MaxMessageLength {
		answer.InsertAVP(sessionID)
	}
	// RFC 6733 §8.3.2 places Result-Code before the Origin AVPs in RAA.
	if !protocolError {
		if _, err := answer.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(resultCode)); err != nil {
			return fmt.Errorf("add Result-Code to Diameter answer: %w", err)
		}
	}

	if _, err := answer.NewAVP(avp.OriginHost, avp.Mbit, 0, sm.cfg.OriginHost); err != nil {
		return fmt.Errorf("add Origin-Host to Diameter error answer: %w", err)
	}
	// RFC 6733 §6.2, Verified Erratum 4887 requires the local Origin-Realm.
	if _, err := answer.NewAVP(avp.OriginRealm, avp.Mbit, 0, sm.cfg.OriginRealm); err != nil {
		return fmt.Errorf("add Origin-Realm to Diameter error answer: %w", err)
	}
	if protocolError {
		if _, err := answer.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(resultCode)); err != nil {
			return fmt.Errorf("add Result-Code to Diameter error answer: %w", err)
		}
	}
	if sm.cfg.OriginStateID != 0 {
		if _, err := answer.NewAVP(avp.OriginStateID, avp.Mbit, 0, sm.cfg.OriginStateID); err != nil {
			return fmt.Errorf("add Origin-State-Id to Diameter error answer: %w", err)
		}
	}
	if len(failedAVPs) != 0 {
		// RFC 6733 Section 7.5 and Verified Errata 4615 require one
		// Failed-AVP container; it may retain the Grouped hierarchy.
		failed := &diam.GroupedAVP{AVP: failedAVPs}
		if _, err := answer.NewAVP(avp.FailedAVP, avp.Mbit, 0, failed); err != nil {
			return fmt.Errorf("add Failed-AVP to Diameter error answer: %w", err)
		}
	}
	// RFC 6733 Section 7.2 makes Session-Id optional in the generic error
	// answer. Preserve it only when the complete answer still fits on the wire.
	if protocolError {
		if sessionID, err := request.FindAVP(avp.SessionID, 0); err == nil &&
			answer.Len()+sessionID.Len() <= diam.MaxMessageLength {
			answer.InsertAVP(sessionID)
		}
	}

	if _, err := answer.WriteTo(c); err != nil {
		return fmt.Errorf("write Diameter error answer: %w", err)
	}
	return nil
}
