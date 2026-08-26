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

	answer := request.Answer(0)
	// RFC 6733 Section 7.2: clear R and T, set E, and copy only P from the
	// request. NewMessage already emits Diameter version 1.
	answer.Header.CommandFlags = request.Header.CommandFlags&diam.ProxiableFlag | diam.ErrorFlag

	if _, err := answer.NewAVP(avp.OriginHost, avp.Mbit, 0, sm.cfg.OriginHost); err != nil {
		return fmt.Errorf("add Origin-Host to Diameter error answer: %w", err)
	}
	if _, err := answer.NewAVP(avp.OriginRealm, avp.Mbit, 0, sm.cfg.OriginRealm); err != nil {
		return fmt.Errorf("add Origin-Realm to Diameter error answer: %w", err)
	}
	if _, err := answer.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(messageErr.ResultCode)); err != nil {
		return fmt.Errorf("add Result-Code to Diameter error answer: %w", err)
	}
	if sm.cfg.OriginStateID != 0 {
		if _, err := answer.NewAVP(avp.OriginStateID, avp.Mbit, 0, sm.cfg.OriginStateID); err != nil {
			return fmt.Errorf("add Origin-State-Id to Diameter error answer: %w", err)
		}
	}
	if messageErr.FailedAVP != nil {
		// RFC 6733 Section 7.5 and Verified Errata 4615 require one
		// Failed-AVP container; it may retain the Grouped hierarchy.
		failed := &diam.GroupedAVP{AVP: []*diam.AVP{messageErr.FailedAVP}}
		if _, err := answer.NewAVP(avp.FailedAVP, avp.Mbit, 0, failed); err != nil {
			return fmt.Errorf("add Failed-AVP to Diameter error answer: %w", err)
		}
	}
	// RFC 6733 Section 7.2 makes Session-Id optional in the generic error
	// answer. Preserve it only when the complete answer still fits on the wire.
	if sessionID, err := request.FindAVP(avp.SessionID, 0); err == nil &&
		answer.Len()+sessionID.Len() <= diam.MaxMessageLength {
		answer.InsertAVP(sessionID)
	}

	if _, err := answer.WriteTo(c); err != nil {
		return fmt.Errorf("write Diameter error answer: %w", err)
	}
	return nil
}
