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

// HandleMessageError implements diam.MessageErrorHandler. RFC 6733 §§7.1-7.2
// reserve E for protocol errors; answers never receive answers.
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
	protocolError := messageErr.ResultCode >= 3000 && messageErr.ResultCode < 4000
	if messageErr.FailedAVP != nil {
		return sm.writeErrorAnswer(c, request, messageErr.ResultCode, []*diam.AVP{messageErr.FailedAVP}, protocolError)
	}
	return sm.writeErrorAnswer(c, request, messageErr.ResultCode, nil, protocolError)
}

func (sm *StateMachine) writeErrorAnswer(c diam.Conn, request *diam.Message, resultCode uint32, failedAVPs []*diam.AVP, protocolError bool) error {
	answer := request.Answer(0)
	// RFC 6733 §§7 and 7.2: application errors such as 5001 clear R and T
	// without E; protocol errors such as 3001 set E. Both copy only P.
	answer.Header.CommandFlags = request.Header.CommandFlags & diam.ProxiableFlag
	if !protocolError &&
		(request.Header.CommandCode == diam.CapabilitiesExchange || request.Header.CommandCode == diam.DeviceWatchdog || request.Header.CommandCode == diam.DisconnectPeer) {
		answer.Header.CommandFlags = 0
		answer.Header.ApplicationID = 0
	}
	if protocolError {
		answer.Header.CommandFlags |= diam.ErrorFlag
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
	if !protocolError && request.Header.CommandCode == diam.CapabilitiesExchange {
		// RFC 6733 §5.3.2: even a permanent-error CEA retains its required
		// local capability fields when E is clear.
		addresses := sm.cfg.HostIPAddresses
		if len(addresses) == 0 {
			var err error
			addresses, err = getLocalAddresses(c)
			if err != nil {
				return fmt.Errorf("find local addresses for error CEA: %w", err)
			}
		}
		if len(addresses) == 0 {
			return fmt.Errorf("cannot build CEA without a local Host-IP-Address")
		}
		for _, address := range addresses {
			if _, err := answer.NewAVP(avp.HostIPAddress, avp.Mbit, 0, address); err != nil {
				return err
			}
		}
		if _, err := answer.NewAVP(avp.VendorID, avp.Mbit, 0, sm.cfg.VendorID); err != nil {
			return err
		}
		if _, err := answer.NewAVP(avp.ProductName, 0, 0, sm.cfg.ProductName); err != nil {
			return err
		}
	}
	// RFC 6733 §§7.2 and 8.3.2: copy Session-Id when the complete answer
	// still fits, and place it first for application-specific answers.
	if sessionID, err := request.FindAVP(avp.SessionID, 0); err == nil &&
		answer.Len()+sessionID.Len() <= diam.MaxMessageLength {
		// Do not echo malformed flag bits from the rejected request.
		answer.InsertAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, sessionID.Data))
	}
	// RFC 6733 §§3.2 and 7.1.5: permanent errors keep the application
	// answer grammar. If the request omitted a field also required in that
	// answer, use the dictionary's zero-filled example for that field.
	if !protocolError {
		for i := 0; i < 32; i++ {
			validationErr := answer.Validate()
			if validationErr == nil {
				break
			}
			if validationErr.ResultCode != diam.MissingAVP || validationErr.FailedAVP == nil {
				return fmt.Errorf("cannot form valid Diameter error answer: %w", validationErr)
			}
			missing := validationErr.FailedAVP
			// RFC 8506 §3.2 requires the CCA's application and request
			// identifiers. Reuse matching request values before falling back
			// to RFC 6733 §7.5's zero-filled missing-AVP example.
			for _, received := range request.AVP {
				if received != nil && received.Code == missing.Code && received.VendorID == missing.VendorID && received.Data != nil {
					missing = diam.NewAVP(missing.Code, missing.Flags, missing.VendorID, received.Data)
					break
				}
			}
			if missing.Code == avp.SessionID && missing.VendorID == 0 {
				if _, ok := missing.Data.(datatype.Unknown); ok {
					missing = diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String(""))
				}
				answer.InsertAVP(missing)
			} else {
				answer.AddAVP(missing)
			}
			if i == 31 {
				return fmt.Errorf("too many missing AVPs in Diameter error answer")
			}
		}
	}
	if validationErr := answer.Validate(); validationErr != nil {
		return fmt.Errorf("cannot form valid Diameter error answer: %w", validationErr)
	}

	if _, err := answer.WriteTo(c); err != nil {
		return fmt.Errorf("write Diameter error answer: %w", err)
	}
	return nil
}
