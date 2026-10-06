// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"fmt"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// handleUnsupportedCommand is the default ALL handler. A caller's ALL
// registration replaces it, preserving ServeMux dispatch precedence.
func (sm *StateMachine) handleUnsupportedCommand(c diam.Conn, request *diam.Message) {
	isRequest := request.Header.CommandFlags&diam.RequestFlag != 0
	// RFC 6733 §§7.1.3 and 7.2: 3007 for an application this node does not
	// support, 3001 for a command it does not support in one it does. Both
	// are protocol errors on a request; an answer never causes another answer.
	if isRequest {
		resultCode := uint32(diam.CommandUnsupported)
		if !sm.supportsApplication(request.Header.ApplicationID) {
			resultCode = diam.ApplicationUnsupported
		}
		if err := sm.HandleMessageError(c, request, &diam.MessageError{ResultCode: resultCode}); err != nil {
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

// supportsApplication reports whether appID is the base application or one
// this state machine advertises in CER/CEA. Advertising the relay
// application (RFC 6733 §2.4) covers every application.
func (sm *StateMachine) supportsApplication(appID uint32) bool {
	if appID == 0 {
		return true
	}
	for _, app := range sm.supportedApps {
		if app.ID == appID || app.ID == relayApplicationID {
			return true
		}
	}
	return false
}

// relayApplicationID is the Relay Application-Id (RFC 6733 §2.4).
const relayApplicationID = 0xffffffff

// HandleMessageError implements diam.MessageErrorHandler. RFC 6733 §§7.1-7.2
// reserve E for protocol errors; answers never receive answers.
func (sm *StateMachine) HandleMessageError(c diam.Conn, request *diam.Message, messageErr *diam.MessageError) error {
	if !sm.preCERMessageAllowed(c, request) {
		c.Close()
		return nil
	}
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
	var failedAVPs []*diam.AVP
	if messageErr.FailedAVP != nil {
		failedAVPs = []*diam.AVP{messageErr.FailedAVP}
	}
	err := sm.writeErrorAnswer(c, request, messageErr.ResultCode, failedAVPs, protocolError)
	if request.Header.CommandCode == diam.CapabilitiesExchange && !admittedPeer(c) {
		// RFC 6733 §§5.3 and 5.6.1: a rejected CER admits no peer, and the
		// transport connection is closed, as handleCER does.
		c.Close()
	}
	return err
}

func (sm *StateMachine) writeErrorAnswer(c diam.Conn, request *diam.Message, resultCode uint32, failedAVPs []*diam.AVP, protocolError bool) error {
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
