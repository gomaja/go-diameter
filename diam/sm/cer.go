// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// handleCER handles Capabilities-Exchange-Request messages.
//
// If mandatory AVPs such as Origin-Host or Origin-Realm
// are missing, we close the connection.
//
// See RFC 6733 section 5.3 for details.
func handleCER(sm *StateMachine) diam.HandlerFunc {
	return func(c diam.Conn, m *diam.Message) {
		release := m.BeginDispatch()
		defer release()
		if meta, ok := smpeer.FromContext(c.Context()); ok && meta.CEA != nil {
			// Dialed Client repeated CER handling remains on the #111 adapter.
			if sm.cfg.OnCER != nil {
				sm.cfg.OnCER(c, m)
			}
			sm.ignoreRepeatedCER(c, m)
			return
		}
		if s := sm.acceptedCore(c, m, true); s != nil {
			s.apply(protocol.Input{Kind: protocol.Receive, Message: m})
		}
	}
}

// ignoreRepeatedCER preserves the Client rejection path shared by decoded and
// malformed CERs. Only decoded dispatch invokes OnCER before this decision.
func (sm *StateMachine) ignoreRepeatedCER(c diam.Conn, m *diam.Message) {
	if !c.Closed() {
		logMessage(c, m, slog.LevelWarn, "sm: ignoring CER on admitted connection; accepted CER renewal is disabled or ineligible", nil)
		sm.protocolError(c, m, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
	}
}

// errorCEA sends the capability failure answer (RFC 6733 §5.3.2).
func errorCEA(sm *StateMachine, c diam.Conn, m *diam.Message, errMessage error) error {
	_, err := errorCEAResult(sm, c, m, errMessage)
	return err
}

func rejectedCERCode(err error) uint32 {
	if code := protocolResultCode(err); code != 0 {
		return code
	}
	if errors.Is(err, smparser.ErrNoCommonSecurity) {
		return diam.NoCommonSecurity
	}
	if errors.Is(err, smparser.ErrNoCommonApplication) {
		return diam.NoCommonApplication
	}
	return diam.UnableToComply
}

func errorCEAResult(sm *StateMachine, c diam.Conn, m *diam.Message, errMessage error) (replyCode uint32, resultErr error) {
	replyCode = rejectedCERCode(errMessage)
	hostAddresses := sm.cfg.HostIPAddresses
	if len(hostAddresses) == 0 {
		var err error
		hostAddresses, err = getLocalAddresses(c)
		if err != nil {
			return replyCode, fmt.Errorf("error CEA '%w' create failure: %w", errMessage, err)
		}
	}
	var resultCode uint32
	switch {
	case errors.Is(errMessage, smparser.ErrNoCommonSecurity):
		resultCode = diam.NoCommonSecurity
	case errors.Is(errMessage, smparser.ErrNoCommonApplication):
		resultCode = diam.NoCommonApplication
	default:
		resultCode = diam.UnableToComply
	}
	cfg := baseSettings(sm.cfg)
	cfg.HostIPAddresses = hostAddresses
	var a *diam.Message
	var err error
	var messageErr *diam.MessageError
	if errors.As(errMessage, &messageErr) {
		// RFC 6733 §7.1.5, Verified Erratum 4615: one Failed-AVP.
		var failed []*diam.AVP
		if messageErr.FailedAVP != nil {
			failed = []*diam.AVP{messageErr.FailedAVP}
		}
		a, err = base.BuildErrorAnswer(m, cfg, messageErr.ResultCode, failed, messageErr.ResultCode >= 3000 && messageErr.ResultCode < 4000)
		if err != nil {
			return replyCode, err
		}
	} else {
		a, err = base.BuildCEA(m, cfg, resultCode)
		if err != nil {
			return replyCode, fmt.Errorf("error CEA '%w' create failure: %w", errMessage, err)
		}
	}
	if sm.cfg.OnCEA != nil {
		sm.cfg.OnCEA(c, a)
	}
	if sm.cfg.OnProtocolError != nil {
		replyCode = protocolAnswerCode(a)
	}
	err = writeRequiredReply(c, a)
	if err != nil {
		err = fmt.Errorf("error CEA '%w' send failure: %w", errMessage, err)
	}
	return replyCode, err
}

func buildSuccessCEA(sm *StateMachine, c diam.Conn, m *diam.Message) (*diam.Message, error) {
	hostAddresses := sm.cfg.HostIPAddresses
	if len(hostAddresses) == 0 {
		var err error
		hostAddresses, err = getLocalAddresses(c)
		if err != nil {
			return nil, err
		}
	}
	cfg := sm.capabilities(c, m)
	cfg.HostIPAddresses = hostAddresses
	// The caller runs OnCEA only once the CEA will be sent.
	return base.BuildCEA(m, cfg, diam.Success)
}

// capabilities derives advertisement and validation from the same dictionary
// as the connection when Settings.Dict is unset (RFC 6733 §5.3).
func (sm *StateMachine) capabilities(c diam.Conn, m *diam.Message) base.Settings {
	cfg := baseSettings(sm.cfg)
	apps := sm.supportedApps
	if sm.dictionary == nil {
		apps = PrepareSupportedApps(sm.capabilityDictionary(c, m))
	}
	for _, app := range apps {
		cfg.Applications = append(cfg.Applications, base.LocalApplication{
			ID: app.ID, AppType: app.AppType, Vendor: app.Vendor, SupportedVendors: app.SupportedVendors,
		})
	}
	return cfg
}

func (sm *StateMachine) capabilityDictionary(c diam.Conn, m *diam.Message) *dict.Parser {
	if sm.dictionary != nil {
		return sm.dictionary
	}
	if dp := c.Dictionary(); dp != nil {
		return dp
	}
	if m != nil {
		return m.Dictionary()
	}
	return dict.Default
}
