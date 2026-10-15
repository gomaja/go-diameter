// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
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
		if c.Closed() {
			return
		}
		ctx := c.Context()
		if _, ok := smpeer.FromContext(ctx); ok {
			logMessage(c, m, slog.LevelWarn, "sm: ignoring CER on admitted connection; accepted CER renewal is disabled or ineligible", nil)
			sm.protocolError(c, m, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
			return
		}
		local := base.AdvertisedApplicationIDs(sm.capabilities(c, m))
		cer := new(smparser.CER)
		_, err := cer.Parse(m, smparser.ParseOptions{Role: smparser.Server, TLS: c.TLS() != nil, Dictionary: sm.capabilityDictionary(c, m), LocalApplications: local})
		if err != nil {
			logMessage(c, m, slog.LevelWarn, "sm: rejected CER; closing connection", err)
			code := rejectedCERCode(err)
			replyCode, answerErr := errorCEAResult(sm, c, m, err)
			err = answerErr
			if err != nil {
				logMessage(c, m, slog.LevelError, "sm: CEA failed; closing connection", err)
			}
			sm.closeRequiredReply(c)
			sm.protocolError(c, m, diam.ProtocolCERRejected, code, true, protocolReply(err), replyCode)
			return
		}
		a, err := buildSuccessCEA(sm, c, m)
		if err == nil {
			if c.Closed() {
				return
			}
			meta := smpeer.FromCER(cer)
			c.SetContext(smpeer.NewContext(context.WithValue(ctx, advertisedAppsKey{}, local), meta))
			// Publish admission before the peer can respond to the CEA (RFC 6733 §5.6.1).
			if !sm.completeAcceptedHandshake(c) {
				// The handshake timer won: no peer was admitted and no CEA is sent.
				c.SetContext(ctx)
				logMessage(c, m, slog.LevelWarn, "sm: CER after handshake timeout; closing connection", nil)
				c.Close()
				sm.protocolError(c, m, diam.ProtocolHandshakeState, 0, true, diam.ProtocolReplyNone, 0)
				return
			}
			if sm.cfg.OnCEA != nil {
				sm.cfg.OnCEA(c, a)
			}
			err = writeRequiredReply(c, a)
		}
		if err != nil {
			logMessage(c, m, slog.LevelError, "sm: CEA failed; closing connection", err)
			code := uint32(diam.Success)
			if a != nil {
				code = protocolAnswerCode(a)
			}
			sm.requiredReplyFailed(c, m, code)
			return
		}
		// RFC 6733 §5.6 and RFC 3539 Appendix A: supervise only an admitted
		// connection, after OnHandshake returns (including panic unwinding).
		defer sm.startWatchdog(c)
		if sm.cfg.OnHandshake != nil {
			metadata, _ := smpeer.FromContext(c.Context())
			sm.cfg.OnHandshake(c, metadata)
		}
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
	return m.Dictionary()
}
