// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"context"
	"errors"
	"fmt"

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
		ctx := c.Context()
		if _, ok := smpeer.FromContext(ctx); ok {
			// Ignore retransmission.
			return
		}
		local := base.AdvertisedApplicationIDs(sm.capabilities(c, m))
		cer := new(smparser.CER)
		_, err := cer.Parse(m, smparser.ParseOptions{Role: smparser.Server, TLS: c.TLS() != nil, Dictionary: sm.capabilityDictionary(c, m), LocalApplications: local})
		if err != nil {
			err = errorCEA(sm, c, m, err)
			if err != nil {
				sm.Error(&diam.ErrorReport{
					Conn:    c,
					Message: m,
					Error:   err,
				})
			}
			c.Close()
			return
		}
		a, err := buildSuccessCEA(sm, c, m)
		if err == nil {
			meta := smpeer.FromCER(cer)
			c.SetContext(smpeer.NewContext(context.WithValue(ctx, advertisedAppsKey{}, local), meta))
			// Publish admission before the peer can respond to the CEA (RFC 6733 §5.6.1).
			if !sm.completeAcceptedHandshake(c) {
				// The handshake timer won: no peer was admitted and no CEA is sent.
				c.SetContext(ctx)
				c.Close()
				return
			}
			if sm.cfg.OnCEA != nil {
				sm.cfg.OnCEA(c, a)
			}
			_, err = a.WriteTo(c)
		}
		if err != nil {
			sm.Error(&diam.ErrorReport{
				Conn:    c,
				Message: m,
				Error:   err,
			})
			c.Close()
			return
		}
		// Notify about peer passing the handshake.
		select {
		case sm.hsNotifyc <- c:
		default:
		}
	}
}

// errorCEA sends the capability failure answer (RFC 6733 §5.3.2).
func errorCEA(sm *StateMachine, c diam.Conn, m *diam.Message, errMessage error) error {
	hostAddresses := sm.cfg.HostIPAddresses
	if len(hostAddresses) == 0 {
		var err error
		hostAddresses, err = getLocalAddresses(c)
		if err != nil {
			return fmt.Errorf("error CEA '%w' create failure: %w", errMessage, err)
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
			return err
		}
	} else {
		a, err = base.BuildCEA(m, cfg, resultCode)
		if err != nil {
			return fmt.Errorf("error CEA '%w' create failure: %w", errMessage, err)
		}
	}
	if sm.cfg.OnCEA != nil {
		sm.cfg.OnCEA(c, a)
	}
	_, err = a.WriteTo(c)
	if err != nil {
		err = fmt.Errorf("error CEA '%w' send failure: %w", errMessage, err)
	}
	return err
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
