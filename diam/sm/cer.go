// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"fmt"

	"github.com/gomaja/go-diameter/diam"
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
		cer := new(smparser.CER)
		_, err := cer.ParseWithSecurity(m, smparser.Server, c.TLS() != nil)
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
		err = successCEA(sm, c, m)

		if err != nil {
			sm.Error(&diam.ErrorReport{
				Conn:    c,
				Message: m,
				Error:   err,
			})
			return
		}
		meta := smpeer.FromCER(cer)
		c.SetContext(smpeer.NewContext(ctx, meta))
		// Notify about peer passing the handshake.
		select {
		case sm.hsNotifyc <- c:
		default:
		}
	}
}

// errorCEA sends the legacy capability failure answer (RFC 6733 §5.3.2).
func errorCEA(sm *StateMachine, c diam.Conn, m *diam.Message, errMessage error) error {
	hostAddresses := sm.cfg.HostIPAddresses
	if len(hostAddresses) == 0 {
		var err error
		hostAddresses, err = getLocalAddresses(c)
		if err != nil {
			return fmt.Errorf("error CEA '%s' create failure: %v", errMessage, err)
		}
	}
	var resultCode uint32
	switch errMessage {
	case smparser.ErrNoCommonSecurity:
		resultCode = diam.NoCommonSecurity
	case smparser.ErrNoCommonApplication:
		resultCode = diam.NoCommonApplication
	default:
		resultCode = diam.UnableToComply
	}
	cfg := baseSettings(sm.cfg)
	cfg.HostIPAddresses = hostAddresses
	a := base.BuildCEA(m, cfg, resultCode)
	if sm.cfg.OnCEA != nil {
		sm.cfg.OnCEA(c, a)
	}
	_, err := a.WriteTo(c)
	if err != nil {
		err = fmt.Errorf("error CEA '%s' send failure: %v", errMessage, err)
	}
	return err
}

// successCEA sends the legacy capability success answer (RFC 6733 §5.3.2).
func successCEA(sm *StateMachine, c diam.Conn, m *diam.Message) error {
	hostAddresses := sm.cfg.HostIPAddresses
	if len(hostAddresses) == 0 {
		var err error
		hostAddresses, err = getLocalAddresses(c)
		if err != nil {
			return err
		}
	}
	cfg := baseSettings(sm.cfg)
	cfg.HostIPAddresses = hostAddresses
	for _, app := range sm.supportedApps {
		cfg.Applications = append(cfg.Applications, base.LocalApplication{
			ID: app.ID, AppType: app.AppType, Vendor: app.Vendor,
		})
	}
	a := base.BuildCEA(m, cfg, diam.Success)
	if sm.cfg.OnCEA != nil {
		sm.cfg.OnCEA(c, a)
	}
	_, err := a.WriteTo(c)
	return err
}
