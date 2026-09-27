// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
)

// handleDWR handles Device-Watchdog-Request messages.
//
// If mandatory AVPs such as Origin-Host or Origin-Realm are missing,
// we ignore the message.
//
// See RFC 6733 section 5.5 for details.
func handleDWR(sm *StateMachine) diam.HandlerFunc {
	return func(c diam.Conn, m *diam.Message) {
		dwr := new(smparser.DWR)
		err := dwr.Parse(m)
		if err != nil {
			sm.Error(&diam.ErrorReport{
				Conn:    c,
				Message: m,
				Error:   err,
			})
			return
		}
		a, err := base.BuildDWA(m, baseSettings(sm.cfg))
		if err != nil {
			sm.Error(&diam.ErrorReport{Conn: c, Message: m, Error: err})
			return
		}
		if sm.cfg.OnDWA != nil {
			sm.cfg.OnDWA(c, a)
		}
		_, err = a.WriteTo(c)
		if err != nil {
			sm.Error(&diam.ErrorReport{
				Conn:    c,
				Message: m,
				Error:   err,
			})
		}
	}
}
