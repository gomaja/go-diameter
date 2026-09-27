// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
)

var dwaACK = struct{}{}

// handleDWA handles Device-Watchdog-Answer messages.
func handleDWA(
	sm *StateMachine,
	dwac chan struct{},
	observer func(diam.Conn, WatchdogEvent),
) diam.HandlerFunc {
	observe := func(c diam.Conn, event WatchdogEvent) {
		if observer != nil {
			observer(c, event)
		}
	}
	return func(c diam.Conn, m *diam.Message) {
		dwa := new(smparser.DWA)
		if err := dwa.Parse(m); err != nil {
			observe(c, WatchdogInvalidAnswer)
			sm.Error(&diam.ErrorReport{
				Conn:    c,
				Message: m,
				Error:   err,
			})
			return
		}
		if dwa.ResultCode != diam.Success {
			observe(c, WatchdogInvalidAnswer)
			return
		}
		select {
		case dwac <- dwaACK:
		default:
		}
		observe(c, WatchdogAnswerReceived)
	}
}
