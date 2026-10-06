// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"context"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// handleCEA handles Capabilities-Exchange-Answer messages.
func handleCEA(sm *StateMachine, activity *watchdogActivity) diam.HandlerFunc {
	return func(c diam.Conn, m *diam.Message) {
		cea := new(smparser.CEA)
		if err := cea.ParseWithApplicationIDs(m, smparser.Client, activity.advertised); err != nil {
			activity.ceac <- err
			return
		}
		meta := smpeer.FromCEA(cea)
		ctx := c.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		ctx = context.WithValue(ctx, advertisedAppsKey{}, activity.advertised)
		c.SetContext(smpeer.NewContext(ctx, meta))
		// Notify about peer passing the handshake.
		select {
		case sm.hsNotifyc <- c:
		default:
		}
		// Done receiving and validating this CEA.
		close(activity.ceac)
	}
}
