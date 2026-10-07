// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"context"
	"errors"
	"log/slog"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// handleCEA handles Capabilities-Exchange-Answer messages.
func handleCEA(sm *StateMachine, activity *watchdogActivity) diam.HandlerFunc {
	return func(c diam.Conn, m *diam.Message) {
		cea := new(smparser.CEA)
		if err := cea.Parse(m, smparser.ParseOptions{Role: smparser.Client, LocalApplications: activity.advertised}); err != nil {
			logMessage(c, m, slog.LevelWarn, "sm: CEA rejected; closing connection", err)
			activity.ceac <- err
			return
		}
		if !activity.handshakePhase.CompareAndSwap(0, 1) {
			return // The handshake deadline already closed this connection.
		}
		close(activity.ceaValidated)
		meta := smpeer.FromCEA(cea)
		ctx := c.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		ctx = context.WithValue(ctx, advertisedAppsKey{}, activity.advertised)
		c.SetContext(smpeer.NewContext(ctx, meta))
		activity.ceaReceived.Store(true)
		callbackReturned := false
		defer func() {
			if !callbackReturned {
				// Preserve panic/Goexit propagation to Server while completing Dial.
				// The protocol timeout has ended, so it cannot release this waiter.
				err := errors.New("sm: OnHandshake terminated without returning")
				logMessage(c, m, slog.LevelError, "sm: OnHandshake terminated; closing connection", err)
				activity.ceac <- err
				c.Close()
			}
		}()
		if sm.cfg.OnHandshake != nil {
			metadata, _ := smpeer.FromContext(c.Context())
			sm.cfg.OnHandshake(c, metadata)
		}
		callbackReturned = true
		// Done receiving and validating this CEA.
		close(activity.ceac)
	}
}
