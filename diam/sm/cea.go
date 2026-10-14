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
		kind, code := processCEA(sm, activity, c, m)
		if kind != "" {
			sm.protocolError(c, m, kind, code, true, diam.ProtocolReplyNone, 0)
		}
	}
}

func processCEA(sm *StateMachine, activity *watchdogActivity, c diam.Conn, m *diam.Message) (diam.ProtocolErrorKind, uint32) {
	cea := new(smparser.CEA)
	if err := cea.Parse(m, smparser.ParseOptions{Role: smparser.Client, LocalApplications: activity.advertised}); err != nil {
		logMessage(c, m, slog.LevelWarn, "sm: CEA rejected; closing connection", err)
		activity.ceac <- err
		return diam.ProtocolCEARejected, protocolResultCode(err)
	}
	if !activity.handshakePhase.CompareAndSwap(0, 1) {
		return "", 0 // The handshake deadline already closed this connection.
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
	return "", 0
}
