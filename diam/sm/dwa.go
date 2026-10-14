// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"fmt"
	"log/slog"

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
	return func(c diam.Conn, m *diam.Message) {
		kind, code := processDWA(c, m, dwac, observer)
		if kind != "" {
			sm.protocolError(c, m, kind, code, false, diam.ProtocolReplyNone, 0)
		}
	}
}

func processDWA(c diam.Conn, m *diam.Message, dwac chan struct{}, observer func(diam.Conn, WatchdogEvent)) (diam.ProtocolErrorKind, uint32) {
	observe := func(c diam.Conn, event WatchdogEvent) {
		if observer != nil {
			observer(c, event)
		}
	}
	if c.Closed() {
		return "", 0
	}
	dwa := new(smparser.DWA)
	if err := dwa.Parse(m); err != nil {
		observe(c, WatchdogInvalidAnswer)
		logMessage(c, m, slog.LevelWarn, "sm: invalid DWA", err)
		return diam.ProtocolInvalidDWA, 0
	}
	if dwa.ResultCode != diam.Success {
		logMessage(c, m, slog.LevelWarn, "sm: rejected DWA", fmt.Errorf("DWA Result-Code %d", dwa.ResultCode))
		observe(c, WatchdogInvalidAnswer)
		return diam.ProtocolRejectedDWA, dwa.ResultCode
	}
	if c.Closed() {
		return "", 0
	}
	select {
	case dwac <- dwaACK:
	default:
	}
	observe(c, WatchdogAnswerReceived)
	return "", 0
}
