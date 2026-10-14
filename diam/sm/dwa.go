// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"fmt"
	"log/slog"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

var dwaACK = struct{}{}

// handleDWA handles Device-Watchdog-Answer messages.
func handleDWA(
	sm *StateMachine,
	signals *watchdogSignals,
	observer func(diam.Conn, WatchdogEvent),
) diam.HandlerFunc {
	return func(c diam.Conn, m *diam.Message) {
		kind, code := processDWA(c, m, signals, observer)
		if kind != "" {
			sm.protocolError(c, m, kind, code, false, diam.ProtocolReplyNone, 0)
		}
	}
}

func processDWA(c diam.Conn, m *diam.Message, signals *watchdogSignals, observer func(diam.Conn, WatchdogEvent)) (diam.ProtocolErrorKind, uint32) {
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
		if _, err := m.FindAVP(avp.ResultCode, 0); err != nil {
			observe(c, WatchdogInvalidAnswer)
			logMessage(c, m, slog.LevelWarn, "sm: invalid DWA", err)
			return diam.ProtocolInvalidDWA, 0
		}
		logMessage(c, m, slog.LevelWarn, "sm: rejected DWA", fmt.Errorf("DWA Result-Code %d", dwa.ResultCode))
		observe(c, WatchdogInvalidAnswer)
		return diam.ProtocolRejectedDWA, dwa.ResultCode
	}
	if err := validateSuccessfulDWA(c, m); err != nil {
		observe(c, WatchdogInvalidAnswer)
		logMessage(c, m, slog.LevelWarn, "sm: invalid DWA", err)
		return diam.ProtocolInvalidDWA, 0
	}
	if c.Closed() {
		return "", 0
	}
	// RFC 6733 §§3, 6.2.1 and RFC 3539 §3.4.1, Appendix A: only the
	// outstanding DWR's answer clears Pending; consume it once, including
	// when duplicate answers are dispatched concurrently.
	request := signals.request.Load()
	if request == nil || m.Header.HopByHopID != request.HopByHopID || m.Header.EndToEndID != request.EndToEndID ||
		!signals.request.CompareAndSwap(request, nil) {
		logMessage(c, m, slog.LevelWarn, "sm: unhandled answer discarded", nil)
		return diam.ProtocolUnexpectedMessage, 0
	}
	select {
	case signals.dwac <- dwaACK:
	default:
	}
	observe(c, WatchdogAnswerReceived)
	return "", 0
}

func validateSuccessfulDWA(c diam.Conn, m *diam.Message) error {
	// RFC 6733 §§3, 5.5.2, 6.3: singleton result and identities, with
	// defined flags clear. Receivers ignore reserved command-header bits.
	if m.Header.CommandFlags&(diam.RequestFlag|diam.ProxiableFlag|diam.ErrorFlag|diam.RetransmittedFlag) != 0 {
		return fmt.Errorf("invalid DWA flags")
	}
	ctx := c.Context()
	if ctx == nil {
		return fmt.Errorf("DWA before peer admission")
	}
	meta, ok := smpeer.FromContext(ctx)
	if !ok || meta == nil {
		return fmt.Errorf("DWA before peer admission")
	}
	var hosts, realms, results int
	for _, a := range m.AVP {
		if a.VendorID != 0 {
			continue
		}
		switch a.Code {
		case avp.OriginHost:
			hosts++
			host, ok := a.Data.(datatype.DiameterIdentity)
			if !ok || !boundHost(c, host) {
				return fmt.Errorf("DWA Origin-Host mismatch")
			}
		case avp.OriginRealm:
			realms++
			realm, ok := a.Data.(datatype.DiameterIdentity)
			if !ok || len(realm) == 0 || !equalIdentity(realm, meta.OriginRealm) {
				return fmt.Errorf("DWA Origin-Realm mismatch")
			}
		case avp.ResultCode:
			results++
			if value, ok := a.Data.(datatype.Unsigned32); !ok || uint32(value) != diam.Success {
				return fmt.Errorf("invalid successful DWA Result-Code")
			}
		}
	}
	if hosts != 1 || realms != 1 || results != 1 {
		return fmt.Errorf("DWA requires one Result-Code, Origin-Host and Origin-Realm")
	}
	return nil
}
