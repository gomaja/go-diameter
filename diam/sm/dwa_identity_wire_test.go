package sm

import (
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
)

func removeWireAVP(m *diam.Message, code uint32) {
	for i, a := range m.AVP {
		if a.Code == code && a.VendorID == 0 {
			m.AVP = append(m.AVP[:i], m.AVP[i+1:]...)
			return
		}
	}
}

// RFC 6733 §§3, 5.5.2, 6.3 and RFC 3539 §3.4.1, Appendix A:
// decoded DWA resets Tw, but recovery and Pending credit require validation.
func TestDWABodyAndRecoveryWire(t *testing.T) {
	for _, mode := range []string{"accepted", "dialed"} {
		for _, scenario := range []string{
			"missing-host", "missing-realm", "missing-result", "duplicate-host", "duplicate-realm", "duplicate-result",
			"wrong-host", "wrong-realm", "empty-host", "empty-realm", "proxiable", "retransmitted", "error",
			"rejected", "wrong-hop", "wrong-end", "valid", "reserved", "case", "non-DWA",
		} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				events := make(chan acceptedWatchdogEvent, 32)
				p := newWatchdogCorrelationWire(t, mode, events)
				request := acceptedWatchdogOnWire(t, p.peer)
				awaitAcceptedEvent(t, events, WatchdogRequestSent, p.conn)
				awaitAcceptedEvent(t, events, WatchdogSuspect, p.conn)
				answer := boundWireAnswer(t, p, request, diam.Success)
				kind := diam.ProtocolInvalidDWA
				code := uint32(0)
				valid := false
				switch scenario {
				case "missing-host":
					code = diam.MissingAVP
					removeWireAVP(answer, avp.OriginHost)
				case "missing-realm":
					code = diam.MissingAVP
					removeWireAVP(answer, avp.OriginRealm)
				case "missing-result":
					code = diam.MissingAVP
					removeWireAVP(answer, avp.ResultCode)
				case "duplicate-host", "duplicate-realm", "duplicate-result":
					code = diam.AVPOccursTooManyTimes
					field := map[string]uint32{"duplicate-host": avp.OriginHost, "duplicate-realm": avp.OriginRealm, "duplicate-result": avp.ResultCode}[scenario]
					a, _ := answer.FindAVP(field, 0)
					answer.AddAVP(diam.NewAVP(a.Code, a.Flags, a.VendorID, a.Data))
				case "wrong-host", "empty-host":
					value := "stranger.example"
					if scenario == "empty-host" {
						value = ""
						code = diam.InvalidAVPValue
					}
					setWireIdentity(t, answer, avp.OriginHost, value)
				case "wrong-realm", "empty-realm":
					value := "elsewhere.example"
					if scenario == "empty-realm" {
						value = ""
						code = diam.InvalidAVPValue
					}
					setWireIdentity(t, answer, avp.OriginRealm, value)
				case "proxiable":
					kind, code = diam.ProtocolInvalidHeader, diam.InvalidHDRBits
					answer.Header.CommandFlags |= diam.ProxiableFlag
				case "retransmitted":
					kind, code = diam.ProtocolInvalidHeader, diam.InvalidHDRBits
					answer.Header.CommandFlags |= diam.RetransmittedFlag
				case "error":
					code = diam.InvalidHDRBits
					answer.Header.CommandFlags |= diam.ErrorFlag
				case "rejected":
					a, _ := answer.FindAVP(avp.ResultCode, 0)
					a.Data = datatype.Unsigned32(5012)
					kind, code = diam.ProtocolRejectedDWA, 5012
				case "wrong-hop":
					answer.Header.HopByHopID++
					kind = diam.ProtocolUnexpectedMessage
				case "wrong-end":
					answer.Header.EndToEndID++
					kind = diam.ProtocolUnexpectedMessage
				case "reserved":
					answer.Header.CommandFlags |= 0x0f
					valid = true
				case "case":
					for _, field := range []uint32{avp.OriginHost, avp.OriginRealm} {
						a, _ := answer.FindAVP(field, 0)
						setWireIdentity(t, answer, field, strings.ToUpper(string(a.Data.(datatype.DiameterIdentity))))
					}
					valid = true
				case "valid":
					valid = true
				case "non-DWA":
					answer = diam.NewMessage(0xfedc, 0, 0, 101, 102, p.conn.Dictionary())
					kind = diam.ProtocolUnexpectedMessage
				}
				header := p.send(t, answer)
				if valid {
					for range 2 {
						awaitCorrelationRecovery(t, events, p.conn)
					}
					acceptedWatchdogOnWire(t, p.peer)
					awaitAcceptedEvent(t, events, WatchdogRequestSent, p.conn)
					return
				}
				assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, &header, kind, code, false, diam.ProtocolReplyNone, 0)
				if scenario == "non-DWA" {
					awaitAcceptedEvent(t, events, WatchdogRecovered, p.conn)
					// Non-DWA recovers health, while the original probe stays Pending.
					awaitAcceptedEvent(t, events, WatchdogSuspect, p.conn)
				} else {
					if kind != diam.ProtocolUnexpectedMessage && kind != diam.ProtocolInvalidHeader {
						awaitAcceptedEvent(t, events, WatchdogInvalidAnswer, p.conn)
					}
					select {
					case event := <-events:
						t.Fatalf("discarded DWA changed health/Pending: %s", event.event)
					case <-time.After(20 * time.Millisecond):
					}
				}
				// The very same outstanding probe must still be completable once.
				p.send(t, boundWireAnswer(t, p, request, diam.Success))
				for range 2 {
					awaitCorrelationRecovery(t, events, p.conn)
				}
				acceptedWatchdogOnWire(t, p.peer)
				awaitAcceptedEvent(t, events, WatchdogRequestSent, p.conn)
			})
		}
	}
}

// Removing reset-only activity would time out at the original deadline;
// treating it as Receive would emit Recovered while the probe is unvalidated.
func TestDWAActivityResetsTwWithoutRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		activity := newWatchdogActivity()
		activity.ceaReceived.Store(true)
		p := &loopWatchdogProbe{conn: newWatchdogProbeConn(), signals: &activity.watchdogSignals,
			events: make(chan WatchdogEvent, 16), stop: make(chan struct{}), exited: make(chan struct{})}
		w := connWatchdog{conn: p.conn, done: p.conn.closed, stop: p.stop, signals: p.signals,
			interval: func() time.Duration { return loopWatchdogTw },
			send:     func() bool { _, _ = p.conn.Write(nil); p.events <- WatchdogRequestSent; return true },
			observe:  func(event WatchdogEvent) { p.events <- event }}
		go func() { w.run(); close(p.exited) }()
		t.Cleanup(func() { p.conn.Close(); <-p.exited })
		synctest.Wait()
		time.Sleep(2 * loopWatchdogTw)
		synctest.Wait()
		p.wantEvent(t, WatchdogRequestSent)
		p.wantEvent(t, WatchdogSuspect)
		time.Sleep(loopWatchdogTw / 2)
		// A decoded DWA gets timer credit before body/correlation validation.
		h := activityHandler{activity: activity, dwa: watchdogDWAHandler(func(c diam.Conn, m *diam.Message, receipt watchdogReceipt) {
			_, _ = processDWAReceipt(c, m, &activity.watchdogSignals, nil, receipt)
		})}
		h.ServeDIAM(p.conn, &diam.Message{Header: &diam.Header{Version: 1, CommandCode: diam.DeviceWatchdog}})
		synctest.Wait()
		p.wantNoEvent(t)
		time.Sleep(loopWatchdogTw - time.Nanosecond)
		synctest.Wait()
		p.wantNoEvent(t)
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		p.wantEvent(t, WatchdogTimedOut)
		p.wantWrites(t, 1)
	})
}
