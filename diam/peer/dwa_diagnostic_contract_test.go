package peer

import (
	"fmt"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

// Grammar diagnostics are independent of exchange ownership. Only an owned
// answer can report its unsuccessful Result-Code as rejection of a local DWR.
func TestManagerDWAOwnershipPreservesDiagnosticsTCP(t *testing.T) {
	for _, dialed := range []bool{false, true} {
		for _, phase := range []string{"unsolicited", "current", "stray", "completed"} {
			for _, fault := range []string{"grammar", "header", "unsuccessful"} {
				t.Run(fmt.Sprintf("dialed=%t/%s/%s", dialed, phase, fault), func(t *testing.T) {
					p := newCoreActivityWire(t, dialed)
					probe := watchdogRequest(t)
					if phase != "unsolicited" {
						p.expire(t)
						probe = read(t, p.c)
						if probe.Header.CommandCode != diam.DeviceWatchdog || probe.Header.CommandFlags&diam.RequestFlag == 0 {
							t.Fatalf("expected local DWR, got %+v", probe.Header)
						}
					}
					answer, err := base.BuildDWA(probe, testBase("known.example.net"))
					if err != nil {
						t.Fatal(err)
					}
					if phase == "completed" {
						write(t, p.c, answer)
						write(t, p.c, watchdogRequest(t))
						_ = read(t, p.c)
						p.fence(t)
						if p.state(t).pending || p.s.requests.HasPending() {
							t.Fatal("successful DWA did not finish the original probe")
						}
					}
					if phase == "stray" {
						answer.Header.HopByHopID++
					}
					kind, result := diam.ProtocolInvalidDWA, uint32(diam.MissingAVP)
					switch fault {
					case "grammar":
						answer.AVP = nil
					case "header":
						answer.Header.CommandFlags |= diam.ProxiableFlag
						kind, result = diam.ProtocolInvalidHeader, diam.InvalidHDRBits
					case "unsuccessful":
						field, err := answer.FindAVP(avp.ResultCode, 0)
						if err != nil {
							t.Fatal(err)
						}
						field.Data = datatype.Unsigned32(diam.UnableToComply)
						kind, result = diam.ProtocolUnexpectedMessage, 0
						if phase == "current" {
							kind, result = diam.ProtocolRejectedDWA, diam.UnableToComply
						}
					}
					before := p.state(t)
					write(t, p.c, answer)
					notice := protocolErrorReceive(t, p.events)
					expected := *answer.Header
					expected.MessageLength = uint32(answer.Len())
					protocolErrorCheck(t, notice, p.s.c, expected, kind, result, false, diam.ProtocolReplyNone, 0, 0)
					p.fence(t)
					after := p.state(t)
					if after.pending != before.pending || after.health != before.health || after.num != before.num {
						t.Fatalf("invalid or unowned DWA changed watchdog credit: before=%+v after=%+v", before, after)
					}
					// This reply fences the wire and proves that the DWA selected no answer.
					request := watchdogRequest(t)
					write(t, p.c, request)
					next := read(t, p.c)
					if next.Header.CommandCode != request.Header.CommandCode || next.Header.HopByHopID != request.Header.HopByHopID || code(t, next) != diam.Success {
						t.Fatalf("DWA selected a reply or disturbed the next DWR: %+v", next.Header)
					}
					select {
					case extra := <-p.events:
						t.Fatalf("duplicate DWA notification: %+v", extra)
					default:
					}
				})
			}
		}
	}
}
