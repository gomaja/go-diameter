package sm

import (
	"sync/atomic"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
)

// RFC 6733 §§5.5.1,7.2: automatic validation/decoding error answers retain
// their rejection boundary; only the normal DWR response invokes OnDWA.
func TestAcceptedMalformedDWRBypassesAnswerHookWire(t *testing.T) {
	for _, malformed := range []string{"grammar", "decoding"} {
		t.Run(malformed, func(t *testing.T) {
			var calls atomic.Int32
			p := newProtocolDeliveryWire(t, 2, true, func(cfg *Settings) {
				cfg.OnDWA = func(diam.Conn, *diam.Message) { calls.Add(1) }
			})
			code := uint32(diam.MissingAVP)
			if malformed == "grammar" {
				p.send(t, protocolGenerationInvalidDWR(t, 0x93c0))
			} else {
				wire := testSMErrorMessage(t, diam.RequestFlag, []byte{0, 0, 1, 2, avp.Mbit, 0xff, 0xff, 0xff})
				wire[5], wire[6], wire[7] = 0, byte(diam.DeviceWatchdog>>8), byte(diam.DeviceWatchdog&0xff)
				writeSMErrorWire(t, p.peer, wire)
				code = diam.InvalidAVPLength
			}
			answer, err := diam.ReadMessage(p.peer, p.conn.Dictionary())
			if err != nil || !testResultCode(answer, code) {
				t.Fatalf("malformed DWR answer=%v error=%v", answer, err)
			}
			if got := calls.Load(); got != 0 {
				t.Fatalf("automatic DWR rejection invoked OnDWA %d times", got)
			}
			request := regressionDWR(t)
			setWireIdentity(t, request, avp.OriginHost, "peer.example")
			p.send(t, request)
			answer, err = diam.ReadMessage(p.peer, p.conn.Dictionary())
			if err != nil || !testResultCode(answer, diam.Success) || calls.Load() != 1 {
				t.Fatalf("normal DWR hook boundary: answer=%v error=%v calls=%d", answer, err, calls.Load())
			}
		})
	}
}
