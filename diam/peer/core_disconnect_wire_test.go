package peer

import (
	"fmt"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

// RFC 6733 §5.4.3: the first valid peer cause governs reconnect suppression,
// including a DPR received while our own DPR is awaiting its answer.
func TestManagerCrossedDPRKeepsFirstPeerCauseTCP(t *testing.T) {
	for _, dialed := range []bool{false, true} {
		for _, cause := range []uint32{0, 1, 2} {
			t.Run(fmt.Sprintf("dialed=%t/cause=%d", dialed, cause), func(t *testing.T) {
				p := newCoreActivityWire(t, dialed)
				p.a.post(event{kind: stop})
				local := read(t, p.c)
				if local.Header.CommandCode != diam.DisconnectPeer || local.Header.CommandFlags&diam.RequestFlag == 0 {
					t.Fatalf("local shutdown sent %+v", local.Header)
				}
				for _, receivedCause := range []uint32{cause, (cause + 1) % 3} {
					request, err := base.BuildDPR(p.m.dictionary(), testBase("known.example.net"), receivedCause)
					if err != nil {
						t.Fatal(err)
					}
					write(t, p.c, request)
					answer := read(t, p.c)
					if answer.Header.CommandCode != diam.DisconnectPeer || answer.Header.HopByHopID != request.Header.HopByHopID || answer.Header.EndToEndID != request.Header.EndToEndID || code(t, answer) != diam.Success {
						t.Fatalf("crossed DPR answer = %+v", answer)
					}
					var suppressed bool
					p.a.commit(event{testHook: func() { suppressed = p.a.suppressReconnect }}, newProtocolDelivery())
					if suppressed != (cause != 0) {
						t.Fatalf("first peer cause %d, later %d: suppression=%t", cause, receivedCause, suppressed)
					}
				}
				answer, err := base.BuildDPA(local, testBase("known.example.net"))
				if err != nil {
					t.Fatal(err)
				}
				write(t, p.c, answer)
				awaitState(t, p.m, Closed)
			})
		}
	}
}
