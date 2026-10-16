package peer

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/sm"
)

// Close passes its uint32 cause through to the DPR. This is API
// compatibility for local callers; RFC 6733 §5.4.3 defines only values 0–2.
func TestManagerClosePreservesLocalDisconnectCause(t *testing.T) {
	for _, dialed := range []bool{false, true} {
		for _, cause := range []uint32{3, ^uint32(0)} {
			t.Run(fmt.Sprintf("dialed=%t/cause=%d", dialed, cause), func(t *testing.T) {
				m, c, _, _ := closingPeer(t, dialed)
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- m.Close(ctx, sm.DisconnectCause(cause)) }()
				if err := c.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
				dpr, err := diam.ReadMessage(c, m.dictionary())
				if err != nil {
					t.Fatalf("Close(%d) did not send DPR: %v", cause, err)
				}
				if dpr.Header.CommandCode != diam.DisconnectPeer || dpr.Header.CommandFlags&diam.RequestFlag == 0 {
					t.Fatalf("Close sent %+v", dpr.Header)
				}
				value, err := dpr.FindAVP(avp.DisconnectCause, 0)
				if err != nil || value.Data != datatype.Enumerated(cause) {
					t.Fatalf("Disconnect-Cause=%v, %v; want raw %d", value, err, cause)
				}
				answer, err := base.BuildDPA(dpr, testBase("known.example.net"))
				if err != nil {
					t.Fatal(err)
				}
				write(t, c, answer)
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				if p := m.Peers()[0]; p.State != Closed || p.Eligible {
					t.Fatalf("Close did not finish: %+v", p)
				}
			})
		}
	}
}
