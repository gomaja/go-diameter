package peer

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/sm"
)

func TestManagerCloseRejectsInvalidLocalDisconnectCause(t *testing.T) {
	for _, dialed := range []bool{false, true} {
		for _, cause := range []uint32{3, ^uint32(0)} {
			t.Run(fmt.Sprintf("dialed=%t/cause=%d", dialed, cause), func(t *testing.T) {
				m, c, _, _ := closingPeer(t, dialed)
				before := m.Peers()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				err := m.Close(ctx, sm.DisconnectCause(cause))
				if fmt.Sprint(err) != fmt.Sprintf("invalid Disconnect-Cause %d", cause) || fmt.Sprintf("%T", err) != "*errors.errorString" {
					t.Fatalf("Close(%d) error=%T %v", cause, err, err)
				}
				if m.closing || !reflect.DeepEqual(m.Peers(), before) {
					t.Fatal("invalid cause changed manager shutdown or peer state")
				}
				probe := watchdogRequest(t)
				write(t, c, probe)
				if answer := read(t, c); answer.Header.CommandCode != probe.Header.CommandCode || answer.Header.HopByHopID != probe.Header.HopByHopID {
					t.Fatalf("invalid Close sent a DPR or stopped the peer: %+v", answer.Header)
				}
			})
		}
	}
}
