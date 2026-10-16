package protocol

import (
	"fmt"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
)

func TestLocalDisconnectAllowsOpaqueCause(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, cause := range []uint32{0, 1, 2, 3, ^uint32(0)} {
			t.Run(fmt.Sprintf("allow-any=%t/cause=%d", enabled, cause), func(t *testing.T) {
				c := opened(t, func(cfg *Config) { cfg.AllowAnyLocalDisconnectCause = enabled })
				in := event(Disconnect)
				in.Cause = cause
				if !enabled && cause > 2 {
					wantKinds(t, c.Handle(in), Notify)
					if c.Snapshot().Phase() != Open {
						t.Fatal("default rejected cause changed connection phase")
					}
					return
				}
				reservation := find(t, fence(t, c, in, false), ReserveIDs)
				allocated := event(ReserveResult)
				allocated.Token = reservation.Token
				allocated.Reservation = Reservation{Token: reservation.Token, Hop: 71, End: 72}
				sent := find(t, c.Handle(allocated), Send)
				value, err := sent.Message.FindAVP(avp.DisconnectCause, 0)
				if err != nil || value.Data != datatype.Enumerated(cause) {
					t.Fatalf("Disconnect-Cause=%v, %v; want %d", value, err, cause)
				}
				if sent.Message.Header.CommandCode != diam.DisconnectPeer || c.Snapshot().Phase() != Closing {
					t.Fatal("local disconnect did not send DPR in Closing")
				}
			})
		}
	}
}

func TestOpaqueLocalCauseDoesNotRelaxReceivedDPR(t *testing.T) {
	c := opened(t, func(cfg *Config) { cfg.AllowAnyLocalDisconnectCause = true })
	dpr := request(t, diam.DisconnectPeer)
	value, err := dpr.FindAVP(avp.DisconnectCause, 0)
	if err != nil {
		t.Fatal(err)
	}
	value.Data = datatype.Enumerated(3)
	answer := find(t, c.Handle(receive(dpr)), Send)
	if resultCode(t, answer.Message) != diam.InvalidAVPValue {
		t.Fatal("invalid received cause was not rejected with 5004")
	}
	if c.Snapshot().Phase() != Open {
		t.Fatal("invalid received cause changed connection phase")
	}
}
