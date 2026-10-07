package base_test

import (
	"fmt"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

func TestBuildErrorAnswerRebuildsReceivedFlags(t *testing.T) {
	for _, flags := range []uint8{0, avp.Mbit | 0x1f, avp.Mbit | avp.Pbit, avp.Mbit | avp.Vbit} {
		for _, raw := range []bool{false, true} {
			t.Run(fmt.Sprintf("flags_%02x/raw_%t", flags, raw), func(t *testing.T) {
				// Received evidence may have invalid flags; NewAVP normalizes V.
				receivedAVP := func(code uint32, data datatype.Type) *diam.AVP {
					a := diam.NewAVP(code, flags, 0, data)
					a.Flags = flags
					a.Length = a.Len() - data.Padding()
					return a
				}
				request := diam.NewRequest(diam.UserAuthorization, diam.TGPP_CX_APP_ID, dict.Default)
				vendor := receivedAVP(avp.VendorID, datatype.Unsigned32(10415))
				application := receivedAVP(avp.AuthApplicationID, datatype.Unsigned32(diam.TGPP_CX_APP_ID))
				group := &diam.GroupedAVP{AVP: []*diam.AVP{vendor, application}}
				var data datatype.Type = group
				if raw {
					// A V bit with Vendor-Id zero cannot be decoded as a base AVP.
					if flags&avp.Vbit != 0 {
						t.Skip("inconsistent V tested on decoded AVPs")
					}
					data = datatype.Grouped(group.Serialize())
				}
				received := receivedAVP(avp.VendorSpecificApplicationID, data)
				request.AddAVP(received)
				request.AddAVP(receivedAVP(avp.SessionID, datatype.UTF8String("cx;123")))
				request.AddAVP(receivedAVP(avp.AuthSessionState, datatype.Enumerated(1)))
				answer, err := base.BuildErrorAnswer(request, fixtureSettings(), diam.InvalidAVPValue, []*diam.AVP{received}, false)
				if err != nil {
					t.Fatal(err)
				}
				validateBuiltMessage(t, answer)
				var copied *diam.AVP
				for _, a := range answer.AVP {
					if a.Code == avp.VendorSpecificApplicationID && a.VendorID == 0 {
						copied = a
						break
					}
				}
				if copied == nil {
					t.Fatal("missing Vendor-Specific-Application-Id")
				}
				rebuilt, ok := copied.Data.(*diam.GroupedAVP)
				if !ok {
					t.Fatalf("rebuilt group type = %T", copied.Data)
				}
				children := rebuilt.AVP
				if copied == received || copied.Flags != avp.Mbit || len(children) != 2 {
					t.Fatalf("rebuilt group = %v", copied)
				}
				for i, original := range group.AVP {
					if children[i] == original || children[i].Flags != avp.Mbit || children[i].Data != original.Data {
						t.Fatalf("rebuilt member %d = %v, original %v", i, children[i], original)
					}
					if original.Flags != flags {
						t.Fatal("request member flags changed")
					}
				}
				if received.Flags != flags {
					t.Fatal("request group flags changed")
				}
				failed, err := answer.FindAVP(avp.FailedAVP, 0)
				if err != nil {
					t.Fatal(err)
				}
				if failed.Data.(*diam.GroupedAVP).AVP[0] != received {
					t.Fatal("Failed-AVP evidence changed")
				}
				session, err := answer.FindAVP(avp.SessionID, 0)
				if err != nil || session.Data != datatype.UTF8String("cx;123") {
					t.Fatalf("Session-Id = %v, %v", session, err)
				}
				state, err := answer.FindAVP(avp.AuthSessionState, 0)
				if err != nil || state.Flags != avp.Mbit || state.Data != datatype.Enumerated(1) {
					t.Fatalf("Auth-Session-State = %v, %v", state, err)
				}
			})
		}
	}
}
