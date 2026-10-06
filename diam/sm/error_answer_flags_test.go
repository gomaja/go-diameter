package sm

import (
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
)

func TestCxErrorAnswerCopiedGroupedFlagsTCP(t *testing.T) {
	for _, trigger := range []struct {
		name string
		code uint32
	}{
		{"validation missing Public-Identity", diam.MissingAVP},
		{"application error", diam.UnableToComply},
	} {
		for _, flags := range []struct {
			name string
			bits uint8
		}{
			{"child M clear", 0},
			{"child reserved bits", avp.Mbit | 0x1f},
		} {
			t.Run(trigger.name+"/"+flags.name, func(t *testing.T) {
				settings := testMessageErrorSettings()
				settings.ValidateRequests = true
				sm := mustNewStateMachine(t, settings)
				sm.HandleFunc("UAR", func(c diam.Conn, m *diam.Message) {
					if trigger.code == diam.MissingAVP {
						t.Error("request missing Public-Identity reached application handler")
						return
					}
					if err := sm.writeErrorAnswer(c, m, trigger.code, nil, false); err != nil {
						t.Errorf("write application error answer: %v", err)
					}
				})
				server := diamtest.NewServer(sm, dict.Default)
				defer server.Close()
				conn := dialHandshakeUnknownTest(t, server.Addr)
				defer func() { _ = conn.Close() }()

				request := diam.NewMessage(diam.UserAuthorization, diam.RequestFlag|diam.ProxiableFlag, diam.TGPP_CX_APP_ID, 0x12345678, 0x87654321, dict.Default)
				mustSMClientAVP(t, request, avp.SessionID, avp.Mbit, 0, datatype.UTF8String("cx-error-session"))
				mustSMClientAVP(t, request, avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{
					diam.NewAVP(avp.VendorID, flags.bits, 0, datatype.Unsigned32(10415)),
					diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(diam.TGPP_CX_APP_ID)),
				}})
				mustSMClientAVP(t, request, avp.AuthSessionState, avp.Mbit, 0, datatype.Enumerated(1))
				mustSMClientAVP(t, request, avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example"))
				mustSMClientAVP(t, request, avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example"))
				mustSMClientAVP(t, request, avp.DestinationRealm, avp.Mbit, 0, datatype.DiameterIdentity("example"))
				mustSMClientAVP(t, request, avp.UserName, avp.Mbit, 0, datatype.UTF8String("private@example"))
				mustSMClientAVP(t, request, avp.VisitedNetworkIdentifier, avp.Mbit, 10415, datatype.OctetString("example"))
				if trigger.code != diam.MissingAVP {
					mustSMClientAVP(t, request, avp.PublicIdentity, avp.Mbit, 10415, datatype.UTF8String("sip:public@example"))
					if err := request.Validate(); err != nil {
						t.Fatalf("invalid application-error fixture: %v", err)
					}
				} else if err := request.Validate(); err == nil || err.ResultCode != diam.MissingAVP || err.FailedAVP.Code != avp.PublicIdentity {
					t.Fatalf("fixture must fail only for missing Public-Identity: %v", err)
				}
				if _, err := request.WriteTo(conn); err != nil {
					t.Fatal(err)
				}
				if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				answer, err := diam.ReadMessage(conn, dict.Default)
				if err != nil {
					t.Fatalf("read Cx error answer %d: %v", trigger.code, err)
				}
				if !testResultCode(answer, trigger.code) || answer.Header.CommandFlags != diam.ProxiableFlag {
					t.Fatalf("unexpected Cx error answer: %v", answer)
				}
				if answer.Header.HopByHopID != request.Header.HopByHopID || answer.Header.EndToEndID != request.Header.EndToEndID {
					t.Fatal("error answer changed request identifiers")
				}
				if err := answer.ValidateOutgoing(); err != nil {
					t.Fatalf("error answer violates sending rules: %v", err)
				}
				vsa, err := answer.FindAVP(avp.VendorSpecificApplicationID, 0)
				if err != nil {
					t.Fatal(err)
				}
				group, ok := vsa.Data.(*diam.GroupedAVP)
				if !ok || len(group.AVP) != 2 || vsa.Flags != avp.Mbit {
					t.Fatalf("invalid copied VSA: %v", vsa)
				}
				for i, want := range []struct {
					code, value uint32
				}{{avp.VendorID, 10415}, {avp.AuthApplicationID, diam.TGPP_CX_APP_ID}} {
					child := group.AVP[i]
					if child.Code != want.code || child.VendorID != 0 || child.Flags != avp.Mbit || child.Data != datatype.Unsigned32(want.value) {
						t.Fatalf("copied VSA child %d = %v, want code %d value %d with M only", i, child, want.code, want.value)
					}
				}
			})
		}
	}
}
