package diam

import (
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// marshalRATType returns the RAT-Type AVP that Message.Marshal builds, with
// the flags of its definition, in application app.
func marshalRATType(t *testing.T, app uint32) *AVP {
	t.Helper()
	m := NewMessage(0, 0, app, 1, 2, dict.Default)
	if err := m.Marshal(&struct {
		RATType datatype.Enumerated `avp:"RAT-Type"`
	}{1000}); err != nil {
		t.Fatal(err)
	}
	return m.AVP[0]
}

// TestRATTypeFlagsFollowEachApplication guards the M bit each bundled
// application gives RAT-Type (1032, 3GPP) on outgoing AVPs. Gx defines it
// as V must, P may, M must not (TS 29.212 V20.0.0 Table 5.3.0.1). SWx
// reuses it with a blank M-bit override (TS 29.273 V19.2.0 Table 8.2.3.0/2,
// NOTE 1), so the Gx rule applies; S6a overrides it to M must (TS 29.272
// V19.6.0 Table 7.3.1/2, NOTE 1).
func TestRATTypeFlagsFollowEachApplication(t *testing.T) {
	for _, tc := range []struct {
		name string
		app  uint32
		want uint8
	}{
		{"Gx", GX_CHARGING_CONTROL_APP_ID, avp.Vbit},
		{"SWx", TGPP_SWX_APP_ID, avp.Vbit},
		{"S6a", TGPP_S6A_APP_ID, avp.Vbit | avp.Mbit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := marshalRATType(t, tc.app).Flags; got != tc.want {
				t.Fatalf("RAT-Type flags = %#x, want %#x", got, tc.want)
			}
		})
	}
}

// TestSWxRATTypeWithoutMValidates guards that an SWx Multimedia-Auth-Request
// (TS 29.273 V19.2.0 §8.2.2.1) carrying RAT-Type as SWx defines it, V set
// and M clear, passes Message.Validate.
func TestSWxRATTypeWithoutMValidates(t *testing.T) {
	m := NewRequest(MultimediaAuth, TGPP_SWX_APP_ID, dict.Default)
	for _, a := range []*AVP{
		NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("aaa.example.org;1")),
		NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &GroupedAVP{AVP: []*AVP{
			NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(vendor3GPP)),
			NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(TGPP_SWX_APP_ID)),
		}}),
		NewAVP(avp.AuthSessionState, avp.Mbit, 0, datatype.Enumerated(1)),
		NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("aaa.example.org")),
		NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example.org")),
		NewAVP(avp.DestinationRealm, avp.Mbit, 0, datatype.DiameterIdentity("example.org")),
		NewAVP(avp.UserName, avp.Mbit, 0, datatype.UTF8String("001010000000001@example.org")),
		NewAVP(avp.RATType, avp.Vbit, vendor3GPP, datatype.Enumerated(0)),
		NewAVP(avp.SIPAuthDataItem, avp.Vbit|avp.Mbit, vendor3GPP, &GroupedAVP{}),
		NewAVP(avp.SIPNumberAuthItems, avp.Vbit|avp.Mbit, vendor3GPP, datatype.Unsigned32(1)),
	} {
		m.AddAVP(a)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}
