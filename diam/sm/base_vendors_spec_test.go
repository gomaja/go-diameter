package sm

import (
	"fmt"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// RFC 6733 §§5.3.6, 6.11: pin CER vendors for every application in Default.
// Base alone declares no vendors; the loaded TS 32.299 V19.0.0 §§7.2–7.4
// contribution to application 3 declares the three Rf charging suppliers.
func TestBaseRefreshApplicationVendors(t *testing.T) {
	for _, tc := range []struct {
		id      uint32
		vendors []uint32
	}{
		{0, nil}, {1, nil}, {3, []uint32{5535, 10415, 13019}}, {4, []uint32{5535, 10415, 13019}},
		{16777216, []uint32{10415, 13019}}, {16777217, []uint32{10415}},
		{16777236, []uint32{10415, 13019}}, {16777238, []uint32{5535, 10415, 13019}},
		{16777251, []uint32{10415}}, {16777252, []uint32{10415}},
		{16777265, []uint32{10415, 13019}}, {16777302, []uint32{10415, 13019}},
		{16777312, []uint32{10415}}, {16777313, []uint32{10415}},
	} {
		t.Run(fmt.Sprint(tc.id), func(t *testing.T) {
			settings := *serverSettings
			settings.Dict = dict.Default
			client := &Client{Handler: mustNew(&settings), Dict: dict.Default,
				AuthApplicationID: []*diam.AVP{}, AcctApplicationID: []*diam.AVP{}, VendorSpecificApplicationID: []*diam.AVP{},
			}
			switch {
			case tc.id == 0:
			case tc.id == 3:
				client.AcctApplicationID = []*diam.AVP{diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(tc.id))}
			case tc.id >= 16777216:
				client.VendorSpecificApplicationID = []*diam.AVP{smVendorApp(tc.id, 10415)}
			default:
				client.AuthApplicationID = []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(tc.id))}
			}
			request, err := client.makeCER([]datatype.Address{localhostAddress})
			if err != nil {
				t.Fatal(err)
			}
			got := readSMCapabilities(t, request, dict.Default)
			checkSMVendors(t, got.supported, tc.vendors)
		})
	}
}
