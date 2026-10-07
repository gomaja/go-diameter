package sm

import (
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// TS 29.212 V20.0.0 Table 5.4.0.1; RFC 6733 §§5.3.6, 6.11: 3GPP authors Gx;
// ETSI supplies Logical-Access-ID and Physical-Access-ID, and 3GPP2 supplies
// 3GPP2-BSID, so a Gx node lists both in Supported-Vendor-Id.
func TestGxCapabilitiesWire(t *testing.T) {
	for _, dictionary := range []*dict.Parser{dict.Default, dict.New(dict.Gx)} {
		settings := *serverSettings
		settings.Dict = dictionary
		client := &Client{Handler: mustNew(&settings), Dict: dictionary}
		client.VendorSpecificApplicationID = []*diam.AVP{smVendorApp(16777238, 10415)}
		request, err := client.makeCER([]datatype.Address{localhostAddress})
		if err != nil {
			t.Fatal(err)
		}
		got := readSMCapabilities(t, request, dictionary)
		checkSMVendors(t, got.supported, []uint32{5535, 10415, 13019})
		if len(got.groups) != 1 || countSMGroup(got.groups, 16777238, 10415, avp.AuthApplicationID) != 1 {
			t.Fatalf("Gx VSAI = %+v", got.groups)
		}
	}
}
