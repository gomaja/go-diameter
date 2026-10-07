package sm

import (
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// TS 29.219 V19.0.0 §5.1.5 and Table 5.4; RFC 6733 §§5.3.6, 6.11:
// 3GPP authors Sy; ETSI supplies Logical-Access-ID and Physical-Access-ID.
func TestSyCapabilitiesWire(t *testing.T) {
	for _, dictionary := range []*dict.Parser{dict.Default, dict.New(dict.Sy)} {
		settings := *serverSettings
		settings.Dict = dictionary
		client := &Client{Handler: mustNew(&settings), Dict: dictionary}
		client.VendorSpecificApplicationID = []*diam.AVP{smVendorApp(16777302, 10415)}
		request, err := client.makeCER([]datatype.Address{localhostAddress})
		if err != nil {
			t.Fatal(err)
		}
		got := readSMCapabilities(t, request, dictionary)
		checkSMVendors(t, got.supported, []uint32{10415, 13019})
		if len(got.groups) != 1 || countSMGroup(got.groups, 16777302, 10415, avp.AuthApplicationID) != 1 {
			t.Fatalf("Sy VSAI = %+v", got.groups)
		}
	}
}
