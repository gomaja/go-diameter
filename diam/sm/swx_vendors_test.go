package sm

import (
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// TS 29.273 V19.2.0 Table 8.2.3.0/1 and §5.2.3.24 use 3GPP and ETSI AVPs;
// RFC 6733 §5.3.6 defines Supported-Vendor-Id.
func TestSWxSupportedVendors(t *testing.T) {
	for _, dictionary := range []*dict.Parser{dict.New(dict.SWx), dict.Default} {
		settings := *serverSettings
		settings.Dict = dictionary
		settings.HostIPAddresses = []datatype.Address{localhostAddress}
		handler := mustNew(&settings)
		client := &Client{Handler: handler, Dict: dictionary,
			VendorSpecificApplicationID: []*diam.AVP{smVendorApp(16777265, 10415)},
		}
		if dictionary == dict.Default {
			client.VendorSpecificApplicationID = nil
		}
		request, err := client.makeCER(settings.HostIPAddresses)
		if err != nil {
			t.Fatal(err)
		}
		got := readSMCapabilities(t, request, dictionary)
		want := []uint32{10415, 13019}
		if dictionary == dict.Default {
			want = []uint32{5535, 10415, 13019}
		}
		checkSMVendors(t, got.supported, want)
		if n := countSMGroup(got.groups, 16777265, 10415, avp.AuthApplicationID); n != 1 {
			t.Errorf("3GPP SWx groups = %d, want 1", n)
		}
		if n := countSMGroup(got.groups, 16777265, 13019, avp.AuthApplicationID); n != 0 {
			t.Errorf("ETSI SWx groups = %d, want 0", n)
		}
	}
}
