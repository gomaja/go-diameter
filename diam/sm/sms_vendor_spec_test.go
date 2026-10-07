package sm

import (
	"bytes"
	"slices"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// TS 29.338 V19.3.0 §4.7; RFC 6733 §5.3.6. S6c and SGd use vendor
// 10415. Their bundled charging dependency also advertises 5535 and 13019.
func TestSMSCERSupportedVendors(t *testing.T) {
	for _, bundle := range dict.AllBundled() {
		t.Run(string(bundle), func(t *testing.T) {
			dictionary := dict.New(bundle)
			settings := testMessageErrorSettings()
			settings.HostIPAddresses = []datatype.Address{localhostAddress}
			settings.VendorID = 1
			settings.ProductName = "sms-test"
			machine := mustNewStateMachine(t, settings)
			client := &Client{Dict: dictionary, Handler: machine}
			m, err := client.makeCER(settings.HostIPAddresses)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := m.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			got, err := diam.ReadMessage(bytes.NewReader(wire), dictionary)
			if err != nil {
				t.Fatal(err)
			}
			var vendors []uint32
			for _, a := range got.AVP {
				if a.Code == avp.SupportedVendorID {
					vendors = append(vendors, uint32(a.Data.(datatype.Unsigned32)))
				}
			}
			t.Logf("Supported-Vendor-Id %v", vendors)
			if bundle == dict.S6c || bundle == dict.SGd {
				if !slices.Equal(vendors, []uint32{5535, 10415, 13019}) {
					t.Errorf("vendors %v, want [5535 10415 13019]", vendors)
				}
			}
		})
	}
}
