package sm

import (
	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"testing"
)

// TS 29.214 V20.0.0 Table 5.4.0.1 requires ETSI advertisement for
// Reservation-Priority; RFC 6733 §5.3.6 defines Supported-Vendor-Id.
func TestRxSupportedVendors(t *testing.T) {
	dictionary := dict.New(dict.Rx)
	settings := *serverSettings
	settings.Dict = dictionary
	settings.HostIPAddresses = []datatype.Address{localhostAddress}
	handler := mustNew(&settings)
	client := &Client{Handler: handler, Dict: dictionary,
		VendorSpecificApplicationID: []*diam.AVP{smVendorApp(16777236, 10415)},
	}
	request, err := client.makeCER(settings.HostIPAddresses)
	if err != nil {
		t.Fatal(err)
	}
	got := readSMCapabilities(t, request, dictionary)
	checkSMVendors(t, got.supported, []uint32{10415, 13019})
	if n := countSMGroup(got.groups, 16777236, 10415, avp.AuthApplicationID); n != 1 {
		t.Errorf("3GPP Rx groups = %d, want 1", n)
	}
	if n := countSMGroup(got.groups, 16777236, 13019, avp.AuthApplicationID); n != 0 {
		t.Errorf("ETSI Rx groups = %d, want 0", n)
	}
}
