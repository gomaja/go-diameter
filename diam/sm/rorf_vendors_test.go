package sm

import (
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// TS 32.299 V19.0.0 §§7.2–7.5 uses 3GPP, 3GPP2, ETSI and oneM2M AVPs; RFC 6733 §5.3.6 defines Supported-Vendor-Id.
func TestRoRfSupportedVendors(t *testing.T) {
	dictionary := dict.New(dict.RoRf)
	settings := *serverSettings
	settings.Dict = dictionary
	settings.HostIPAddresses = []datatype.Address{localhostAddress}
	handler := mustNew(&settings)
	client := &Client{Handler: handler, Dict: dictionary,
		AuthApplicationID: []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4))},
	}
	request, err := client.makeCER(settings.HostIPAddresses)
	if err != nil {
		t.Fatal(err)
	}
	got := readSMCapabilities(t, request, dictionary)
	checkSMVendors(t, got.supported, []uint32{5535, 10415, 13019, 45687})
}

// RFC 6733 §5.3.6: the charging refresh must preserve the inferred
// Supported-Vendor-Id set for every selectable bundle and the default bundle.
func TestRoRfAllBundleVendors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		bundles []dict.Bundled
		vendors []uint32
	}{
		{"default", nil, []uint32{5535, 10415, 13019, 45687}},
		{"base", []dict.Bundled{dict.Base}, nil},
		{"nasreq", []dict.Bundled{dict.NASREQ}, nil},
		{"credit-control", []dict.Bundled{dict.CreditControl}, []uint32{5535, 10415, 13019, 45687}},
		{"rorf", []dict.Bundled{dict.RoRf}, []uint32{5535, 10415, 13019, 45687}},
		{"gx", []dict.Bundled{dict.Gx}, []uint32{5535, 10415, 13019, 45687}},
		{"rx", []dict.Bundled{dict.Rx}, []uint32{5535, 10415, 13019, 45687}},
		{"sy", []dict.Bundled{dict.Sy}, []uint32{5535, 10415, 13019, 45687}},
		{"s6a", []dict.Bundled{dict.S6a}, []uint32{5535, 10415, 13019, 45687}},
		{"swx", []dict.Bundled{dict.SWx}, []uint32{5535, 10415, 13019, 45687}},
		{"s6c", []dict.Bundled{dict.S6c}, []uint32{5535, 10415, 13019, 45687}},
		{"sgd", []dict.Bundled{dict.SGd}, []uint32{5535, 10415, 13019, 45687}},
		{"s13", []dict.Bundled{dict.S13}, []uint32{10415}},
		{"cx", []dict.Bundled{dict.Cx}, []uint32{10415, 13019}},
		{"sh", []dict.Bundled{dict.Sh}, []uint32{10415, 13019}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := dict.Default
			if tc.bundles != nil {
				p = dict.New(tc.bundles...)
			}
			settings := *serverSettings
			settings.Dict = p
			settings.HostIPAddresses = []datatype.Address{localhostAddress}
			handler := mustNew(&settings)
			client := &Client{Handler: handler, Dict: p}
			request, err := client.makeCER(settings.HostIPAddresses)
			if err != nil {
				t.Fatal(err)
			}
			got := readSMCapabilities(t, request, p)
			checkSMVendors(t, got.supported, tc.vendors)
		})
	}
}
