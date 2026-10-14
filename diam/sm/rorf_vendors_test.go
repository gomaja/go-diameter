package sm

import (
	"testing"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"
	"github.com/gomaja/go-diameter/diam/dict/cx"
	"github.com/gomaja/go-diameter/diam/dict/gx"
	"github.com/gomaja/go-diameter/diam/dict/nasreq"
	"github.com/gomaja/go-diameter/diam/dict/rorf"
	"github.com/gomaja/go-diameter/diam/dict/rx"
	"github.com/gomaja/go-diameter/diam/dict/s13"
	"github.com/gomaja/go-diameter/diam/dict/s6a"
	"github.com/gomaja/go-diameter/diam/dict/s6c"
	"github.com/gomaja/go-diameter/diam/dict/sgd"
	"github.com/gomaja/go-diameter/diam/dict/sh"
	"github.com/gomaja/go-diameter/diam/dict/swx"
	"github.com/gomaja/go-diameter/diam/dict/sy"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// TS 32.299 V19.0.0 §§7.2–7.5 uses 3GPP, 3GPP2, ETSI and oneM2M AVPs; RFC 6733 §5.3.6 defines Supported-Vendor-Id.
func TestRoRfSupportedVendors(t *testing.T) {
	testDict := newSMTestDictionary(dict.Base())
	serverSettings := cloneTestSettings(serverSettings, testDict)

	dictionary := newTestDictionary(rorf.Dictionary())
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
	testDict := newSMTestDictionary(dict.Base())
	serverSettings := cloneTestSettings(serverSettings, testDict)

	for _, tc := range []struct {
		name    string
		bundles []dict.Dictionary
		vendors []uint32
	}{
		{"base fallback", nil, nil},
		{"base", []dict.Dictionary{dict.Base()}, nil},
		{"nasreq", []dict.Dictionary{nasreq.Dictionary()}, nil},
		{"credit-control", []dict.Dictionary{creditcontrol.Dictionary()}, []uint32{5535, 10415, 13019, 45687}},
		{"rorf", []dict.Dictionary{rorf.Dictionary()}, []uint32{5535, 10415, 13019, 45687}},
		{"gx", []dict.Dictionary{gx.Dictionary()}, []uint32{5535, 10415, 13019, 45687}},
		{"rx", []dict.Dictionary{rx.Dictionary()}, []uint32{5535, 10415, 13019, 45687}},
		{"sy", []dict.Dictionary{sy.Dictionary()}, []uint32{5535, 10415, 13019, 45687}},
		{"s6a", []dict.Dictionary{s6a.Dictionary()}, []uint32{5535, 10415, 13019, 45687}},
		{"swx", []dict.Dictionary{swx.Dictionary()}, []uint32{5535, 10415, 13019, 45687}},
		{"s6c", []dict.Dictionary{s6c.Dictionary()}, []uint32{5535, 10415, 13019, 45687}},
		{"sgd", []dict.Dictionary{sgd.Dictionary()}, []uint32{5535, 10415, 13019, 45687}},
		{"s13", []dict.Dictionary{s13.Dictionary()}, []uint32{10415}},
		{"cx", []dict.Dictionary{cx.Dictionary()}, []uint32{10415, 13019}},
		{"sh", []dict.Dictionary{sh.Dictionary()}, []uint32{10415, 13019}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testDict
			if tc.bundles != nil {
				p = newTestDictionary(tc.bundles...)
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
