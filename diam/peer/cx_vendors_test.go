package peer

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

type peerCapabilityGroup struct {
	app, vendor, kind uint32
}

type peerWireCapabilities struct {
	supported []uint32
	auth      []uint32
	acct      []uint32
	groups    []peerCapabilityGroup
}

func readPeerCapabilities(t *testing.T, message *diam.Message, dictionary *dict.Parser) peerWireCapabilities {
	t.Helper()
	wire, err := message.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := diam.ReadMessage(bytes.NewReader(wire), dictionary)
	if err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
	var got peerWireCapabilities
	for _, a := range decoded.AVP {
		switch a.Code {
		case avp.SupportedVendorID:
			got.supported = append(got.supported, uint32(a.Data.(datatype.Unsigned32)))
		case avp.AuthApplicationID:
			got.auth = append(got.auth, uint32(a.Data.(datatype.Unsigned32)))
		case avp.AcctApplicationID:
			got.acct = append(got.acct, uint32(a.Data.(datatype.Unsigned32)))
		case avp.VendorSpecificApplicationID:
			group := a.Data.(*diam.GroupedAVP)
			if len(group.AVP) != 2 || group.AVP[0].Code != avp.VendorID ||
				(group.AVP[1].Code != avp.AuthApplicationID && group.AVP[1].Code != avp.AcctApplicationID) {
				t.Fatalf("Vendor-Specific-Application-Id children = %v, want one Vendor-Id and one application ID", group.AVP)
			}
			got.groups = append(got.groups, peerCapabilityGroup{
				app:    uint32(group.AVP[1].Data.(datatype.Unsigned32)),
				vendor: uint32(group.AVP[0].Data.(datatype.Unsigned32)),
				kind:   group.AVP[1].Code,
			})
		}
	}
	t.Logf("request=%t Supported-Vendor-Id=%v Auth=%v Acct=%v VSAI=%+v", message.Header.CommandFlags&diam.RequestFlag != 0, got.supported, got.auth, got.acct, got.groups)
	return got
}

func countPeerGroup(groups []peerCapabilityGroup, app, vendor, kind uint32) int {
	count := 0
	for _, group := range groups {
		if group.app == app && group.vendor == vendor && group.kind == kind {
			count++
		}
	}
	return count
}

func checkPeerVendors(t *testing.T, got, want []uint32) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Supported-Vendor-Id = %v, want %v", got, want)
	}
}

func peerSupportedVendor(id uint32) *diam.AVP {
	return diam.NewAVP(avp.SupportedVendorID, avp.Mbit, 0, datatype.Unsigned32(id))
}

func peerAuth(id uint32) *diam.AVP {
	return diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(id))
}

func peerVendorApp(id, vendor uint32) *diam.AVP {
	return diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{
		diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(vendor)), peerAuth(id),
	}})
}

func TestPeerRejectsMalformedConfiguredVSAI(t *testing.T) {
	settings := testSettings("invalid.example.net")
	settings.VendorSpecificApplicationID = []*diam.AVP{diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{peerAuth(4)}})}
	if _, err := New(Config{Settings: settings}); err == nil || !strings.Contains(err.Error(), "exactly one Vendor-Id") {
		t.Fatalf("peer.New malformed VSAI error = %v", err)
	}
}

func TestPeerExplicitCapabilitiesVerbatim(t *testing.T) {
	settings := testSettings("explicit.example.net")
	settings.SupportedVendorID = []*diam.AVP{peerSupportedVendor(10415), peerSupportedVendor(42), peerSupportedVendor(10415)}
	settings.AuthApplicationID = []*diam.AVP{peerAuth(4), peerAuth(999), peerAuth(4)}
	settings.AcctApplicationID = []*diam.AVP{diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(3))}
	settings.VendorSpecificApplicationID = []*diam.AVP{peerVendorApp(4, 10415)}
	request, answer := peerMessages(t, Config{Settings: settings})
	for _, message := range []*diam.Message{request, answer} {
		got := readPeerCapabilities(t, message, dict.Default)
		if !reflect.DeepEqual(got.supported, []uint32{10415, 42, 10415}) ||
			!reflect.DeepEqual(got.auth, []uint32{4, 999, 4}) ||
			!reflect.DeepEqual(got.acct, []uint32{3}) ||
			!reflect.DeepEqual(got.groups, []peerCapabilityGroup{{app: 4, vendor: 10415, kind: avp.AuthApplicationID}}) {
			t.Errorf("explicit capabilities changed: %+v", got)
		}
	}
}

func TestPeerDictionaryApplicationFallbacks(t *testing.T) {
	for _, tc := range []struct {
		name       string
		dictionary *dict.Parser
		app        uint32
		vendor     uint32
		vendors    []uint32
	}{
		{"vendorless-private", dict.New(dict.Base), 16777999, 0, nil},
		{"bare-typeless", dict.New(dict.Base), 999, 0, nil},
		{"Gx-extended", dict.New(dict.Base, dict.NASREQ, dict.CreditControl, dict.RoRf, dict.Gx), 16777238, 10415, []uint32{5535, 9999, 10415, 13019, 45687}},
		{"Credit-Control-RoRf", dict.New(dict.Base, dict.NASREQ, dict.CreditControl, dict.RoRf), 4, 0, []uint32{5535, 10415, 13019, 45687}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var extension string
			switch tc.name {
			case "vendorless-private":
				extension = `<diameter><application id="16777999" type="auth" name="Private"/></diameter>`
			case "bare-typeless":
				extension = `<diameter><application id="999" name="Bare"/></diameter>`
			case "Gx-extended":
				extension = `<diameter><application id="16777238" type="auth" name="Gx extension"><vendor id="9999" name="Extension"/></application></diameter>`
			}
			if extension != "" {
				if err := tc.dictionary.Load(strings.NewReader(extension)); err != nil {
					t.Fatal(err)
				}
			}
			settings := testSettings(tc.name + ".example.net")
			settings.Dict = tc.dictionary
			request, answer := peerMessages(t, Config{Settings: settings})
			for _, message := range []*diam.Message{request, answer} {
				got := readPeerCapabilities(t, message, tc.dictionary)
				checkPeerVendors(t, got.supported, tc.vendors)
				if tc.vendor == 0 {
					if countPeerValue(got.auth, tc.app) != 1 {
						t.Errorf("plain Auth-Application-Id %d missing: %+v", tc.app, got)
					}
				} else if countPeerGroup(got.groups, tc.app, tc.vendor, avp.AuthApplicationID) != 1 {
					t.Errorf("application %d author %d missing: %+v", tc.app, tc.vendor, got)
				}
			}
		})
	}
}

func TestPeerManufacturerIsAdvertisedApplicationAuthor(t *testing.T) {
	settings := testSettings("3gpp.example.net")
	settings.VendorID = 10415
	settings.Dict = dict.New(dict.Base, dict.NASREQ, dict.CreditControl, dict.RoRf, dict.S6c, dict.S6a, dict.Cx, dict.Sy)
	request, answer := peerMessages(t, Config{Settings: settings})
	for _, message := range []*diam.Message{request, answer} {
		got := readPeerCapabilities(t, message, settings.Dict)
		if countPeerValue(got.supported, 10415) != 1 || countPeerValue(got.supported, 13019) != 1 {
			t.Errorf("3GPP manufacturer and Cx supplier missing: %+v", got)
		}
		for _, id := range []uint32{16777302, 16777216, 16777251} {
			if countPeerGroup(got.groups, id, 10415, avp.AuthApplicationID) != 1 {
				t.Errorf("application %d has no 3GPP author group: %+v", id, got)
			}
		}
	}
}

func peerMessages(t *testing.T, settings Config) (*diam.Message, *diam.Message) {
	t.Helper()
	manager, err := New(settings)
	if err != nil {
		t.Fatal(err)
	}
	defer closeManager(t, manager, nil)
	cfg := manager.baseSettings(nil)
	dictionary := settings.Settings.Dict
	if dictionary == nil {
		dictionary = dict.Default
	}
	request, err := base.BuildCER(dictionary, cfg)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := base.BuildCEA(request, cfg, diam.Success)
	if err != nil {
		t.Fatal(err)
	}
	return request, answer
}

// RFC 6733 §§5.3.6, 6.11 and TS 29.229 V19.1.0 §5.6: Cx uses one 3GPP
// application group and includes ETSI only as a supported AVP vendor.
func TestCxSupportedVendors(t *testing.T) {
	for _, tc := range []struct {
		name       string
		dictionary *dict.Parser
		want       []uint32
		cx         bool
	}{
		{"base-only", dict.New(dict.Base), nil, false},
		{"Cx", dict.New(dict.Base, dict.NASREQ, dict.Cx), []uint32{10415, 13019}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := testSettings("cx.example.net")
			settings.Dict = tc.dictionary
			request, answer := peerMessages(t, Config{Settings: settings})
			for _, message := range []*diam.Message{request, answer} {
				name := "CER"
				if message == answer {
					name = "CEA"
				}
				t.Run(name, func(t *testing.T) {
					got := readPeerCapabilities(t, message, tc.dictionary)
					checkPeerVendors(t, got.supported, tc.want)
					wantCxGroups := 0
					if tc.cx {
						wantCxGroups = 1
					}
					if n := countPeerGroup(got.groups, 16777216, 10415, avp.AuthApplicationID); n != wantCxGroups {
						t.Errorf("3GPP Cx groups = %d, want %d", n, wantCxGroups)
					}
					if n := countPeerGroup(got.groups, 16777216, 13019, avp.AuthApplicationID); n != 0 {
						t.Errorf("ETSI Cx groups = %d, want 0", n)
					}
				})
			}
		})
	}
}

func TestPeerS6aBundledCapabilities(t *testing.T) {
	settings := testSettings("s6a.example.net")
	settings.Dict = dict.New(dict.Base, dict.NASREQ, dict.CreditControl, dict.RoRf, dict.S6c, dict.S6a)
	request, answer := peerMessages(t, Config{Settings: settings})
	for _, message := range []*diam.Message{request, answer} {
		got := readPeerCapabilities(t, message, settings.Dict)
		checkPeerVendors(t, got.supported, []uint32{5535, 10415, 13019, 45687})
		if n := countPeerGroup(got.groups, 16777251, 10415, avp.AuthApplicationID); n != 1 {
			t.Errorf("3GPP S6a groups = %d, want 1", n)
		}
	}
}

func TestPeerDefaultDictionaryCapabilities(t *testing.T) {
	settings := testSettings("default.example.net")
	settings.Dict = dict.Default
	request, answer := peerMessages(t, Config{Settings: settings})
	for _, message := range []*diam.Message{request, answer} {
		name := "CER"
		if message == answer {
			name = "CEA"
		}
		t.Run(name, func(t *testing.T) {
			got := readPeerCapabilities(t, message, dict.Default)
			checkPeerVendors(t, got.supported, []uint32{5535, 10415, 13019, 45687})
			for _, app := range []uint32{1, 4} {
				if n := countPeerValue(got.auth, app); n != 1 {
					t.Errorf("plain Auth-Application-Id %d count = %d, want 1", app, n)
				}
			}
			if n := countPeerValue(got.acct, 3); n != 1 {
				t.Errorf("plain Acct-Application-Id 3 count = %d, want 1", n)
			}
			vendorApps := []uint32{16777216, 16777217, 16777236, 16777238, 16777251, 16777252, 16777265, 16777302, 16777312, 16777313}
			if len(got.groups) != len(vendorApps) {
				t.Errorf("vendor application group count = %d, want %d", len(got.groups), len(vendorApps))
			}
			for _, app := range vendorApps {
				if n := countPeerGroup(got.groups, app, 10415, avp.AuthApplicationID); n != 1 {
					t.Errorf("3GPP application %d groups = %d, want 1", app, n)
				}
			}
			for _, group := range got.groups {
				if group.app == 4 || group.vendor != 10415 {
					t.Errorf("unexpected vendor application group %+v", group)
				}
			}
		})
	}
}

func countPeerValue(values []uint32, want uint32) int {
	count := 0
	for _, value := range values {
		if value == want {
			count++
		}
	}
	return count
}

func TestPeerConfiguredSupportedVendors(t *testing.T) {
	for _, tc := range []struct {
		name         string
		manufacturer uint32
		configured   []*diam.AVP
		want         []uint32
	}{
		{"auto-42", 42, nil, []uint32{10415, 13019}},
		{"auto-own-3gpp", 10415, nil, []uint32{10415, 13019}},
		{"auto-own-etsi", 13019, nil, []uint32{10415}},
		{"duplicates", 42, []*diam.AVP{peerSupportedVendor(13019), peerSupportedVendor(42), peerSupportedVendor(10415), peerSupportedVendor(777), peerSupportedVendor(777)}, []uint32{13019, 42, 10415, 777, 777}},
		{"empty", 42, []*diam.AVP{}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := testSettings("configured.example.net")
			settings.Dict = dict.New(dict.Base, dict.NASREQ, dict.Cx)
			settings.VendorID = datatype.Unsigned32(tc.manufacturer)
			settings.SupportedVendorID = tc.configured
			request, answer := peerMessages(t, Config{Settings: settings})
			for _, message := range []*diam.Message{request, answer} {
				got := readPeerCapabilities(t, message, settings.Dict)
				checkPeerVendors(t, got.supported, tc.want)
			}
		})
	}
}

// RFC 6733 §2.4 assigns 0xffffffff to relays; its capability is a plain
// Auth-Application-Id and has no vendor application group.
func TestPeerRelayApplicationPlain(t *testing.T) {
	dictionary := dict.New(dict.Base)
	if err := dictionary.Load(bytes.NewReader([]byte(`<diameter><application id="4294967295" type="auth" name="Relay"/></diameter>`))); err != nil {
		t.Fatal(err)
	}
	settings := testSettings("relay.example.net")
	settings.Dict = dictionary
	request, answer := peerMessages(t, Config{Settings: settings})
	for _, message := range []*diam.Message{request, answer} {
		got := readPeerCapabilities(t, message, dictionary)
		if n := countPeerValue(got.auth, 0xffffffff); n != 1 {
			t.Errorf("plain relay Auth-Application-Id count = %d, want 1", n)
		}
		if len(got.groups) != 0 {
			t.Errorf("relay vendor application groups = %v, want none", got.groups)
		}
		checkPeerVendors(t, got.supported, nil)
	}
}
