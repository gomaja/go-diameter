package base_test

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

func capabilityFields(t *testing.T, m *diam.Message) []string {
	t.Helper()
	wire, err := m.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := diam.ReadMessage(bytes.NewReader(wire), dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	var fields []string
	for _, a := range decoded.AVP {
		switch a.Code {
		case avp.AuthApplicationID, avp.AcctApplicationID, avp.SupportedVendorID:
			fields = append(fields, fmt.Sprintf("%d=%d", a.Code, a.Data.(datatype.Unsigned32)))
		case avp.VendorSpecificApplicationID:
			var members []string
			for _, child := range a.Data.(*diam.GroupedAVP).AVP {
				members = append(members, fmt.Sprintf("%d=%d", child.Code, child.Data.(datatype.Unsigned32)))
			}
			fields = append(fields, fmt.Sprint(members))
		}
	}
	return fields
}

func TestCapabilityMetadataFallbacks(t *testing.T) {
	for _, tc := range []struct {
		name string
		apps []base.LocalApplication
		want []string
	}{
		{"no vendor", []base.LocalApplication{{ID: 16777999, AppType: "auth"}}, []string{"258=16777999"}},
		{"no type", []base.LocalApplication{{ID: 999}}, []string{"258=999"}},
		{"unknown type", []base.LocalApplication{{ID: 999, AppType: "other"}}, []string{"258=999"}},
		{"conflicting vendors", []base.LocalApplication{{ID: 16777238, AppType: "auth", Vendor: 10415}, {ID: 16777238, AppType: "auth", Vendor: 9999}}, []string{"265=9999", "265=10415", "[266=10415 258=16777238]"}},
		{"first lacks author", []base.LocalApplication{{ID: 16777999}, {ID: 16777999, AppType: "auth", Vendor: 9999}}, []string{"265=9999", "258=16777999"}},
		{"base excluded", []base.LocalApplication{{ID: 0, Vendor: 10415}}, nil},
		{"relay plain", []base.LocalApplication{{ID: 0xffffffff, Vendor: 10415, AppType: "acct"}}, []string{"265=10415", "259=4294967295"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := fixtureSettings()
			cfg.AcctApplicationID = nil
			cfg.Applications = tc.apps
			cer, err := base.BuildCER(dict.Default, cfg)
			if err != nil {
				t.Fatal(err)
			}
			cea, err := base.BuildCEA(cer, cfg, diam.Success)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range []*diam.Message{cer, cea} {
				if got := capabilityFields(t, m); !reflect.DeepEqual(got, tc.want) {
					t.Errorf("fields=%v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestExplicitCapabilitiesVerbatim(t *testing.T) {
	cfg := fixtureSettings()
	cfg.VendorID = 10415
	cfg.Applications = []base.LocalApplication{{ID: 4, Vendor: 0, AppType: "auth"}, {ID: 16777251, Vendor: 10415, AppType: "auth"}}
	cfg.AuthApplicationID = []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(16777251)), diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4))}
	cfg.AcctApplicationID = []*diam.AVP{diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(999))}
	cfg.VendorSpecificApplicationID = []*diam.AVP{capabilityGroup(4, 13019), capabilityGroup(4, 13019)}
	cfg.SupportedVendorID = []*diam.AVP{diam.NewAVP(avp.SupportedVendorID, avp.Mbit, 0, datatype.Unsigned32(13019)), diam.NewAVP(avp.SupportedVendorID, avp.Mbit, 0, datatype.Unsigned32(10415)), diam.NewAVP(avp.SupportedVendorID, avp.Mbit, 0, datatype.Unsigned32(13019))}
	want := []string{"265=13019", "265=10415", "265=13019", "258=16777251", "258=4", "259=999", "[266=13019 258=4]", "[266=13019 258=4]"}
	cer, err := base.BuildCER(dict.Default, cfg)
	if err != nil {
		t.Fatal(err)
	}
	cea, err := base.BuildCEA(cer, cfg, diam.Success)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []*diam.Message{cer, cea} {
		if got := capabilityFields(t, m); !reflect.DeepEqual(got, want) {
			t.Errorf("fields=%v, want %v", got, want)
		}
	}
}

func TestApplicationAuthorIncludesDeviceVendor(t *testing.T) {
	cfg := fixtureSettings()
	cfg.VendorID = 10415
	cfg.AcctApplicationID = nil
	cfg.Applications = []base.LocalApplication{{ID: 16777216, Vendor: 10415, SupportedVendors: []uint32{10415, 13019, 13019}}}
	cer, err := base.BuildCER(dict.Default, cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"265=10415", "265=13019", "[266=10415 258=16777216]"}
	if got := capabilityFields(t, cer); !reflect.DeepEqual(got, want) {
		t.Errorf("fields=%v, want %v", got, want)
	}
}

func TestEmptyExplicitApplicationsDisableInference(t *testing.T) {
	for _, kind := range []string{"auth", "acct", "vendor"} {
		t.Run(kind, func(t *testing.T) {
			cfg := fixtureSettings()
			cfg.AcctApplicationID = nil
			switch kind {
			case "auth":
				cfg.AuthApplicationID = []*diam.AVP{}
			case "acct":
				cfg.AcctApplicationID = []*diam.AVP{}
			case "vendor":
				cfg.VendorSpecificApplicationID = []*diam.AVP{}
			}
			cer, err := base.BuildCER(dict.Default, cfg)
			if err != nil {
				t.Fatal(err)
			}
			cea, err := base.BuildCEA(cer, cfg, diam.Success)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range []*diam.Message{cer, cea} {
				if got := capabilityFields(t, m); len(got) != 0 {
					t.Errorf("explicit empty apps: %v", got)
				}
			}
			if ids := base.AdvertisedApplicationIDs(cfg); ids == nil || len(ids) != 0 {
				t.Errorf("negotiated IDs=%v", ids)
			}
		})
	}
}

func TestInferredSuppliersFollowAdvertisedApplications(t *testing.T) {
	cfg := fixtureSettings()
	cfg.VendorID = 13019
	cfg.AcctApplicationID = nil
	cfg.Applications = []base.LocalApplication{
		{ID: 16777216, Vendor: 10415, AppType: "auth", SupportedVendors: []uint32{13019, 5535, 5535}},
		{ID: 16777251, Vendor: 9999, AppType: "auth", SupportedVendors: []uint32{7777}},
	}
	cfg.AuthApplicationID = []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(16777216))}
	cer, err := base.BuildCER(dict.Default, cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"265=5535", "265=10415", "258=16777216"}
	if got := capabilityFields(t, cer); !reflect.DeepEqual(got, want) {
		t.Errorf("fields=%v, want %v", got, want)
	}
	cfg.SupportedVendorID = []*diam.AVP{}
	cer, err = base.BuildCER(dict.Default, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := capabilityFields(t, cer); !reflect.DeepEqual(got, []string{"258=16777216"}) {
		t.Errorf("empty explicit vendors: %v", got)
	}
}

func TestExplicitVSAIValidity(t *testing.T) {
	member := func(code uint32, value uint32) *diam.AVP {
		return diam.NewAVP(code, avp.Mbit, 0, datatype.Unsigned32(value))
	}
	vendor := member(avp.VendorID, 10415)
	auth := member(avp.AuthApplicationID, 4)
	acct := member(avp.AcctApplicationID, 4)
	for _, tc := range []struct {
		name    string
		members []*diam.AVP
		valid   bool
	}{
		{"auth", []*diam.AVP{vendor, auth}, true},
		{"accounting", []*diam.AVP{vendor, acct}, true},
		{"order", []*diam.AVP{acct, vendor}, true},
		{"extension", []*diam.AVP{vendor, auth, member(99999, 42)}, true},
		{"no vendor", []*diam.AVP{auth}, false},
		{"two vendors", []*diam.AVP{vendor, vendor, auth}, false},
		{"no application", []*diam.AVP{vendor}, false},
		{"two auth", []*diam.AVP{vendor, auth, auth}, false},
		{"both types", []*diam.AVP{vendor, auth, acct}, false},
		{"wrong type", []*diam.AVP{vendor, diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.UTF8String("4"))}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := fixtureSettings()
			cfg.VendorSpecificApplicationID = []*diam.AVP{diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{AVP: tc.members})}
			if err := base.ValidateCapabilities(cfg); (err == nil) != tc.valid {
				t.Errorf("valid=%v: %v", tc.valid, err)
			}
		})
	}
}

func TestCapabilitiesDoNotRequireDictionaryMetadata(t *testing.T) {
	cfg := fixtureSettings()
	cfg.AcctApplicationID = nil
	cfg.Applications = []base.LocalApplication{{ID: 999}, {ID: 16777999}}
	cer, err := base.BuildCER(dict.New(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	cea, err := base.BuildCEA(cer, cfg, diam.Success)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []*diam.Message{cer, cea} {
		if got := capabilityFields(t, m); !reflect.DeepEqual(got, []string{"258=999", "258=16777999"}) {
			t.Errorf("fields=%v", got)
		}
	}
}

func TestExplicitCapabilitiesPreserveEncoding(t *testing.T) {
	cfg := fixtureSettings()
	cfg.AcctApplicationID = nil
	// RFC 6733 §6.11 permits extension AVPs. Preserve their vendor flag and
	// payload, and do not reorder the required members when sending a VSAI.
	group := diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{
		diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)),
		diam.NewAVP(4294967200, avp.Vbit, 13019, datatype.OctetString("\x00\x01\x02\x03\x04")),
		diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(10415)),
	}})
	cfg.VendorSpecificApplicationID = []*diam.AVP{group, group}
	if err := base.ValidateCapabilities(cfg); err != nil {
		t.Fatal(err)
	}
	expected, err := group.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	cer, err := base.BuildCER(dict.Default, cfg)
	if err != nil {
		t.Fatal(err)
	}
	cea, err := base.BuildCEA(cer, cfg, diam.Success)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []*diam.Message{cer, cea} {
		wire, err := m.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := diam.ReadMessage(bytes.NewReader(wire), dict.Default)
		if err != nil {
			t.Fatal(err)
		}
		groups, err := decoded.FindAVPs(avp.VendorSpecificApplicationID, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(groups) != 2 {
			t.Fatalf("explicit repeated groups=%d, want 2", len(groups))
		}
		for _, got := range groups {
			encoded, err := got.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encoded, expected) {
				t.Errorf("configured=%x, transmitted=%x", expected, encoded)
			}
		}
	}
}
