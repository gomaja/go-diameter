package base_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

func capabilityGroup(id, vendor uint32) *diam.AVP {
	return diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{
		diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(vendor)),
		diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(id)),
	}})
}

// RFC 6733 §§5.3.1–5.3.2, 6.11 and Verified Erratum 4808.
func TestApplicationAdvertisementPolicy(t *testing.T) {
	for _, tc := range []struct {
		id, author uint32
		vendors    []uint32
	}{
		{4, 0, []uint32{10415, 13019, 5535}},
		{16777215, 0, nil},
		{16777216, 10415, []uint32{10415, 13019}},
		{4294967294, 12345, []uint32{12345, 13019}},
		{4294967295, 0, nil},
	} {
		cfg := fixtureSettings()
		cfg.AcctApplicationID = nil
		cfg.Applications = []base.LocalApplication{{ID: tc.id, AppType: "auth", Vendor: tc.author, SupportedVendors: tc.vendors}}
		// With no explicit configuration, metadata determines the wire form.
		cer, err := base.BuildCER(dict.Default, cfg)
		if err != nil {
			t.Fatal(err)
		}
		cea, err := base.BuildCEA(cer, cfg, diam.Success)
		if err != nil {
			t.Fatal(err)
		}
		for _, message := range []*diam.Message{cer, cea} {
			wire, err := message.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := diam.ReadMessage(bytes.NewReader(wire), dict.Default)
			if err != nil {
				t.Fatal(err)
			}
			var plain []uint32
			var groups [][2]uint32
			for _, a := range decoded.AVP {
				switch a.Code {
				case avp.AuthApplicationID:
					plain = append(plain, uint32(a.Data.(datatype.Unsigned32)))
				case avp.VendorSpecificApplicationID:
					g := a.Data.(*diam.GroupedAVP)
					if len(g.AVP) != 2 {
						t.Fatalf("VSAI has %d members", len(g.AVP))
					}
					groups = append(groups, [2]uint32{uint32(g.AVP[0].Data.(datatype.Unsigned32)), uint32(g.AVP[1].Data.(datatype.Unsigned32))})
				}
			}
			if tc.author == 0 {
				if !reflect.DeepEqual(plain, []uint32{tc.id}) || len(groups) != 0 {
					t.Errorf("app %d: plain=%v groups=%v; want one plain application", tc.id, plain, groups)
				}
			} else if len(plain) != 0 || !reflect.DeepEqual(groups, [][2]uint32{{tc.author, tc.id}}) {
				t.Errorf("app %d: plain=%v groups=%v; want one author group %d", tc.id, plain, groups, tc.author)
			}
		}
	}
}

func TestSupportedVendorPolicy(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		cfg := fixtureSettings()
		cfg.VendorID = 10415
		cfg.AcctApplicationID = nil
		cfg.Applications = []base.LocalApplication{
			{ID: 16777216, AppType: "auth", Vendor: 10415, SupportedVendors: []uint32{13019, 10415, 13019}},
			{ID: 16777251, AppType: "auth", Vendor: 10415, SupportedVendors: []uint32{5535}},
		}
		cfg.VendorSpecificApplicationID = []*diam.AVP{capabilityGroup(16777216, 10415)}
		want := []uint32{10415, 13019}
		if explicit {
			cfg.SupportedVendorID = []*diam.AVP{
				diam.NewAVP(avp.SupportedVendorID, avp.Mbit, 0, datatype.Unsigned32(9000)),
				diam.NewAVP(avp.SupportedVendorID, avp.Mbit, 0, datatype.Unsigned32(10415)),
				diam.NewAVP(avp.SupportedVendorID, avp.Mbit, 0, datatype.Unsigned32(9000)),
			}
			want = []uint32{9000, 10415, 9000}
		}
		cer, err := base.BuildCER(dict.Default, cfg)
		if err != nil {
			t.Fatal(err)
		}
		var got []uint32
		for _, a := range cer.AVP {
			if a.Code == avp.SupportedVendorID {
				got = append(got, uint32(a.Data.(datatype.Unsigned32)))
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("explicit=%t Supported-Vendor-Id=%v, want %v", explicit, got, want)
		}
	}
}

func TestMalformedConfiguredApplications(t *testing.T) {
	for _, group := range []*diam.AVP{
		nil,
		diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)),
		diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{}),
		&diam.AVP{Code: avp.VendorSpecificApplicationID, Flags: avp.Mbit, Data: &diam.GroupedAVP{AVP: []*diam.AVP{nil}}},
	} {
		cfg := fixtureSettings()
		cfg.VendorSpecificApplicationID = []*diam.AVP{group}
		if err := base.ValidateCapabilities(cfg); err == nil {
			t.Errorf("accepted malformed configured VSAI: %v", group)
		}
	}
	cfg := fixtureSettings()
	cfg.AuthApplicationID = []*diam.AVP{nil}
	if err := base.ValidateCapabilities(cfg); err == nil {
		t.Error("accepted nil configured application")
	}
}

func TestVendorAccountingApplication(t *testing.T) {
	cfg := fixtureSettings()
	cfg.AcctApplicationID = nil
	cfg.Applications = []base.LocalApplication{{ID: 16777216, AppType: "acct", Vendor: 10415, SupportedVendors: []uint32{13019}}}
	group := capabilityGroup(16777216, 10415)
	group.Data.(*diam.GroupedAVP).AVP[1].Code = avp.AcctApplicationID
	cfg.VendorSpecificApplicationID = []*diam.AVP{group}
	cer, err := base.BuildCER(dict.Default, cfg)
	if err != nil {
		t.Fatal(err)
	}
	cea, err := base.BuildCEA(cer, cfg, diam.Success)
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range []*diam.Message{cer, cea} {
		wire, err := message.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := diam.ReadMessage(bytes.NewReader(wire), dict.Default)
		if err != nil {
			t.Fatal(err)
		}
		groups, err := decoded.FindAVPs(avp.VendorSpecificApplicationID, 0)
		if err != nil || len(groups) != 1 {
			t.Fatalf("accounting VSAI: %v, %v", groups, err)
		}
		members := groups[0].Data.(*diam.GroupedAVP).AVP
		if len(members) != 2 || members[0].Data != datatype.Unsigned32(10415) || members[1].Code != avp.AcctApplicationID || members[1].Data != datatype.Unsigned32(16777216) {
			t.Fatalf("wrong accounting capability: %v", members)
		}
	}
}
