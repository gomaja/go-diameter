package dict

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestSMSApplicationsAndCommands(t *testing.T) {
	// 3GPP TS 29.338 V19.3.0 §§4.1, 5.3.2.2, 6.3.2.2; Tables 5.3.2.2/1, 6.3.2.2/1.
	for _, tc := range []struct {
		app      uint32
		commands []uint32
	}{
		{16777312, []uint32{8388647, 8388648, 8388649}},
		{16777313, []uint32{8388645, 8388646}},
	} {
		if _, err := Default.App(tc.app); err != nil {
			t.Errorf("application %d: %v", tc.app, err)
		}
		for _, code := range tc.commands {
			if _, err := Default.FindCommand(tc.app, code); err != nil {
				t.Errorf("application %d command %d: %v", tc.app, code, err)
			}
		}
	}
}

func TestSMSRequiredRules(t *testing.T) {
	// 3GPP TS 29.338 V19.3.0 §§5.3.2.3-5.3.2.8, 6.3.2.3-6.3.2.6.
	commonRequest := []string{"Session-Id", "Auth-Session-State", "Origin-Host", "Origin-Realm", "Destination-Realm"}
	commonAnswer := []string{"Session-Id", "Auth-Session-State", "Origin-Host", "Origin-Realm"}
	for _, tc := range []struct {
		app, code       uint32
		request, answer []string
	}{
		{16777312, 8388647, commonRequest, commonAnswer},
		{16777312, 8388648, append(slices.Clone(commonRequest), "SC-Address", "User-Identifier"), commonAnswer},
		{16777312, 8388649, append(slices.Clone(commonRequest), "User-Identifier", "SC-Address", "SM-Delivery-Outcome"), commonAnswer},
		{16777313, 8388645, append(slices.Clone(commonRequest), "SC-Address", "User-Identifier", "SM-RP-UI"), commonAnswer},
		{16777313, 8388646, []string{"Session-Id", "Auth-Session-State", "Origin-Host", "Origin-Realm", "Destination-Host", "Destination-Realm", "User-Name", "SC-Address", "SM-RP-UI"}, commonAnswer},
	} {
		cmd, err := Default.FindCommand(tc.app, tc.code)
		if err != nil {
			t.Fatal(err)
		}
		for _, side := range []struct {
			name  string
			rules []*Rule
			want  []string
		}{{"request", cmd.Request.Rule, tc.request}, {"answer", cmd.Answer.Rule, tc.answer}} {
			var got []string
			for _, rule := range side.rules {
				if rule.Required {
					got = append(got, rule.AVP)
				}
			}
			if !reflect.DeepEqual(got, side.want) {
				t.Errorf("%d/%d %s required = %v, want %v", tc.app, tc.code, side.name, got, side.want)
			}
		}
	}
}

func TestSMSAVPCodesAndTypes(t *testing.T) {
	// 3GPP TS 29.338 V19.3.0 Tables 5.3.3.1/1, 6.3.3.1/1-2.
	for _, tc := range []struct {
		name      string
		code      uint32
		typ       string
		mandatory bool
	}{
		{"SC-Address", 3300, "OctetString", true},
		{"SM-RP-UI", 3301, "OctetString", true},
		{"SM-Delivery-Failure-Cause", 3303, "Grouped", true},
		{"SM-RP-MTI", 3308, "Enumerated", true},
		{"SM-Delivery-Outcome", 3316, "Grouped", true},
		{"SMSMI-Correlation-ID", 3324, "Grouped", false},
		{"User-Identifier", 3102, "Grouped", true},
		{"MSISDN", 701, "OctetString", true},
	} {
		for _, app := range []uint32{16777312, 16777313} {
			a, err := Default.FindAVPWithVendor(app, tc.name, 10415)
			if err != nil {
				t.Fatal(err)
			}
			if a.Code != tc.code || a.Data.TypeName != tc.typ || a.VendorID != 10415 || strings.Contains(a.Must, "M") != tc.mandatory {
				t.Errorf("%d %s = %#v", app, tc.name, a)
			}
		}
	}
}

func TestSMSServingNodeReferences(t *testing.T) {
	// 3GPP TS 29.173 V19.0.0 §6.4.6, Table 6.4.1/1; TS 29.273
	// V19.2.0 §8.2.3.24, Table 8.2.3.0/1.
	for _, tc := range []struct {
		name string
		code uint32
		typ  string
		apps []uint32
	}{
		{"TGPP-AAA-Server-Name", 318, "DiameterIdentity", []uint32{4, 16777312, 16777313, 16777265}},
		{"LCS-Capabilities-Sets", 2404, "Unsigned32", []uint32{4, 16777312, 16777313}},
	} {
		for _, appID := range tc.apps {
			got, err := Default.FindAVPWithVendor(appID, tc.name, 10415)
			if err != nil || got.Code != tc.code || got.Data.TypeName != tc.typ || got.VendorID != 10415 || got.Must != "M,V" {
				t.Errorf("app %d %s: got %v, err %v", appID, tc.name, got, err)
			}
		}
	}
}

func TestSMSFlagRuleFormat(t *testing.T) {
	// Parse source XML so the check fails before code generation too.
	p, err := NewParser("testdata/tgpp_s6c.xml")
	if err != nil {
		t.Fatal(err)
	}
	app, err := p.App(16777312)
	if err != nil {
		t.Fatal(err)
	}
	var normalized int
	for _, avp := range app.AVP {
		if avp.Must == "MV" || avp.Must == "VM" {
			t.Errorf("%s has nonstandard flag notation %q", avp.Name, avp.Must)
		}
		if avp.Must == "M,V" || avp.Must == "V,M" {
			normalized++
		}
	}
	if normalized != 30 {
		t.Errorf("normalized dual-flag definitions = %d, want 30", normalized)
	}
}
