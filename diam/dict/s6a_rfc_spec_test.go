package dict

import (
	"reflect"
	"testing"
)

// RFC 7683 §§7.1–7.8, updated by RFC 8581 §§7.1–7.4; RFC 8583 §7.
// TS 29.272 V19.6.0 Table 7.3.1/2 clears M for the enclosing S6a AVPs.
func TestS6aOverloadAndLoadSpec(t *testing.T) {
	for _, tc := range []struct {
		name string
		code uint32
		typ  string
	}{
		{"OC-Supported-Features", 621, "Grouped"},
		{"OC-Feature-Vector", 622, "Unsigned64"},
		{"OC-OLR", 623, "Grouped"},
		{"OC-Sequence-Number", 624, "Unsigned64"},
		{"OC-Validity-Duration", 625, "Unsigned32"},
		{"OC-Report-Type", 626, "Enumerated"},
		{"OC-Reduction-Percentage", 627, "Unsigned32"},
		{"OC-Peer-Algo", 648, "Unsigned64"},
		{"SourceID", 649, "DiameterIdentity"},
		{"Load", 650, "Grouped"},
		{"Load-Type", 651, "Enumerated"},
		{"Load-Value", 652, "Unsigned64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := Default.FindAVP(16777251, tc.name)
			if err != nil {
				t.Fatal(err)
			}
			if a.Code != tc.code || a.VendorID != 0 || a.Data.TypeName != tc.typ || a.Must != "" {
				t.Fatalf("code/vendor/type/must = %d/%d/%s/%s", a.Code, a.VendorID, a.Data.TypeName, a.Must)
			}
			wantMustNot := "V"
			if tc.code == 621 || tc.code == 623 || tc.code == 650 {
				wantMustNot = "M,V"
			}
			if a.MustNot != wantMustNot {
				t.Errorf("must-not = %q, want %q", a.MustNot, wantMustNot)
			}
		})
	}
	for _, tc := range []struct {
		name    string
		grammar string
	}{
		{"OC-Supported-Features", "[ OC-Feature-Vector ]\n[ SourceID ]\n[ OC-Peer-Algo ]\n*[ AVP ]"},
		{"OC-OLR", "< OC-Sequence-Number >\n< OC-Report-Type >\n[ OC-Reduction-Percentage ]\n[ OC-Validity-Duration ]\n[ SourceID ]\n*[ AVP ]"},
		{"Load", "[ Load-Type ]\n[ Load-Value ]\n[ SourceID ]\n*[ AVP ]"},
	} {
		a, err := Default.FindAVP(16777251, tc.name)
		if err != nil {
			t.Fatal(err)
		}
		if want := transcribeCommandRules(t, tc.grammar); !reflect.DeepEqual(a.Data.Rule, want) {
			t.Errorf("%s grammar differs from its RFC", tc.name)
		}
	}
	for _, tc := range []struct {
		code uint32
		want []Enum
	}{
		{626, []Enum{{Code: 0, Name: "HOST_REPORT"}, {Code: 1, Name: "REALM_REPORT"}, {Code: 2, Name: "PEER_REPORT"}}},
		{651, []Enum{{Code: 0, Name: "HOST"}, {Code: 1, Name: "PEER"}}},
	} {
		a, err := Default.FindAVPWithVendor(16777251, tc.code, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(a.Data.Enum) != len(tc.want) {
			t.Errorf("%s has %d enum values, want %d", a.Name, len(a.Data.Enum), len(tc.want))
		}
		for i, want := range tc.want {
			if i < len(a.Data.Enum) && *a.Data.Enum[i] != want {
				t.Errorf("%s enum %d = %+v, want %+v", a.Name, i, a.Data.Enum[i], want)
			}
		}
	}
}
