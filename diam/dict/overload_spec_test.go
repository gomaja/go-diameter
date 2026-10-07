package dict

import "testing"

// These expectations transcribe RFC 7683 §§7.1–7.8, RFC 8581 §§7.1–7.4,
// and RFC 8583 §§7.1–7.5 independently of the application-specific copies.
// Only Base is loaded so a Cx/Sh override cannot conceal a base definition error.
func TestBaseOverloadLoadAVPs(t *testing.T) {
	d := New(Base)
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
			byName, err := d.FindAVPByName(0, tc.name)
			if err != nil {
				t.Fatal(err)
			}
			byCode, err := d.FindAVP(0, tc.code, 0)
			if err != nil {
				t.Fatal(err)
			}
			if byName != byCode {
				t.Fatal("name and wire-code lookups disagree")
			}
			if byName.Name != tc.name || byName.Code != tc.code || byName.VendorID != 0 || byName.Data.TypeName != tc.typ {
				t.Fatalf("AVP = %+v, want name=%s code=%d vendor=0 type=%s", byName, tc.name, tc.code, tc.typ)
			}
			// Each RFC's flag table forbids V and leaves M to applications.
			if byName.Must != "" || byName.May != "" || byName.MustNot != "V" {
				t.Fatalf("flags: must=%q may=%q must-not=%q, want empty/empty/V", byName.Must, byName.May, byName.MustNot)
			}
		})
	}
}

func TestBaseOverloadLoadGroupedRules(t *testing.T) {
	d := New(Base)
	for _, tc := range []struct {
		name  string
		rules []Rule
	}{
		// RFC 7683 §7.1, replaced by RFC 8581 §7.1.
		{"OC-Supported-Features", []Rule{
			{AVP: "OC-Feature-Vector", Max: 1, MaxSet: true},
			{AVP: "SourceID", Max: 1, MaxSet: true},
			{AVP: "OC-Peer-Algo", Max: 1, MaxSet: true},
			{AVP: "AVP"},
		}},
		// RFC 7683 §7.3, replaced by RFC 8581 §7.2. Angle brackets
		// require the sequence number and report type in this fixed order.
		{"OC-OLR", []Rule{
			{AVP: "OC-Sequence-Number", Required: true, Max: 1, MaxSet: true, Fixed: true},
			{AVP: "OC-Report-Type", Required: true, Max: 1, MaxSet: true, Fixed: true},
			{AVP: "OC-Reduction-Percentage", Max: 1, MaxSet: true},
			{AVP: "OC-Validity-Duration", Max: 1, MaxSet: true},
			{AVP: "SourceID", Max: 1, MaxSet: true},
			{AVP: "AVP"},
		}},
		// RFC 8583 §7.1.
		{"Load", []Rule{
			{AVP: "Load-Type", Max: 1, MaxSet: true},
			{AVP: "Load-Value", Max: 1, MaxSet: true},
			{AVP: "SourceID", Max: 1, MaxSet: true},
			{AVP: "AVP"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := d.FindAVPByName(0, tc.name)
			if err != nil {
				t.Fatal(err)
			}
			if len(a.Data.Rule) != len(tc.rules) {
				t.Fatalf("rule count = %d, want %d", len(a.Data.Rule), len(tc.rules))
			}
			for i, want := range tc.rules {
				if got := a.Data.Rule[i]; *got != want {
					t.Errorf("rule %d = %+v, want %+v", i, *got, want)
				}
				if want.AVP != "AVP" {
					if _, err := d.FindAVPByName(0, want.AVP); err != nil {
						t.Errorf("rule %d does not resolve in Base: %v", i, err)
					}
				}
			}
		})
	}
}

func TestBaseOverloadLoadEnumerations(t *testing.T) {
	d := New(Base)
	for _, tc := range []struct {
		name  string
		items []Enum
	}{
		// RFC 7683 §7.6 with the addition from RFC 8581 §7.2.1.
		{"OC-Report-Type", []Enum{
			{Code: 0, Name: "HOST_REPORT"},
			{Code: 1, Name: "REALM_REPORT"},
			{Code: 2, Name: "PEER_REPORT"},
		}},
		// RFC 8583 §7.2.
		{"Load-Type", []Enum{
			{Code: 0, Name: "HOST"},
			{Code: 1, Name: "PEER"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := d.FindAVPByName(0, tc.name)
			if err != nil {
				t.Fatal(err)
			}
			if len(a.Data.Enum) != len(tc.items) {
				t.Fatalf("enumeration count = %d, want %d", len(a.Data.Enum), len(tc.items))
			}
			for i, want := range tc.items {
				if got := a.Data.Enum[i]; *got != want {
					t.Errorf("enumeration %d = %+v, want %+v", i, *got, want)
				}
			}
		})
	}
}
