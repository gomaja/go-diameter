package dict

import "testing"

// TS 29.173 V19.0.0 §§6.4.5, 6.4.13–6.4.14 define the inherited
// node identities. TS 29.272 V19.6.0 Table 7.3.1/2 reuses Supported-Features
// and Feature-List-ID. Identical definitions resolve to their Ro/Rf owner.
func TestS6aRefreshInheritedAVPs(t *testing.T) {
	for _, d := range []*Parser{Default, New(S6a, S6c, CreditControl, RoRf, NASREQ, Base)} {
		for _, tc := range []struct {
			name string
			code uint32
			typ  string
		}{
			{"MSC-Number", 2403, "OctetString"},
			{"SGSN-Name", 2409, "DiameterIdentity"},
			{"SGSN-Realm", 2410, "DiameterIdentity"},
			{"Supported-Features", 628, "Grouped"},
			{"Feature-List-ID", 629, "Unsigned32"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				a, err := d.FindAVPByName(16777251, tc.name)
				if err != nil {
					t.Fatal(err)
				}
				owner := uint32(4)
				byCode, err := d.FindAVP(16777251, tc.code, 10415)
				if err != nil || a != byCode || a.Code != tc.code || a.Data.TypeName != tc.typ || a.App.ID != owner {
					t.Fatalf("%s: definition=%+v owner=%d code lookup=%+v err=%v; want owner %d", tc.name, a, a.App.ID, byCode, err, owner)
				}
				if tc.code == 629 && (a.Must != "V" || a.MustNot != "M") {
					t.Fatalf("Feature-List-ID flags: must=%q must-not=%q", a.Must, a.MustNot)
				}
			})
		}
	}
}

// RFC 5777 §§4.2.2–4.2.4; TS 29.336 V20.0.0 §8.4.30 imports these
// fields for Scheduled-Communication-Time, used by S6a communication patterns.
// TS 29.272 V19.6.0 has no override: inherit the defining application-4 AVPs.
func TestS6aRefreshInheritedTimeAVPs(t *testing.T) {
	for _, tc := range []struct {
		name string
		code uint32
	}{
		{"Time-Of-Day-Start", 561},
		{"Time-Of-Day-End", 562},
		{"Day-Of-Week-Mask", 563},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := New(S6a)
			a, err := d.FindAVPByName(16777251, tc.name)
			if err != nil {
				t.Fatal(err)
			}
			if a.App.ID != 4 || a.Code != tc.code || a.Data.TypeName != "Unsigned32" || a.Must != "-" || a.May != "M" || a.MustNot != "V" {
				t.Fatalf("S6a time definition: %+v owner=%d", a, a.App.ID)
			}
			if _, err := d.FindAVP(0, tc.code, 0); err == nil {
				t.Fatal("time AVP leaked into base")
			}
		})
	}
}

// TS 29.272 V19.6.0 Table 7.3.1/2 applies the same M-bit policy to S13/S13'.
func TestS13RefreshDRMP(t *testing.T) {
	d := New(Base, S13)
	a, err := d.FindAVPByName(16777252, "DRMP")
	if err != nil {
		t.Fatal(err)
	}
	if a.App.ID != 16777252 || a.Code != 301 || a.Data.TypeName != "Enumerated" || a.Must != "" || a.MustNot != "M,V" || len(a.Data.Enum) != 16 {
		t.Fatalf("S13 DRMP definition: %+v owner=%d", a, a.App.ID)
	}
	for i, item := range a.Data.Enum {
		if item.Code != int32(i) {
			t.Errorf("priority %d has code %d", i, item.Code)
		}
	}
	base, err := d.FindAVPByName(0, "DRMP")
	if err != nil || base.MustNot != "V" {
		t.Fatalf("base DRMP changed: %+v, %v", base, err)
	}
}

// TS 29.229 V19.1.0 §6.3.29; reused by TS 29.272 V19.6.0 Table 7.3.1/2.
func TestS6aRefreshSupportedFeaturesGrammar(t *testing.T) {
	for _, appID := range []uint32{16777251, 4, 16777236} {
		a, err := Default.FindAVPByName(appID, "Supported-Features")
		if err != nil {
			t.Fatal(err)
		}
		want := []Rule{
			{AVP: "Vendor-Id", Required: true, Max: 1, MaxSet: true},
			{AVP: "Feature-List-ID", Required: true, Max: 1, MaxSet: true},
			{AVP: "Feature-List", Required: true, Max: 1, MaxSet: true},
			{AVP: "AVP"},
		}
		if len(a.Data.Rule) != len(want) {
			t.Fatalf("Supported-Features has %d rules, want %d including extension wildcard", len(a.Data.Rule), len(want))
		}
		for i, rule := range want {
			if *a.Data.Rule[i] != rule {
				t.Errorf("rule %d: %+v, want %+v", i, *a.Data.Rule[i], rule)
			}
		}
	}
}
