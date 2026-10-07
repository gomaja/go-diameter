package dict

import (
	"encoding/json"
	"os"
	"strconv"
	"testing"
)

// TS 29.212 V20.0.0 §5.3.31 defines the complete RAT-Type enumeration.
// Every effective application view must retain the complete list, whether
// declared locally or inherited from a bundled dependency.
func TestRATTypeSpec(t *testing.T) {
	data, err := os.ReadFile("testdata/s6a_enums_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture map[string]s6aEnumExpectation
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	want := fixture["RAT-Type"].Items
	if len(want) != 37 {
		t.Fatalf("specification fixture has %d values, want 37", len(want))
	}
	cases := []struct {
		bundle                      Bundled
		app                         uint32
		must, may, mustNot, encrypt string
	}{
		// TS 29.272 V19.6.0 Table 7.3.1/2 overrides the defining M bit.
		{S6a, 16777251, "M,V", "P", "", "Y"},
		// TS 29.214 V20.0.0 §5.4 retains TS 29.212 Table 5.3.0.1 flags.
		{Rx, 16777236, "V", "P", "M", "Y"},
		{RoRf, 4, "V", "P", "M", "Y"},
		// TS 29.273 V19.2.0 Table 8.2.3.0/2 NOTE 1: blank M retains defining flags.
		{SWx, 16777265, "V", "P", "M", "Y"},
	}
	for _, tc := range cases {
		t.Run(string(tc.bundle), func(t *testing.T) {
			// Reused AVPs may come from a bundled dependency. Check the
			// application's effective view with both loader configurations.
			selected := mustRATType(t, New(tc.bundle), tc.app)
			for label, a := range map[string]*AVP{"selected": selected, "default": mustRATType(t, Default, tc.app)} {
				t.Run(label, func(t *testing.T) {
					if a.Name != "RAT-Type" || a.Data.TypeName != "Enumerated" || len(a.Data.Enum) != len(want) {
						t.Fatalf("RAT-Type identity/type/count = %s/%s/%d", a.Name, a.Data.TypeName, len(a.Data.Enum))
					}
					seen := make(map[int32]bool)
					for _, item := range a.Data.Enum {
						if seen[item.Code] {
							t.Fatalf("duplicate code %d", item.Code)
						}
						seen[item.Code] = true
						if name, ok := want[strconv.FormatInt(int64(item.Code), 10)]; !ok || item.Name != name {
							t.Errorf("code %d name %q; spec %q (present %t)", item.Code, item.Name, name, ok)
						}
						e, err := Default.Enum(tc.app, 1032, 10415, item.Code)
						if err != nil || *e != *item {
							t.Fatalf("enum %d = %v, %v", item.Code, e, err)
						}
					}
					if a.Must != tc.must || a.May != tc.may || a.MustNot != tc.mustNot || a.MayEncrypt != tc.encrypt {
						t.Errorf("flags %q/%q/%q/%q; want %q/%q/%q/%q", a.Must, a.May, a.MustNot, a.MayEncrypt, tc.must, tc.may, tc.mustNot, tc.encrypt)
					}
				})
			}
		})
	}
}

func mustRATType(t *testing.T, p *Parser, app uint32) *AVP {
	t.Helper()
	a, err := p.FindAVP(app, 1032, 10415)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
