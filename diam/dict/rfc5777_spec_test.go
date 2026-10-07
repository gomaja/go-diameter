package dict

import (
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"testing"
)

func loadRFC5777Spec(t *testing.T) creditControlSpec {
	t.Helper()
	b, err := os.ReadFile("testdata/rfc5777_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec creditControlSpec
	if err := json.Unmarshal(b, &spec); err != nil {
		t.Fatal(err)
	}
	groups, rules, enums := 0, 0, 0
	for _, a := range spec.AVPs {
		if a.Type == "Grouped" {
			groups++
		}
		rules += len(a.Rules)
		enums += len(a.Items)
	}
	if len(spec.AVPs) != 71 || groups != 23 || rules != 115 || enums != 292 {
		t.Fatalf("incomplete RFC 5777 fixture: %d AVPs, %d groups, %d rules, %d values", len(spec.AVPs), groups, rules, enums)
	}
	return spec
}

// RFC 5777 §§3–6, 10.1; Verified Errata 2333–2336. RFC 6733 §4.1
// governs vendor-zero flags; §3.2 and Erratum 4803 govern CCF notation.
func TestRFC5777EffectiveDefinitions(t *testing.T) {
	spec := loadRFC5777Spec(t)
	for _, app := range []uint32{4, 16777236, 16777238, 16777251, 16777265, 16777302, 16777312, 16777313} {
		t.Run(strconv.FormatUint(uint64(app), 10), func(t *testing.T) {
			for _, want := range spec.AVPs {
				t.Run(want.Name, func(t *testing.T) {
					got, err := Default.FindAVP(app, want.Code, 0)
					if err != nil {
						t.Fatal(err)
					}
					byName, err := Default.FindAVPByName(app, want.Name)
					if err != nil || byName != got {
						t.Fatalf("name/code disagree: %v", err)
					}
					if got.Name != want.Name || got.Code != want.Code || got.VendorID != 0 || got.Data.TypeName != want.Type {
						t.Errorf("identity/type = %s/%d/%d/%s", got.Name, got.Code, got.VendorID, got.Data.TypeName)
					}
					may, origin := want.May, uint32(4)
					if got.App.ID != origin {
						t.Errorf("origin %d, want %d", got.App.ID, origin)
					}
					if creditControlFlagSet(t, got.Must) != creditControlFlagSet(t, want.Must) || creditControlFlagSet(t, got.May) != creditControlFlagSet(t, may) || creditControlFlagSet(t, got.MustNot) != creditControlFlagSet(t, want.MustNot) || got.MayEncrypt != "" {
						t.Errorf("flags/encryption %q/%q/%q/%q", got.Must, got.May, got.MustNot, got.MayEncrypt)
					}
					if len(got.Data.Enum) != len(want.Items) {
						t.Errorf("enum count %d, want %d", len(got.Data.Enum), len(want.Items))
					}
					for _, e := range got.Data.Enum {
						if label, ok := want.Items[strconv.Itoa(int(e.Code))]; !ok || label != e.Name {
							t.Errorf("enum %d=%q, want %q", e.Code, e.Name, label)
						}
					}
					checkCreditControlRules(t, got.Data.Rule, want.Rules)
					for _, r := range want.Rules {
						if r.Name != "AVP" {
							if _, err := Default.FindAVPByName(app, r.Name); err != nil {
								t.Errorf("unresolved %s: %v", r.Name, err)
							}
						}
					}
				})
			}
		})
	}
	// The remaining six of fourteen effective application views do not
	// inherit application 4. QoS support must not leak into their dictionaries.
	for _, app := range []uint32{0, 1, 3, 16777216, 16777217, 16777252} {
		for _, a := range spec.AVPs {
			if _, err := Default.FindAVP(app, a.Code, 0); !errors.Is(err, ErrNotFound) {
				t.Errorf("app %d unexpectedly resolves %s: %v", app, a.Name, err)
			}
		}
	}
}
