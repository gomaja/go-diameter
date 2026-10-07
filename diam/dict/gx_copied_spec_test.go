package dict

import (
	"encoding/json"
	"os"
	"testing"
)

// gx_copied_spec.json independently pins reused grammars and recursively all
// their named descendants, including Gx's TS 29.212 V20.0.0 Table 5.4.0.1
// overrides. Source clauses and the original CCF are retained in the fixture.
func TestGxCopiedSpec(t *testing.T) {
	var spec struct {
		Roots []string
		AVPs  []struct {
			gxAVPSpec
			Rules []struct {
				s6aGroupedRuleSpec
				MustNot string `json:"must_not"`
			}
		}
	}
	b, err := os.ReadFile("testdata/gx_copied_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &spec); err != nil {
		t.Fatal(err)
	}
	if len(spec.Roots) != 11 || len(spec.AVPs) != 86 {
		t.Fatalf("incomplete fixture: %d roots, %d definitions", len(spec.Roots), len(spec.AVPs))
	}
	names := map[string]bool{}
	for _, want := range spec.AVPs {
		names[gxNormalized(want.Name)] = true
	}
	for _, root := range spec.Roots {
		if !names[gxNormalized(root)] {
			t.Errorf("missing root %s", root)
		}
	}
	for _, want := range spec.AVPs {
		t.Run(want.Name, func(t *testing.T) {
			a := gxLookup(t, want.Name)
			if a.Code != want.Code || a.VendorID != want.Vendor || a.Data.TypeName != want.Type {
				t.Errorf("identity/type = %d/%d/%s, want %d/%d/%s", a.Code, a.VendorID, a.Data.TypeName, want.Code, want.Vendor, want.Type)
			}
			if gxFlags(a.Must) != gxFlags(want.Must) || gxFlags(a.May) != gxFlags(want.May) || gxFlags(a.MustNot) != gxFlags(want.MustNot) {
				t.Errorf("flags = %q/%q/%q, want %q/%q/%q", a.Must, a.May, a.MustNot, want.Must, want.May, want.MustNot)
			}
			var rules []s6aGroupedRuleSpec
			for _, r := range want.Rules {
				rules = append(rules, r.s6aGroupedRuleSpec)
				if r.Name != "AVP" && !names[gxNormalized(r.Name)] {
					t.Errorf("uncovered descendant %s", r.Name)
				}
			}
			gxCheckRules(t, a.Data.Rule, rules)
			for i, r := range want.Rules {
				if i < len(a.Data.Rule) && gxFlags(a.Data.Rule[i].MustNot) != gxFlags(r.MustNot) {
					t.Errorf("member %s restriction = %q, want %q", r.Name, a.Data.Rule[i].MustNot, r.MustNot)
				}
			}
		})
	}
}
