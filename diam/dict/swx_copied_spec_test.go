package dict

import (
	"encoding/json"
	"os"
	"testing"
)

type swxCopiedSpec struct {
	Roots []string
	AVPs  []swxAVPSpec
}

func loadSWxCopiedSpec(t *testing.T) swxCopiedSpec {
	t.Helper()
	b, err := os.ReadFile("testdata/swx_copied_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var s swxCopiedSpec
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.Roots) != 20 || len(s.AVPs) != 169 {
		t.Fatalf("incomplete copied SWx fixture: %d roots, %d definitions", len(s.Roots), len(s.AVPs))
	}
	return s
}

// TS 29.273 V19.2.0 Table 8.2.3.0/2: imported definitions and every named
// descendant are pinned to their source registry and grouped grammar.
func TestSWxCopiedSpec(t *testing.T) {
	s := loadSWxCopiedSpec(t)
	names := map[string]bool{}
	for _, a := range loadSWxSpec(t).AVPs {
		names[swxName(a.Name)] = true
	}
	seen := map[string]bool{}
	for _, want := range s.AVPs {
		name := swxName(want.Name)
		if seen[name] {
			t.Errorf("duplicate copied definition %s", want.Name)
		}
		seen[name] = true
		names[name] = true
	}
	for _, root := range s.Roots {
		if !names[swxName(root)] {
			t.Errorf("missing copied root %s", root)
		}
	}
	for _, want := range s.AVPs {
		t.Run(want.Name, func(t *testing.T) {
			a := swxLookup(t, want.Name)
			swxCheckAVP(t, a, want)
			for _, rule := range want.Rules {
				if rule.Name != "AVP" && !names[swxName(rule.Name)] {
					t.Errorf("uncovered descendant %s", rule.Name)
				}
			}
		})
	}
}

// The source closure includes command members as well as recursively reused
// groups, preventing a missing enum registry or leaf from silently escaping.
func TestSWxCopiedCoverage(t *testing.T) {
	s := loadSWxCopiedSpec(t)
	groups, rules, enums, values := 0, 0, 0, 0
	identities := map[[2]uint32]bool{}
	for _, a := range s.AVPs {
		key := [2]uint32{a.Code, a.Vendor}
		if identities[key] {
			t.Errorf("duplicate wire identity %v", key)
		}
		identities[key] = true
		if a.Type == "Grouped" {
			groups++
			rules += len(a.Rules)
			if len(a.Rules) == 0 {
				t.Errorf("missing grammar for %s", a.Name)
			}
		}
		if a.Type == "Enumerated" {
			enums++
			values += len(a.Items)
			if len(a.Items) == 0 {
				t.Errorf("missing registry for %s", a.Name)
			}
		}
	}
	if groups != 31 || rules != 197 || enums != 37 || values != 264 {
		t.Fatalf("closure groups/rules/enums/values %d/%d/%d/%d, want 31/197/37/264", groups, rules, enums, values)
	}
}
