package dict

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

type rxCopiedSpec struct {
	Roots []string
	AVPs  []rxAVPSpec
}

func loadRxCopiedSpec(t *testing.T) rxCopiedSpec {
	t.Helper()
	b, err := os.ReadFile("testdata/rx_copied_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var s rxCopiedSpec
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.Roots) != 9 || len(s.AVPs) != 34 {
		t.Fatalf("incomplete copied Rx fixture: %d roots, %d definitions; want 9/34", len(s.Roots), len(s.AVPs))
	}
	return s
}

// TS 29.214 V20.0.0 Table 5.4.0.1: imported definitions and every named
// descendant are pinned to their source registry and grouped grammar.
func TestRxCopiedSpec(t *testing.T) {
	s := loadRxCopiedSpec(t)
	names := map[string]bool{}
	for _, want := range s.AVPs {
		name := rxName(want.Name)
		if names[name] {
			t.Errorf("duplicate copied definition %s", want.Name)
		}
		names[name] = true
	}
	for _, root := range s.Roots {
		if !names[rxName(root)] {
			t.Errorf("missing copied root %s", root)
		}
	}
	for _, want := range s.AVPs {
		t.Run(want.Name, func(t *testing.T) {
			a := rxLookup(t, want.Name)
			rxCheckAVP(t, a, want)
			for _, rule := range want.Rules {
				if rule.Name != "AVP" && !names[rxName(rule.Name)] {
					t.Errorf("uncovered descendant %s", rule.Name)
				}
			}
		})
	}
}

// RFC 8506 §8.52 includes one optional extension AVP. All consumers must
// inherit the same definition from application 4, including Rx.
func TestRxUserEquipmentInfoExtensionInheritance(t *testing.T) {
	var want rxAVPSpec
	for _, a := range loadRxCopiedSpec(t).AVPs {
		if a.Name == "User-Equipment-Info-Extension" {
			want = a
			break
		}
	}
	if want.Name == "" {
		t.Fatal("missing User-Equipment-Info-Extension source fixture")
	}
	for _, app := range []uint32{4, 16777236, 16777238, 16777251, 16777265, 16777302, 16777312, 16777313} {
		t.Run(strconv.FormatUint(uint64(app), 10), func(t *testing.T) {
			a, err := Default.FindAVP(app, 653, 0)
			if err != nil {
				t.Fatal(err)
			}
			rxCheckAVP(t, a, want)
			if a.App.ID != 4 {
				t.Errorf("definition belongs to application %d, want inherited application 4", a.App.ID)
			}
		})
	}
}

// TS 29.214 V20.0.0 Table 5.4.0.1: the stated application-specific M
// policy applies to reused roots, including the nested unit and Load members.
func TestRxReusedMPolicy(t *testing.T) {
	for _, want := range loadRxSpec(t).Reused {
		t.Run(want.Name, func(t *testing.T) {
			a := rxLookup(t, want.Name)
			if !want.ClearM {
				return
			}
			if rxFlags(t, a.Must)&flagM != 0 || rxFlags(t, a.MustNot)&flagM == 0 {
				t.Errorf("%s: M must be cleared, flags %+v", a.Name, a)
			}
			if !want.NestedClearM {
				return
			}
			visited := map[string]bool{}
			var walk func(*AVP)
			walk = func(group *AVP) {
				if visited[group.Name] || group.Data.TypeName != "Grouped" {
					return
				}
				visited[group.Name] = true
				wildcardClearsM := false
				for _, r := range group.Data.Rule {
					if r.AVP == "AVP" {
						wildcardClearsM = rxFlags(t, r.MustNot)&flagM != 0
						continue
					}
					member := rxLookup(t, r.AVP)
					walk(member)
				}
				if group.Name == "Load" && !wildcardClearsM {
					t.Error("Load wildcard must prohibit M on every member")
				}
			}
			walk(a)
		})
	}
}

func TestRxCopiedEnumAndEncryptionCoverage(t *testing.T) {
	s := loadRxCopiedSpec(t)
	groups, enums, values, encrypt := 0, 0, 0, 0
	for _, a := range s.AVPs {
		if a.Type == "Grouped" {
			groups++
			if len(a.Rules) == 0 {
				t.Errorf("%s has no grouped rules", a.Name)
			}
		}
		if a.Items != nil {
			enums++
			values += len(a.Items)
			if len(a.Items) == 0 {
				t.Errorf("%s has empty enum registry", a.Name)
			}
			for code := range a.Items {
				if _, err := strconv.ParseInt(code, 10, 32); err != nil {
					t.Errorf("%s has invalid enum code %s", a.Name, code)
				}
			}
		}
		if strings.TrimSpace(a.MayEncrypt) != "" {
			encrypt++
		}
	}
	if groups != 9 || enums != 4 || values != 14 || encrypt != 3 {
		t.Fatalf("copied fixture groups/enums/values/encryption %d/%d/%d/%d, want 9/4/14/3", groups, enums, values, encrypt)
	}
}
