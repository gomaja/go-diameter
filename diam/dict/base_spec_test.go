package dict

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

type baseSpec struct {
	AVPs     []rxAVPSpec
	Commands []struct {
		Section            string
		Code               uint32
		Request, Proxiable bool
		Rules              []rxRuleSpec
	}
}

func loadBaseSpec(t *testing.T) baseSpec {
	t.Helper()
	b, err := os.ReadFile("testdata/base_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var s baseSpec
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.AVPs) != 63 || len(s.Commands) != 14 {
		t.Fatalf("incomplete base fixture: %d AVPs, %d command bodies", len(s.AVPs), len(s.Commands))
	}
	return s
}

// RFC 6733 §4.5 and the companion flag tables cited by each fixture row.
// Both application views must resolve every named descendant to its source.
func TestBaseAVPSpec(t *testing.T) {
	s := loadBaseSpec(t)
	names := map[string]bool{}
	groups, enums, values := 0, 0, 0
	for _, a := range s.AVPs {
		if names[a.Name] {
			t.Fatalf("duplicate fixture %s", a.Name)
		}
		names[a.Name] = true
		if a.Type == "Grouped" {
			groups++
		}
		if a.Type == "Enumerated" {
			enums++
			values += len(a.Items)
		}
	}
	if groups != 7 || enums != 12 || values != 79 {
		t.Fatalf("fixture groups/enums/values = %d/%d/%d", groups, enums, values)
	}
	for _, app := range []uint32{0, 3} {
		for _, want := range s.AVPs {
			t.Run(fmt.Sprintf("%d/%s", app, want.Name), func(t *testing.T) {
				got, err := Default.FindAVP(app, want.Code, want.Vendor)
				if err != nil {
					t.Fatal(err)
				}
				rxCheckAVP(t, got, want)
				if got.MayEncrypt != "" {
					t.Errorf("encryption metadata %q is not specified by the current source", got.MayEncrypt)
				}
				for _, r := range want.Rules {
					if r.Name != "AVP" && !names[r.Name] {
						t.Errorf("uncovered descendant %s", r.Name)
					}
				}
				byName, err := Default.FindAVPByName(app, want.Name)
				if err != nil || byName != got {
					t.Fatalf("name/code lookups disagree: %v", err)
				}
				if got.App.ID != 0 {
					t.Errorf("definition copied into application %d", got.App.ID)
				}
			})
		}
	}
	app, err := Default.App(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(app.AVP) != len(s.AVPs) {
		t.Errorf("uncovered base definitions: %d versus %d", len(app.AVP), len(s.AVPs))
	}
	// The base-only bundle contributes no local accounting definitions.
	// RoRf adds application-3 command extensions when selected.
	acct, err := New(Base).App(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(acct.AVP) != 0 || len(acct.Command) != 0 || len(app.Vendor) != 0 || len(acct.Vendor) != 0 {
		t.Error("base accounting must inherit; base AVPs use no vendor declaration")
	}
}

// RFC 6733 §§5.3–5.5, 8.3–8.5, 9.7; Verified Errata 4803, 4808, 4887.
func TestBaseCommandSpec(t *testing.T) {
	for _, app := range []uint32{0, 3} {
		for _, want := range loadBaseSpec(t).Commands {
			t.Run(fmt.Sprintf("%d/%d/%t", app, want.Code, want.Request), func(t *testing.T) {
				c, err := Default.FindCommand(app, want.Code)
				if err != nil {
					t.Fatal(err)
				}
				got := c.Answer
				if want.Request {
					got = c.Request
				}
				if got.Proxiable == nil || *got.Proxiable != want.Proxiable {
					t.Error("incorrect PXY rule")
				}
				rules := got.Rule
				if app == 3 && want.Code == 271 {
					names := make([]string, len(want.Rules))
					for i, r := range want.Rules {
						names[i] = r.Name
					}
					rules = roRfRFCOnlyRules(rules, names)
				}
				rxCheckRules(t, rules, want.Rules)
			})
		}
	}
}
