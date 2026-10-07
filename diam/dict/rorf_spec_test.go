package dict

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// TS 32.299 V19.0.0 §§6.2.2–6.2.3, 6.4.2–6.4.5, 7.1.9,
// 7.1.14 and 7.1.17 extend the current RFC grammars without dropping their rules.
func TestRoRfSharedGrammars(t *testing.T) {
	b, err := os.ReadFile("testdata/rorf_commands_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	type grammar struct {
		Name, Section      string
		Application, Code  uint32
		Request, Proxiable bool
		Rules              []rxRuleSpec
		Effective          []rxRuleSpec `json:"effective_rules"`
		RFCSource          string       `json:"rfc_source"`
	}
	var s struct {
		Commands []grammar
		Groups   []grammar `json:"shared_groups"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.Commands) != 6 || len(s.Groups) != 3 {
		t.Fatal("incomplete shared grammar audit")
	}
	for _, want := range append(s.Commands, s.Groups...) {
		t.Run(want.Section, func(t *testing.T) {
			if want.RFCSource == "" || len(want.Rules) == 0 || len(want.Effective) == 0 {
				t.Fatal("missing source or composed grammar")
			}
			var rules []*Rule
			if want.Name != "" {
				a, err := Default.FindAVPByName(4, want.Name)
				if err != nil {
					t.Fatal(err)
				}
				rules = a.Data.Rule
			} else {
				c, err := Default.FindCommand(want.Application, want.Code)
				if err != nil {
					t.Fatal(err)
				}
				body := c.Answer
				if want.Request {
					body = c.Request
				}
				if body.Proxiable == nil || *body.Proxiable != want.Proxiable {
					t.Fatal("P bit differs from charging command")
				}
				rules = body.Rule
			}
			rxCheckRules(t, rules, want.Effective)
		})
	}
}

type roRfSpec struct{ AVPs []rxAVPSpec }

// TS 32.299 V19.0.0 §§6.2.2–6.2.3, 7.2–7.4: Rf resolves the same
// charging definitions as Ro without copying them or changing base accounting.
func TestRoRfApplicationViews(t *testing.T) {
	for _, dictionary := range []*Parser{Default, New(RoRf), New(CreditControl)} {
		for _, want := range loadRoRfSpec(t).AVPs {
			ro, err := dictionary.FindAVP(4, want.Code, want.Vendor)
			if err != nil {
				t.Fatal(err)
			}
			rf, err := dictionary.FindAVP(3, want.Code, want.Vendor)
			if err != nil || ro != rf {
				t.Fatalf("Rf does not inherit %s from Ro: %v", want.Name, err)
			}
		}
		app, err := dictionary.App(3)
		if err != nil {
			t.Fatal(err)
		}
		var vendors []uint32
		for _, v := range app.Vendor {
			vendors = append(vendors, v.ID)
		}
		slices.Sort(vendors)
		if !slices.Equal(vendors, []uint32{5535, 10415, 13019, 45687}) {
			t.Fatalf("Rf vendor declarations: %v", vendors)
		}
	}
	base := New(Base)
	if _, err := base.FindAVPByName(3, "Service-Information"); err == nil {
		t.Fatal("base-only accounting unexpectedly exposes charging definitions")
	}
	for _, source := range loadBaseSpec(t).Commands {
		c, err := base.FindCommand(3, source.Code)
		if err != nil {
			t.Fatal(err)
		}
		body := c.Answer
		if source.Request {
			body = c.Request
		}
		rxCheckRules(t, body.Rule, source.Rules)
	}
}

func loadRoRfSpec(t *testing.T) roRfSpec {
	t.Helper()
	b, err := os.ReadFile("testdata/rorf_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var s roRfSpec
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.AVPs) != 744 {
		t.Fatalf("fixture has %d AVPs, want 744", len(s.AVPs))
	}
	return s
}

// TS 32.299 V19.0.0 Table 7.2.0.1 and each AVP's independently cited
// defining clause, including the current RFC base and QoS definitions.
func TestRoRfAVPSpec(t *testing.T) {
	for _, want := range loadRoRfSpec(t).AVPs {
		t.Run(want.Name, func(t *testing.T) {
			a, err := Default.FindAVP(4, want.Code, want.Vendor)
			if err != nil {
				t.Fatal(err)
			}
			rxCheckAVP(t, a, want)
		})
	}
}

func TestRoRfFixtureClosure(t *testing.T) {
	s := loadRoRfSpec(t)
	s.AVPs = append(s.AVPs, loadOneM2MSpec(t)...)
	names := map[string]bool{}
	codes := map[[2]uint32]bool{}
	for _, a := range s.AVPs {
		k := [2]uint32{a.Code, a.Vendor}
		if names[rxName(a.Name)] || codes[k] {
			t.Errorf("duplicate fixture definition %s", a.Name)
		}
		names[rxName(a.Name)] = true
		codes[k] = true
		if a.Section == "" {
			t.Errorf("missing source for %s", a.Name)
		}
	}
	for _, a := range s.AVPs {
		members := map[string]bool{}
		for _, r := range a.Rules {
			if members[rxName(r.Name)] {
				t.Errorf("%s has duplicate member %s", a.Name, r.Name)
			}
			members[rxName(r.Name)] = true
			if r.Name != "AVP" && !names[rxName(r.Name)] {
				t.Errorf("%s has uncovered member %s", a.Name, r.Name)
			}
		}
	}
	for _, app := range Default.Apps() {
		if app.ID != 4 {
			continue
		}
		for _, a := range app.AVP {
			if a.VendorID != 0 && !codes[[2]uint32{a.Code, a.VendorID}] {
				t.Errorf("uncovered charging AVP %s", a.Name)
			}
		}
	}
}

// Project a composed grammar onto the RFC's members. The charging test
// independently checks the exact full union, including every added rule.
func roRfRFCOnlyRules(got []*Rule, names []string) []*Rule {
	allowed := make(map[string]bool, len(names))
	for _, name := range names {
		allowed[name] = true
	}
	var rules []*Rule
	for _, rule := range got {
		if allowed[rule.AVP] {
			rules = append(rules, rule)
		}
	}
	return rules
}

func roRfCreditControlRules(t *testing.T, got []*Rule, want []creditControlRule, name string) {
	t.Helper()
	if name == "Multiple-Services-Credit-Control" || name == "Used-Service-Unit" {
		names := make([]string, len(want))
		for i, rule := range want {
			names[i] = rule.Name
		}
		got = roRfRFCOnlyRules(got, names)
	}
	checkCreditControlRules(t, got, want)
}
