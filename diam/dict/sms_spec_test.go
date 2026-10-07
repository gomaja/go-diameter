package dict

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

type smsRuleSpec struct {
	s6aGroupedRuleSpec
	MustNot string `json:"must_not"`
}
type smsSharedGap struct {
	Dictionary, Reason string
	May                *string
	Rules              *[]smsRuleSpec
}
type smsDefinitionSpec struct {
	gxAVPSpec
	SharedGap        *smsSharedGap `json:"shared_dictionary_gap"`
	Rules            []smsRuleSpec
	ApplicationFlags map[uint32]struct {
		Must, May string
		MustNot   string `json:"must_not"`
	} `json:"application_flags"`
}
type smsCommandSpec struct {
	Section            string
	Code               uint32
	Request, Proxiable bool
	Rules              []smsRuleSpec
}
type smsSpec struct {
	Application uint32
	AVPs        []gxAVPSpec
	Definitions []smsDefinitionSpec
	Commands    []smsCommandSpec
	Reused      []struct{ Name string }
	Vendors     []uint32
}

func loadSMSSpec(t *testing.T, label string) smsSpec {
	t.Helper()
	b, err := os.ReadFile("testdata/" + label + "_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var s smsSpec
	if err = json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	wantAVPs, wantCommands, wantReused, wantDefinitions := 33, 6, 24, 109
	if label == "sgd" {
		wantAVPs, wantCommands, wantReused, wantDefinitions = 16, 4, 13, 112
	}
	if len(s.AVPs) != wantAVPs || len(s.Commands) != wantCommands || len(s.Reused) != wantReused || len(s.Definitions) != wantDefinitions {
		t.Fatalf("incomplete %s fixture: %d/%d/%d/%d", label, len(s.AVPs), len(s.Commands), len(s.Reused), len(s.Definitions))
	}
	return s
}
func smsCheckRules(t *testing.T, got []*Rule, want []smsRuleSpec) {
	t.Helper()
	var plain []s6aGroupedRuleSpec
	for _, r := range want {
		plain = append(plain, r.s6aGroupedRuleSpec)
	}
	gxCheckRules(t, got, plain)
	for i, r := range want {
		if i < len(got) && gxFlags(got[i].MustNot) != gxFlags(r.MustNot) {
			t.Errorf("member %s must-not %q, want %q", r.Name, got[i].MustNot, r.MustNot)
		}
	}
}

// TS 29.338 V19.3.0 Tables 5.3.3.1/1–2 and 6.3.3.1/1–2.
// Source clauses in the fixtures pin reused grammars and their full closure.
func TestSMSApplicationSpec(t *testing.T) {
	for _, label := range []string{"s6c", "sgd"} {
		t.Run(label, func(t *testing.T) {
			s := loadSMSSpec(t, label)
			names := map[string]bool{}
			for _, a := range s.Definitions {
				names[gxNormalized(a.Name)] = true
			}
			for _, a := range s.AVPs {
				if !names[gxNormalized(a.Name)] {
					t.Errorf("uncovered specific AVP %s", a.Name)
				}
			}
			for _, a := range s.Reused {
				if !names[gxNormalized(a.Name)] {
					t.Errorf("uncovered reused AVP %s", a.Name)
				}
			}
			for _, w := range s.Definitions {
				t.Run(w.Name, func(t *testing.T) {
					// Keep source expectations intact; separately pin explicit shared-file
					// defects that this refresh is forbidden to edit.
					if gap := w.SharedGap; gap != nil {
						if gap.Dictionary == "base.xml" {
							t.Fatal("base RFC definitions must use exact source expectations")
						}
						t.Logf("shared dictionary gap in %s: %s", gap.Dictionary, gap.Reason)
						if gap.May != nil {
							w.May = *gap.May
						}
						if gap.Rules != nil {
							w.Rules = *gap.Rules
						}
					}
					a, err := Default.FindAVP(s.Application, w.Code, w.Vendor)
					if err != nil {
						t.Fatal(err)
					}
					if gxNormalized(a.Name) != gxNormalized(w.Name) || a.Data.TypeName != w.Type {
						t.Errorf("identity/type %s/%s, want %s/%s (%s)", a.Name, a.Data.TypeName, w.Name, w.Type, w.Section)
					}
					if gxFlags(a.Must) != gxFlags(w.Must) || gxFlags(a.May) != gxFlags(w.May) || gxFlags(a.MustNot) != gxFlags(w.MustNot) {
						t.Errorf("flags %q/%q/%q, want %q/%q/%q (%s)", a.Must, a.May, a.MustNot, w.Must, w.May, w.MustNot, w.Section)
					}
					if w.MayEncrypt != "" && strings.ToUpper(a.MayEncrypt) != w.MayEncrypt {
						t.Errorf("encryption %q want %q", a.MayEncrypt, w.MayEncrypt)
					}
					if len(a.Data.Enum) != len(w.Items) {
						t.Errorf("enum count %d want %d", len(a.Data.Enum), len(w.Items))
					}
					for _, e := range a.Data.Enum {
						if e.Name != w.Items[strconv.Itoa(int(e.Code))] {
							t.Errorf("enum %d=%s differs from source", e.Code, e.Name)
						}
					}
					smsCheckRules(t, a.Data.Rule, w.Rules)
					for _, r := range w.Rules {
						if r.Name != "AVP" && !names[gxNormalized(r.Name)] {
							t.Errorf("uncovered descendant %s", r.Name)
						}
					}
				})
			}
			for _, w := range s.Commands {
				t.Run(w.Section, func(t *testing.T) {
					c, err := Default.FindCommand(s.Application, w.Code)
					if err != nil {
						t.Fatal(err)
					}
					got := c.Answer
					if w.Request {
						got = c.Request
					}
					if got.Proxiable == nil || *got.Proxiable != w.Proxiable {
						t.Error("wrong PXY constraint")
					}
					smsCheckRules(t, got.Rule, w.Rules)
					for _, r := range w.Rules {
						if r.Name != "AVP" && !names[gxNormalized(r.Name)] {
							t.Errorf("uncovered command member %s", r.Name)
						}
					}
				})
			}
		})
	}
}

// TS 29.338 V19.3.0 §4.7 and RFC 6733 §5.3.6: advertise supported AVP vendors.
func TestSMSVendorDeclarations(t *testing.T) {
	for _, label := range []string{"s6c", "sgd"} {
		s := loadSMSSpec(t, label)
		a, err := Default.App(s.Application)
		if err != nil {
			t.Fatal(err)
		}
		var got []uint32
		for _, v := range a.Vendor {
			got = append(got, v.ID)
		}
		if !slices.Equal(got, s.Vendors) {
			t.Errorf("%s vendors %v, want %v", label, got, s.Vendors)
		}
		for _, d := range s.Definitions {
			if d.Vendor != 0 && !slices.Contains(got, d.Vendor) {
				t.Errorf("%s lacks vendor %d for %s", label, d.Vendor, d.Name)
			}
		}
	}
}

// Pin every local definition to the independent fixture, including inherited
// SGd definitions stored in S6c for the bundled application hierarchy.
func TestSMSLocalDefinitionCoverage(t *testing.T) {
	for _, label := range []string{"s6c", "sgd"} {
		s := loadSMSSpec(t, label)
		a, err := Default.App(s.Application)
		if err != nil {
			t.Fatal(err)
		}
		known := map[string]bool{}
		for _, d := range s.Definitions {
			known[fmt.Sprintf("%d/%d", d.Code, d.Vendor)] = true
		}
		for _, d := range a.AVP {
			if !known[fmt.Sprintf("%d/%d", d.Code, d.VendorID)] {
				t.Errorf("%s local definition %s absent from fixture", label, d.Name)
			}
		}
	}
}
