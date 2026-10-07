package dict

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

type syRuleSpec struct {
	s6aGroupedRuleSpec
	MustNot string `json:"must_not"`
}

type syAVPSpec struct {
	Name, Section, Type, Must, May string
	Code, Vendor                   uint32
	MustNot                        string `json:"must_not"`
	MayEncrypt                     string `json:"may_encrypt"`
	Items                          map[string]string
	Rules                          []syRuleSpec
}
type sySpec struct {
	AVPs     []syAVPSpec
	Commands []struct {
		Section            string
		Code               uint32
		Request, Proxiable bool
		Rules              []syRuleSpec
	}
	Reused []struct{ Name, Reference string }
}

func loadSySpec(t *testing.T) sySpec {
	t.Helper()
	b, err := os.ReadFile("testdata/sy_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var s sySpec
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.AVPs) != 7 || len(s.Commands) != 6 || len(s.Reused) != 8 {
		t.Fatalf("incomplete Sy fixture: %d/%d/%d", len(s.AVPs), len(s.Commands), len(s.Reused))
	}
	return s
}
func syNormalized(s string) string {
	return normalizeS6aABNFName(strings.ReplaceAll(s, "3GPP", "TGPP"))
}
func syLookup(t *testing.T, name string) *AVP {
	t.Helper()
	a, err := Default.FindAVPByName(16777302, name)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func syFlags(s string) string {
	flags, err := parseFlags(s)
	if err != nil {
		return "invalid:" + s
	}
	return strconv.Itoa(flags)
}

// TS 29.219 V19.0.0 Table 5.3.0.1 and §§5.3.1–5.3.7.
func TestSyAVPSpec(t *testing.T) {
	s := loadSySpec(t)
	for _, want := range s.AVPs {
		t.Run(want.Section+"/"+want.Name, func(t *testing.T) {
			got, err := Default.FindAVP(16777302, want.Code, want.Vendor)
			if err != nil {
				t.Fatal(err)
			}
			if syNormalized(got.Name) != syNormalized(want.Name) || got.Data.TypeName != want.Type {
				t.Errorf("name/type %s/%s, want %s/%s", got.Name, got.Data.TypeName, want.Name, want.Type)
			}
			if syFlags(got.Must) != syFlags(want.Must) || syFlags(got.May) != syFlags(want.May) || syFlags(got.MustNot) != syFlags(want.MustNot) || (want.MayEncrypt != "" && strings.ToUpper(got.MayEncrypt) != want.MayEncrypt) {
				t.Errorf("flags must/may/must-not/encrypt %s/%s/%s/%s, want %s/%s/%s/%s", got.Must, got.May, got.MustNot, got.MayEncrypt, want.Must, want.May, want.MustNot, want.MayEncrypt)
			}
			if len(got.Data.Enum) != len(want.Items) {
				t.Errorf("enum count %d, want %d", len(got.Data.Enum), len(want.Items))
			}
			for _, item := range got.Data.Enum {
				name, ok := want.Items[strconv.Itoa(int(item.Code))]
				if !ok || normalizeEnumName(item.Name) != normalizeEnumName(name) {
					t.Errorf("enum %d=%s, want %s", item.Code, item.Name, name)
				}
			}
			syCheckRules(t, got.Data.Rule, want.Rules)
		})
	}
}
func syCheckRules(t *testing.T, got []*Rule, want []syRuleSpec) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("member count %d, want %d", len(got), len(want))
	}
	for i := 0; i < len(got) && i < len(want); i++ {
		a, b := got[i], want[i]
		min := a.Min
		if a.Required && min == 0 {
			min = 1
		}
		if syFlags(a.MustNot) != syFlags(b.MustNot) {
			t.Errorf("member %s flags %q, want %q", a.AVP, a.MustNot, b.MustNot)
		}
		if syNormalized(a.AVP) != syNormalized(b.Name) || min != b.Min || a.Required != (b.Min > 0) || a.Fixed != b.Fixed || (b.Max == nil && a.MaxSet) || (b.Max != nil && (!a.MaxSet || a.Max != *b.Max)) {
			t.Errorf("member %d: %+v, want %+v", i, a, b)
		}
	}
}

// TS 29.219 V19.0.0 §§5.6.2–5.6.7; RFC 6733 §3.2 CCF.
func TestSyCommandSpec(t *testing.T) {
	for _, want := range loadSySpec(t).Commands {
		t.Run(want.Section, func(t *testing.T) {
			c, err := Default.FindCommand(16777302, want.Code)
			if err != nil {
				t.Fatal(err)
			}
			got := c.Answer
			if want.Request {
				got = c.Request
			}
			if got.Proxiable == nil || *got.Proxiable != want.Proxiable {
				t.Error("incorrect proxiable constraint")
			}
			syCheckRules(t, got.Rule, want.Rules)
		})
	}
}

// TS 29.219 V19.0.0 Table 5.4: every reused root and named descendant
// is pinned against its defining document, including parent-scoped flags.
func TestSyReusedSpec(t *testing.T) {
	var spec struct {
		Roots []string
		AVPs  []syAVPSpec
	}
	b, err := os.ReadFile("testdata/sy_reused_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &spec); err != nil {
		t.Fatal(err)
	}
	if len(spec.Roots) != 8 || len(spec.AVPs) != 22 {
		t.Fatalf("incomplete reused fixture: %d/%d", len(spec.Roots), len(spec.AVPs))
	}
	names := map[string]bool{}
	for _, a := range spec.AVPs {
		names[a.Name] = true
	}
	for _, r := range spec.Roots {
		if !names[r] {
			t.Errorf("missing root %s", r)
		}
	}
	for _, want := range spec.AVPs {
		t.Run(want.Name, func(t *testing.T) {
			a := syLookup(t, want.Name)
			if a.Code != want.Code || a.VendorID != want.Vendor || a.Data.TypeName != want.Type {
				t.Errorf("identity/type %d/%d/%s, want %d/%d/%s", a.Code, a.VendorID, a.Data.TypeName, want.Code, want.Vendor, want.Type)
			}
			if syFlags(a.Must) != syFlags(want.Must) || syFlags(a.May) != syFlags(want.May) || syFlags(a.MustNot) != syFlags(want.MustNot) || (want.MayEncrypt != "" && a.MayEncrypt != want.MayEncrypt) {
				t.Errorf("flags %q/%q/%q/%q, want %q/%q/%q/%q", a.Must, a.May, a.MustNot, a.MayEncrypt, want.Must, want.May, want.MustNot, want.MayEncrypt)
			}
			syCheckRules(t, a.Data.Rule, want.Rules)
			for _, r := range want.Rules {
				if r.Name != "AVP" && !names[r.Name] {
					t.Errorf("uncovered member %s", r.Name)
				}
			}
			if len(a.Data.Enum) != len(want.Items) {
				t.Errorf("enum count %d, want %d", len(a.Data.Enum), len(want.Items))
			}
			for _, e := range a.Data.Enum {
				if normalizeEnumName(e.Name) != normalizeEnumName(want.Items[strconv.Itoa(int(e.Code))]) {
					t.Errorf("enum %d=%s differs", e.Code, e.Name)
				}
			}
		})
	}
}

// TS 29.219 V19.0.0 §5.1.5 and Table 5.4; RFC 6733 §5.3.6.
func TestSyVendorsAndCoverage(t *testing.T) {
	a, err := Default.App(16777302)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Vendor) != 2 || a.Vendor[0].ID != 10415 || a.Vendor[1].ID != 13019 || a.ApplicationVendor() != 10415 {
		t.Fatalf("Sy vendors = %+v", a.Vendor)
	}
	s := loadSySpec(t)
	groups, enums, values := 0, 0, 0
	for _, a := range s.AVPs {
		if a.Type == "Grouped" {
			groups++
		}
		if a.Type == "Enumerated" {
			enums++
			values += len(a.Items)
		}
	}
	if groups != 2 || enums != 1 || values != 2 {
		t.Fatalf("coverage %d/%d/%d", groups, enums, values)
	}
	if len(a.Command) != 3 || len(a.AVP) != 10 {
		t.Fatalf("local coverage %d commands/%d AVPs", len(a.Command), len(a.AVP))
	}
	for _, local := range a.AVP {
		inherited, err := Default.FindAVP(4, local.Code, local.VendorID)
		if err == nil && sameAVP(local, inherited) {
			t.Errorf("redundant local copy %s", local.Name)
		}
	}
}
