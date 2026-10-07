package dict

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

type gxAVPSpec struct {
	Name, Section, Type, Must, May string
	Code, Vendor                   uint32
	MustNot                        string `json:"must_not"`
	MayEncrypt                     string `json:"may_encrypt"`
	Items                          map[string]string
	Rules                          []s6aGroupedRuleSpec
}
type gxSpec struct {
	AVPs     []gxAVPSpec
	Commands []struct {
		Section            string
		Code               uint32
		Request, Proxiable bool
		Rules              []s6aGroupedRuleSpec
	}
	Reused []struct {
		Name, Reference string
		Metadata        *gxAVPSpec
		Registry        *struct{ Code, Vendor uint32 }
		ClearM          bool `json:"clear_m"`
		NestedClearM    bool `json:"nested_clear_m"`
	}
}

func loadGxSpec(t *testing.T) gxSpec {
	t.Helper()
	b, err := os.ReadFile("testdata/gx_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var s gxSpec
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.AVPs) != 130 || len(s.Commands) != 4 || len(s.Reused) != 70 {
		t.Fatalf("incomplete Gx fixture: %d/%d/%d", len(s.AVPs), len(s.Commands), len(s.Reused))
	}
	return s
}
func gxNormalized(s string) string {
	return normalizeS6aABNFName(strings.ReplaceAll(s, "3GPP", "TGPP"))
}
func gxLookup(t *testing.T, name string) *AVP {
	t.Helper()
	for _, app := range Default.Apps() {
		for _, a := range app.AVP {
			if gxNormalized(a.Name) == gxNormalized(name) {
				if found, err := Default.FindAVPByName(16777238, a.Name); err == nil {
					return found
				}
			}
		}
	}
	t.Fatalf("Gx cannot resolve %s", name)
	return nil
}
func gxFlags(s string) string {
	flags, err := parseFlags(s)
	if err != nil {
		return "invalid:" + s
	}
	return strconv.Itoa(flags)
}

// TS 29.212 V20.0.0 Table 5.3.0.1 and §§5.3.1–5.3.141.
func TestGxAVPSpec(t *testing.T) {
	s := loadGxSpec(t)
	for _, want := range s.AVPs {
		t.Run(want.Section+"/"+want.Name, func(t *testing.T) {
			got, err := Default.FindAVP(16777238, want.Code, want.Vendor)
			if err != nil {
				t.Fatal(err)
			}
			if gxNormalized(got.Name) != gxNormalized(want.Name) || got.Data.TypeName != want.Type {
				t.Errorf("name/type %s/%s, want %s/%s", got.Name, got.Data.TypeName, want.Name, want.Type)
			}
			if gxFlags(got.Must) != gxFlags(want.Must) || gxFlags(got.May) != gxFlags(want.May) || gxFlags(got.MustNot) != gxFlags(want.MustNot) || strings.ToUpper(got.MayEncrypt) != want.MayEncrypt {
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
			gxCheckRules(t, got.Data.Rule, want.Rules)
		})
	}
}
func gxCheckRules(t *testing.T, got []*Rule, want []s6aGroupedRuleSpec) {
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
		if gxNormalized(a.AVP) != gxNormalized(b.Name) || min != b.Min || a.Required != (b.Min > 0) || a.Fixed != b.Fixed || (b.Max == nil && a.MaxSet) || (b.Max != nil && (!a.MaxSet || a.Max != *b.Max)) {
			t.Errorf("member %d: %+v, want %+v", i, a, b)
		}
	}
}

// TS 29.212 V20.0.0 §§5.6.2–5.6.5; RFC 6733 §3.2 CCF.
func TestGxCommandSpec(t *testing.T) {
	for _, want := range loadGxSpec(t).Commands {
		t.Run(want.Section, func(t *testing.T) {
			c, err := Default.FindCommand(16777238, want.Code)
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
			gxCheckRules(t, got.Rule, want.Rules)
		})
	}
}

// TS 29.212 V20.0.0 Table 5.4.0.1 and Note 5: overrides are Gx-local,
// including members nested in usage units and Trace-Data. Load already clears M.
func TestGxReusedAVPSpec(t *testing.T) {
	for _, want := range loadGxSpec(t).Reused {
		t.Run(want.Name, func(t *testing.T) {
			a := gxLookup(t, want.Name)
			if r := want.Registry; r != nil && (a.Code != r.Code || a.VendorID != r.Vendor) {
				t.Errorf("registry identity %d/%d, want %d/%d", a.Code, a.VendorID, r.Code, r.Vendor)
			}
			if m := want.Metadata; m != nil {
				if a.Code != m.Code || a.VendorID != m.Vendor || (m.Type != "" && a.Data.TypeName != m.Type) || gxFlags(a.Must) != gxFlags(m.Must) || gxFlags(a.May) != gxFlags(m.May) || gxFlags(a.MustNot) != gxFlags(m.MustNot) || (m.MayEncrypt != "" && strings.ToUpper(a.MayEncrypt) != m.MayEncrypt) {
					t.Errorf("reused metadata %+v, want %+v", a, m)
				}
				if m.Items != nil {
					if len(a.Data.Enum) != len(m.Items) {
						t.Errorf("enum count %d, want %d", len(a.Data.Enum), len(m.Items))
					}
					for _, e := range a.Data.Enum {
						if normalizeEnumName(e.Name) != normalizeEnumName(m.Items[strconv.Itoa(int(e.Code))]) {
							t.Errorf("enum %d=%s differs from source", e.Code, e.Name)
						}
					}
				}
			}
			if want.ClearM {
				gxCheckClearM(t, a)
			}
			if want.NestedClearM {
				visited := map[string]bool{}
				var walk func(*AVP)
				walk = func(group *AVP) {
					if visited[group.Name] {
						return
					}
					visited[group.Name] = true
					if group.Name == "Load" {
						clearsM := false
						for _, r := range group.Data.Rule {
							clearsM = clearsM || r.AVP == "AVP" && gxFlags(r.MustNot) == gxFlags("M")
						}
						if !clearsM {
							t.Error("Load wildcard must clear M on every member")
						}
					}
					for _, r := range group.Data.Rule {
						if r.AVP == "AVP" {
							continue
						}
						member := gxLookup(t, r.AVP)
						if group.Name != "Load" {
							gxCheckClearM(t, member)
						}
						walk(member)
					}
				}
				walk(a)
			}
		})
	}
}
func gxCheckClearM(t *testing.T, a *AVP) {
	t.Helper()
	if strings.Contains(a.Must, "M") || !strings.Contains(a.MustNot, "M") {
		t.Errorf("%s: M must be cleared, flags %+v", a.Name, a)
	}
}

// Pin coverage totals so extraction cannot silently omit a grammar or registry.
func TestGxFixtureCoverage(t *testing.T) {
	s := loadGxSpec(t)
	groups, enums := 0, 0
	for _, a := range s.AVPs {
		if a.Type == "Grouped" {
			groups++
			if len(a.Rules) == 0 {
				t.Error(a.Name)
			}
		}
		if a.Type == "Enumerated" {
			enums++
			if len(a.Items) == 0 {
				t.Error(a.Name)
			}
		}
	}
	if groups != 30 || enums != 40 {
		t.Fatalf("groups/enums %d/%d, want 30/40", groups, enums)
	}
}
