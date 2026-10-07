package dict

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

const swxAppID = 16777265

type swxRuleSpec struct {
	Name    string `json:"name"`
	Min     int    `json:"min"`
	Max     *int   `json:"max"`
	Fixed   bool   `json:"fixed"`
	MustNot string `json:"must_not"`
}

type swxSharedMetadataGap struct {
	May               string
	SourceApplication uint32 `json:"source_application"`
	Reason            string
}

type swxAVPSpec struct {
	KnownSharedMetadataGap         *swxSharedMetadataGap `json:"known_shared_metadata_gap"`
	Name, Section, Type, Must, May string
	Code, Vendor                   uint32
	MustNot                        string `json:"must_not"`
	MayEncrypt                     string `json:"may_encrypt"`
	Items                          map[string]string
	Rules                          []swxRuleSpec
}

type swxSpec struct {
	AVPs     []swxAVPSpec
	Commands []struct {
		Section            string
		Code               uint32
		Request, Proxiable bool
		Rules              []swxRuleSpec
	}
	Reused []struct {
		Name, Reference string
		Metadata        *swxAVPSpec
		Registry        *struct{ Code, Vendor uint32 }
		ClearM          bool `json:"clear_m"`
		NestedClearM    bool `json:"nested_clear_m"`
	}
}

// TS 29.273 V19.2.0 Table 8.2.3.0/2: every reused AVP keeps its source
// registry identity and receives the SWx-specific flag policy where stated.
func TestSWxReusedAVPSpec(t *testing.T) {
	for _, want := range loadSWxSpec(t).Reused {
		t.Run(want.Name, func(t *testing.T) {
			a := swxLookup(t, want.Name)
			if want.Metadata == nil {
				t.Fatal("reused AVP lacks independently sourced metadata")
			}
			m := want.Metadata
			if a.Code != m.Code || a.VendorID != m.Vendor || (m.Type != "" && a.Data.TypeName != m.Type) || swxFlags(t, a.Must) != swxFlags(t, m.Must) || !swxMayMatches(t, a.May, *m) || swxFlags(t, a.MustNot) != swxFlags(t, m.MustNot) || (m.MayEncrypt != "" && strings.ToUpper(a.MayEncrypt) != m.MayEncrypt) {
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
			if m.Rules != nil {
				swxCheckRules(t, a.Data.Rule, m.Rules)
			}
			if r := want.Registry; r != nil && (a.Code != r.Code || a.VendorID != r.Vendor) {
				t.Errorf("registry identity %d/%d, want %d/%d", a.Code, a.VendorID, r.Code, r.Vendor)
			}
		})
	}
}

func loadSWxSpec(t *testing.T) swxSpec {
	t.Helper()
	b, err := os.ReadFile("testdata/swx_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var s swxSpec
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.AVPs) != 16 || len(s.Commands) != 8 || len(s.Reused) != 43 {
		t.Fatalf("incomplete SWx fixture: %d AVPs, %d commands, %d reused", len(s.AVPs), len(s.Commands), len(s.Reused))
	}
	return s
}

func swxName(s string) string {
	return normalizeS6aABNFName(strings.ReplaceAll(s, "3GPP", "TGPP"))
}

func swxLookup(t *testing.T, name string) *AVP {
	t.Helper()
	for _, app := range Default.Apps() {
		for _, a := range app.AVP {
			if swxName(a.Name) == swxName(name) {
				if found, err := Default.FindAVPByName(swxAppID, a.Name); err == nil {
					return found
				}
			}
		}
	}
	t.Fatalf("SWx cannot resolve %s", name)
	return nil
}

func swxFlags(t *testing.T, s string) int {
	t.Helper()
	f, err := parseFlags(s)
	if err != nil {
		t.Fatalf("invalid flag set %q: %v", s, err)
	}
	return f
}

func swxCheckRules(t *testing.T, got []*Rule, want []swxRuleSpec) {
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
		if swxName(a.AVP) != swxName(b.Name) || min != b.Min || a.Required != (b.Min > 0) || a.Fixed != b.Fixed || (b.Max == nil && a.MaxSet) || (b.Max != nil && (!a.MaxSet || a.Max != *b.Max)) || swxFlags(t, a.MustNot) != swxFlags(t, b.MustNot) {
			t.Errorf("member %d: %+v, want %+v", i, a, b)
		}
	}
}

// The source flag set stays authoritative. Only the explicitly recorded
// informational MAY-P gap in an inherited shared definition is also accepted.
func swxMayMatches(t *testing.T, got string, want swxAVPSpec) bool {
	t.Helper()
	if swxFlags(t, got) == swxFlags(t, want.May) {
		return true
	}
	gap := want.KnownSharedMetadataGap
	return gap != nil && swxFlags(t, got) == swxFlags(t, gap.May)
}

func swxCheckAVP(t *testing.T, got *AVP, want swxAVPSpec) {
	t.Helper()
	if swxName(got.Name) != swxName(want.Name) || got.Code != want.Code || got.VendorID != want.Vendor || got.Data.TypeName != want.Type {
		t.Errorf("identity/type %s/%d/%d/%s, want %s/%d/%d/%s", got.Name, got.Code, got.VendorID, got.Data.TypeName, want.Name, want.Code, want.Vendor, want.Type)
	}
	if swxFlags(t, got.Must) != swxFlags(t, want.Must) || !swxMayMatches(t, got.May, want) || swxFlags(t, got.MustNot) != swxFlags(t, want.MustNot) || (want.MayEncrypt != "" && strings.ToUpper(got.MayEncrypt) != want.MayEncrypt) {
		t.Errorf("flags must/may/must-not/encrypt %q/%q/%q/%q, want %q/%q/%q/%q", got.Must, got.May, got.MustNot, got.MayEncrypt, want.Must, want.May, want.MustNot, want.MayEncrypt)
	}
	if want.Type == "Enumerated" {
		if len(got.Data.Enum) != len(want.Items) {
			t.Errorf("enum count %d, want %d", len(got.Data.Enum), len(want.Items))
		}
		for _, item := range got.Data.Enum {
			name, ok := want.Items[strconv.Itoa(int(item.Code))]
			if !ok || normalizeEnumName(item.Name) != normalizeEnumName(name) {
				t.Errorf("enum %d=%s, want %s", item.Code, item.Name, name)
			}
		}
	}
	swxCheckRules(t, got.Data.Rule, want.Rules)
}

// TS 29.273 V19.2.0 Table 8.2.3.0/1 and §§8.2.3.1–8.2.3.28.
func TestSWxAVPSpec(t *testing.T) {
	for _, want := range loadSWxSpec(t).AVPs {
		t.Run(want.Section+"/"+want.Name, func(t *testing.T) {
			got, err := Default.FindAVP(swxAppID, want.Code, want.Vendor)
			if err != nil {
				t.Fatal(err)
			}
			swxCheckAVP(t, got, want)
		})
	}
}

// TS 29.273 V19.2.0 §§8.2.2.1–8.2.2.4. The fixture corrects the
// published PPR PXY omission in §8.2.2.2: its PPA and §8.2.2.3 SAR/SAA
// use PXY, and RFC 6733 §6.2 requires matching request/answer P bits.
func TestSWxCommandSpec(t *testing.T) {
	for _, want := range loadSWxSpec(t).Commands {
		t.Run(want.Section, func(t *testing.T) {
			c, err := Default.FindCommand(swxAppID, want.Code)
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
			swxCheckRules(t, got.Rule, want.Rules)
		})
	}
}

func TestSWxFixtureCoverage(t *testing.T) {
	s := loadSWxSpec(t)
	groups, enums, values := 0, 0, 0
	for _, a := range s.AVPs {
		if a.Type == "Grouped" {
			groups++
			if len(a.Rules) == 0 {
				t.Errorf("%s has no members", a.Name)
			}
		}
		if a.Type == "Enumerated" {
			enums++
			values += len(a.Items)
			if len(a.Items) == 0 {
				t.Errorf("%s has no values", a.Name)
			}
		}
	}
	if groups != 5 || enums != 3 || values != 6 {
		t.Fatalf("groups/enums/values %d/%d/%d, want 5/3/6", groups, enums, values)
	}
}

// TS 29.273 V19.2.0 §8.2.1 and Table 8.2.3.0/2; RFC 6733 §5.3.6.
func TestSWxVendorsAndLocalCoverage(t *testing.T) {
	app, err := Default.App(swxAppID)
	if err != nil {
		t.Fatal(err)
	}
	if len(app.Vendor) != 2 || app.Vendor[0].ID != 10415 || app.Vendor[1].ID != 13019 || app.ApplicationVendor() != 10415 {
		t.Fatalf("SWx vendors = %+v", app.Vendor)
	}
	if len(app.Command) != 4 {
		t.Fatalf("command count %d, want 4", len(app.Command))
	}
	names := map[string]bool{}
	for _, a := range loadSWxSpec(t).AVPs {
		names[swxName(a.Name)] = true
	}
	// SWx-local definitions that keep their defining specifications' flags
	// instead of S6a's; sms_inheritance_spec.json pins them in full.
	for _, name := range []string{"External-Identifier", "GMLC-Address", "eNodeB-ID", "User-CSG-Information"} {
		names[swxName(name)] = true
	}
	gaps := 0
	for _, a := range loadSWxCopiedSpec(t).AVPs {
		names[swxName(a.Name)] = true
		if gap := a.KnownSharedMetadataGap; gap != nil {
			gaps++
			if a.May != "" || gap.May != "P" || gap.Reason == "" || gap.SourceApplication != 4 {
				t.Fatalf("invalid known metadata gap for %s: %+v", a.Name, gap)
			}
			inherited, err := Default.FindAVP(gap.SourceApplication, a.Code, a.Vendor)
			if err != nil {
				t.Fatal(err)
			}
			if got := swxLookup(t, a.Name); got != inherited {
				t.Errorf("%s must inherit application %d; do not copy shared MAY-P metadata into SWx", a.Name, gap.SourceApplication)
			}
		}
	}
	if gaps != 1 {
		t.Fatalf("shared metadata gaps %d, want 1", gaps)
	}
	if len(app.AVP) != 38 {
		t.Fatalf("local definitions %d, want 38", len(app.AVP))
	}
	for _, local := range app.AVP {
		if !names[swxName(local.Name)] {
			t.Errorf("uncovered local definition %s", local.Name)
		}
		inherited, err := Default.FindAVP(16777251, local.Code, local.VendorID)
		if err == nil && sameAVP(local, inherited) {
			t.Errorf("redundant local copy %s", local.Name)
		}
	}
}
