package dict

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

const rxAppID = 16777236

type rxRuleSpec struct {
	Name    string `json:"name"`
	Min     int    `json:"min"`
	Max     *int   `json:"max"`
	Fixed   bool   `json:"fixed"`
	MustNot string `json:"must_not"`
}

type rxAVPSpec struct {
	Name, Section, Type, Must, May string
	Code, Vendor                   uint32
	MustNot                        string `json:"must_not"`
	MayEncrypt                     string `json:"may_encrypt"`
	Items                          map[string]string
	Rules                          []rxRuleSpec
}

type rxSpec struct {
	AVPs     []rxAVPSpec
	Commands []struct {
		Section            string
		Code               uint32
		Request, Proxiable bool
		Rules              []rxRuleSpec
	}
	Reused []struct {
		Name, Reference string
		Metadata        *rxAVPSpec
		Registry        *struct{ Code, Vendor uint32 }
		ClearM          bool `json:"clear_m"`
		NestedClearM    bool `json:"nested_clear_m"`
	}
}

// TS 29.214 V20.0.0 Table 5.4.0.1: every reused AVP keeps its source
// registry identity and receives the Rx-specific flag policy where stated.
func TestRxReusedAVPSpec(t *testing.T) {
	for _, want := range loadRxSpec(t).Reused {
		t.Run(want.Name, func(t *testing.T) {
			a := rxLookup(t, want.Name)
			if want.Metadata == nil {
				t.Fatal("reused AVP lacks independently sourced metadata")
			}
			m := want.Metadata
			if a.Code != m.Code || a.VendorID != m.Vendor || (m.Type != "" && a.Data.TypeName != m.Type) || rxFlags(t, a.Must) != rxFlags(t, m.Must) || rxFlags(t, a.May) != rxFlags(t, m.May) || rxFlags(t, a.MustNot) != rxFlags(t, m.MustNot) || (m.MayEncrypt != "" && strings.ToUpper(a.MayEncrypt) != m.MayEncrypt) {
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
				rxCheckRules(t, a.Data.Rule, m.Rules)
			}
			if r := want.Registry; r != nil && (a.Code != r.Code || a.VendorID != r.Vendor) {
				t.Errorf("registry identity %d/%d, want %d/%d", a.Code, a.VendorID, r.Code, r.Vendor)
			}
		})
	}
}

func loadRxSpec(t *testing.T) rxSpec {
	t.Helper()
	b, err := os.ReadFile("testdata/rx_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var s rxSpec
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.AVPs) != 84 || len(s.Commands) != 8 || len(s.Reused) != 39 {
		t.Fatalf("incomplete Rx fixture: %d AVPs, %d commands, %d reused", len(s.AVPs), len(s.Commands), len(s.Reused))
	}
	return s
}

func rxName(s string) string {
	return normalizeS6aABNFName(strings.ReplaceAll(s, "3GPP", "TGPP"))
}

func rxLookup(t *testing.T, name string) *AVP {
	t.Helper()
	for _, app := range Default.Apps() {
		for _, a := range app.AVP {
			if rxName(a.Name) == rxName(name) {
				if found, err := Default.FindAVPByName(rxAppID, a.Name); err == nil {
					return found
				}
			}
		}
	}
	t.Fatalf("Rx cannot resolve %s", name)
	return nil
}

func rxFlags(t *testing.T, s string) int {
	t.Helper()
	f, err := parseFlags(s)
	if err != nil {
		t.Fatalf("invalid flag set %q: %v", s, err)
	}
	return f
}

func rxCheckRules(t *testing.T, got []*Rule, want []rxRuleSpec) {
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
		if rxName(a.AVP) != rxName(b.Name) || min != b.Min || a.Required != (b.Min > 0) || a.Fixed != b.Fixed || (b.Max == nil && a.MaxSet) || (b.Max != nil && (!a.MaxSet || a.Max != *b.Max)) || rxFlags(t, a.MustNot) != rxFlags(t, b.MustNot) {
			t.Errorf("member %d: %+v, want %+v", i, a, b)
		}
	}
}

func rxCheckAVP(t *testing.T, got *AVP, want rxAVPSpec) {
	t.Helper()
	if rxName(got.Name) != rxName(want.Name) || got.Code != want.Code || got.VendorID != want.Vendor || got.Data.TypeName != want.Type {
		t.Errorf("identity/type %s/%d/%d/%s, want %s/%d/%d/%s", got.Name, got.Code, got.VendorID, got.Data.TypeName, want.Name, want.Code, want.Vendor, want.Type)
	}
	if rxFlags(t, got.Must) != rxFlags(t, want.Must) || rxFlags(t, got.May) != rxFlags(t, want.May) || rxFlags(t, got.MustNot) != rxFlags(t, want.MustNot) || (want.MayEncrypt != "" && strings.ToUpper(got.MayEncrypt) != want.MayEncrypt) {
		t.Errorf("flags must/may/must-not/encrypt %q/%q/%q/%q, want %q/%q/%q/%q", got.Must, got.May, got.MustNot, got.MayEncrypt, want.Must, want.May, want.MustNot, want.MayEncrypt)
	}
	if want.Items != nil {
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
	rxCheckRules(t, got.Data.Rule, want.Rules)
}

// TS 29.214 V20.0.0 Table 5.3.0.1 and §§5.3.1–5.3.83.
func TestRxAVPSpec(t *testing.T) {
	for _, want := range loadRxSpec(t).AVPs {
		t.Run(want.Section+"/"+want.Name, func(t *testing.T) {
			got, err := Default.FindAVP(rxAppID, want.Code, want.Vendor)
			if err != nil {
				t.Fatal(err)
			}
			rxCheckAVP(t, got, want)
		})
	}
}

// TS 29.214 V20.0.0 §§5.6.1–5.6.8.
func TestRxCommandSpec(t *testing.T) {
	for _, want := range loadRxSpec(t).Commands {
		t.Run(want.Section, func(t *testing.T) {
			c, err := Default.FindCommand(rxAppID, want.Code)
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
			rxCheckRules(t, got.Rule, want.Rules)
		})
	}
}

func TestRxFixtureCoverage(t *testing.T) {
	s := loadRxSpec(t)
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
	if groups != 11 || enums != 17 || values != 78 {
		t.Fatalf("groups/enums/values %d/%d/%d, want 11/17/78", groups, enums, values)
	}
}

// TS 29.214 V20.0.0 Table 5.4.0.1 requires the ETSI supplier declaration
// for Reservation-Priority while 3GPP remains the application vendor.
func TestRxVendorDeclaration(t *testing.T) {
	app, err := Default.App(rxAppID)
	if err != nil {
		t.Fatal(err)
	}
	if len(app.Vendor) != 2 || app.Vendor[0].ID != 10415 || app.Vendor[0].Name != "TGPP" || app.Vendor[1].ID != 13019 || app.Vendor[1].Name != "ETSI" {
		t.Fatalf("Rx vendor declarations = %+v, want TGPP/10415, ETSI/13019", app.Vendor)
	}
}

// TS 32.299 V19.0.0 Table 7.2.0.1 does not specify per-AVP encryption.
func TestRxChargingEncryptionUnspecified(t *testing.T) {
	for _, name := range []string{"Calling-Party-Address", "Called-Party-Address", "Called-Asserted-Identity", "Requested-Party-Address"} {
		if a := rxLookup(t, name); a.MayEncrypt != "" {
			t.Errorf("%s encryption = %q, want unspecified", name, a.MayEncrypt)
		}
	}
}
