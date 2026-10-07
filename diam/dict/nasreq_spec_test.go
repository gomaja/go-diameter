package dict

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

type nasreqRuleSpec struct {
	Name    string `json:"name"`
	Min     int    `json:"min"`
	Max     *int   `json:"max"`
	Fixed   bool   `json:"fixed"`
	MustNot string `json:"must_not"`
}

type nasreqAVPSpec struct {
	Name, Section, Type, Must, May string
	Code, Vendor                   uint32
	MustNot                        string `json:"must_not"`
	Items                          map[string]string
	Rules                          []nasreqRuleSpec
}

type nasreqCommandSpec struct {
	Section            string
	Code               uint32
	Request, Proxiable bool
	Rules              []nasreqRuleSpec
}

type nasreqSupplementalSpec struct {
	Name, Type, Reference, Must, May string
	RadiusType                       string `json:"radius_type"`
	FlagNote                         string `json:"flag_note"`
	MustNot                          string `json:"must_not"`
	Code, Vendor                     uint32
}

type nasreqSpec struct {
	AVPs         []nasreqAVPSpec
	Commands     []nasreqCommandSpec
	Supplemental []nasreqSupplementalSpec
}

func loadNASREQSpec(t *testing.T) nasreqSpec {
	t.Helper()
	b, err := os.ReadFile("testdata/nasreq_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var s nasreqSpec
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.AVPs) != 78 || len(s.Commands) != 10 || len(s.Supplemental) != 4 {
		t.Fatalf("incomplete RFC 7155 fixture: %d AVPs, %d commands", len(s.AVPs), len(s.Commands))
	}
	return s
}

func nasreqFlags(t *testing.T, s string) int {
	t.Helper()
	f, err := parseFlags(s)
	if err != nil {
		t.Fatalf("invalid flag set %q: %v", s, err)
	}
	return f
}

func nasreqRules(t *testing.T, got []*Rule, want []nasreqRuleSpec) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("rule count %d, want %d", len(got), len(want))
	}
	for i := 0; i < len(got) && i < len(want); i++ {
		a, b := got[i], want[i]
		min := a.Min
		if a.Required && min == 0 {
			min = 1
		}
		if a.AVP != b.Name || min != b.Min || a.Fixed != b.Fixed || nasreqFlags(t, a.MustNot) != nasreqFlags(t, b.MustNot) || (b.Max == nil && a.MaxSet) || (b.Max != nil && (!a.MaxSet || a.Max != *b.Max)) {
			t.Errorf("rule %d: %+v, want %+v", i, a, b)
		}
	}
}

// RFC 7155 §§4.2–4.6; Verified Errata 6119, 5995. Enumerations include
// the IANA RADIUS Types and AAA Parameters registries referenced by the RFC.
func TestNASREQAVPSpec(t *testing.T) {
	for _, want := range loadNASREQSpec(t).AVPs {
		t.Run(want.Section+"/"+want.Name, func(t *testing.T) {
			got, err := Default.FindAVP(1, want.Code, want.Vendor)
			if err != nil {
				t.Fatal(err)
			}
			if got.Name != want.Name || got.Data.TypeName != want.Type {
				t.Errorf("name/type %s/%s, want %s/%s", got.Name, got.Data.TypeName, want.Name, want.Type)
			}
			if nasreqFlags(t, got.Must) != nasreqFlags(t, want.Must) || nasreqFlags(t, got.May) != nasreqFlags(t, want.May) || nasreqFlags(t, got.MustNot) != nasreqFlags(t, want.MustNot) || got.MayEncrypt != "" {
				t.Errorf("flags must/may/must-not/encrypt %q/%q/%q/%q, want %q/%q/%q/empty", got.Must, got.May, got.MustNot, got.MayEncrypt, want.Must, want.May, want.MustNot)
			}
			if want.Items != nil {
				if len(got.Data.Enum) != len(want.Items) {
					t.Errorf("enum count %d, want %d", len(got.Data.Enum), len(want.Items))
				}
				for _, item := range got.Data.Enum {
					label, ok := want.Items[strconv.Itoa(int(item.Code))]
					if !ok || normalizeEnumName(item.Name) != normalizeEnumName(label) {
						t.Errorf("enum %d=%s, want %s", item.Code, item.Name, label)
					}
				}
			}
			if want.Type == "Grouped" {
				nasreqRules(t, got.Data.Rule, want.Rules)
			}
		})
	}
}

// RFC 7155 §§3.1–3.10; Verified Errata 5993, 5994 and 5995.
func TestNASREQCommandSpec(t *testing.T) {
	for _, want := range loadNASREQSpec(t).Commands {
		t.Run(want.Section, func(t *testing.T) {
			c, err := Default.FindCommand(1, want.Code)
			if err != nil {
				t.Fatal(err)
			}
			got := c.Answer
			if want.Request {
				got = c.Request
			}
			if got.Proxiable == nil || *got.Proxiable != want.Proxiable {
				t.Error("incorrect PXY constraint")
			}
			nasreqRules(t, got.Rule, want.Rules)
		})
	}
}

func TestNASREQFixtureCoverage(t *testing.T) {
	s := loadNASREQSpec(t)
	groups, enums, values := 0, 0, 0
	for _, a := range s.AVPs {
		if a.Type == "Grouped" {
			groups++
			if len(a.Rules) == 0 {
				t.Error(a.Name)
			}
		}
		if a.Type == "Enumerated" {
			enums++
			values += len(a.Items)
			if len(a.Items) == 0 {
				t.Error(a.Name)
			}
		}
		if strings.Contains(a.Must, "P") || strings.Contains(a.May, "P") {
			t.Errorf("legacy P rule on %s", a.Name)
		}
	}
	if groups != 2 || enums != 14 || values != 132 {
		t.Fatalf("grouped/enumerated/values %d/%d/%d, want 2/14/132", groups, enums, values)
	}
}

// RFC 7155 §§3–4 reuses these AVPs from RFC 6733. Compare the complete
// effective definitions with the base application, including recursive Grouped
// members; base specification tests separately pin that source to RFC 6733.
func TestNASREQReusedBaseAVPs(t *testing.T) {
	s := loadNASREQSpec(t)
	local := map[string]bool{"NAS-IP-Address": true, "NAS-IPv6-Address": true, "NAS-Identifier": true, "State": true}
	for _, a := range s.AVPs {
		local[a.Name] = true
	}
	base := New(Base)
	seen := map[string]bool{}
	var check func(string)
	check = func(name string) {
		t.Helper()
		if local[name] || name == "AVP" || seen[name] {
			return
		}
		seen[name] = true
		want, err := base.FindAVPByName(0, name)
		if err != nil {
			t.Fatalf("RFC 7155 reused %s missing in RFC 6733 source: %v", name, err)
		}
		got, err := Default.FindAVPByName(1, name)
		if err != nil {
			t.Fatal(err)
		}
		if got.Code != want.Code || got.VendorID != want.VendorID || got.Data.TypeName != want.Data.TypeName ||
			nasreqFlags(t, got.Must) != nasreqFlags(t, want.Must) || nasreqFlags(t, got.May) != nasreqFlags(t, want.May) ||
			nasreqFlags(t, got.MustNot) != nasreqFlags(t, want.MustNot) || got.MayEncrypt != want.MayEncrypt {
			t.Errorf("%s differs from RFC 6733 source: got %+v, want %+v", name, got, want)
		}
		if len(got.Data.Enum) != len(want.Data.Enum) {
			t.Errorf("%s enum count %d, want %d", name, len(got.Data.Enum), len(want.Data.Enum))
		}
		for i := range got.Data.Enum {
			if i >= len(want.Data.Enum) {
				break
			}
			if *got.Data.Enum[i] != *want.Data.Enum[i] {
				t.Errorf("%s enum %d differs", name, i)
			}
		}
		if len(got.Data.Rule) != len(want.Data.Rule) {
			t.Errorf("%s member count %d, want %d", name, len(got.Data.Rule), len(want.Data.Rule))
		}
		for i := range got.Data.Rule {
			if i >= len(want.Data.Rule) {
				break
			}
			a, b := got.Data.Rule[i], want.Data.Rule[i]
			if a.AVP != b.AVP || a.Required != b.Required || a.Min != b.Min || a.Max != b.Max || a.MaxSet != b.MaxSet || a.Fixed != b.Fixed ||
				nasreqFlags(t, a.MustNot) != nasreqFlags(t, b.MustNot) {
				t.Errorf("%s member %d differs: %+v vs %+v", name, i, a, b)
			}
			check(b.AVP)
		}
	}
	for _, c := range s.Commands {
		for _, r := range c.Rules {
			check(r.Name)
		}
	}
	if len(seen) < 20 {
		t.Fatalf("only %d reused base AVPs checked", len(seen))
	}
}

// RFC 7155 command grammars use four RADIUS attributes without defining
// Diameter AVP rows. IANA pins their RADIUS identities; the analogous RFC
// 7155 NAS AVPs establish their Diameter wire data representations.
func TestNASREQSupplementalRADIUSAVPs(t *testing.T) {
	for _, want := range loadNASREQSpec(t).Supplemental {
		t.Run(want.Name, func(t *testing.T) {
			got, err := Default.FindAVP(1, want.Code, want.Vendor)
			if err != nil {
				t.Fatal(err)
			}
			if got.Name != want.Name || got.Data.TypeName != want.Type {
				t.Errorf("%s/%s, want %s/%s", got.Name, got.Data.TypeName, want.Name, want.Type)
			}
			if nasreqFlags(t, got.Must) != nasreqFlags(t, want.Must) || nasreqFlags(t, got.May) != nasreqFlags(t, want.May) || nasreqFlags(t, got.MustNot) != nasreqFlags(t, want.MustNot) || got.MayEncrypt != "" {
				t.Errorf("supplemental flags %q/%q/%q/%q, want %q/%q/%q/empty", got.Must, got.May, got.MustNot, got.MayEncrypt, want.Must, want.May, want.MustNot)
			}
			if want.FlagNote == "" || want.Reference == "" || want.RadiusType == "" {
				t.Error("supplemental source and policy omission must be recorded")
			}
		})
	}
}

type nasreqReusedAVPSpec struct {
	Name, Section, Type, Must string
	Code                      uint32
	MustNot                   string `json:"must_not"`
	Items                     map[string]string
	Rules                     []nasreqRuleSpec
}

// RFC 6733 §4.5 has no P or encryption columns. These are the exact
// out-of-scope base.xml annotations inherited by NASREQ before base refresh.
// An empty annotation is also accepted so the source can be corrected later.
var nasreqLegacyBaseP = func() map[string]bool {
	names := strings.Fields(`Accounting-Realtime-Required Accounting-Record-Number Accounting-Record-Type Accounting-Sub-Session-Id Acct-Application-Id Acct-Interim-Interval Acct-Multi-Session-Id Acct-Session-Id Auth-Application-Id Auth-Grace-Period Auth-Request-Type Auth-Session-State Authorization-Lifetime Class Destination-Host Destination-Realm Error-Message Error-Reporting-Host Event-Timestamp Failed-AVP Multi-Round-Time-Out Origin-Host Origin-Realm Origin-State-Id Re-Auth-Request-Type Redirect-Host Redirect-Host-Usage Redirect-Max-Cache-Time Result-Code Session-Id Session-Timeout Termination-Cause User-Name`)
	result := make(map[string]bool, len(names))
	for _, name := range names {
		result[name] = true
	}
	return result
}()

var nasreqLegacyBaseEncryptY = func() map[string]bool {
	names := strings.Fields(`Accounting-Realtime-Required Accounting-Record-Number Accounting-Record-Type Accounting-Sub-Session-Id Acct-Interim-Interval Acct-Multi-Session-Id Acct-Session-Id Class Multi-Round-Time-Out Session-Id User-Name`)
	result := make(map[string]bool, len(names))
	for _, name := range names {
		result[name] = true
	}
	return result
}()

// RFC 6733 §4.5 and §6.7.2 are independent source data for the AVPs
// referenced by RFC 7155 command bodies but inherited from the base app.
func TestNASREQReusedSourceSpec(t *testing.T) {
	b, err := os.ReadFile("testdata/nasreq_reused_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var source struct{ AVPs []nasreqReusedAVPSpec }
	if err := json.Unmarshal(b, &source); err != nil {
		t.Fatal(err)
	}
	if len(source.AVPs) != 37 {
		t.Fatalf("incomplete reused source: %d", len(source.AVPs))
	}
	for _, want := range source.AVPs {
		t.Run(want.Name, func(t *testing.T) {
			got, err := Default.FindAVP(1, want.Code, 0)
			if err != nil {
				t.Fatal(err)
			}
			if got.Name != want.Name || got.Data.TypeName != want.Type || nasreqFlags(t, got.Must) != nasreqFlags(t, want.Must) || nasreqFlags(t, got.MustNot) != nasreqFlags(t, want.MustNot) {
				t.Errorf("RFC 6733 §%s identity/type/M/V: got %s/%s/%s/%s, want %s/%s/%s/%s", want.Section, got.Name, got.Data.TypeName, got.Must, got.MustNot, want.Name, want.Type, want.Must, want.MustNot)
			}
			if nasreqFlags(t, got.May) != 0 && (got.May != "P" || !nasreqLegacyBaseP[want.Name]) {
				t.Errorf("%s has unexpected inherited MAY flags %q", want.Name, got.May)
			}
			legacyEncrypt := "-"
			if nasreqLegacyBaseEncryptY[want.Name] {
				legacyEncrypt = "Y"
			}
			if got.MayEncrypt != "" && got.MayEncrypt != legacyEncrypt {
				t.Errorf("%s has unexpected inherited encryption annotation %q", want.Name, got.MayEncrypt)
			}
			if want.Items != nil {
				// IANA assigns Termination-Cause 11–32 beyond RFC 6733's
				// eight base values. base.xml owns this inherited gap.
				if want.Name == "Termination-Cause" {
					if len(got.Data.Enum) != 8 && len(got.Data.Enum) != len(want.Items) {
						t.Errorf("enum count %d, want 8 or %d", len(got.Data.Enum), len(want.Items))
					}
					if len(got.Data.Enum) == 8 {
						for code := 1; code <= 8; code++ {
							found := false
							for _, item := range got.Data.Enum {
								found = found || item.Code == int32(code)
							}
							if !found {
								t.Errorf("missing RFC 6733 Termination-Cause %d", code)
							}
						}
					}
				} else if len(got.Data.Enum) != len(want.Items) {
					t.Errorf("enum count %d, want %d", len(got.Data.Enum), len(want.Items))
				}
				for _, item := range got.Data.Enum {
					label, ok := want.Items[strconv.Itoa(int(item.Code))]
					if !ok || normalizeEnumName(item.Name) != normalizeEnumName(label) {
						t.Errorf("enum %d=%s, want %s", item.Code, item.Name, label)
					}
				}
			}
			if want.Name == "Proxy-Info" {
				// The missing RFC 6733 §6.7.2 extension point is a base.xml
				// change outside this NASREQ-only update. Pin the two present
				// members and reject any other divergence until base is fixed.
				if len(got.Data.Rule) != 2 && len(got.Data.Rule) != len(want.Rules) {
					t.Fatalf("Proxy-Info has %d members, want 2 or 3", len(got.Data.Rule))
				}
				for i, r := range got.Data.Rule {
					min := r.Min
					if r.Required && min == 0 {
						min = 1
					}
					if r.AVP != want.Rules[i].Name || min != want.Rules[i].Min || r.Fixed != want.Rules[i].Fixed || nasreqFlags(t, r.MustNot) != nasreqFlags(t, want.Rules[i].MustNot) || (want.Rules[i].Max == nil && r.MaxSet) || (want.Rules[i].Max != nil && (!r.MaxSet || r.Max != *want.Rules[i].Max)) {
						t.Errorf("Proxy-Info member %d: %+v, want %+v", i, r, want.Rules[i])
					}
				}
			}
		})
	}
}

// RFC 6733 §4.1 forbids V for vendor-zero IETF AVPs, independently of
// whether an application's individual flag table repeats that prohibition.
func TestNASCCIETFVendorFlagPolicy(t *testing.T) {
	for _, bundle := range []Bundled{NASREQ, CreditControl} {
		t.Run(string(bundle), func(t *testing.T) {
			for _, app := range bundledFiles()[bundle].App {
				for _, a := range app.AVP {
					if a.VendorID == 0 && nasreqFlags(t, a.MustNot)&nasreqFlags(t, "V") == 0 {
						t.Errorf("%s (%d) must prohibit V under RFC 6733 §4.1", a.Name, a.Code)
					}
				}
			}
		})
	}
}
