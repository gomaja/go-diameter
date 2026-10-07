package dict

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"os"
	"strconv"
	"strings"
	"testing"
)

// The fixture records RFC 8506 §§3 and 8, with the §12 IANA registries.
// Its grouped and command rules are extracted from the printed CCF, not XML.
type creditControlSpec struct {
	AVPs []struct {
		Name, Section, Type, Must, May string
		Code                           uint32
		MustNot                        string `json:"must_not"`
		Items                          map[string]string
		Rules                          []creditControlRule
	}
	Commands []struct {
		Section            string
		Code               uint32
		Request, Proxiable bool
		Rules              []creditControlRule
	}
}
type creditControlRule struct {
	Name    string
	Min     int
	Max     *int
	Fixed   bool
	MustNot string `json:"must_not"`
}

func loadCreditControlSpec(t *testing.T) creditControlSpec {
	t.Helper()
	data, err := os.ReadFile("testdata/credit_control_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec creditControlSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	if len(spec.AVPs) != 68 || len(spec.Commands) != 2 {
		t.Fatalf("incomplete RFC 8506 fixture: %d AVPs, %d commands", len(spec.AVPs), len(spec.Commands))
	}
	groups, values := 0, 0
	for _, a := range spec.AVPs {
		if a.Type == "Grouped" {
			groups++
		}
		values += len(a.Items)
	}
	if groups != 17 || values != 46 || len(spec.Commands[0].Rules) != 30 || len(spec.Commands[1].Rules) != 29 {
		t.Fatalf("incomplete RFC 8506 fixture: %d groups, %d enum values, %d/%d command rules", groups, values, len(spec.Commands[0].Rules), len(spec.Commands[1].Rules))
	}
	return spec
}

func creditControlFlagSet(t *testing.T, s string) int {
	t.Helper()
	flags, err := parseFlags(s)
	if err != nil {
		t.Fatalf("invalid flag set %q: %v", s, err)
	}
	return flags
}

func checkCreditControlRules(t *testing.T, got []*Rule, want []creditControlRule) {
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
		if a.AVP != b.Name || min != b.Min || a.Required != (b.Min > 0) || a.Fixed != b.Fixed || (b.Max == nil && a.MaxSet) || (b.Max != nil && (!a.MaxSet || a.Max != *b.Max)) {
			t.Errorf("rule %d: %+v, want %+v", i, a, b)
		}
		if creditControlFlagSet(t, a.MustNot) != creditControlFlagSet(t, b.MustNot) {
			t.Errorf("rule %d (%s) must-not=%q, want %q", i, a.AVP, a.MustNot, b.MustNot)
		}
	}
}

// RFC 8506 §8 table, §§8.1–8.68; current IANA AAA Parameters AVP values
// allocated under §12. This exercises application 4 after inheritance loads.
func TestCreditControlAVPSpec(t *testing.T) {
	seen := map[uint32]bool{}
	for _, want := range loadCreditControlSpec(t).AVPs {
		t.Run(want.Section+"/"+want.Name, func(t *testing.T) {
			if seen[want.Code] {
				t.Fatalf("duplicate fixture code %d", want.Code)
			}
			seen[want.Code] = true
			got, err := Default.FindAVP(4, want.Code, 0)
			if err != nil {
				t.Fatal(err)
			}
			if got.Name != want.Name || got.Code != want.Code || got.VendorID != 0 || got.Data.TypeName != want.Type {
				t.Errorf("identity/type = %s/%d/%d/%s, want %s/%d/0/%s", got.Name, got.Code, got.VendorID, got.Data.TypeName, want.Name, want.Code, want.Type)
			}
			if creditControlFlagSet(t, got.Must) != creditControlFlagSet(t, want.Must) || creditControlFlagSet(t, got.May) != creditControlFlagSet(t, want.May) || creditControlFlagSet(t, got.MustNot) != creditControlFlagSet(t, want.MustNot) {
				t.Errorf("must/may/must-not = %q/%q/%q, want %q/%q/%q", got.Must, got.May, got.MustNot, want.Must, want.May, want.MustNot)
			}
			if got.MayEncrypt != "" {
				t.Errorf("legacy encryption metadata %q, want empty", got.MayEncrypt)
			}
			if len(got.Data.Enum) != len(want.Items) {
				t.Errorf("enum count %d, want %d", len(got.Data.Enum), len(want.Items))
			}
			for _, item := range got.Data.Enum {
				name, ok := want.Items[strconv.Itoa(int(item.Code))]
				if !ok || item.Name != name {
					t.Errorf("enum %d=%q, want %q", item.Code, item.Name, name)
				}
			}
			checkCreditControlRules(t, got.Data.Rule, want.Rules)
		})
	}
}

// RFC 8506 §§3.1–3.2. TS 32.299's application-4 Service-Information
// extension remains in the CCR immediately before the RFC extension point.
func TestCreditControlCommandSpec(t *testing.T) {
	for _, want := range loadCreditControlSpec(t).Commands {
		t.Run(want.Section, func(t *testing.T) {
			command, err := Default.FindCommand(4, want.Code)
			if err != nil {
				t.Fatal(err)
			}
			got := command.Answer
			if want.Request {
				got = command.Request
			}
			if got.Proxiable == nil || *got.Proxiable != want.Proxiable {
				t.Errorf("proxiable constraint %v, want %t", got.Proxiable, want.Proxiable)
			}
			rules := got.Rule
			if want.Request {
				if len(rules) != len(want.Rules)+1 || rules[len(rules)-2].AVP != "Service-Information" || rules[len(rules)-2].Required || !rules[len(rules)-2].MaxSet || rules[len(rules)-2].Max != 1 {
					t.Fatalf("unexpected Ro/Rf extension in CCR: %+v", rules)
				}
				rules = append(append([]*Rule(nil), rules[:len(rules)-2]...), rules[len(rules)-1])
			}
			checkCreditControlRules(t, rules, want.Rules)
		})
	}
}

// RFC 8506 §8 definitions flow into all seven charging descendants unless
// that application or an intermediate parent provides an explicit override.
func TestCreditControlInheritedAVPSpec(t *testing.T) {
	for _, appID := range []uint32{16777236, 16777238, 16777251, 16777265, 16777302, 16777312, 16777313} {
		inherited := 0
		for _, want := range loadCreditControlSpec(t).AVPs {
			got, err := Default.FindAVP(appID, want.Code, 0)
			if err != nil {
				t.Errorf("app %d %s: %v", appID, want.Name, err)
				continue
			}
			if got.App.ID != 4 {
				continue // Source specification for the explicit local override is tested separately.
			}
			inherited++
			if got.Name != want.Name || got.Data.TypeName != want.Type || creditControlFlagSet(t, got.Must) != creditControlFlagSet(t, want.Must) || creditControlFlagSet(t, got.May) != creditControlFlagSet(t, want.May) || creditControlFlagSet(t, got.MustNot) != creditControlFlagSet(t, want.MustNot) || got.MayEncrypt != "" {
				t.Errorf("app %d inherited %s as %s/%s/%s/%s/%s/encrypt=%s", appID, want.Name, got.Name, got.Data.TypeName, got.Must, got.May, got.MustNot, got.MayEncrypt)
			}
			if len(got.Data.Enum) != len(want.Items) {
				t.Errorf("app %d %s: enum count %d, want %d", appID, want.Name, len(got.Data.Enum), len(want.Items))
			}
			for _, item := range got.Data.Enum {
				if want.Items[strconv.Itoa(int(item.Code))] != item.Name {
					t.Errorf("app %d %s: enum %d=%s", appID, want.Name, item.Code, item.Name)
				}
			}
			checkCreditControlRules(t, got.Data.Rule, want.Rules)
		}
		if inherited < 40 {
			t.Errorf("app %d inherits only %d RFC 8506 definitions", appID, inherited)
		}
	}
}

// RFC 8506 §§3.1–3.2 and §8.68 reuse these Grouped AVPs. Their source
// grammars live outside this RFC. Require the complete RFC 5777 grammar;
// only the two documented RFC 6733 shared gaps may retain partial rules.
func TestCreditControlReferencedGroupedSourceGaps(t *testing.T) {
	data, err := os.ReadFile("testdata/credit_control_reused_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	type groupedSource struct {
		Name, Source, Type string
		Code               uint32
		Rules              []creditControlRule
		KnownRuleCount     *int `json:"known_shared_rule_count"`
	}
	var fixture struct {
		KnownSharedGaps []groupedSource `json:"known_shared_gaps"`
		RequiredGrouped []groupedSource `json:"required_grouped"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.KnownSharedGaps) != 2 || len(fixture.RequiredGrouped) != 1 || fixture.RequiredGrouped[0].Name != "Filter-Rule" || fixture.RequiredGrouped[0].KnownRuleCount != nil {
		t.Fatal("expected two base gaps and a strict Filter-Rule grammar")
	}
	for _, want := range append(fixture.RequiredGrouped, fixture.KnownSharedGaps...) {
		t.Run(want.Name, func(t *testing.T) {
			if want.Source == "" || len(want.Rules) == 0 {
				t.Fatal("missing source grammar")
			}
			got, err := Default.FindAVP(4, want.Code, 0)
			if err != nil {
				t.Fatal(err)
			}
			if got.Name != want.Name || got.Data.TypeName != want.Type {
				t.Errorf("identity/type = %s/%s, want %s/%s", got.Name, got.Data.TypeName, want.Name, want.Type)
			}
			if want.KnownRuleCount == nil || len(got.Data.Rule) == len(want.Rules) {
				checkCreditControlRules(t, got.Data.Rule, want.Rules)
				return
			}
			if len(got.Data.Rule) != *want.KnownRuleCount || *want.KnownRuleCount >= len(want.Rules) {
				t.Errorf("%s grammar has %d rules; source has %d; documented shared state is %d", want.Source, len(got.Data.Rule), len(want.Rules), *want.KnownRuleCount)
				return
			}
			for i := 0; i < len(got.Data.Rule); i++ {
				checkCreditControlRules(t, got.Data.Rule[i:i+1], want.Rules[i:i+1])
			}
			t.Logf("documented shared gap: %s has %d of %d %s rules", want.Name, len(got.Data.Rule), len(want.Rules), want.Source)
		})
	}
}

// RFC 8506 §§3.1–3.2, 8.16–8.68 reuse NASREQ/base AVPs. Walk every
// named member reachable from the CC grammars and pin metadata and enums to
// the source fixtures for RFC 7155 and RFC 6733, including Proxy-Info's two
// required descendants and the complete RFC 5777 Filter-Rule closure.
func TestCreditControlReusedSourceClosure(t *testing.T) {
	checkCreditControlReusedSourceClosure(t, Default)
}

func checkCreditControlReusedSourceClosure(t *testing.T, dictionary *Parser) {
	t.Helper()
	type sourceAVP struct {
		Name, Type, Must, May string
		Code                  uint32
		MustNot               string `json:"must_not"`
		Items                 map[string]string
		Rules                 []creditControlRule
	}
	sources := map[string]sourceAVP{}
	for _, filename := range []string{"testdata/nasreq_spec.json", "testdata/nasreq_reused_spec.json", "testdata/rfc5777_spec.json", "testdata/credit_control_reused_spec.json"} {
		b, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		var source struct {
			AVPs         []sourceAVP
			Supplemental []sourceAVP
		}
		if err := json.Unmarshal(b, &source); err != nil {
			t.Fatal(err)
		}
		for _, a := range append(source.AVPs, source.Supplemental...) {
			if previous, ok := sources[a.Name]; ok && previous.Code != a.Code {
				t.Fatalf("conflicting source identity %s: %d/%d", a.Name, previous.Code, a.Code)
			}
			sources[a.Name] = a
		}
	}
	local := map[string]bool{}
	cc := loadCreditControlSpec(t)
	for _, a := range cc.AVPs {
		local[a.Name] = true
	}
	var pending []string
	for _, a := range cc.AVPs {
		for _, r := range a.Rules {
			pending = append(pending, r.Name)
		}
	}
	for _, c := range cc.Commands {
		for _, r := range c.Rules {
			pending = append(pending, r.Name)
		}
	}
	// The legacy MAY-P values are shared base.xml metadata under the separate
	// RFC 6733 refresh. Both the printed RFC flag set and this exact current
	// shared gap are accepted; no other flag relaxation is allowed here.
	legacyMayP := map[string]bool{
		"Acct-Multi-Session-Id": true, "Auth-Application-Id": true,
		"Destination-Host": true, "Destination-Realm": true,
		"Event-Timestamp": true, "Failed-AVP": true,
		"Origin-Host": true, "Origin-Realm": true, "Origin-State-Id": true,
		"Redirect-Host": true, "Redirect-Host-Usage": true,
		"Redirect-Max-Cache-Time": true, "Result-Code": true,
		"Session-Id": true, "Termination-Cause": true, "User-Name": true, "Vendor-Id": true,
	}
	visited := map[string]bool{}
	for len(pending) != 0 {
		name := pending[0]
		pending = pending[1:]
		if name == "AVP" || local[name] || visited[name] {
			continue
		}
		visited[name] = true
		want, ok := sources[name]
		if !ok {
			t.Errorf("no source fixture for reused AVP %s", name)
			continue
		}
		got, err := dictionary.FindAVPByName(4, name)
		if err != nil {
			t.Error(err)
			continue
		}
		if got.Code != want.Code || got.VendorID != 0 || got.Data.TypeName != want.Type || creditControlFlagSet(t, got.Must) != creditControlFlagSet(t, want.Must) || creditControlFlagSet(t, got.MustNot) != creditControlFlagSet(t, want.MustNot) {
			t.Errorf("%s identity/type/flags = %d/%d/%s/%q/%q; source %d/0/%s/%q/%q", name, got.Code, got.VendorID, got.Data.TypeName, got.Must, got.MustNot, want.Code, want.Type, want.Must, want.MustNot)
		}
		allowedLegacyMayP := legacyMayP[name] && got.App.ID == 0 && creditControlFlagSet(t, got.May) == creditControlFlagSet(t, "P") && creditControlFlagSet(t, want.May) == 0
		if creditControlFlagSet(t, got.May) != creditControlFlagSet(t, want.May) && !allowedLegacyMayP {
			t.Errorf("%s MAY flags %q, source %q", name, got.May, want.May)
		}
		knownTerminationGap := name == "Termination-Cause" && got.App.ID == 0 && len(got.Data.Enum) == 8 && len(want.Items) == 30
		if len(got.Data.Enum) != len(want.Items) && !knownTerminationGap {
			t.Errorf("%s enum count %d, source %d", name, len(got.Data.Enum), len(want.Items))
		}
		for _, item := range got.Data.Enum {
			label, ok := want.Items[strconv.Itoa(int(item.Code))]
			if !ok || normalizeEnumName(label) != normalizeEnumName(item.Name) {
				t.Errorf("%s enum %d=%s, source %s", name, item.Code, item.Name, label)
			}
		}
		if name != "Proxy-Info" && name != "Failed-AVP" {
			checkCreditControlRules(t, got.Data.Rule, want.Rules)
		}
		for _, rule := range want.Rules {
			pending = append(pending, rule.Name)
		}
	}
	if len(visited) != 91 { // Includes Filter-Rule's 68 descendants and Vendor-Id.
		t.Errorf("source closure covered %d reused AVPs, want 91", len(visited))
	}
}

// Current IANA labels may be spaced or normalized by a base dictionary refresh.
// Exercise the complete reused-source check with all 30 assigned values in an
// isolated dictionary, preserving the global default and the source fixture.
func TestCreditControlReusedIANAEnumLabels(t *testing.T) {
	b, err := os.ReadFile("testdata/nasreq_reused_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var source struct{ AVPs []nasreqReusedAVPSpec }
	if err := json.Unmarshal(b, &source); err != nil {
		t.Fatal(err)
	}
	dictionary := New(AllBundled()...)
	existing, err := dictionary.FindAVPByName(0, "Termination-Cause")
	if err != nil {
		t.Fatal(err)
	}
	replacement := *existing
	replacement.Data.Enum = nil
	for _, a := range source.AVPs {
		if a.Name != "Termination-Cause" {
			continue
		}
		for code, label := range a.Items {
			n, err := strconv.ParseInt(code, 10, 32)
			if err != nil {
				t.Fatal(err)
			}
			replacement.Data.Enum = append(replacement.Data.Enum, &Enum{Code: int32(n), Name: strings.ToUpper(strings.ReplaceAll(label, " ", "_"))})
		}
	}
	if len(replacement.Data.Enum) != 30 {
		t.Fatalf("incomplete IANA registry: %d", len(replacement.Data.Enum))
	}
	document, err := xml.Marshal(&File{App: []*App{{ID: 0, AVP: []*AVP{&replacement}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := dictionary.Load(bytes.NewReader(document)); err != nil {
		t.Fatal(err)
	}
	checkCreditControlReusedSourceClosure(t, dictionary)
}
