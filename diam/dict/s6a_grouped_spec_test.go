package dict

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

type s6aGroupedRuleSpec struct {
	Name  string `json:"name"`
	Min   int    `json:"min"`
	Max   *int   `json:"max"` // nil means unbounded.
	Fixed bool   `json:"fixed"`
}

type s6aGroupedAVPSpec struct {
	Name    string               `json:"name"`
	Section string               `json:"section"`
	Rules   []s6aGroupedRuleSpec `json:"rules"`
}

// The fixture contains all machine-extracted 61 grouped ABNF blocks in TS 29.272 V19.6.0
// §7.3, including the S6a/S6d-specific forms of reused AVPs.
func TestS6aGroupedABNFSpec(t *testing.T) {
	b, err := os.ReadFile("testdata/s6a_grouped_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected []s6aGroupedAVPSpec
	if err := json.Unmarshal(b, &expected); err != nil {
		t.Fatal(err)
	}
	if len(expected) != 61 {
		t.Fatalf("grouped ABNF fixture has %d groups, want 61", len(expected))
	}
	for _, tc := range expected {
		t.Run(tc.Section+"/"+tc.Name, func(t *testing.T) {
			checkS6aGroupedGrammar(t, 16777251, tc)
			if tc.Name == "Terminal-Information" {
				checkS6aGroupedGrammar(t, 16777252, tc)
			}
		})
	}
}

func checkS6aGroupedGrammar(t *testing.T, appID uint32, tc s6aGroupedAVPSpec) {
	t.Helper()
	name := tc.Name
	if name == "Monitoring Event Report" { // §7.3.196 uses spaces in its ABNF label.
		name = "Monitoring-Event-Report"
	}
	if name == "Service-Type" { // §7.3.94's AVP is 3GPP Service-Type.
		name = "TGPP-Service-Type"
	}
	avp, err := Default.FindAVPByName(appID, name)
	if err != nil {
		t.Fatalf("TS 29.272 V19.6.0 %s app %d: %v", tc.Section, appID, err)
	}
	if avp.Data.TypeName != "Grouped" {
		t.Fatalf("app %d %s: type %s, want Grouped", appID, name, avp.Data.TypeName)
	}
	got := avp.Data.Rule
	if len(got) != len(tc.Rules) {
		t.Errorf("app %d %s: %d members, want %d", appID, name, len(got), len(tc.Rules))
	}
	for i := 0; i < len(got) && i < len(tc.Rules); i++ {
		want := tc.Rules[i]
		wantName := s6aABNFMemberAlias(appID, want.Name)
		if normalizeS6aABNFName(got[i].AVP) != normalizeS6aABNFName(wantName) {
			t.Errorf("app %d %s member %d: name %q, want %q", appID, name, i, got[i].AVP, wantName)
		}
		min := got[i].Min
		if got[i].Required && min == 0 {
			min = 1
		}
		if min != want.Min || got[i].Required != (want.Min > 0) || got[i].Fixed != want.Fixed {
			t.Errorf("app %d %s member %d (%s): min/required/fixed %d/%t/%t, want %d/%t/%t",
				appID, name, i, want.Name, min, got[i].Required, got[i].Fixed,
				want.Min, want.Min > 0, want.Fixed)
		}
		if want.Max == nil {
			if got[i].MaxSet {
				t.Errorf("app %d %s member %d (%s): max %d, want unbounded", appID, name, i, want.Name, got[i].Max)
			}
		} else if !got[i].MaxSet || got[i].Max != *want.Max {
			t.Errorf("app %d %s member %d (%s): max %s, want %d", appID, name, i, want.Name,
				actualRuleMax(got[i]), *want.Max)
		}
	}
}

func s6aABNFMemberAlias(appID uint32, name string) string {
	switch name {
	case "Service-Type":
		return "TGPP-Service-Type"
	case "3GPP-Charging-Characteristics":
		return "TGPP-Charging-Characteristics"
	case "3GPP2-MEID":
		if appID == 16777252 {
			return "TGPP2-MEID"
		}
	}
	return name
}

func normalizeS6aABNFName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(unicode.ToUpper(r))
		}
	}
	return b.String()
}

func actualRuleMax(r *Rule) string {
	if !r.MaxSet {
		return "unbounded"
	}
	return strconv.Itoa(r.Max)
}
