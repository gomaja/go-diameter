package dict

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
	"testing"
)

// TS 29.214 V20.0.0 §§5.3.34, 5.3.49, 5.3.62; RFC 8583 §7.3.
func TestGxReusedDefinitionsMatchSources(t *testing.T) {
	for _, app := range []uint32{16777238, 16777236} {
		t.Run(fmt.Sprint(app), func(t *testing.T) {
			a, err := Default.FindAVPByName(app, "Callee-Information")
			if err != nil {
				t.Fatal(err)
			}
			want := []s6aGroupedRuleSpec{{Name: "Called-Party-Address", Max: new(1)}, {Name: "Requested-Party-Address"}, {Name: "Called-Asserted-Identity"}, {Name: "AVP"}}
			gxCheckRules(t, a.Data.Rule, want)
			a, err = Default.FindAVPByName(app, "Required-Access-Info")
			if err != nil {
				t.Fatal(err)
			}
			if len(a.Data.Enum) != 3 || a.Data.Enum[2].Code != 2 || a.Data.Enum[2].Name != "UE_SAT_INFO" {
				t.Errorf("Required-Access-Info: %+v", a.Data.Enum)
			}
			a, err = Default.FindAVPByName(app, "Content-Version")
			if err != nil {
				t.Fatal(err)
			}
			if a.Data.TypeName != "Unsigned64" {
				t.Errorf("Content-Version = %s", a.Data.TypeName)
			}
		})
	}
	for _, app := range Default.Apps() {
		for _, a := range app.AVP {
			if a.Name == "Load-Value" && a.Data.TypeName != "Unsigned64" {
				t.Errorf("application %d Load-Value = %s", app.ID, a.Data.TypeName)
			}
		}
	}
}

func TestGxFlagSetsAreExact(t *testing.T) {
	for _, bad := range []string{"M.V", "M|V", "M,X", "M V", "MANDATORY", "m", "V;M", "M,?"} {
		if gxFlags(bad) == gxFlags("M,V") || gxFlags(bad) == gxFlags("M") || gxFlags(bad) == gxFlags("") {
			t.Errorf("invalid flag set %q normalized to valid flags %q", bad, gxFlags(bad))
		}
	}
	for _, app := range Default.Apps() {
		for _, a := range app.AVP {
			for _, s := range []string{a.Must, a.May, a.MustNot} {
				if _, err := parseFlags(s); err != nil {
					t.Errorf("%s: %v", a.Name, err)
				}
			}
		}
	}
	a, err := Default.FindAVPByName(16777238, "Event-Trigger")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range a.Data.Enum {
		if e.Code == 36 && e.Name != "USER_CSG_HYBRID_UNSUBSCRIBED_INFORMATION_CHANGE" {
			t.Errorf("Event-Trigger 36 = %q", e.Name)
		}
	}
}

func TestLoadRejectsUnknownFlags(t *testing.T) {
	for _, attr := range []string{"must", "may", "must-not"} {
		for _, bad := range []string{"M.V", "X", "M V", "M|V", "M,X", "m", "M\u00a0V"} {
			t.Run(attr+"/"+bad, func(t *testing.T) {
				p := new(Parser)
				before := p.Snapshot()
				src := fmt.Sprintf(`<diameter><application id="42"><avp name="Bad" code="99" %s="%s"><data type="Unsigned32"/></avp></application></diameter>`, attr, bad)
				if err := p.Load(strings.NewReader(src)); err == nil || !strings.Contains(err.Error(), "unknown flag") {
					t.Errorf("Load error = %v", err)
				}
				if p.Snapshot() != before {
					t.Error("failed load published a snapshot")
				}
			})
		}
	}
}

func TestGroupedMemberFlagRuleXML(t *testing.T) {
	var rule Rule
	if err := xml.Unmarshal([]byte(`<rule avp="SourceID" max="1" must-not="M"/>`), &rule); err != nil {
		t.Fatal(err)
	}
	b, err := xml.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `must-not="M"`) {
		t.Fatalf("member restriction lost: %s", b)
	}
}

func TestLoadAcceptsValidFlags(t *testing.T) {
	for _, value := range []string{"", "-", "M", "V", "P", "M,V", "MV", " P, VM ", "M,M"} {
		for _, attr := range []string{"must", "may", "must-not"} {
			p := new(Parser)
			src := fmt.Sprintf(`<diameter><application id="42"><avp name="Example" code="99" %s="%s"><data type="Unsigned32"/></avp></application></diameter>`, attr, value)
			if err := p.Load(strings.NewReader(src)); err != nil {
				t.Errorf("%s=%q: %v", attr, value, err)
			}
		}
	}
}
func TestMemberFlagsRegistration(t *testing.T) {
	p := new(Parser)
	a := vendorAVP("Group", 70001, "Grouped")
	a.Data.Rule = []*Rule{{AVP: "AVP", MustNot: "M.X"}}
	if err := p.RegisterAVP(4, a); err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Fatalf("RegisterAVP: %v", err)
	}
	a.Data.Rule[0].MustNot = "M"
	if err := p.RegisterAVP(4, a); err != nil {
		t.Fatal(err)
	}
	a.Data.Rule[0].MustNot = "P"
	if err := p.RegisterAVP(4, a); err == nil {
		t.Fatal("different member restriction accepted as identical")
	}
}
func FuzzDictionaryFlagRules(f *testing.F) {
	for _, s := range []string{"", "-", "M,V", "MV", "M.V", "M,X", "M V", " V,P ", "M\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 256 {
			t.Skip()
		}
		var value bytes.Buffer
		if err := xml.EscapeText(&value, []byte(s)); err != nil {
			return
		}
		src := `<diameter><application id="42"><avp name="Example" code="99" must="` + value.String() + `"><data type="Unsigned32"/></avp></application></diameter>`
		// EscapeText replaces characters forbidden by XML 1.0 (for example
		// form feed). Only compare flag parsing for losslessly represented input.
		var attr struct {
			Must string `xml:"must,attr"`
		}
		if err := xml.Unmarshal([]byte(`<avp must="`+value.String()+`"/>`), &attr); err != nil || attr.Must != s {
			return
		}
		p := new(Parser)
		err := p.Load(strings.NewReader(src))
		_, flagErr := parseFlags(s)
		if err == nil && flagErr != nil {
			t.Fatalf("accepted malformed rule %q: %v", s, flagErr)
		}
		if flagErr == nil && err != nil {
			t.Fatalf("rejected valid rule %q: %v", s, err)
		}
	})
}
