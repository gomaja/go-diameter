package diam

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// RFC 7155 §§3–4 and RFC 8506 §§3, 8 reuse RFC 6733 and NASREQ AVPs.
// Exercise their complete available named-member closure in each effective
// application, using the same independent source metadata as the spec tests.
func TestNASCCReusedAVPWireRoundTrip(t *testing.T) {
	lookup := map[string]nasreqWireAVP{}
	_, qos := rfc5777WireSpec(t)
	var baseNames []string
	for _, file := range []string{"nasreq_reused_spec.json", "nasreq_spec.json", "credit_control_spec.json", "rfc5777_spec.json", "credit_control_reused_spec.json"} {
		b, err := os.ReadFile("dict/testdata/" + file)
		if err != nil {
			t.Fatal(err)
		}
		var s nasreqWireSpec
		if err := json.Unmarshal(b, &s); err != nil {
			t.Fatal(err)
		}
		for _, a := range append(s.AVPs, s.Supplemental...) {
			lookup[a.Name] = a
			if file == "nasreq_reused_spec.json" {
				baseNames = append(baseNames, a.Name)
			}
		}
	}
	if len(baseNames) != 37 {
		t.Fatalf("incomplete reused NASREQ fixture: %d", len(baseNames))
	}
	for _, app := range []uint32{1, 4} {
		names := baseNames
		if app == 4 {
			names = nil
			seen := map[string]bool{}
			var visit func(string)
			visit = func(name string) {
				if name == "AVP" || seen[name] {
					return
				}
				seen[name] = true
				a, ok := lookup[name]
				if !ok {
					t.Fatalf("missing source metadata for reused %s", name)
				}
				names = append(names, name)
				for _, r := range a.Rules {
					visit(r.Name)
				}
			}
			s := loadCreditControlWireSpec(t)
			for _, a := range s.AVPs {
				seen[a.Name] = true // Already covered by the application wire test.
			}
			for _, a := range s.AVPs {
				for _, r := range a.Rules {
					visit(r.Name)
				}
			}
			for _, c := range s.Commands {
				for _, r := range c.Rules {
					visit(r.Name)
				}
			}
			if len(names) != 91 {
				t.Fatalf("incomplete reused Credit-Control closure: %d", len(names))
			}
		}
		for _, name := range names {
			t.Run(string(rune('0'+app))+"/"+name, func(t *testing.T) {
				want := lookup[name]
				def, err := dict.Default.FindAVP(app, want.Code, want.Vendor)
				if err != nil {
					t.Fatal(err)
				}
				var data datatype.Type
				if source, ok := qos[name]; ok {
					// RFC 5777 §§3–5 source grammar must not regress to an unchecked stub.
					if source.Type == "Grouped" && len(def.Data.Rule) != len(source.Rules) {
						t.Fatalf("%s has %d rules, source has %d", name, len(def.Data.Rule), len(source.Rules))
					}
					data = rfc5777Data(t, source, qos)
				} else {
					data = nasreqWireData(t, want, lookup)
				}
				m := NewRequest(265, app, dict.Default)
				if _, err := m.NewAVPByName(def.Name, gxWireFlags(def.Must), data); err != nil {
					t.Fatal(err)
				}
				assertRefreshWire(t, m, want.Code, gxWireFlags(want.Must), want.Vendor, data)
			})
		}
	}
}
