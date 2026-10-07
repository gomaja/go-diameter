package dict

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestMemberProhibitionsRejectContradictions(t *testing.T) {
	for _, tc := range []struct {
		name, must, forbid string
		wildcard           bool
	}{
		{"required M", "M", "M", false}, {"required P", "P", "P", false},
		{"wildcard M", "M", "M", true}, {"wildcard P", "P", "P", true},
		{"V is structural", "V", "V", false}, {"wildcard V", "V", "V", true},
	} {
		for _, register := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/register=%t", tc.name, register), func(t *testing.T) {
				p := New(Base)
				before := p.Snapshot()
				rules := []*Rule{{AVP: "Leaf", MustNot: tc.forbid}}
				if tc.wildcard {
					rules = []*Rule{{AVP: "AVP", MustNot: tc.forbid}, {AVP: "Leaf"}}
				}
				leaf := &AVP{Name: "Leaf", Code: 70000, VendorID: 777, Must: tc.must, Data: Data{TypeName: "Unsigned32"}}
				group := &AVP{Name: "Group", Code: 70001, VendorID: 777, Must: "V", Data: Data{TypeName: "Grouped", Rule: rules}}
				var err error
				if register {
					err = p.RegisterAVP(42, group, leaf)
				} else {
					b, e := xml.Marshal(File{App: []*App{{ID: 42, AVP: []*AVP{group, leaf}}}})
					if e != nil {
						t.Fatal(e)
					}
					err = p.Load(strings.NewReader(string(b)))
				}
				if err == nil {
					t.Fatal("accepted contradictory prohibition")
				}
				if tc.forbid == "V" {
					if !strings.Contains(err.Error(), "V") {
						t.Error(err)
					}
				} else if !errors.Is(err, ErrAVPConflict) || !strings.Contains(err.Error(), "Leaf") || !strings.Contains(err.Error(), "required") {
					t.Errorf("unclear conflict: %v", err)
				}
				if p.Snapshot() != before {
					t.Fatal("failed operation published state")
				}
			})
		}
	}
}

func TestCommandMemberProhibitionsRejectContradictions(t *testing.T) {
	for _, side := range []string{"request", "answer"} {
		for _, wildcard := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/wildcard=%t", side, wildcard), func(t *testing.T) {
				p := New(Base)
				before := p.Snapshot()
				rule := `<rule avp="Origin-Host" must-not="M"/>`
				if wildcard {
					rule = `<rule avp="Origin-Host"/><rule avp="AVP" must-not="M"/>`
				}
				src := fmt.Sprintf(`<diameter><application id="42"><command code="70000" name="Example"><%s>%s</%s></command></application></diameter>`, side, rule, side)
				err := p.Load(strings.NewReader(src))
				if err == nil || !errors.Is(err, ErrAVPConflict) || !strings.Contains(err.Error(), "Origin-Host") || !strings.Contains(err.Error(), side) {
					t.Fatalf("contradiction: %v", err)
				}
				if p.Snapshot() != before {
					t.Fatal("failed command load published state")
				}
			})
		}
	}
}

// Resolve against the final state, including inherited groups and commands.
func TestMemberProhibitionsRecheckReplacements(t *testing.T) {
	for _, command := range []bool{false, true} {
		t.Run(fmt.Sprintf("command=%t", command), func(t *testing.T) {
			p := New(Base)
			owner := `<avp name="Group" code="70001"><data type="Grouped"><rule avp="Leaf" must-not="M"/></data></avp>`
			if command {
				owner = `<command code="70000" name="Example"><request><rule avp="Leaf" must-not="M"/></request></command>`
			}
			src := `<diameter><application id="0"><avp name="Leaf" code="70000"><data type="Unsigned32"/></avp>` + owner + `</application></diameter>`
			if err := p.Load(strings.NewReader(src)); err != nil {
				t.Fatal(err)
			}
			before := p.Snapshot()
			if err := p.Load(strings.NewReader(`<diameter><application id="42"><avp name="Leaf" code="70000" must="M"><data type="Unsigned32"/></avp></application></diameter>`)); err == nil || !errors.Is(err, ErrAVPConflict) {
				t.Fatalf("inherited contradiction: %v", err)
			}
			if p.Snapshot() != before {
				t.Fatal("failed replacement published state")
			}
			// A compatible replacement is still valid; failed publication left no debris.
			if err := p.Load(strings.NewReader(`<diameter><application id="42"><avp name="Leaf" code="70000" may="M"><data type="Unsigned32"/></avp></application></diameter>`)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRuleUnmarshalRejectsInvalidProhibitions(t *testing.T) {
	for _, bad := range []string{"V", "M,V", "PV", "X", "M.X", "M X"} {
		t.Run(bad, func(t *testing.T) {
			var r Rule
			if err := xml.Unmarshal([]byte(`<rule avp="Leaf" must-not="`+bad+`"/>`), &r); err == nil {
				t.Fatalf("accepted %q", bad)
			}
		})
	}
	for _, valid := range []string{"", "-", "M", "P", "M,P", "PM", " P, M "} {
		var r Rule
		if err := xml.Unmarshal([]byte(`<rule avp="Leaf" must-not="`+valid+`"/>`), &r); err != nil {
			t.Errorf("%q: %v", valid, err)
		}
	}
}

func TestSnapshotStringPrintsMemberProhibitions(t *testing.T) {
	p := New()
	src := `<diameter><application id="42"><avp name="Leaf" code="70000"><data type="Unsigned32"/></avp><avp name="Group" code="70001"><data type="Grouped"><rule avp="Leaf" must-not="M"/></data></avp><command code="70000" name="Example"><request><rule avp="Leaf" must-not="P"/></request><answer><rule avp="Leaf" must-not="M,P"/></answer></command></application></diameter>`
	if err := p.Load(strings.NewReader(src)); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{`must-not="M"`, `must-not="P"`, `must-not="M,P"`} {
		if !strings.Contains(p.Snapshot().String(), value) {
			t.Errorf("missing %s from snapshot", value)
		}
	}
}

func FuzzMemberProhibitions(f *testing.F) {
	for _, flags := range []string{"", "-", "M", "P", "PM", "M,P", "V", "M.V", "X", " P, M "} {
		for required := uint8(0); required < 4; required++ {
			f.Add(flags, required)
		}
	}
	f.Fuzz(func(t *testing.T, flags string, required uint8) {
		if len(flags) > 256 {
			t.Skip()
		}
		must := "V"
		if required&1 != 0 {
			must += "M"
		}
		if required&2 != 0 {
			must += "P"
		}
		leaf := &AVP{Name: "Leaf", Code: 70000, VendorID: 777, Must: must, Data: Data{TypeName: "Unsigned32"}}
		group := &AVP{Name: "Group", Code: 70001, Data: Data{TypeName: "Grouped", Rule: []*Rule{{AVP: "Leaf", MustNot: flags}}}}
		b, err := xml.Marshal(File{App: []*App{{ID: 42, AVP: []*AVP{group, leaf}}}})
		if err != nil {
			return
		}
		// XML replaces some forbidden characters. Compare the two entry points
		// only when the attribute survives encoding without a transformation.
		var raw struct {
			App []struct {
				AVP []struct {
					Data struct {
						Rule []struct {
							MustNot string `xml:"must-not,attr"`
						} `xml:"rule"`
					} `xml:"data"`
				} `xml:"avp"`
			} `xml:"application"`
		}
		if err := xml.Unmarshal(b, &raw); err != nil || raw.App[0].AVP[0].Data.Rule[0].MustNot != flags {
			return
		}
		mask, flagErr := parseFlags(flags)
		wantOK := flagErr == nil && mask&flagV == 0 && mask&int(required&3) == 0
		for _, register := range []bool{false, true} {
			p := New()
			before := p.Snapshot()
			if register {
				err = p.RegisterAVP(42, group, leaf)
			} else {
				err = p.Load(strings.NewReader(string(b)))
			}
			if (err == nil) != wantOK {
				t.Fatalf("flags=%q required=%q register=%t: %v, want acceptance %t", flags, must, register, err, wantOK)
			}
			if err != nil && p.Snapshot() != before {
				t.Fatal("rejected prohibition changed the snapshot")
			}
		}
	})
}
