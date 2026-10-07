package dict

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestInheritanceParentNameAgreement(t *testing.T) {
	for _, tc := range []struct {
		name, graph, avpName               string
		ancestor, ancestorCode, nearerCode uint32
		parents                            [2]uint32
	}{
		{"B3", `<application id="40" inherits="42 43"/><application id="42" inherits="44"/><application id="43" inherits="44"/><application id="44"/>` + nameDefinition(42, 6, 10415, "Foo", "Unsigned32"), "Foo", 44, 4, 6, [2]uint32{42, 43}},
		{"C1", `<application id="40" inherits="41 42"/><application id="42" inherits="43"/><application id="43" inherits="41"/><application id="41"/>` + nameDefinition(43, 2, 10415, "N", "Unsigned32"), "N", 41, 1, 2, [2]uint32{41, 42}},
		{"base fallback", `<application id="40" inherits="42 43"/><application id="42"/><application id="43"/><application id="0"/>` + nameDefinition(42, 6, 10415, "Foo", "Unsigned32"), "Foo", 0, 4, 6, [2]uint32{42, 43}},
		// The middle parent does not resolve Foo; the first and third disagree.
		{"third parent", `<application id="40" inherits="41 42 43"/><application id="41"/><application id="42"/><application id="43"/>` + nameDefinition(43, 6, 10415, "Foo", "Unsigned32"), "Foo", 41, 1, 6, [2]uint32{41, 43}},
	} {
		for _, registered := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/registered=%t", tc.name, registered), func(t *testing.T) {
				p := new(Parser)
				if registered {
					if err := p.Load(strings.NewReader("<diameter>" + tc.graph + "</diameter>")); err != nil {
						t.Fatal(err)
					}
				}
				before := p.Snapshot()
				dump := dumpSnapshot(before)
				var err error
				if registered {
					defs := []*AVP{{Name: tc.avpName, Code: tc.ancestorCode, VendorID: 10415, Data: Data{TypeName: "Unsigned32"}}}
					if tc.name == "B3" {
						// Install the member and group together: RegisterAVP cannot replace
						// an already resolved name. The group is then inherited by 43.
						defs = append(defs, &AVP{Name: "G", Code: 8, VendorID: 10415, Data: Data{TypeName: "Grouped", Rule: []*Rule{{AVP: "Foo", Required: true, Max: 1}}}})
					}
					err = p.RegisterAVP(tc.ancestor, defs...)
				} else {
					input := tc.graph + nameDefinition(tc.ancestor, tc.ancestorCode, 10415, tc.avpName, "Unsigned32")
					if tc.name == "B3" {
						input += `<application id="43"><avp name="G" code="8" vendor-id="10415"><data type="Grouped"><rule avp="Foo" required="true" max="1"/></data></avp></application>`
					}
					err = p.Load(strings.NewReader("<diameter>" + input + "</diameter>"))
				}
				if !errors.Is(err, ErrAVPConflict) {
					t.Fatalf("parent disagreement accepted: %v; want ErrAVPConflict", err)
				}
				for _, part := range []string{"application 40", tc.avpName, fmt.Sprintf("parent %d", tc.parents[0]), fmt.Sprintf("parent %d", tc.parents[1]), fmt.Sprintf("code %d", tc.ancestorCode), fmt.Sprintf("code %d", tc.nearerCode), "vendor 10415"} {
					if !strings.Contains(err.Error(), part) {
						t.Errorf("parent disagreement error %q lacks %q", err, part)
					}
				}
				if p.Snapshot() != before {
					t.Error("rejected disagreement published a snapshot")
				}
				diffDumps(t, "rejected parent disagreement", dumpSnapshot(p.Snapshot()), dump)
			})
		}
	}
	for _, tc := range []struct {
		name, graph, avpName string
		code                 uint32
		absent               string
	}{
		{"diamond", `<application id="40" inherits="42 43"/><application id="42" inherits="44"/><application id="43" inherits="44"/>` + nameDefinition(44, 4, 10415, "Foo", "Unsigned32"), "Foo", 4, ""},
		{"same identity", `<application id="40" inherits="42 43"/><application id="42" inherits="44"/><application id="43" inherits="44"/>` + nameDefinition(44, 4, 10415, "Foo", "Unsigned32") + nameDefinition(42, 4, 10415, "Foo", "OctetString") + nameDefinition(43, 4, 10415, "Foo", "OctetString"), "Foo", 4, ""},
		{"both rename", `<application id="40" inherits="42 43"/><application id="42" inherits="44"/><application id="43" inherits="44"/>` + nameDefinition(44, 4, 10415, "Foo", "Unsigned32") + nameDefinition(42, 4, 10415, "Renamed", "Unsigned32") + nameDefinition(43, 4, 10415, "Renamed", "Unsigned32"), "Renamed", 4, "Foo"},
		{"single explicit base shadow", `<application id="40" inherits="0 42"/>` + nameDefinition(0, 4, 10415, "Foo", "Unsigned32") + nameDefinition(42, 6, 10415, "Foo", "Unsigned32"), "Foo", 6, ""},
		{"own base shadow", `<application id="40" inherits="0"/>` + nameDefinition(0, 4, 10415, "Foo", "Unsigned32") + nameDefinition(40, 6, 10415, "Foo", "Unsigned32"), "Foo", 6, ""},
		{"three level chain", `<application id="40" inherits="42"/><application id="42" inherits="43"/><application id="43" inherits="44"/>` + nameDefinition(44, 4, 10415, "Foo", "Unsigned32") + nameDefinition(43, 6, 10415, "Foo", "Unsigned32"), "Foo", 6, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := new(Parser)
			if err := p.Load(strings.NewReader("<diameter>" + tc.graph + "</diameter>")); err != nil {
				t.Fatalf("allowed parent views rejected: %v", err)
			}
			a, err := p.FindAVPByName(40, tc.avpName)
			if err != nil || a.Code != tc.code {
				t.Fatalf("name view = %v, %v; want code %d", a, err, tc.code)
			}
			if b, err := p.FindAVP(40, tc.code, 10415); err != nil || b != a {
				t.Errorf("wire view = %v, %v", b, err)
			}
			if tc.absent != "" {
				if a, err := p.FindAVPByName(40, tc.absent); a != nil || !errors.Is(err, ErrNotFound) {
					t.Errorf("renamed ancestor revived: %v, %v", a, err)
				}
			}
		})
	}
	t.Run("Sh Cx", func(t *testing.T) {
		p := New(Sh)
		if a, err := p.FindAVPByName(16777217, "User-Data"); err != nil || a.Code != 702 {
			t.Fatalf("Sh User-Data = %v, %v", a, err)
		}
		if a, err := p.FindAVP(16777217, 606, 10415); err != nil || a.Name != "User-Data" {
			t.Fatalf("Cx User-Data in Sh = %v, %v", a, err)
		}
	})
}

func TestInheritanceOwnNameResolvesParentDisagreement(t *testing.T) {
	for _, registered := range []bool{false, true} {
		t.Run(fmt.Sprintf("registered=%t", registered), func(t *testing.T) {
			p := new(Parser)
			graph := `<application id="40" inherits="42 43"/>` + nameDefinition(42, 4, 10415, "Foo", "Unsigned32") + nameDefinition(43, 6, 10415, "Foo", "Unsigned32")
			if registered {
				mustRegister(t, p, 40, &AVP{Name: "Foo", Code: 8, VendorID: 10415, Data: Data{TypeName: "Unsigned32"}})
			} else {
				graph += nameDefinition(40, 8, 10415, "Foo", "Unsigned32")
			}
			if err := p.Load(strings.NewReader("<diameter>" + graph + "</diameter>")); err != nil {
				t.Fatalf("own-name exemption rejected: %v", err)
			}
			if a, err := p.FindAVPByName(40, "Foo"); err != nil || a.Code != 8 {
				t.Fatalf("own name = %v, %v; want code 8", a, err)
			}
			// Name agreement does not change breadth-first code/vendor lookup.
			for _, code := range []uint32{4, 6, 8} {
				if _, err := p.FindAVP(40, code, 10415); err != nil {
					t.Errorf("wire identity %d lost: %v", code, err)
				}
			}
		})
	}
}

func TestInheritanceBaseParentWithoutDictionary(t *testing.T) {
	p := new(Parser)
	if err := p.Load(strings.NewReader(`<diameter><application id="40" inherits="0"/></diameter>`)); err != nil {
		t.Fatalf("implicit base parent rejected: %v", err)
	}
	if _, err := p.App(0); !errors.Is(err, ErrApplicationUnsupported) {
		t.Fatalf("base parent invented an application: %v", err)
	}
	if _, err := p.FindAVPByName(40, "Session-Id"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("base parent invented definitions: %v", err)
	}
}
