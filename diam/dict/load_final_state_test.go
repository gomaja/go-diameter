package dict

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadNameReuseUsesFinalState(t *testing.T) {
	initial := nameDefinition(4, 70001, 10415, "X", "UTF8String")
	rename := nameDefinition(4, 70001, 10415, "Z", "UTF8String")
	reuse := nameDefinition(4, 70003, 10415, "X", "Unsigned32")
	for _, reverse := range []bool{false, true} {
		for _, files := range []bool{false, true} {
			t.Run(fmt.Sprintf("reverse=%t/files=%t", reverse, files), func(t *testing.T) {
				defs := []string{rename, reuse}
				if reverse {
					defs[0], defs[1] = defs[1], defs[0]
				}
				var p *Parser
				if files {
					dir := t.TempDir()
					var names []string
					for i, body := range []string{initial + defs[0], defs[1]} {
						name := filepath.Join(dir, fmt.Sprintf("%d.xml", i))
						if err := os.WriteFile(name, []byte("<diameter>"+body+"</diameter>"), 0600); err != nil {
							t.Fatal(err)
						}
						names = append(names, name)
					}
					var err error
					p, err = NewParser(names...)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					p = New()
					if err := p.Load(strings.NewReader("<diameter>" + initial + "</diameter>")); err != nil {
						t.Fatal(err)
					}
					if err := p.Load(strings.NewReader("<diameter>" + strings.Join(defs, "") + "</diameter>")); err != nil {
						t.Fatal(err)
					}
				}
				for name, code := range map[string]uint32{"X": 70003, "Z": 70001} {
					a, err := p.FindAVPByName(4, name)
					if err != nil || a.Code != code {
						t.Fatalf("name %s = %v, %v; want code %d", name, a, err, code)
					}
					byCode, err := p.FindAVP(4, code, 10415)
					if err != nil || byCode != a {
						t.Fatalf("code %d = %v, %v; want %v", code, byCode, err, a)
					}
				}
			})
		}
	}
}

func groupedDefinition(app, code uint32, name, member string) string {
	return fmt.Sprintf(`<application id="%d"><avp name="%s" code="%d"><data type="Grouped"><rule avp="%s"/><rule avp="AVP"/></data></avp></application>`, app, name, code, member)
}

func TestLoadGroupedRuleResolution(t *testing.T) {
	member := nameDefinition(4, 70001, 10415, "Member", "Unsigned32")
	group := groupedDefinition(4, 70002, "Group", "Member")
	for _, scenario := range []string{"missing member", "renamed member", "child group loses inherited member"} {
		t.Run(scenario, func(t *testing.T) {
			p := New()
			input := group
			switch scenario {
			case "renamed member":
				if err := p.Load(strings.NewReader("<diameter>" + member + group + "</diameter>")); err != nil {
					t.Fatal(err)
				}
				input = nameDefinition(4, 70001, 10415, "Renamed", "Unsigned32")
			case "child group loses inherited member":
				if err := p.Load(strings.NewReader("<diameter>" + nameDefinition(4, 70001, 10415, "Member", "Unsigned32") + groupedDefinition(16777238, 70002, "Group", "Member") + "</diameter>")); err != nil {
					t.Fatal(err)
				}
				input = nameDefinition(4, 70001, 10415, "Renamed", "Unsigned32")
			}
			before := p.Snapshot()
			dump := dumpSnapshot(before)
			err := p.Load(strings.NewReader("<diameter>" + input + nameDefinition(4, 70009, 0, "Unpublished", "Unsigned32") + "</diameter>"))
			if !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "member Member does not resolve") {
				t.Errorf("Load = %v; want unresolved member wrapping ErrNotFound", err)
			}
			if p.Snapshot() != before {
				t.Error("failed load published a snapshot")
			}
			diffDumps(t, "failed load", dumpSnapshot(p.Snapshot()), dump)
		})
	}
	for _, input := range []string{group + member, member + group, groupedDefinition(16777238, 70002, "Group", "Member") + member, groupedDefinition(4, 70002, "Group", "Group")} {
		p := New()
		if err := p.Load(strings.NewReader("<diameter>" + input + "</diameter>")); err != nil {
			t.Fatalf("forward, inherited, recursive and wildcard members must resolve: %v", err)
		}
	}
}

func TestInheritedNameTracksCodeReplacement(t *testing.T) {
	const child = 16777238
	parent := nameDefinition(4, 70001, 10415, "X", "Unsigned32")
	replacement := nameDefinition(child, 70001, 10415, "Z", "Unsigned32")
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprintf("reverse=%t", reverse), func(t *testing.T) {
			defs := parent + replacement
			if reverse {
				defs = replacement + parent
			}
			p := New()
			if err := p.Load(strings.NewReader("<diameter>" + defs + "</diameter>")); err != nil {
				t.Fatal(err)
			}
			if a, err := p.FindAVPByName(child, "X"); a != nil || !errors.Is(err, ErrNotFound) {
				t.Fatalf("shadowed inherited name X = %v, %v; want nil, ErrNotFound", a, err)
			}
			a, err := p.FindAVPByName(child, "Z")
			if err != nil {
				t.Fatal(err)
			}
			byCode, err := p.FindAVP(child, 70001, 10415)
			if err != nil || byCode != a {
				t.Fatalf("replacement code = %v, %v; want %v", byCode, err, a)
			}
			if a, err := p.FindAVPByName(4, "X"); err != nil || a.Name != "X" {
				t.Fatalf("parent X = %v, %v", a, err)
			}
		})
	}
	for _, groupApp := range []uint32{4, child} {
		t.Run(fmt.Sprintf("group-app=%d", groupApp), func(t *testing.T) {
			p := New()
			if err := p.Load(strings.NewReader("<diameter>" + parent + groupedDefinition(groupApp, 70002, "Group", "X") + "</diameter>")); err != nil {
				t.Fatal(err)
			}
			before := p.Snapshot()
			err := p.Load(strings.NewReader("<diameter>" + replacement + "</diameter>"))
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("stale Group member X = %v; want ErrNotFound", err)
			}
			if p.Snapshot() != before {
				t.Fatal("stale inherited group member published")
			}
		})
	}
}
