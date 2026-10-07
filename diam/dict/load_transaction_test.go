package dict

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func commandDefinition(app uint32, direction, member string) string {
	return fmt.Sprintf(`<application id="%d"><command code="70000" name="Test"><%s><rule avp="%s"/><rule avp="AVP"/></%s></command></application>`, app, direction, member, direction)
}

func TestLoadCommandRuleResolution(t *testing.T) {
	for _, direction := range []string{"request", "answer"} {
		for _, rename := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/rename=%t", direction, rename), func(t *testing.T) {
				p := New()
				command := commandDefinition(4, direction, "Member")
				input := command
				if rename {
					if err := p.Load(strings.NewReader("<diameter>" + nameDefinition(0, 70001, 0, "Member", "Unsigned32") + command + "</diameter>")); err != nil {
						t.Fatal(err)
					}
					input = nameDefinition(0, 70001, 0, "Renamed", "Unsigned32")
				}
				before := p.Snapshot()
				err := p.Load(strings.NewReader("<diameter>" + input + nameDefinition(4, 70009, 0, "Unpublished", "Unsigned32") + "</diameter>"))
				if !errors.Is(err, ErrAVPConflict) || !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), direction) || !strings.Contains(err.Error(), "Member") {
					t.Errorf("Load = %v; want %s unresolved Member wrapping ErrAVPConflict and ErrNotFound", err, direction)
				}
				if p.Snapshot() != before {
					t.Error("failed load published a snapshot")
				}
			})
		}
	}
}

func TestLoadMultipleReaders(t *testing.T) {
	for _, files := range []bool{false, true} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("files=%t/reverse=%t", files, reverse), func(t *testing.T) {
				p := New()
				a := "<diameter>" + groupedDefinition(4, 70001, "A", "B") + commandDefinition(4, "request", "B") + "</diameter>"
				b := "<diameter>" + groupedDefinition(4, 70002, "B", "A") + "</diameter>"
				before := p.Snapshot()
				if err := p.Load(strings.NewReader(a)); !errors.Is(err, ErrNotFound) {
					t.Fatalf("A alone = %v; want unresolved B", err)
				}
				if p.Snapshot() != before {
					t.Fatal("A alone was published")
				}
				docs := []string{a, b}
				if reverse {
					docs[0], docs[1] = docs[1], docs[0]
				}
				if files {
					var names []string
					for i, doc := range docs {
						name := filepath.Join(t.TempDir(), fmt.Sprintf("%d.xml", i))
						if err := os.WriteFile(name, []byte(doc), 0600); err != nil {
							t.Fatal(err)
						}
						names = append(names, name)
					}
					if err := p.LoadFile(names...); err != nil {
						t.Fatal(err)
					}
				} else if err := p.Load(strings.NewReader(docs[0]), strings.NewReader(docs[1])); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"A", "B"} {
					if _, err := p.FindAVPByName(4, name); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := before.FindAVPByName(4, "A"); !errors.Is(err, ErrNotFound) {
					t.Fatalf("old snapshot changed: %v", err)
				}
			})
		}
	}
}

func TestLoadMultipleAtomicFailure(t *testing.T) {
	p := New(Base)
	good := "<diameter>" + nameDefinition(4, 70001, 0, "Unpublished", "Unsigned32") + "</diameter>"
	before := p.Snapshot()
	for _, bad := range []string{"<diameter>", "<diameter>" + commandDefinition(4, "answer", "Missing") + "</diameter>"} {
		if err := p.Load(strings.NewReader(good), strings.NewReader(bad)); err == nil {
			t.Fatal("invalid batch accepted")
		}
		if p.Snapshot() != before {
			t.Fatal("invalid batch partially published")
		}
	}
	name := filepath.Join(t.TempDir(), "good.xml")
	if err := os.WriteFile(name, []byte(good), 0600); err != nil {
		t.Fatal(err)
	}
	if err := p.LoadFile(name, name+".missing"); err == nil {
		t.Fatal("missing file accepted")
	}
	if p.Snapshot() != before {
		t.Fatal("file batch partially published")
	}
	if err := p.Load(); err != nil {
		t.Fatal(err)
	}
	if err := p.LoadFile(); err != nil {
		t.Fatal(err)
	}
	if p.Snapshot() != before {
		t.Fatal("empty load published a snapshot")
	}
}

func TestLoadInheritedCommandRuleResolution(t *testing.T) {
	for _, direction := range []string{"request", "answer"} {
		t.Run(direction, func(t *testing.T) {
			p := New()
			initial := "<diameter>" + nameDefinition(0, 70001, 0, "Member", "Unsigned32") + commandDefinition(0, direction, "Member") + `<application id="4"/></diameter>`
			if err := p.Load(strings.NewReader(initial)); err != nil {
				t.Fatal(err)
			}
			if _, err := p.FindCommand(4, 70000); err != nil {
				t.Fatal(err)
			}
			before := p.Snapshot()
			replacement := "<diameter>" + nameDefinition(4, 70001, 0, "Renamed", "Unsigned32") + "</diameter>"
			if err := p.Load(strings.NewReader(replacement)); !errors.Is(err, ErrAVPConflict) || !errors.Is(err, ErrNotFound) {
				t.Errorf("shadow base command member: %v; want unresolved-rule conflict", err)
			}
			if p.Snapshot() != before {
				t.Fatal("failed load published a snapshot")
			}
			// A child command replaces the base command's grammar for its code.
			override := "<diameter>" + nameDefinition(4, 70001, 0, "Renamed", "Unsigned32") + commandDefinition(4, direction, "Renamed") + "</diameter>"
			if err := p.Load(strings.NewReader(override)); err != nil {
				t.Fatal(err)
			}
		})
	}
}
