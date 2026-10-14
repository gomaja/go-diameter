package dict

import (
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func sourceXML(name string, code int) string {
	return `<diameter><application id="4"><avp name="` + name + `" code="` + strconv.Itoa(code) + `"><data type="Unsigned32"/></avp></application></diameter>`
}

func TestDictionarySourcesShareApplication(t *testing.T) {
	first := Embedded("a.xml", sourceXML("First", 70001))
	second := Embedded("b.xml", sourceXML("Second", 70002), first)
	p, err := New(Combine(second, first, second))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"First", "Second"} {
		if _, err := p.FindAVPByName(4, name); err != nil {
			t.Fatal(err)
		}
	}
	if len(p.Snapshot().files) != 2 {
		t.Fatalf("loaded sources = %d; want two distinct sources", len(p.Snapshot().files))
	}
}

func TestDictionaryCanonicalOrder(t *testing.T) {
	first := Embedded("a.xml", sourceXML("First", 70001))
	last := Embedded("z.xml", sourceXML("Last", 70001))
	for _, selected := range [][]Dictionary{{last, first}, {first, last, first}} {
		p, err := New(selected...)
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.FindAVP(4, 70001, 0)
		if err != nil || got.Name != "Last" {
			t.Fatalf("canonical replacement = %v, %v", got, err)
		}
		if _, err := p.FindAVPByName(4, "First"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("replaced name remains visible: %v", err)
		}
	}
}

func TestDictionaryRejectsConflictingSourceIdentity(t *testing.T) {
	first := Embedded("same.xml", sourceXML("First", 70001))
	second := Embedded("same.xml", sourceXML("Second", 70002))
	p, err := New(first, second)
	if p != nil || !errors.Is(err, ErrDictionaryConflict) {
		t.Fatalf("New collision = %v, %v", p, err)
	}
}

func TestDictionaryCopiesPrerequisites(t *testing.T) {
	deps := []Dictionary{Embedded("first.xml", sourceXML("First", 70001))}
	dependent := Embedded("dependent.xml", sourceXML("Dependent", 70003), deps...)
	group := Combine(deps...)
	deps[0] = Embedded("second.xml", sourceXML("Second", 70002))
	for _, d := range []Dictionary{dependent, group} {
		p, err := New(d)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.FindAVPByName(4, "First"); err != nil {
			t.Fatal(err)
		}
		if _, err := p.FindAVPByName(4, "Second"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("prerequisite mutation leaked: %v", err)
		}
	}
}

func TestDictionaryCachesParseErrors(t *testing.T) {
	d := Embedded("bad.xml", `<diameter>`)
	_, first := New(d)
	_, second := New(d)
	if first == nil || second == nil || errors.Unwrap(first) != errors.Unwrap(second) {
		t.Fatalf("parse error was not cached: %v, %v", first, second)
	}
	if !strings.Contains(first.Error(), "bad.xml") {
		t.Fatal("parse error does not identify its source")
	}
}

func TestDictionaryConstructionRejectsIncompleteSelection(t *testing.T) {
	member := Embedded("member.xml", sourceXML("Member", 70001))
	groupXML := `<diameter><application id="4"><avp name="Group" code="70002"><data type="Grouped"><rule avp="Member" required="true"/></data></avp></application></diameter>`
	group := Embedded("group.xml", groupXML)
	if p, err := New(group); p != nil || !errors.Is(err, ErrNotFound) {
		t.Fatalf("incomplete dictionary = %v, %v", p, err)
	}
	if p, err := New(Combine(group, member)); err != nil || p == nil {
		t.Fatalf("complete dictionary = %v, %v", p, err)
	}
}

func TestDictionaryEmptyAndInvalid(t *testing.T) {
	for _, selected := range [][]Dictionary{nil, {Combine()}} {
		p, err := New(selected...)
		if err != nil || len(p.Apps()) != 0 || !p.Strict() {
			t.Fatalf("empty dictionary = %v, %v", p, err)
		}
	}
	for _, d := range []Dictionary{{}, Embedded("", `<diameter/>`), Combine(Dictionary{})} {
		if p, err := New(d); p != nil || err == nil {
			t.Fatalf("invalid dictionary = %v, %v", p, err)
		}
	}
}

func TestDictionaryConcurrentConstructionAndIndependentUpdates(t *testing.T) {
	d := Embedded("shared.xml", sourceXML("Shared", 70001))
	const count = 16
	parsers := make([]*Parser, count)
	var wg sync.WaitGroup
	for i := range count {
		wg.Go(func() {
			p, err := New(d)
			if err != nil {
				t.Error(err)
				return
			}
			parsers[i] = p
		})
	}
	wg.Wait()
	for _, p := range parsers {
		if p == nil {
			t.Fatal("construction failed")
		}
	}
	first := parsers[0]
	before := first.Snapshot()
	first.SetStrict(false)
	first.SetMaxGroupedDepth(3)
	if err := first.Load(strings.NewReader(sourceXML("Local", 70002))); err != nil {
		t.Fatal(err)
	}
	shared, err := first.FindAVPByName(4, "Shared")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range parsers[1:] {
		if p == first || !p.Strict() || p.MaxGroupedDepth() != DefaultMaxGroupedDepth {
			t.Fatal("mutable parser state shared between constructions")
		}
		if _, err := p.FindAVPByName(4, "Local"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("local definition leaked: %v", err)
		}
		cached, err := p.FindAVPByName(4, "Shared")
		if err != nil || cached != shared {
			t.Fatal("immutable source was parsed repeatedly")
		}
	}
	if !before.Strict() || before.MaxGroupedDepth() != DefaultMaxGroupedDepth {
		t.Fatal("published policy changed")
	}
	if _, err := before.FindAVPByName(4, "Local"); !errors.Is(err, ErrNotFound) {
		t.Fatal("published definitions changed")
	}
	if err := first.Load(strings.NewReader(`<diameter><application id="4"><avp name="Bad" code="70003"><data type="Grouped"><rule avp="Missing"/></data></avp></application></diameter>`)); err == nil {
		t.Fatal("unresolved update accepted")
	}
	if _, err := first.FindAVPByName(4, "Bad"); !errors.Is(err, ErrNotFound) {
		t.Fatal("failed update published a partial state")
	}
}
