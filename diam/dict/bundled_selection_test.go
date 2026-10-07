package dict

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func newBundledSelection(t *testing.T, selected []Bundled) *Parser {
	t.Helper()
	defer func() {
		if err := recover(); err != nil {
			t.Fatalf("New(%v) panicked: %v", selected, err)
		}
	}()
	return New(selected...)
}

func TestNewIncludesBundleDependencies(t *testing.T) {
	p := newBundledSelection(t, []Bundled{Base, Gx})
	for _, tc := range []struct {
		app  uint32
		name string
	}{
		{16777238, "Charging-Rule-Install"}, {4, "CC-Request-Type"},
		{4, "Service-Information"}, {1, "NAS-Port"}, {0, "Origin-Host"},
	} {
		if _, err := p.FindAVPByName(tc.app, tc.name); err != nil {
			t.Error(err)
		}
	}
}

// TestNewEveryBundledSubset covers every selection of bundled dictionaries.
// New loads exactly bundledClosure of its selection, so each selection's
// closure is checked, and each distinct closure is loaded once.
func TestNewEveryBundledSubset(t *testing.T) {
	all := AllBundled()
	if len(all) != 14 {
		t.Fatalf("update subset coverage for %d bundles", len(all))
	}
	closures := make(map[string][]Bundled)
	for subset := 1; subset < 1<<len(all); subset++ {
		var selected []Bundled
		for i, b := range all {
			if subset&(1<<i) != 0 {
				selected = append(selected, b)
			}
		}
		// The closure is exactly the selection and everything reachable
		// from it through bundledDependencies, in file name order.
		reached := make(map[Bundled]bool)
		pending := slices.Clone(selected)
		for len(pending) > 0 {
			b := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			if !reached[b] {
				reached[b] = true
				pending = append(pending, bundledDependencies[b]...)
			}
		}
		var want []Bundled
		for _, b := range all {
			if reached[b] {
				want = append(want, b)
			}
		}
		closure := bundledClosure(selected)
		if !slices.Equal(closure, want) {
			t.Fatalf("closure of %v = %v; want %v", selected, closure, want)
		}
		closures[fmt.Sprint(closure)] = closure
	}
	for key, closure := range closures {
		t.Run(key, func(t *testing.T) {
			p := newBundledSelection(t, closure)
			if len(p.Apps()) == 0 {
				t.Fatal("selection produced an empty Parser")
			}
		})
	}
	t.Logf("%d selections, %d distinct closures", 1<<len(all)-1, len(closures))
}

// New shares immutable definitions, but loading, registering and policy changes
// must remain local to the returned Parser and leave existing Snapshots intact.
func TestNewBundledParsersAreIndependent(t *testing.T) {
	first, second := New(Gx), New(Gx)
	before := first.Snapshot()
	original := second.Snapshot()
	first.SetStrict(false)
	first.SetMaxGroupedDepth(3)
	if err := first.RegisterAVP(4, vendorAVP("Local-Only", 70001, "Unsigned32")); err != nil {
		t.Fatal(err)
	}
	if err := first.Load(strings.NewReader(`<diameter><application id="4"><avp name="Local-Loaded" code="70002"><data type="Unsigned32"/></avp></application></diameter>`)); err != nil {
		t.Fatal(err)
	}
	for _, p := range []*Parser{second, New(Gx)} {
		if !p.Strict() || p.MaxGroupedDepth() != DefaultMaxGroupedDepth {
			t.Fatal("policy leaked between bundled Parsers")
		}
		for _, name := range []string{"Local-Only", "Local-Loaded"} {
			if _, err := p.FindAVPByName(4, name); !errors.Is(err, ErrNotFound) {
				t.Errorf("%s leaked: %v", name, err)
			}
		}
	}
	if second.Snapshot() != original {
		t.Fatal("independent Parser snapshot changed")
	}
	if _, err := before.FindAVPByName(4, "Local-Only"); !errors.Is(err, ErrNotFound) {
		t.Errorf("old Snapshot changed: %v", err)
	}
}
