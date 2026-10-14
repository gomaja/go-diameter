package dict_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/dict/gx"
)

func TestNewIncludesApplicationDependencies(t *testing.T) {
	p := newTestParser(t, dict.Base(), gx.Dictionary())
	for _, tc := range []struct {
		app  uint32
		name string
	}{{16777238, "Charging-Rule-Install"}, {4, "CC-Request-Type"}, {4, "Service-Information"}, {1, "NAS-Port"}, {0, "Origin-Host"}} {
		if _, err := p.FindAVPByName(tc.app, tc.name); err != nil {
			t.Error(err)
		}
	}
}

// Every public selector subset is checked against independent expected source
// closures. One representative per closure is compared to a strict raw XML load.
func TestNewEveryApplicationSubset(t *testing.T) {
	selections := applicationSelections()
	if len(selections) != 14 {
		t.Fatalf("update subset coverage for %d selections", len(selections))
	}
	type closureSelection struct {
		names    []string
		selected []dict.Dictionary
	}
	closures := make(map[string]closureSelection)
	for subset := 0; subset < 1<<len(selections); subset++ {
		var selected []dict.Dictionary
		reached := make(map[string]bool)
		for i, selection := range selections {
			if subset&(1<<i) == 0 {
				continue
			}
			selected = append(selected, selection.dictionary)
			for _, name := range selection.sources {
				reached[name] = true
			}
		}
		var want []string
		for name := range reached {
			want = append(want, name)
		}
		sort.Strings(want)
		actual, err := dict.SourceNamesForTesting(selected...)
		if err != nil {
			t.Fatalf("subset %d: %v", subset, err)
		}
		if !slices.Equal(actual, want) {
			t.Fatalf("subset %d sources=%v, want %v", subset, actual, want)
		}
		key := strings.Join(want, ",")
		if _, exists := closures[key]; !exists {
			closures[key] = closureSelection{want, selected}
		}
	}
	if len(closures) != 345 {
		t.Fatalf("distinct closures=%d, want 345", len(closures))
	}
	for key, closure := range closures {
		t.Run(key, func(t *testing.T) {
			p := newTestParser(t, closure.selected...)
			if len(closure.names) > 0 && len(p.Apps()) == 0 {
				t.Fatal("nonempty selection produced empty parser")
			}
			var readers []io.Reader
			for _, name := range closure.names {
				data, err := os.ReadFile(sourcePath(t, name))
				if err != nil {
					t.Fatal(err)
				}
				readers = append(readers, bytes.NewReader(data))
			}
			strict := new(dict.Parser)
			if !strict.Strict() {
				t.Fatal("raw Load must be strict")
			}
			if err := strict.Load(readers...); err != nil {
				t.Fatalf("strict Load(%v): %v", closure.names, err)
			}
			diffDumps(t, "selected versus strict raw load", dumpSnapshot(p.Snapshot()), dumpSnapshot(strict.Snapshot()))
		})
	}
	t.Logf("%d selections, %d distinct closures", 1<<len(selections), len(closures))
}

// New shares immutable definitions, but loading, registering and policy changes
// must remain local to the returned Parser and leave existing Snapshots intact.
func TestNewApplicationParsersAreIndependent(t *testing.T) {
	first, second := newTestParser(t, gx.Dictionary()), newTestParser(t, gx.Dictionary())
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
	for _, p := range []*dict.Parser{second, newTestParser(t, gx.Dictionary())} {
		if !p.Strict() || p.MaxGroupedDepth() != dict.DefaultMaxGroupedDepth {
			t.Fatal("policy leaked between application Parsers")
		}
		for _, name := range []string{"Local-Only", "Local-Loaded"} {
			if _, err := p.FindAVPByName(4, name); !errors.Is(err, dict.ErrNotFound) {
				t.Errorf("%s leaked: %v", name, err)
			}
		}
	}
	if second.Snapshot() != original {
		t.Fatal("independent Parser snapshot changed")
	}
	if _, err := before.FindAVPByName(4, "Local-Only"); !errors.Is(err, dict.ErrNotFound) {
		t.Errorf("old Snapshot changed: %v", err)
	}
}
