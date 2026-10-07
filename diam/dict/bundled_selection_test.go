package dict

import (
	"errors"
	"fmt"
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

func TestNewEveryBundledSubset(t *testing.T) {
	all := AllBundled()
	if len(all) != 14 {
		t.Fatalf("update subset coverage for %d bundles", len(all))
	}
	for subset := 1; subset < 1<<len(all); subset++ {
		var selected []Bundled
		for i, b := range all {
			if subset&(1<<i) != 0 {
				selected = append(selected, b)
			}
		}
		t.Run(fmt.Sprintf("%04x", subset), func(t *testing.T) {
			p := newBundledSelection(t, selected)
			if len(p.Apps()) == 0 {
				t.Fatal("selection produced an empty Parser")
			}
		})
	}
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
