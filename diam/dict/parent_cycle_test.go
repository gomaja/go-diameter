package dict

import (
	"errors"
	"strings"
	"testing"
)

func TestParentAppIDsAcyclic(t *testing.T) {
	for start := range parentAppIds {
		seen := map[uint32]bool{}
		for app := start; ; {
			if seen[app] {
				t.Fatalf("parent application cycle from %d at %d", start, app)
			}
			seen[app] = true
			parent, ok := parentAppIds[app]
			if !ok {
				break
			}
			app = parent
		}
	}
}

func withParentAppCycle(t *testing.T) {
	t.Helper()
	previous, existed := parentAppIds[1]
	parentAppIds[1] = 4 // existing 4 -> 1 now cycles
	t.Cleanup(func() {
		if existed {
			parentAppIds[1] = previous
		} else {
			delete(parentAppIds, 1)
		}
	})
}

func TestFindAVPByNameTerminatesOnParentCycle(t *testing.T) {
	withParentAppCycle(t)
	for label, lookup := range map[string]vendorLookup{"parser": Default, "snapshot": Default.Snapshot()} {
		a, err := lookup.FindAVPByName(4, "Not-Defined")
		if a != nil || !errors.Is(err, ErrParentCycle) || errors.Is(err, ErrNotFound) {
			t.Errorf("%s: lookup = %v, %v; want nil and ErrParentCycle", label, a, err)
		}
	}
}

func TestFindAVPTerminatesOnParentCycle(t *testing.T) {
	withParentAppCycle(t)
	avp, err := Default.FindAVP(16777238, 999999, 99999)
	if avp != nil || !errors.Is(err, ErrParentCycle) || errors.Is(err, ErrNotFound) {
		t.Fatalf("lookup = %v, %v; want nil and ErrParentCycle", avp, err)
	}
}

func TestLoadTerminatesOnParentCycle(t *testing.T) {
	withParentAppCycle(t)
	p, err := NewParser()
	if err != nil {
		t.Fatal(err)
	}
	err = p.Load(strings.NewReader(`<diameter><application id="4" type="auth"/></diameter>`))
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("load error = %v, want parent cycle", err)
	}
}
