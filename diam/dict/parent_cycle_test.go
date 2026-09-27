package dict

import (
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

func TestFindAVPWithVendorTerminatesOnParentCycle(t *testing.T) {
	withParentAppCycle(t)
	_, err := Default.FindAVPWithVendor(4, uint32(999999), UndefinedVendorID)
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("lookup error = %v, want parent cycle", err)
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
