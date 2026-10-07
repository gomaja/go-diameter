package dict

import (
	"errors"
	"strings"
	"testing"
)

func TestParentAppIDsAcyclic(t *testing.T) {
	if err := Default.Snapshot().validateParents(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadTerminatesOnParentCycle(t *testing.T) {
	p := new(Parser)
	if err := p.Load(strings.NewReader(`<diameter><application id="40" inherits="41"/><application id="41"/></diameter>`)); err != nil {
		t.Fatal(err)
	}
	before := p.Snapshot()
	err := p.Load(strings.NewReader(`<diameter><application id="41" inherits="40"/></diameter>`))
	if !errors.Is(err, ErrParentCycle) {
		t.Fatalf("load error = %v, want parent cycle", err)
	}
	if p.Snapshot() != before {
		t.Fatal("cycle changed published snapshot")
	}
	if a, err := p.FindAVP(40, 999, 0); a != nil || !errors.Is(err, ErrNotFound) {
		t.Errorf("lookup after rejection: %v, %v", a, err)
	}
	if a, err := p.FindAVPByName(40, "missing"); a != nil || !errors.Is(err, ErrNotFound) {
		t.Errorf("name lookup after rejection: %v, %v", a, err)
	}
}
