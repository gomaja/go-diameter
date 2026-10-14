package sh_test

import (
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/dict/sh"
	"slices"
	"testing"
)

// This package imports only its application; missing prerequisites must fail here.
func TestDictionaryLoadsAlone(t *testing.T) {
	p, err := dict.New(sh.Dictionary())
	if err != nil {
		t.Fatal(err)
	}
	var ids []uint32
	for _, app := range p.Apps() {
		ids = append(ids, app.ID)
	}
	want := []uint32{0, 3, 1, 16777216, 16777217}
	if !slices.Equal(ids, want) {
		t.Fatalf("applications = %v, want %v", ids, want)
	}
}
