package sy_test

import (
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/dict/sy"
	"slices"
	"testing"
)

// This package imports only its application; missing prerequisites must fail here.
func TestDictionaryLoadsAlone(t *testing.T) {
	p, err := dict.New(sy.Dictionary())
	if err != nil {
		t.Fatal(err)
	}
	var ids []uint32
	for _, app := range p.Apps() {
		ids = append(ids, app.ID)
	}
	want := []uint32{0, 3, 4, 16777302, 1, 4, 3}
	if !slices.Equal(ids, want) {
		t.Fatalf("applications = %v, want %v", ids, want)
	}
}
