package dict

import (
	"errors"
	"strings"
	"testing"
)

func TestLoadBatchReadersPublishesAllOrNothing(t *testing.T) {
	p, err := New(Base())
	if err != nil {
		t.Fatal(err)
	}
	before := p.Snapshot()
	err = p.Load(strings.NewReader(`<diameter><application id="0"><avp name="Batch-Marker" code="70001"><data type="UTF8String"/></avp></application></diameter>`), strings.NewReader(`<diameter>`))
	if err == nil {
		t.Fatal("Load accepted malformed second reader")
	}
	if p.Snapshot() != before {
		t.Fatal("failed batch published a new snapshot")
	}
	if _, err := p.FindAVPByName(0, "Batch-Marker"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("first reader escaped failed batch: %v", err)
	}
}
