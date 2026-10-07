package dict

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func nameDefinition(app, code, vendor uint32, name, typ string) string {
	parents := ""
	if app == 16777238 {
		parents = ` inherits="4"`
	}
	return fmt.Sprintf(`<application id="%d"%s><avp name="%s" code="%d" vendor-id="%d"><data type="%s"/></avp></application>`, app, parents, name, code, vendor, typ)
}

func TestLoadAVPNameScope(t *testing.T) {
	first := nameDefinition(4, 70001, 10415, "Dup-Name", "UTF8String")
	for _, split := range []bool{false, true} {
		for _, other := range []struct{ code, vendor uint32 }{{70001, 99999}, {70002, 10415}} {
			t.Run(fmt.Sprintf("split=%t/%v", split, other), func(t *testing.T) {
				p := New(Base)
				input := first
				if split {
					if err := p.Load(strings.NewReader("<diameter>" + first + "</diameter>")); err != nil {
						t.Fatal(err)
					}
					input = ""
				}
				before := p.Snapshot()
				dump := dumpSnapshot(before)
				input += nameDefinition(4, 70003, 99999, "Unpublished", "Unsigned32") + nameDefinition(4, other.code, other.vendor, "Dup-Name", "Unsigned32")
				err := p.Load(strings.NewReader("<diameter>" + input + "</diameter>"))
				if !errors.Is(err, ErrAVPConflict) {
					t.Errorf("Load clash = %v; want ErrAVPConflict", err)
				}
				if p.Snapshot() != before {
					t.Error("failed load published a snapshot")
				}
				diffDumps(t, "failed load", dumpSnapshot(p.Snapshot()), dump)
			})
		}
	}
	t.Run("child shadows parent", func(t *testing.T) {
		child := nameDefinition(16777238, 70001, 99999, "Dup-Name", "Unsigned32")
		for _, input := range []string{first + child, child + first} {
			p := New()
			if err := p.Load(strings.NewReader("<diameter>" + input + "</diameter>")); err != nil {
				t.Fatal(err)
			}
			for app, vendor := range map[uint32]uint32{4: 10415, 16777238: 99999} {
				a, err := p.FindAVPByName(app, "Dup-Name")
				if err != nil || a.VendorID != vendor {
					t.Fatalf("application %d name = %v, %v", app, a, err)
				}
			}
			if a, err := p.FindAVP(16777238, 70001, 10415); err != nil || a.VendorID != 10415 {
				t.Fatalf("child still inherits parent's distinct code/vendor = %v, %v", a, err)
			}
		}
	})
}

func TestLoadReplacesCodeAndRemovesOldName(t *testing.T) {
	p := New()
	first := nameDefinition(4, 70001, 10415, "Old-Name", "UTF8String")
	if err := p.Load(strings.NewReader("<diameter>" + first + "</diameter>")); err != nil {
		t.Fatal(err)
	}
	before := p.Snapshot()
	replacement := nameDefinition(4, 70001, 10415, "New-Name", "Unsigned32")
	if err := p.Load(strings.NewReader("<diameter>" + replacement + "</diameter>")); err != nil {
		t.Fatal(err)
	}
	if a, err := p.FindAVPByName(4, "Old-Name"); a != nil || err == nil {
		t.Fatalf("stale name = %v, %v", a, err)
	}
	a, err := p.FindAVP(4, 70001, 10415)
	if err != nil || a.Name != "New-Name" || a.Data.TypeName != "Unsigned32" {
		t.Fatalf("replacement = %v, %v", a, err)
	}
	named, err := p.FindAVPByName(4, "New-Name")
	if err != nil || named != a {
		t.Fatalf("replacement name = %v, %v", named, err)
	}
	if old, err := before.FindAVPByName(4, "Old-Name"); err != nil || old.Name != "Old-Name" {
		t.Fatalf("old snapshot changed: %v, %v", old, err)
	}
}
