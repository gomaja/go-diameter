package dict

import (
	"errors"
	"strings"
	"testing"
)

func TestAVPPresence(t *testing.T) {
	p := New(Base)
	if err := p.Load(strings.NewReader(vendorLookupXML)); err != nil {
		t.Fatal(err)
	}
	for label, lookup := range map[string]interface {
		AVP(uint32, uint32, uint32) (*AVP, bool)
	}{"parser": p, "snapshot": p.Snapshot(), "empty": New()} {
		for _, tc := range []struct {
			app, code, vendor uint32
			name              string
		}{{4, 70001, 10415, "Alpha-Level"}, {4, 70001, 99999, "Beta-Level"}, {16777238, 70001, 10415, "Alpha-Level"}, {99999, 264, 0, "Origin-Host"}, {4, 70001, 0, ""}, {4, 70003, 10415, ""}} {
			want := tc.name
			if label == "empty" {
				want = ""
			}
			a, ok := lookup.AVP(tc.app, tc.code, tc.vendor)
			if ok != (want != "") || (ok && (a == nil || a.Name != want)) || (!ok && a != nil) {
				t.Errorf("%s %+v = %v,%v", label, tc, a, ok)
			}
			if n := testing.AllocsPerRun(100, func() { lookup.AVP(tc.app, tc.code, tc.vendor) }); n != 0 {
				t.Errorf("%s %+v allocated %g times", label, tc, n)
			}
		}
	}
	// Publication preserves the meaning of prior snapshots.
	before := p.Snapshot()
	if err := p.Load(strings.NewReader(nameDefinitionXML())); err != nil {
		t.Fatal(err)
	}
	if a, ok := before.AVP(4, 70003, 10415); ok || a != nil {
		t.Fatal("old snapshot changed")
	}
	if a, ok := p.AVP(4, 70003, 10415); !ok || a.Name != "Added" {
		t.Fatalf("current lookup = %v, %v", a, ok)
	}
}

func nameDefinitionXML() string {
	return `<diameter><application id="4"><avp name="Added" code="70003" vendor-id="10415"><data type="Unsigned32"/></avp></application></diameter>`
}

func TestAVPPresenceTerminatesOnCycle(t *testing.T) {
	p := New(Base)
	err := p.Load(strings.NewReader(`<diameter><application id="40" inherits="41"/><application id="41" inherits="40"/></diameter>`))
	if !errors.Is(err, ErrParentCycle) {
		t.Fatalf("cycle error = %v", err)
	}
	if a, ok := p.AVP(40, 999999, 10415); a != nil || ok {
		t.Fatalf("lookup after rejected cycle = %v,%v", a, ok)
	}
}
