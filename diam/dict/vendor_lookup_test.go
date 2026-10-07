package dict

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// RFC 6733 (October 2012) §4.1: an AVP's identity includes its Vendor-Id.
const vendorLookupXML = `<diameter><application id="4">
 <avp name="Alpha-Level" code="70001" vendor-id="10415"><data type="Enumerated"><item code="1" name="ALPHA"/></data></avp>
 <avp name="Beta-Level" code="70001" vendor-id="99999"><data type="Enumerated"><item code="1" name="BETA"/></data></avp>
 <avp name="Alpha-Group" code="70002" vendor-id="10415"><data type="Grouped"><rule avp="Alpha-Level" required="true" max="1"/></data></avp>
 <avp name="Beta-Group" code="70002" vendor-id="99999"><data type="Grouped"><rule avp="Beta-Level" required="true" max="2"/></data></avp>
 </application></diameter>`

type vendorLookup interface {
	FindAVP(uint32, uint32, uint32) (*AVP, error)
	FindAVPByName(uint32, string) (*AVP, error)
	Enum(uint32, uint32, uint32, int32) (*Enum, error)
	Rule(uint32, uint32, uint32, string) (*Rule, error)
	App(uint32, ...string) (*App, error)
}

func TestVendorLookup(t *testing.T) {
	p := New()
	if err := p.Load(strings.NewReader(vendorLookupXML)); err != nil {
		t.Fatal(err)
	}
	before := p.Snapshot()
	// Registration must use the same vendor-explicit index as XML loading.
	mustRegister(t, p, 4, &AVP{Name: "Gamma-Level", Code: 70001, VendorID: 0xffffffff, Must: "V", Data: Data{TypeName: "Enumerated", Enum: []*Enum{{Code: 1, Name: "GAMMA"}}}})
	for label, lookup := range map[string]vendorLookup{"parser": p, "snapshot": p.Snapshot()} {
		t.Run(label, func(t *testing.T) {
			for _, app := range []uint32{4, 16777238, 16777265} {
				for _, tc := range []struct {
					vendor        uint32
					prefix, value string
					max           int
				}{{10415, "Alpha", "ALPHA", 1}, {99999, "Beta", "BETA", 2}} {
					t.Run(fmt.Sprintf("%d/%d", app, tc.vendor), func(t *testing.T) {
						level, err := lookup.FindAVP(app, 70001, tc.vendor)
						if err != nil || level.Name != tc.prefix+"-Level" || level.VendorID != tc.vendor {
							t.Fatalf("level = %v, %v", level, err)
						}
						named, err := lookup.FindAVPByName(app, tc.prefix+"-Level")
						if err != nil || named != level {
							t.Fatalf("name = %v, %v; want %v", named, err, level)
						}
						item, err := lookup.Enum(app, 70001, tc.vendor, 1)
						if err != nil || item.Name != tc.value {
							t.Fatalf("enum = %v, %v; want %s", item, err, tc.value)
						}
						group, err := lookup.FindAVP(app, 70002, tc.vendor)
						if err != nil || group.Name != tc.prefix+"-Group" {
							t.Fatalf("group = %v, %v", group, err)
						}
						rule, err := lookup.Rule(app, 70002, tc.vendor, tc.prefix+"-Level")
						if err != nil || !rule.Required || rule.Max != tc.max {
							t.Fatalf("rule = %v, %v", rule, err)
						}
						if e, err := lookup.Enum(app, 70001, tc.vendor, 2); e != nil || err == nil {
							t.Fatalf("missing enum = %v, %v", e, err)
						}
						if e, err := lookup.Enum(app, 70002, tc.vendor, 1); e != nil || err == nil {
							t.Fatalf("group enum = %v, %v", e, err)
						}
						if r, err := lookup.Rule(app, 70001, tc.vendor, tc.prefix+"-Level"); r != nil || err == nil {
							t.Fatalf("enum rule = %v, %v", r, err)
						}
						other := "Alpha-Level"
						if tc.vendor == 10415 {
							other = "Beta-Level"
						}
						if r, err := lookup.Rule(app, 70002, tc.vendor, other); r != nil || err == nil {
							t.Fatalf("other vendor's rule = %v, %v", r, err)
						}
					})
				}
				gamma, err := lookup.FindAVP(app, 70001, 0xffffffff)
				if err != nil || gamma.Name != "Gamma-Level" {
					t.Fatalf("maximum vendor = %v, %v", gamma, err)
				}
				named, err := lookup.FindAVPByName(app, "Gamma-Level")
				if err != nil || named != gamma {
					t.Fatalf("registered name = %v, %v", named, err)
				}
				item, err := lookup.Enum(app, 70001, 0xffffffff, 1)
				if err != nil || item.Name != "GAMMA" {
					t.Fatalf("registered enum = %v, %v", item, err)
				}
				for _, vendor := range []uint32{0, 12345} {
					unknown, err := lookup.FindAVP(app, 70001, vendor)
					if !errors.Is(err, ErrNotFound) || unknown != nil {
						t.Fatalf("unknown = %v, %v", unknown, err)
					}
					if e, err := lookup.Enum(app, 70001, vendor, 1); e != nil || err == nil {
						t.Fatalf("unknown enum = %v, %v", e, err)
					}
					if r, err := lookup.Rule(app, 70002, vendor, "Alpha-Level"); r != nil || err == nil {
						t.Fatalf("unknown rule = %v, %v", r, err)
					}
				}
			}
			if a, err := lookup.FindAVPByName(4, "Not-Defined"); a != nil || err == nil {
				t.Fatalf("missing name = %v, %v", a, err)
			}
			if _, err := lookup.App(16777238); !errors.Is(err, ErrApplicationUnsupported) {
				t.Fatalf("undeclared app = %v", err)
			}
		})
	}
	if _, err := before.FindAVP(4, 70001, 0xffffffff); err == nil {
		t.Fatal("old snapshot sees registration")
	}
	if _, err := before.FindAVPByName(4, "Gamma-Level"); err == nil {
		t.Fatal("old snapshot sees registered name")
	}
	err := p.RegisterAVP(4, &AVP{Name: "Alpha-Level", Code: 70001, VendorID: 12345, Must: "V", Data: Data{TypeName: "Unsigned32"}})
	if !errors.Is(err, ErrAVPConflict) {
		t.Fatalf("name conflict = %v", err)
	}
}
