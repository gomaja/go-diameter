package dict

import (
	"errors"
	"fmt"
	"testing"
)

func TestLookupMissContract(t *testing.T) {
	for label, lookup := range map[string]*Snapshot{"empty": New().Snapshot(), "loaded": Default.Snapshot()} {
		t.Run(label, func(t *testing.T) {
			a, err := lookup.FindAVP(4, 999999, 10415)
			if a != nil || !errors.Is(err, ErrNotFound) {
				t.Errorf("code miss = %v, %v; want nil, ErrNotFound", a, err)
			}
			if err == nil || err.Error() != "application 4: AVP code 999999 vendor 10415: dictionary entry not found" {
				t.Errorf("code miss context: %v", err)
			}
			a, err = lookup.FindAVPByName(4, "Not-Defined")
			if a != nil || !errors.Is(err, ErrNotFound) {
				t.Errorf("name miss = %v, %v", a, err)
			}
			if err == nil || err.Error() != `application 4: AVP name "Not-Defined": dictionary entry not found` {
				t.Errorf("name miss context: %v", err)
			}
			c, err := lookup.FindCommand(4, 999999)
			if c != nil || !errors.Is(err, ErrNotFound) {
				t.Errorf("command miss = %v, %v", c, err)
			}
			if err == nil || err.Error() != "application 4: command code 999999: dictionary entry not found" {
				t.Errorf("command miss context: %v", err)
			}
		})
	}
	for label, lookup := range map[string]vendorLookup{"parser": Default, "snapshot": Default.Snapshot()} {
		t.Run(label, func(t *testing.T) {
			for _, tc := range []struct {
				code, vendor               uint32
				value                      int32
				member, wantEnum, wantRule string
			}{
				{274, 0, 99, "No-Member", "application 4: AVP code 274 vendor 0: enum value 99: dictionary entry not found", "application 4: AVP code 274 vendor 0: expected Grouped, got Enumerated"},
				{284, 0, 1, "No-Member", "application 4: AVP code 284 vendor 0: expected Enumerated, got Grouped", `application 4: AVP code 284 vendor 0: rule member "No-Member": dictionary entry not found`},
				{1032, 10415, -1, "No-Member", "application 4: AVP code 1032 vendor 10415: enum value -1: dictionary entry not found", "application 4: AVP code 1032 vendor 10415: expected Grouped, got Enumerated"},
				{999999, 10415, 0, "No-Member", "application 4: AVP code 999999 vendor 10415: dictionary entry not found", "application 4: AVP code 999999 vendor 10415: dictionary entry not found"},
			} {
				e, err := lookup.Enum(4, tc.code, tc.vendor, tc.value)
				if e != nil || err == nil || err.Error() != tc.wantEnum {
					t.Errorf("enum = %v, %v; want %s", e, err, tc.wantEnum)
				}
				if tc.code != 284 && !errors.Is(fmt.Errorf("outer: %w", err), ErrNotFound) {
					t.Errorf("enum sentinel: %v", err)
				}
				r, err := lookup.Rule(4, tc.code, tc.vendor, tc.member)
				if r != nil || err == nil || err.Error() != tc.wantRule {
					t.Errorf("rule = %v, %v; want %s", r, err, tc.wantRule)
				}
				if (tc.code == 284 || tc.code == 999999) && !errors.Is(fmt.Errorf("outer: %w", err), ErrNotFound) {
					t.Errorf("rule sentinel: %v", err)
				}
			}
		})
	}
}
