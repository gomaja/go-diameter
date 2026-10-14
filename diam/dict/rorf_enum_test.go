package dict_test

import (
	"regexp"
	"strings"
	"testing"
	"unicode"
)

// TS 32.299 V19.0.0 §7.2.113 lists multiple values in some paragraphs.
func TestRoRfNodeFunctionalityComplete(t *testing.T) {
	reference := newAllTestParser(t)

	want := []string{"S-CSCF", "P-CSCF", "I-CSCF", "MRFC", "MGCF", "BGCF", "AS", "IBCF", "S-GW", "P-GW", "HSGW", "E-CSCF", "MME", "TRF", "TF", "ATCF", "Proxy Function", "ePDG", "TDF", "TWAG", "SCEF", "IWK-SCEF"}
	a, err := reference.FindAVP(4, 862, 10415)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Data.Enum) != len(want) {
		t.Errorf("Node-Functionality has %d values, want all 22", len(a.Data.Enum))
	}
	for code, name := range want {
		got, err := reference.Enum(4, 862, 10415, int32(code))
		if err != nil || got.Name != name {
			t.Errorf("value %d = %v, %v; want %s", code, got, err, name)
		}
	}
}

// TS 32.299 V19.0.0 §§7.2.154J, 7.2.207, 7.2.213: ranges are
// not individual enumerators; labels exclude document layout characters.
func TestBundledEnumerationLabels(t *testing.T) {
	reference := newAllTestParser(t)

	fragment := regexp.MustCompile(`(?i)^(?:[-–.]|[0-9]+\s+(?:unused|reserved|vendor specific))`)
	for _, app := range reference.Apps() {
		for _, a := range app.AVP {
			for _, item := range a.Data.Enum {
				if strings.ContainsFunc(item.Name, unicode.IsControl) || fragment.MatchString(item.Name) {
					t.Errorf("app %d %s value %d has malformed label %q", app.ID, a.Name, item.Code, item.Name)
				}
			}
		}
	}
}

func TestRoRfReservedRangesAreNotValues(t *testing.T) {
	reference := newAllTestParser(t)

	for _, tc := range []struct {
		code   uint32
		values []int32
	}{{3448, []int32{6, 255}}, {2029, []int32{11, 99, 100, 199}}} {
		for _, value := range tc.values {
			if got, err := reference.Enum(4, tc.code, 10415, value); err == nil {
				t.Errorf("reserved/range value %d/%d became %q", tc.code, value, got.Name)
			}
		}
	}
}
