package dict

import (
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

type s6aEnumExpectation struct {
	Code   uint32            `json:"code"`
	Type   string            `json:"type"`
	Items  map[string]string `json:"items"`
	Source string            `json:"source"`
}

// The fixture was machine extracted from TS 29.272 V19.6.0 Table 7.3.1/1 and
// §§7.3.21–7.3.255, with deferred values from TS 32.422 V20.3.0
// §§5.3, 5.9a, 5.10.5–5.10.34. Reused enum values come from TS 29.212
// V20.0.0 §§5.3.17, 5.3.31, 5.3.46–5.3.47; transitive CSG enums
// follow TS 32.299 V19.0.0 §§7.2.46A–7.2.46B.
func TestS6aS13EnumeratedSpec(t *testing.T) {
	b, err := os.ReadFile("testdata/s6a_enums_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]s6aEnumExpectation
	if err := json.Unmarshal(b, &expected); err != nil {
		t.Fatal(err)
	}
	if len(expected) != 54 { // 48 own + 4 directly reused + 2 transitive Enumerated AVPs.
		t.Fatalf("fixture has %d enums, want 54", len(expected))
	}
	for name, want := range expected {
		t.Run(name, func(t *testing.T) {
			appID := uint32(16777251)
			if name == "Equipment-Status" {
				appID = 16777252 // TS 29.272 §7.2.21: S13/S13' only.
			}
			avp, err := Default.FindAVP(appID, name)
			if err != nil {
				t.Fatalf("%s: %v", want.Source, err)
			}
			if avp.Code != want.Code || avp.Data.TypeName != "Enumerated" {
				t.Fatalf("%s: code/type = %d/%s, want %d/Enumerated", want.Source,
					avp.Code, avp.Data.TypeName, want.Code)
			}
			got := make(map[string]string, len(avp.Data.Enum))
			for _, item := range avp.Data.Enum {
				key := strconv.FormatInt(int64(item.Code), 10)
				if _, duplicate := got[key]; duplicate {
					t.Errorf("duplicate enum code %s", key)
				}
				got[key] = item.Name
			}
			if !sameCodes(got, want.Items) {
				t.Errorf("%s: enum codes = %v, want %v", want.Source, sortedCodes(got), sortedCodes(want.Items))
			}
			if s6aCheckEnumLabels(name) {
				for code, specName := range want.Items {
					if actualName, ok := got[code]; ok && normalizeEnumName(actualName) != normalizeEnumName(specName) {
						t.Errorf("%s: code %s name %q, want %q", want.Source, code, actualName, specName)
					}
				}
			}
		})
	}
}

func s6aCheckEnumLabels(name string) bool {
	// TS 32.422 §5.10.5 assigns different durations to the same Report-Interval
	// code by RAT. Duration-based names for these AVPs are local conventions.
	for _, prefix := range []string{"Report-", "Logging-", "Measurement-", "Collection-"} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	// TS 29.272 §7.3.135 writes the two SIPTO names with an internal space.
	return name != "SIPTO-Permission" && name != "CSG-Access-Mode" && name != "CSG-Membership-Indication"
}

func normalizeEnumName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(unicode.ToUpper(r))
		}
	}
	return b.String()
}

func sameCodes(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			return false
		}
	}
	return true
}

func sortedCodes(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TS 29.272 V19.6.0 Table 7.3.1/1, §§7.3.151, 7.3.162, 7.3.175,
// 7.3.177, 7.3.186, 7.3.201–7.3.202, 7.3.254–7.3.255.
func TestS6aS13NewAVPMetadataSpec(t *testing.T) {
	for _, tc := range []struct {
		name, typ string
		code      uint32
	}{
		{"Equivalent-PLMN-List", "Grouped", 1637},
		{"SMS-Register-Request", "Enumerated", 1648},
		{"SGs-MME-Identity", "UTF8String", 1664},
		{"Coupled-Node-Diameter-ID", "DiameterIdentity", 1666},
		{"Adjacent-PLMNs", "Grouped", 1672},
		{"AIR-Flags", "Unsigned32", 1679},
		{"UE-Usage-Type", "Unsigned32", 1680},
		{"SF-ULR-Timestamp", "Time", 1729},
		{"SF-Provisional-Indication", "Enumerated", 1730},
	} {
		t.Run(tc.name, func(t *testing.T) {
			avp, err := Default.FindAVP(16777251, tc.name)
			if err != nil {
				t.Fatal(err)
			}
			if avp.Code != tc.code || avp.Data.TypeName != tc.typ || avp.VendorID != 10415 ||
				avp.Must != "V" || avp.MustNot != "M" || avp.MayEncrypt != "N" {
				t.Errorf("got code=%d type=%s vendor=%d must=%q must-not=%q encrypt=%q; want %d/%s/10415/V/M/N",
					avp.Code, avp.Data.TypeName, avp.VendorID, avp.Must, avp.MustNot, avp.MayEncrypt,
					tc.code, tc.typ)
			}
		})
	}
}
