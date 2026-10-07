package dict

import (
	"fmt"
	"testing"
)

// The defining table governs unless the current application's reuse table
// overrides it: TS 29.338 V19.3.0 Tables 5.3.3.1/2 and 6.3.3.1/2;
// TS 29.272 V19.6.0 Table 7.3.1/2; TS 29.273 V19.2.0 Table 8.2.3.0/2.
func TestSMSApplicationFlagScope(t *testing.T) {
	for _, tc := range []struct {
		name string
		code uint32
		// Flags are ordered S6c, SGd, S6a, SWx.
		must    [4]string
		may     [4]string
		mustNot [4]string
	}{
		// TS 29.173 V19.0.0 Table 6.4.1/1, §6.4.12; S6c alone requires M.
		{"MME-Realm", 2408, [4]string{"M,V", "V", "V", "V"}, [4]string{}, [4]string{"", "M", "M", "M"}},
		// TS 32.299 V19.0.0 Table 7.2.0.1, §7.2.240A. The shared charging
		// definition's legacy MAY-P is pinned explicitly by the SMS fixtures.
		{"User-CSG-Information", 2319, [4]string{"M,V", "M,V", "V", "M,V"}, [4]string{"", "", "", ""}, [4]string{"", "", "M", ""}},
		// TS 29.217 V19.0.0 Table 5.3.1.1, §5.3.10. Only S6a clears M.
		{"eNodeB-ID", 4008, [4]string{"M,V", "M,V", "V", "M,V"}, [4]string{"P", "P", "P", "P"}, [4]string{"", "", "M", ""}},
		// TS 29.217 V19.0.0 Table 5.3.1.1, §5.3.15 itself forbids M.
		{"Extended-eNodeB-ID", 4013, [4]string{"V", "V", "V", "V"}, [4]string{"P", "P", "P", "P"}, [4]string{"M", "M", "M", "M"}},
		// TS 29.173 V19.0.0 Table 6.4.1/1, §6.4.7; S6a alone clears M.
		{"GMLC-Address", 2405, [4]string{"M,V", "M,V", "V", "M,V"}, [4]string{}, [4]string{"", "", "M", ""}},
		// TS 29.336 V20.0.0 Table 6.4.1/1, §6.4.11; SGd and S6a clear M.
		{"External-Identifier", 3111, [4]string{"M,V", "V", "V", "M,V"}, [4]string{}, [4]string{"", "M", "M", ""}},
	} {
		for i, app := range []uint32{16777312, 16777313, 16777251, 16777265} {
			t.Run(fmt.Sprintf("%d/%s", app, tc.name), func(t *testing.T) {
				a, err := Default.FindAVP(app, tc.code, 10415)
				if err != nil {
					t.Fatal(err)
				}
				if a.Name != tc.name || gxFlags(a.Must) != gxFlags(tc.must[i]) || gxFlags(a.May) != gxFlags(tc.may[i]) || gxFlags(a.MustNot) != gxFlags(tc.mustNot[i]) {
					t.Fatalf("%s flags %q/%q/%q, want %q/%q/%q", a.Name, a.Must, a.May, a.MustNot, tc.must[i], tc.may[i], tc.mustNot[i])
				}
			})
		}
	}
}
