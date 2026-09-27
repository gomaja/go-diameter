package diam

import "testing"

// TestFlagListedAcceptsCompactRules checks that the compact flag-rule form
// ("MV") is read like the comma form ("M,V"), so a dictionary written either
// way is validated the same.
func TestFlagListedAcceptsCompactRules(t *testing.T) {
	for _, tc := range []struct {
		list, flag string
		want       bool
	}{
		{"M,V", "M", true}, {"V,M", "V", true}, {"M", "M", true},
		{"MV", "M", true}, {"MV", "V", true}, {"VM", "M", true},
		{"MV", "P", false}, {"V", "M", false}, {"", "M", false}, {"-", "M", false},
	} {
		if got := flagListed(tc.list, tc.flag); got != tc.want {
			t.Errorf("flagListed(%q, %q) = %t, want %t", tc.list, tc.flag, got, tc.want)
		}
	}
}
