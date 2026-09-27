package diam

import "testing"

func TestDefaultTransportAddress(t *testing.T) {
	for _, tc := range []struct {
		address string
		secure  bool
		want    string
	}{
		{"", false, ":3868"},
		{"", true, ":5868"},
		{"127.0.0.1:9999", false, "127.0.0.1:9999"},
		{"127.0.0.1:9999", true, "127.0.0.1:9999"},
	} {
		if got := defaultTransportAddress(tc.address, tc.secure); got != tc.want {
			t.Errorf("defaultTransportAddress(%q, %v) = %q, want %q", tc.address, tc.secure, got, tc.want)
		}
	}
}
