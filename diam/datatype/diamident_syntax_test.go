package datatype

import (
	"strings"
	"testing"
)

func TestDiameterIdentityValid(t *testing.T) {
	maxName := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	tests := []struct {
		name, value string
		valid       bool
	}{
		{"fqdn", "peer.example.net", true},
		{"realm", "example.net", true},
		{"root_dot", "peer.example.net.", true},
		{"empty", "", false},
		{"root_only", ".", false},
		{"one_label", "localhost", true},
		{"one_letter", "a", true},
		{"one_digit", "1", true},
		{"label_63", strings.Repeat("a", 63), true},
		{"label_64", strings.Repeat("a", 64), false},
		{"inner_label_63", "a." + strings.Repeat("b", 63) + ".net", true},
		{"inner_label_64", "a." + strings.Repeat("b", 64) + ".net", false},
		{"name_253", maxName, true},
		{"name_254", maxName + "e", false},
		{"name_255", maxName + "ef", false},
		{"name_253_root_dot", maxName + ".", true},
		{"name_254_root_dot", maxName + "e.", false},
		{"name_255_root_dot", maxName + "ef.", false},
		{"uppercase", "PEER.Example.NET", true},
		{"numeric_label", "123.example.net", true},
		{"numeric_final_label", "peer.123", true},
		{"all_numeric", "123.456", true},
		{"leading_hyphen", "-peer.example", false},
		{"inner_leading_hyphen", "peer.-host.example", false},
		{"trailing_hyphen", "example.peer-", false},
		{"inner_trailing_hyphen", "peer-.example", false},
		{"only_hyphen", "-", false},
		{"interior_hyphen", "peer-1.example", true},
		{"reserved_hyphens", "ab--cd.example", true},
		{"hyphen_position_3", "ab-cd.example", true},
		{"hyphen_position_4", "abc-d.example", true},
		{"a_label", "xn--bcher-kva.example", true},
		{"uppercase_a_label", "XN--BCHER-KVA.example", true},
		{"fake_a_label_control", "xn--a.example", true},
		{"fake_a_label_ascii", "xn--abc-.example", false},
		{"empty_ace_suffix", "xn--.example", false},
		{"u_label", "bücher.example", false},
		{"non_ascii", "peer\xff.example", false},
		{"continuation_byte", "peer\x80.example", false},
		{"underscore", "peer_name.example", false},
		{"service_owner", "_diameter._tcp.example", false},
		{"space", "peer name.example", false},
		{"nul", "peer\x00.example", false},
		{"newline", "peer\n.example", false},
		{"tab", "peer\t.example", false},
		{"delete", "peer\x7f.example", false},
		{"leading_dot", ".example", false},
		{"empty_inner_label", "peer..example", false},
		{"two_root_dots", "peer.example..", false},
		{"ipv4_literal", "192.0.2.1", true},
		{"ipv6_literal", "2001:db8::1", false},
		{"bracketed_ipv6", "[2001:db8::1]", false},
		{"escaped_dot", "peer\\.example", false},
		{"port", "peer.example:3868", false},
		{"slash", "peer/example", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := DiameterIdentity(tt.value)
			if got := identity.Valid(); got != tt.valid {
				t.Fatalf("Valid(%q) = %t, want %t", tt.value, got, tt.valid)
			}
		})
	}
}

func FuzzDiameterIdentityValid(f *testing.F) {
	for _, value := range []string{"", "peer.example", "Peer-1.Example.", "xn--bcher-kva.example", "_diameter._tcp.example", "peer\xff.example", "peer..example", "K.example", strings.Repeat("a", 64)} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		valid := DiameterIdentity(value).Valid()
		// ASCII case does not affect the accepted label syntax.
		lower := []byte(value)
		for i, c := range lower {
			if c >= 'A' && c <= 'Z' {
				lower[i] = c + ('a' - 'A')
			}
		}
		if valid != DiameterIdentity(lower).Valid() {
			t.Fatalf("ASCII case changed validity: %q, %q", value, lower)
		}
		if valid {
			unrooted := strings.TrimSuffix(value, ".")
			if !DiameterIdentity(unrooted).Valid() || !DiameterIdentity(unrooted+".").Valid() {
				t.Fatalf("optional root dot changed validity: %q", value)
			}
		}
	})
}
