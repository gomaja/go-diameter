package dnsdiam

import (
	"strings"
	"testing"
)

func TestAbsoluteIdentitySyntax(t *testing.T) {
	maxName := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	for _, tt := range []struct {
		name, value, want string
	}{
		{"host", "Peer-1.Example.NET", "peer-1.example.net."},
		{"realm", "EXAMPLE.NET.", "example.net."},
		{"one_label", "localhost", "localhost."},
		{"name_limit", maxName + ".", maxName + "."},
		{"empty", "", ""},
		{"empty_label", "peer..example", ""},
		{"label_too_long", strings.Repeat("a", 64) + ".example", ""},
		{"name_too_long", maxName + "e.", ""},
		{"leading_hyphen", "-peer.example", ""},
		{"trailing_hyphen", "peer-.example", ""},
		{"u_label", "bücher.example", ""},
		{"high_octet", "peer\xff.example", ""},
		{"service_owner", "_diameter._tcp.example", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := absolute(tt.value, false)
			if tt.want == "" {
				if got != "" || err != ErrInvalid {
					t.Fatalf("absolute(%q, false) = %q, %v; want empty name and ErrInvalid", tt.value, got, err)
				}
			} else if got != tt.want || err != nil {
				t.Fatalf("absolute(%q, false) = %q, %v; want %q, nil", tt.value, got, err, tt.want)
			}
		})
	}
}

func TestAbsoluteServiceOwnerSyntax(t *testing.T) {
	for _, tt := range []struct {
		name, value, want string
	}{
		{"tcp", "_Diameter._TCP.Example.NET", "_diameter._tcp.example.net."},
		{"sctp", "_diameters._sctp.example.net.", "_diameters._sctp.example.net."},
		{"nonterminal", "_delegate.example.net.", "_delegate.example.net."},
		{"underscore_only_label", "_.example.net", "_.example.net."},
		{"empty", "", ""},
		{"root_only", ".", ""},
		{"long_name", strings.Repeat("a.", 127) + "a", ""},
		{"empty_label", "_diameter..example.net", ""},
		{"long_label", strings.Repeat("_", 64) + ".example.net", ""},
		{"leading_hyphen", "-_diameter.example.net", ""},
		{"trailing_hyphen", "_diameter-.example.net", ""},
		{"non_ascii", "_diameter.éxample.net", ""},
		{"space", "_diameter._tcp.example net", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := absolute(tt.value, true)
			if tt.want == "" {
				if got != "" || err != ErrInvalid {
					t.Fatalf("absolute(%q, true) = %q, %v; want empty name and ErrInvalid", tt.value, got, err)
				}
			} else if got != tt.want || err != nil {
				t.Fatalf("absolute(%q, true) = %q, %v; want %q, nil", tt.value, got, err, tt.want)
			}
		})
	}
}
