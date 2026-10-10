package diam

import "testing"

func TestResolveAddressError(t *testing.T) {
	for _, network := range []string{"", "tcp", "tcp4", "tcp6", "sctp", "sctp4", "sctp6", "invalid"} {
		t.Run(network, func(t *testing.T) {
			addr, err := resolveAddress(network, "127.0.0.1:65536")
			if err == nil {
				t.Fatal("resolveAddress succeeded with an invalid port")
			}
			if addr != nil {
				t.Fatalf("resolveAddress returned non-nil address %#v with error %v", addr, err)
			}
		})
	}
}

func TestResolveAddressSuccess(t *testing.T) {
	for _, network := range []string{"", "tcp", "tcp4", "tcp6", "sctp", "sctp4", "sctp6"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:3868"
			if network == "tcp6" || network == "sctp6" {
				address = "[::1]:3868"
			}
			addr, err := resolveAddress(network, address)
			if err != nil {
				t.Fatal(err)
			}
			if addr == nil || addr.String() != address {
				t.Fatalf("resolveAddress = %v, want %s", addr, address)
			}
		})
	}
}
