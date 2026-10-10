//go:build linux

package diam

import (
	"errors"
	"net"
	"syscall"
	"testing"
)

func TestListenResult(t *testing.T) {
	for _, fn := range []struct {
		name   string
		listen func(string, string) (net.Listener, error)
	}{
		{"Listen", Listen},
		{"MultistreamListen", MultistreamListen},
	} {
		t.Run(fn.name, func(t *testing.T) {
			for _, network := range []string{"sctp", "sctp4", "sctp6", "tcp", "tcp4", "tcp6"} {
				t.Run(network, func(t *testing.T) {
					for _, tc := range []struct {
						name    string
						address string
						wantErr bool
					}{
						{"bind error", "203.0.113.1:0", true},
						{"invalid port", "127.0.0.1:65536", true},
						{"success", "127.0.0.1:0", false},
					} {
						if network == "sctp6" || network == "tcp6" {
							if tc.name == "bind error" {
								continue
							}
							if !tc.wantErr {
								tc.address = "[::1]:0"
							}
						}
						t.Run(tc.name, func(t *testing.T) {
							l, err := fn.listen(network, tc.address)
							if err == nil && l != nil {
								t.Cleanup(func() {
									if err := l.Close(); err != nil {
										t.Error(err)
									}
								})
							}
							if tc.wantErr {
								if err == nil {
									t.Fatal("listen succeeded, want error")
								}
								if tc.name == "bind error" && !errors.Is(err, syscall.EADDRNOTAVAIL) {
									t.Fatalf("listen error = %v, want EADDRNOTAVAIL", err)
								}
								if l != nil {
									t.Fatalf("listen returned non-nil listener %#v with error %v", l, err)
								}
							} else if err != nil || l == nil {
								t.Fatalf("listen = %#v, %v, want listener and nil error", l, err)
							}
						})
					}
				})
			}
		})
	}
}
