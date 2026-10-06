// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package datatype

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"reflect"
	"testing"
)

func TestAddress(t *testing.T) {
	tests := []struct {
		name string
		addr Address
		wire string
		text string
	}{
		{"IPv4", AddressFromIP(netip.MustParseAddr("10.0.0.1")), "00010a000001", "Address{10.0.0.1},Padding:2"},
		{"IPv6", AddressFromIP(netip.MustParseAddr("2001:db8::ff00:42:8329")), "000220010db8000000000000ff0000428329", "Address{2001:db8::ff00:42:8329},Padding:2"},
		{"mapped", AddressFromIP(netip.MustParseAddr("::ffff:10.0.0.1")), "00010a000001", "Address{10.0.0.1},Padding:2"},
		{"zone", AddressFromIP(netip.MustParseAddr("fe80::1%eth0")), "0002fe800000000000000000000000000001", "Address{fe80::1},Padding:2"},
		{"E164 two digits", Address{AddressFamilyE164, []byte("12")}, "00083132", "Address{12},Family:E.164,Padding:0"},
		{"E164 fourteen digits", Address{AddressFamilyE164, []byte("12345678901234")}, "00083132333435363738393031323334", "Address{12345678901234},Family:E.164,Padding:0"},
		{"E164 raw", Address{AddressFamilyE164, []byte{0x21, 0xf3}}, "000821f3", "Address{21f3},Family:8,Padding:0"},
		{"unknown", Address{0x1234, []byte{0, 1}}, "12340001", "Address{0001},Family:4660,Padding:0"},
		{"empty unknown", Address{0x1234, []byte{}}, "1234", "Address{},Family:4660,Padding:2"},
		{"mapped on wire", Address{AddressFamilyIPv6, netip.MustParseAddr("::ffff:10.0.0.1").AsSlice()}, "000200000000000000000000ffff0a000001", "Address{::ffff:10.0.0.1},Padding:2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := hex.DecodeString(tt.wire)
			if err != nil {
				t.Fatal(err)
			}
			if got := tt.addr.Serialize(); !bytes.Equal(got, wire) {
				t.Fatalf("wire %x, want %x", got, wire)
			}
			if tt.addr.Len() != len(wire) || tt.addr.Padding() != (4-len(wire)%4)%4 || tt.addr.Type() != AddressType {
				t.Fatalf("invalid type, length or padding: %v", tt.addr)
			}
			if got := tt.addr.String(); got != tt.text {
				t.Fatalf("String = %q, want %q", got, tt.text)
			}
			decoded, err := DecodeAddress(wire)
			if err != nil {
				t.Fatal(err)
			}
			addr := decoded.(Address)
			if addr.Family != tt.addr.Family || !bytes.Equal(addr.Value, tt.addr.Value) {
				t.Fatalf("decoded %v, want %v", addr, tt.addr)
			}
			clear(wire)
			if !bytes.Equal(addr.Value, tt.addr.Value) || addr.Family != tt.addr.Family {
				t.Fatal("decode aliases input")
			}
			serialized := addr.Serialize()
			clear(serialized)
			clone := addr.Clone()
			clear(clone.Value)
			if !bytes.Equal(addr.Value, tt.addr.Value) {
				t.Fatal("serialize or clone aliases value")
			}
		})
	}
}

func TestDecodeAddressErrors(t *testing.T) {
	for _, wire := range [][]byte{nil, {0}, {0, 0}, {255, 255}, {0, 1}, {0, 1, 1, 2, 3}, {0, 1, 1, 2, 3, 4, 5}, {0, 2}, append([]byte{0, 2}, make([]byte, 15)...), append([]byte{0, 2}, make([]byte, 17)...)} {
		if _, err := DecodeAddress(wire); err == nil {
			t.Errorf("accepted %x", wire)
		}
	}
}

func TestAddressAccessors(t *testing.T) {
	for _, s := range []string{"10.0.0.1", "2001:db8::1", "::ffff:10.0.0.1"} {
		want := netip.MustParseAddr(s).Unmap()
		if got, ok := AddressFromIP(netip.MustParseAddr(s)).IP(); !ok || got != want {
			t.Errorf("IP = %v, %v; want %v", got, ok, want)
		}
	}
	for _, addr := range []Address{{}, {AddressFamilyE164, []byte("1234")}, {AddressFamilyIPv4, make([]byte, 16)}, {AddressFamilyIPv6, make([]byte, 4)}, {1234, make([]byte, 16)}} {
		if ip, ok := addr.IP(); ok || ip.IsValid() {
			t.Errorf("non-IP accepted: %v", addr)
		}
	}
	if got := AddressFromIP(netip.Addr{}); !reflect.DeepEqual(got, Address{}) {
		t.Fatalf("invalid IP = %v", got)
	}
	for _, digits := range []string{"1", "12", "48602007060", "12345678901234", "123456789012345"} {
		addr, err := E164Address(digits)
		if err != nil {
			t.Fatal(err)
		}
		if addr.Family != AddressFamilyE164 || string(addr.Value) != digits {
			t.Fatalf("E164Address = %v", addr)
		}
		if got, ok := addr.E164(); !ok || got != digits {
			t.Fatalf("E164 = %q, %v", got, ok)
		}
	}
	for _, digits := range []string{"", "1234567890123456", "+12", "1 2", "12a", "１２", "\xff"} {
		if _, err := E164Address(digits); err == nil {
			t.Errorf("accepted digits %q", digits)
		}
		if _, ok := (Address{AddressFamilyE164, []byte(digits)}).E164(); ok {
			t.Errorf("E164 accepted %q", digits)
		}
	}
	if _, ok := (Address{1234, []byte("12")}).E164(); ok {
		t.Fatal("E164 ignored family")
	}
}

func FuzzDecodeAddress(f *testing.F) {
	for _, wire := range [][]byte{{0, 1, 127, 0, 0, 1}, {0, 8, '1', '2'}, {0x12, 0x34}, {255, 255}} {
		f.Add(wire)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		got, err := DecodeAddress(wire)
		if err != nil {
			return
		}
		if got.Len() != len(wire) || !bytes.Equal(got.Serialize(), wire) {
			t.Fatalf("round trip %x -> %x", wire, got.Serialize())
		}
	})
}
func BenchmarkAddressIPv4(b *testing.B) {
	address := AddressFromIP(netip.MustParseAddr("10.0.0.1"))
	for n := 0; n < b.N; n++ {
		address.Serialize()
	}
}

func BenchmarkDecodeAddressIPv4(b *testing.B) {
	v := []byte{0x00, 0x01, 0x0a, 0x00, 0x00, 0x01}
	for n := 0; n < b.N; n++ {
		if _, err := DecodeAddress(v); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAddressIPv6(b *testing.B) {
	address := AddressFromIP(netip.MustParseAddr("2001:db8::ff00:42:8329"))
	for n := 0; n < b.N; n++ {
		address.Serialize()
	}
}

func BenchmarkDecodeAddressIPv6(b *testing.B) {
	v := []byte{0x00, 0x02,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0x00, 0x00, 0x42, 0x83, 0x29,
	}
	for n := 0; n < b.N; n++ {
		if _, err := DecodeAddress(v); err != nil {
			b.Fatal(err)
		}
	}
}

func TestAddressValid(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address Address
		valid   bool
	}{
		{"zero", Address{}, false},
		{"value without family", Address{Value: []byte{192, 0, 2, 1}}, false},
		{"reserved high", Address{Family: 65535}, false},
		{"IPv4 short", Address{AddressFamilyIPv4, make([]byte, 3)}, false},
		{"IPv4 long", Address{AddressFamilyIPv4, make([]byte, 16)}, false},
		{"IPv6 short", Address{AddressFamilyIPv6, make([]byte, 4)}, false},
		{"IPv6 long", Address{AddressFamilyIPv6, make([]byte, 17)}, false},
		{"IPv4", Address{AddressFamilyIPv4, make([]byte, 4)}, true},
		{"IPv6", Address{AddressFamilyIPv6, make([]byte, 16)}, true},
		{"E164 raw", Address{AddressFamilyE164, []byte{0xff}}, true},
		{"unknown empty", Address{Family: 1234}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.address.Valid()
			if (err == nil) != tc.valid {
				t.Fatalf("Valid() = %v, want valid=%v", err, tc.valid)
			}
			_, decodeErr := DecodeAddress(tc.address.Serialize())
			if (decodeErr == nil) != tc.valid {
				t.Fatalf("DecodeAddress() = %v, want valid=%v", decodeErr, tc.valid)
			}
		})
	}
}
