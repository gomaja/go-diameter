// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diam

import (
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
)

func TestReflectAddress(t *testing.T) {
	for _, literal := range []string{"192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1"} {
		t.Run(literal, func(t *testing.T) {
			ip := netip.MustParseAddr(literal)
			addr := datatype.AddressFromIP(ip)
			for _, input := range []any{
				&struct {
					IP net.IP `avp:"Host-IP-Address"`
				}{net.ParseIP(literal)},
				&struct {
					IP netip.Addr `avp:"Host-IP-Address"`
				}{ip},
				&struct {
					IP datatype.Address `avp:"Host-IP-Address"`
				}{addr},
			} {
				m := NewRequest(CapabilitiesExchange, 0, nil)
				if err := m.Marshal(input); err != nil {
					t.Fatal(err)
				}
				var out struct {
					IP      net.IP             `avp:"Host-IP-Address"`
					Addr    netip.Addr         `avp:"Host-IP-Address"`
					Raw     datatype.Address   `avp:"Host-IP-Address"`
					IPs     []net.IP           `avp:"Host-IP-Address"`
					Addrs   []netip.Addr       `avp:"Host-IP-Address"`
					Raws    []datatype.Address `avp:"Host-IP-Address"`
					Pointer *netip.Addr        `avp:"Host-IP-Address"`
				}
				if err := m.Unmarshal(&out); err != nil {
					t.Fatal(err)
				}
				if !out.IP.Equal(net.ParseIP(literal)) || out.Addr != ip.Unmap() || !reflect.DeepEqual(out.Raw, addr) ||
					len(out.IPs) != 1 || !out.IPs[0].Equal(out.IP) || len(out.Addrs) != 1 || out.Addrs[0] != out.Addr ||
					len(out.Raws) != 1 || !reflect.DeepEqual(out.Raws[0], addr) || out.Pointer == nil || *out.Pointer != out.Addr {
					t.Fatalf("unmarshal = %+v", out)
				}
				out.IP[0] ^= 255
				out.Raw.Value[0] ^= 255
				if !reflect.DeepEqual(m.AVP[0].Data, addr) {
					t.Fatal("unmarshal aliases message")
				}
			}
		})
	}
}

func TestReflectAddressFamilies(t *testing.T) {
	for _, addr := range []datatype.Address{{Family: datatype.AddressFamilyE164, Value: []byte("1234")}, {Family: 1234, Value: make([]byte, 16)}} {
		m := NewRequest(CapabilitiesExchange, 0, nil)
		input := struct {
			Addresses []datatype.Address `avp:"Host-IP-Address"`
		}{[]datatype.Address{addr, addr.Clone()}}
		if err := m.Marshal(&input); err != nil {
			t.Fatal(err)
		}
		var output struct {
			Addresses []datatype.Address `avp:"Host-IP-Address"`
		}
		if err := m.Unmarshal(&output); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(input, output) {
			t.Fatalf("round trip = %+v", output)
		}
		for _, dst := range []any{&struct {
			IP net.IP `avp:"Host-IP-Address"`
		}{}, &struct {
			IP netip.Addr `avp:"Host-IP-Address"`
		}{}} {
			if err := m.Unmarshal(dst); err == nil {
				t.Fatalf("unmarshal accepted non-IP family %d into %T", addr.Family, dst)
			}
		}
	}
	for _, input := range []any{&struct {
		IP net.IP `avp:"Host-IP-Address"`
	}{net.IP{1}}, &struct {
		IP netip.Addr `avp:"Host-IP-Address"`
	}{}, &struct {
		IP datatype.Address `avp:"Host-IP-Address"`
	}{}, &struct {
		IP string `avp:"Host-IP-Address"`
	}{"1.2.3.4"}} {
		if err := NewRequest(CapabilitiesExchange, 0, nil).Marshal(input); err == nil {
			t.Fatalf("marshal accepted %T", input)
		}
	}
	m := NewRequest(CapabilitiesExchange, 0, nil)
	m.AddAVP(NewAVP(avp.HostIPAddress, avp.Mbit, 0, datatype.Address{Family: datatype.AddressFamilyIPv4, Value: []byte{1}}))
	var dst struct {
		IP netip.Addr `avp:"Host-IP-Address"`
	}
	if err := m.Unmarshal(&dst); err == nil {
		t.Fatal("accepted invalid IPv4 length")
	}
}

func TestReflectAddressOmitEmpty(t *testing.T) {
	m := NewRequest(CapabilitiesExchange, 0, nil)
	input := struct {
		Address datatype.Address `avp:"Host-IP-Address,omitempty"`
		IP      netip.Addr       `avp:"Host-IP-Address,omitempty"`
	}{}
	if err := m.Marshal(&input); err != nil {
		t.Fatal(err)
	}
	if len(m.AVP) != 0 {
		t.Fatalf("zero values were not omitted: %v", m.AVP)
	}
	input.Address = datatype.Address{Family: 1234}
	input.IP = netip.IPv6Unspecified()
	if err := m.Marshal(&input); err != nil {
		t.Fatal(err)
	}
	if len(m.AVP) != 2 {
		t.Fatalf("valid values were omitted: %v", m.AVP)
	}
	input.Address = datatype.Address{Value: []byte{1}}
	if err := m.Marshal(&input); err == nil {
		t.Fatal("malformed Address was omitted")
	}
}
