package base

import (
	"bytes"
	"net/netip"
	"reflect"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
)

func TestCloneAVPPreservesAddress(t *testing.T) {
	for _, address := range []datatype.Address{{}, {Family: datatype.AddressFamilyIPv4, Value: make([]byte, 16)}, datatype.AddressFromIP(netip.MustParseAddr("192.0.2.1")), {Family: 999, Value: []byte{1, 2, 3}}} {
		source := diam.NewAVP(avp.HostIPAddress, avp.Mbit, 0, address)
		copy := CloneAVP(source)
		got, ok := copy.Data.(datatype.Address)
		if !ok {
			t.Fatalf("clone changed Address to %T", copy.Data)
		}
		if copy == source || !reflect.DeepEqual(got, address) {
			t.Fatalf("clone = %v, want %v", copy, address)
		}
		if len(got.Value) > 0 {
			got.Value[0] ^= 0xff
			if bytes.Equal(got.Value, address.Value) {
				t.Fatal("clone aliases Address.Value")
			}
		}
	}
}

func TestCloneAVPAddressPointer(t *testing.T) {
	address := datatype.AddressFromIP(netip.MustParseAddr("2001:db8::1"))
	for _, pointer := range []*datatype.Address{nil, &address} {
		source := &diam.AVP{Code: avp.HostIPAddress, Data: pointer}
		copy := CloneAVP(source)
		got, ok := copy.Data.(*datatype.Address)
		if !ok || !reflect.DeepEqual(got, pointer) {
			t.Fatalf("pointer clone = %v, want %v", copy.Data, pointer)
		}
		if got != nil {
			if got == pointer {
				t.Fatal("clone aliases Address pointer")
			}
			got.Value[0] ^= 0xff
			if bytes.Equal(got.Value, pointer.Value) {
				t.Fatal("pointer clone aliases Address.Value")
			}
		}
	}
}
