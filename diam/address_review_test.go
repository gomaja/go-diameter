package diam

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
)

type addressReviewIP net.IP
type addressReviewNetip netip.Addr
type addressReviewAddress datatype.Address
type addressReviewPointer *addressReviewPointer
type addressReviewSlice []addressReviewSlice

func addressReviewDestination(typ reflect.Type) reflect.Value {
	return reflect.New(reflect.StructOf([]reflect.StructField{{Name: "Host", Type: typ, Tag: `avp:"Host-IP-Address"`}}))
}

func TestUnmarshalAddressUnsupported(t *testing.T) {
	m := NewRequest(CapabilitiesExchange, 0, nil)
	m.AddAVP(NewAVP(avp.HostIPAddress, avp.Mbit, 0, datatype.AddressFromIP(netip.MustParseAddr("192.0.2.1"))))
	for _, typ := range []reflect.Type{reflect.TypeOf([]byte{}), reflect.TypeOf(""), reflect.TypeOf(0), reflect.TypeOf([4]byte{}), reflect.TypeOf(struct{}{}), reflect.TypeOf(map[string]string{}), reflect.TypeFor[any](), reflect.TypeOf([]string{}), reflect.TypeOf((*string)(nil))} {
		t.Run(typ.String(), func(t *testing.T) {
			dst := addressReviewDestination(typ)
			if err := m.Unmarshal(dst.Interface()); err == nil {
				t.Fatalf("unsupported %s accepted as %v", typ, dst.Elem().Field(0))
			}
		})
	}
}

func TestUnmarshalAddressWrongData(t *testing.T) {
	valid := datatype.AddressFromIP(netip.MustParseAddr("192.0.2.1"))
	for _, payload := range []datatype.Type{datatype.Unknown{0, 1, 1}, datatype.UTF8String("192.0.2.1"), nil} {
		for _, typ := range []reflect.Type{reflect.TypeOf(datatype.Address{}), reflect.TypeOf([]datatype.Address{}), reflect.TypeOf([]*datatype.Address{}), reflect.TypeOf(net.IP{}), reflect.TypeOf(netip.Addr{}), reflect.TypeOf([]netip.Addr{}), reflect.TypeOf(addressReviewIP{}), reflect.TypeOf(addressReviewNetip{})} {
			t.Run(fmt.Sprintf("%T/%s", payload, typ), func(t *testing.T) {
				m := NewRequest(CapabilitiesExchange, 0, nil)
				// A partially decoded message may retain Unknown data for an invalid AVP.
				m.AVP = []*AVP{&AVP{Code: avp.HostIPAddress, Flags: avp.Mbit, Data: payload}}
				dst := addressReviewDestination(typ)
				if err := m.Unmarshal(dst.Interface()); err == nil {
					t.Fatalf("Address field %s accepted %T data", typ, payload)
				}
				if typ.Kind() == reflect.Slice && typ.Elem().Kind() != reflect.Uint8 {
					m.AVP = append([]*AVP{NewAVP(avp.HostIPAddress, avp.Mbit, 0, valid)}, m.AVP...)
					if err := m.Unmarshal(dst.Interface()); err == nil {
						t.Fatalf("Address slice %s accepted invalid second AVP", typ)
					}
				}
			})
		}
	}
}

func TestUnmarshalAddressRecursiveType(t *testing.T) {
	m := NewRequest(CapabilitiesExchange, 0, nil)
	m.AddAVP(NewAVP(avp.HostIPAddress, avp.Mbit, 0, datatype.AddressFromIP(netip.MustParseAddr("192.0.2.1"))))
	for _, typ := range []reflect.Type{reflect.TypeFor[addressReviewPointer](), reflect.TypeFor[addressReviewSlice]()} {
		dst := addressReviewDestination(typ)
		if err := m.Unmarshal(dst.Interface()); err == nil {
			t.Errorf("recursive field type %s accepted", typ)
		}
	}
}

func TestReflectAddressNamedTypes(t *testing.T) {
	for _, literal := range []string{"192.0.2.1", "2001:db8::1"} {
		addr := datatype.AddressFromIP(netip.MustParseAddr(literal))
		for _, tc := range []struct {
			typ  reflect.Type
			want any
		}{
			{reflect.TypeOf(addressReviewIP{}), addressReviewIP(addr.Value)},
			{reflect.TypeOf(addressReviewNetip{}), addressReviewNetip(netip.MustParseAddr(literal))},
			{reflect.TypeOf(addressReviewAddress{}), addressReviewAddress(addr)},
		} {
			t.Run(literal+tc.typ.String(), func(t *testing.T) {
				m := NewRequest(CapabilitiesExchange, 0, nil)
				m.AddAVP(NewAVP(avp.HostIPAddress, avp.Mbit, 0, addr))
				dst := addressReviewDestination(tc.typ)
				if err := m.Unmarshal(dst.Interface()); err != nil {
					t.Fatal(err)
				}
				if got := dst.Elem().Field(0).Interface(); !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("named field = %v, want %v", got, tc.want)
				}
				out := NewRequest(CapabilitiesExchange, 0, nil)
				if err := out.Marshal(dst.Interface()); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(out.AVP[0].Data.Serialize(), addr.Serialize()) {
					t.Fatal("named field round trip changed Address")
				}
			})
		}
	}
}

func TestMarshalAddressOwnsValue(t *testing.T) {
	source := struct {
		Host datatype.Address `avp:"Host-IP-Address"`
	}{datatype.AddressFromIP(netip.MustParseAddr("192.0.2.1"))}
	want := source.Host.Serialize()
	m := NewRequest(CapabilitiesExchange, 0, nil)
	if err := m.Marshal(&source); err != nil {
		t.Fatal(err)
	}
	source.Host.Value[0] = 1
	if got := m.AVP[0].Data.Serialize(); !bytes.Equal(got, want) {
		t.Fatalf("Marshal aliases input: %x, want %x", got, want)
	}
	m.AVP[0].Data.(datatype.Address).Value[1] = 99
	if source.Host.Value[1] != 0 {
		t.Fatal("Marshal output mutation changed input")
	}
}

func TestMessageNewAVPRejectsInvalidAddress(t *testing.T) {
	for _, addr := range []datatype.Address{{}, {Family: datatype.AddressFamilyIPv4, Value: make([]byte, 16)}, {Value: []byte{10, 0, 0, 1}}, {Family: 65535}, {Family: datatype.AddressFamilyIPv6, Value: make([]byte, 4)}} {
		for name, add := range map[string]func(*Message) (*AVP, error){
			"code": func(m *Message) (*AVP, error) { return m.NewAVP(avp.HostIPAddress, avp.Mbit, 0, addr) },
			"name": func(m *Message) (*AVP, error) { return m.NewAVPByName("Host-IP-Address", avp.Mbit, addr) },
		} {
			m := NewRequest(CapabilitiesExchange, 0, nil)
			length := m.Header.MessageLength
			if a, err := add(m); err == nil || a != nil {
				t.Errorf("NewAVP accepted invalid Address %v for %s", addr, name)
			}
			if len(m.AVP) != 0 || m.Header.MessageLength != length {
				t.Error("failed NewAVP changed message")
			}
		}
	}
}

func TestReflectMappedAddressRoundTrip(t *testing.T) {
	mapped := netip.MustParseAddr("::ffff:192.0.2.1")
	address := datatype.Address{Family: datatype.AddressFamilyIPv6, Value: mapped.AsSlice()}
	m := NewRequest(CapabilitiesExchange, 0, nil)
	m.AddAVP(NewAVP(avp.HostIPAddress, avp.Mbit, 0, address))
	for _, typ := range []reflect.Type{reflect.TypeFor[net.IP](), reflect.TypeFor[netip.Addr](), reflect.TypeFor[datatype.Address]()} {
		dst := addressReviewDestination(typ)
		if err := m.Unmarshal(dst.Interface()); err != nil {
			t.Fatal(err)
		}
		out := NewRequest(CapabilitiesExchange, 0, nil)
		if err := out.Marshal(dst.Interface()); err != nil {
			t.Fatal(err)
		}
		want := datatype.Address{Family: datatype.AddressFamilyIPv4, Value: []byte{192, 0, 2, 1}}
		if typ == reflect.TypeFor[datatype.Address]() {
			want = address
		}
		got := out.AVP[0].Data.(datatype.Address)
		if got.Family != want.Family || !bytes.Equal(got.Value, want.Value) {
			t.Fatalf("%s round trip = %v, want %v", typ, got, want)
		}
	}
}

func TestReflectAddressNamedOmitEmpty(t *testing.T) {
	for _, value := range []any{addressReviewAddress{Family: 1234}, addressReviewNetip(netip.IPv6Unspecified())} {
		typ := reflect.TypeOf(value)
		dst := reflect.New(reflect.StructOf([]reflect.StructField{{Name: "Host", Type: typ, Tag: `avp:"Host-IP-Address,omitempty"`}}))
		m := NewRequest(CapabilitiesExchange, 0, nil)
		if err := m.Marshal(dst.Interface()); err != nil {
			t.Fatal(err)
		}
		if len(m.AVP) != 0 {
			t.Fatalf("zero named %s not omitted", typ)
		}
		dst.Elem().Field(0).Set(reflect.ValueOf(value))
		if err := m.Marshal(dst.Interface()); err != nil {
			t.Fatal(err)
		}
		if len(m.AVP) != 1 {
			t.Fatalf("valid named %s omitted", typ)
		}
	}
}

func TestMessageNewAVPAddressPointer(t *testing.T) {
	m := NewRequest(CapabilitiesExchange, 0, nil)
	if _, err := m.NewAVP(avp.HostIPAddress, avp.Mbit, 0, (*datatype.Address)(nil)); err == nil {
		t.Fatal("accepted nil Address pointer")
	}
	invalid := datatype.Address{}
	if _, err := m.NewAVP(avp.HostIPAddress, avp.Mbit, 0, &invalid); err == nil {
		t.Fatal("accepted invalid Address pointer")
	}
	valid := datatype.Address{Family: datatype.AddressFamilyIPv4, Value: []byte{192, 0, 2, 1}}
	if _, err := m.NewAVP(avp.HostIPAddress, avp.Mbit, 0, &valid); err != nil {
		t.Fatal(err)
	}
	var dst struct {
		Host datatype.Address `avp:"Host-IP-Address"`
	}
	if err := m.Unmarshal(&dst); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dst.Host, valid) {
		t.Fatalf("pointer constructor = %v", dst.Host)
	}
}
