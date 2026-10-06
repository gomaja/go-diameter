package diam

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
)

func TestUnmarshalRawAVPData(t *testing.T) {
	for _, data := range []datatype.Type{datatype.Unknown{0, 1, 1, 2, 3}, datatype.Address{}, nil} {
		for _, typ := range []reflect.Type{reflect.TypeFor[AVP](), reflect.TypeFor[*AVP](), reflect.TypeFor[[]AVP](), reflect.TypeFor[[]*AVP]()} {
			t.Run(fmt.Sprintf("%T/%s", data, typ), func(t *testing.T) {
				m := NewRequest(CapabilitiesExchange, 0, nil)
				a := &AVP{Code: avp.HostIPAddress, Flags: avp.Mbit, Data: data}
				m.AVP = []*AVP{a, a}
				dst := addressReviewDestination(typ)
				if err := m.Unmarshal(dst.Interface()); err != nil {
					t.Fatalf("raw AVP field rejected %T: %v", data, err)
				}
				value := dst.Elem().Field(0)
				if value.Kind() == reflect.Slice {
					if value.Len() != 2 {
						t.Fatal("lost repeated AVP")
					}
					value = value.Index(1)
				}
				if value.Kind() == reflect.Pointer {
					if value.Interface().(*AVP) != a {
						t.Fatal("raw pointer does not refer to message AVP")
					}
					value = value.Elem()
				}
				if !reflect.DeepEqual(value.Interface().(AVP), *a) {
					t.Fatal("raw AVP changed data")
				}
			})
		}
	}
}

func TestUnmarshalAVPPointerIdentity(t *testing.T) {
	for _, tc := range []struct {
		code uint32
		name string
		data datatype.Type
	}{
		{avp.HostIPAddress, "Host-IP-Address", datatype.AddressFromIP(netip.MustParseAddr("192.0.2.1"))},
		{avp.OriginHost, "Origin-Host", datatype.DiameterIdentity("example")},
		{avp.VendorID, "Vendor-Id", datatype.Unsigned32(1)},
		{avp.ProxyInfo, "Proxy-Info", &GroupedAVP{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewRequest(CapabilitiesExchange, 0, nil)
			a := NewAVP(tc.code, avp.Mbit, 0, tc.data)
			m.AddAVP(a)
			for _, typ := range []reflect.Type{reflect.TypeFor[*AVP](), reflect.TypeFor[[]*AVP](), reflect.TypeFor[AVP](), reflect.TypeFor[[]AVP]()} {
				dst := reflect.New(reflect.StructOf([]reflect.StructField{{Name: "Value", Type: typ, Tag: reflect.StructTag(fmt.Sprintf(`avp:"%s"`, tc.name))}}))
				if typ == reflect.TypeFor[*AVP]() {
					dst.Elem().Field(0).Set(reflect.ValueOf(&AVP{}))
				}
				if err := m.Unmarshal(dst.Interface()); err != nil {
					t.Fatal(err)
				}
				value := dst.Elem().Field(0)
				if value.Kind() == reflect.Slice {
					value = value.Index(0)
				}
				if value.Kind() == reflect.Pointer {
					ptr := value.Interface().(*AVP)
					if ptr != a {
						t.Fatalf("%s does not point to message AVP", typ)
					}
					ptr.Flags ^= avp.Mbit
					if a.Flags != ptr.Flags {
						t.Fatal("pointer mutation not visible in message")
					}
				} else {
					value.FieldByName("Flags").SetUint(0xff)
					if a.Flags == 0xff {
						t.Fatal("value field aliases AVP struct")
					}
				}
			}
		})
	}
}

type addressStreamWriter struct{ bytes.Buffer }

func (w *addressStreamWriter) WriteStream(b []byte, _ uint) (int, error) { return w.Write(b) }

func TestMessageRejectsInvalidAddressOnWire(t *testing.T) {
	for _, addr := range []datatype.Address{{}, {Family: 65535}, {Family: datatype.AddressFamilyIPv4, Value: make([]byte, 16)}, {Family: datatype.AddressFamilyIPv6, Value: make([]byte, 4)}} {
		for _, depth := range []int{0, 1, 3} {
			for _, insert := range []bool{false, true} {
				for _, method := range []string{"Serialize", "SerializeTo", "WriteTo", "WriteToStream", "WriteToWithRetry", "WriteToStreamWithRetry"} {
					t.Run(fmt.Sprintf("%d/%d/%d/%t/%s", addr.Family, len(addr.Value), depth, insert, method), func(t *testing.T) {
						m := NewRequest(CapabilitiesExchange, 0, nil)
						a := NewAVP(avp.HostIPAddress, avp.Mbit, 0, addr)
						for range depth {
							a = NewAVP(avp.ProxyInfo, avp.Mbit, 0, &GroupedAVP{AVP: []*AVP{a}})
						}
						if insert {
							m.InsertAVP(a)
						} else {
							m.AddAVP(a)
						}
						var w addressStreamWriter
						var err error
						switch method {
						case "Serialize":
							_, err = m.Serialize()
						case "SerializeTo":
							err = m.SerializeTo(make([]byte, m.Len()))
						case "WriteTo":
							_, err = m.WriteTo(&w)
						case "WriteToStream":
							_, err = m.WriteToStream(&w, 1)
						case "WriteToWithRetry":
							_, err = m.WriteToWithRetry(&w, 1)
						case "WriteToStreamWithRetry":
							_, err = m.WriteToStreamWithRetry(&w, 1, 1)
						}
						if err == nil {
							t.Fatal("invalid Address reached wire")
						}
						if w.Len() != 0 {
							t.Fatal("invalid message wrote bytes")
						}
					})
				}
			}
		}
	}
}

func TestNewAVPNormalizesAddressPointer(t *testing.T) {
	addr := datatype.AddressFromIP(netip.MustParseAddr("192.0.2.1"))
	a := NewAVP(avp.HostIPAddress, 0, 0, &addr)
	if _, ok := a.Data.(datatype.Address); !ok {
		t.Fatalf("NewAVP retained %T", a.Data)
	}
	m := NewRequest(CapabilitiesExchange, 0, nil)
	m.AddAVP(a)
	if !strings.Contains(m.PrettyDump(), "192.0.2.1") {
		t.Fatal("missing Address value")
	}
}

type unexpectedDumpData struct {
	datatype.Unknown
	typ datatype.TypeID
}

func (d unexpectedDumpData) Type() datatype.TypeID { return d.typ }
func (d unexpectedDumpData) String() string        { return "unexpected data" }
func TestPrettyDumpUnexpectedData(t *testing.T) {
	addr := datatype.AddressFromIP(netip.MustParseAddr("192.0.2.1"))
	data := []datatype.Type{&addr, (*datatype.Address)(nil), (*GroupedAVP)(nil), nil}
	for _, typ := range datatype.Available {
		data = append(data, unexpectedDumpData{typ: typ})
	}
	data = append(data, unexpectedDumpData{typ: GroupedAVPType})
	for _, d := range data {
		t.Run(fmt.Sprintf("%T/%v", d, d), func(t *testing.T) {
			m := NewRequest(CapabilitiesExchange, 0, nil)
			m.AVP = []*AVP{{Code: avp.HostIPAddress, Data: d}}
			if m.PrettyDump() == "" {
				t.Fatal("empty dump")
			}
		})
	}
}

func BenchmarkWriteToNoAddress(b *testing.B) {
	for _, count := range []int{1, 16, 64} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			m := NewRequest(DeviceWatchdog, 0, nil)
			for range count {
				m.AddAVP(NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example.net")))
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := m.WriteTo(io.Discard); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestMessageAddressPointersOnWire(t *testing.T) {
	valid := datatype.AddressFromIP(netip.MustParseAddr("192.0.2.1"))
	invalid := datatype.Address{}
	for _, ptr := range []*datatype.Address{nil, &invalid, &valid} {
		for _, normalize := range []bool{false, true} {
			for _, depth := range []int{0, 2} {
				m := NewRequest(CapabilitiesExchange, 0, nil)
				a := &AVP{Code: avp.HostIPAddress, Data: ptr}
				if normalize {
					a = NewAVP(avp.HostIPAddress, 0, 0, ptr)
				}
				for range depth {
					a = NewAVP(avp.ProxyInfo, 0, 0, &GroupedAVP{AVP: []*AVP{a}})
				}
				m.AddAVP(a)
				wire, err := m.Serialize()
				if ptr != &valid {
					if err == nil {
						t.Fatalf("invalid Address pointer serialized (normalized=%t depth=%d)", normalize, depth)
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					decoded, err := ReadMessage(bytes.NewReader(wire), nil)
					if err != nil {
						t.Fatal(err)
					}
					found, err := decoded.FindAVP(avp.HostIPAddress, 0)
					if err != nil {
						t.Fatal(err)
					}
					if got, ok := found.Data.(datatype.Address); !ok || got.Family != datatype.AddressFamilyIPv4 || !bytes.Equal(got.Value, []byte{192, 0, 2, 1}) {
						t.Fatalf("Address pointer round trip = %v", found.Data)
					}
				}
			}
		}
	}
}

func TestUnmarshalRawAVPUnexportedField(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeFor[AVP](), reflect.TypeFor[*AVP](), reflect.TypeFor[[]AVP](), reflect.TypeFor[[]*AVP]()} {
		dst := reflect.New(reflect.StructOf([]reflect.StructField{{Name: "host", PkgPath: "diam", Type: typ, Tag: `avp:"Host-IP-Address"`}}))
		m := NewRequest(CapabilitiesExchange, 0, nil)
		m.AddAVP(NewAVP(avp.HostIPAddress, 0, 0, datatype.Unknown{0, 1, 1, 2, 3}))
		if err := m.Unmarshal(dst.Interface()); err == nil {
			t.Fatalf("accepted unexported %s field", typ)
		}
	}
}
