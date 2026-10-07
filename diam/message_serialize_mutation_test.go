package diam

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
)

func TestMessageLengthAfterAVPMutation(t *testing.T) {
	for _, path := range []string{"Unmarshal", "FindAVP"} {
		for _, method := range []string{"Serialize", "SerializeTo", "WriteTo", "WriteToStream", "WriteToWithRetry", "WriteToStreamWithRetry"} {
			t.Run(path+"/"+method, func(t *testing.T) {
				m := NewRequest(CapabilitiesExchange, 0, nil)
				m.AddAVP(NewAVP(avp.HostIPAddress, avp.Mbit, 0, datatype.AddressFromIP(netip.MustParseAddr("192.0.2.1"))))
				var a *AVP
				if path == "Unmarshal" {
					var dst struct {
						Host *AVP `avp:"Host-IP-Address"`
					}
					if err := m.Unmarshal(&dst); err != nil {
						t.Fatal(err)
					}
					a = dst.Host
				} else {
					var err error
					a, err = m.FindAVP(avp.HostIPAddress, 0)
					if err != nil {
						t.Fatal(err)
					}
				}
				for _, literal := range []string{"2001:db8::1", "192.0.2.9"} {
					a.Data = datatype.AddressFromIP(netip.MustParseAddr(literal))
					cached := m.Header.MessageLength
					var wire []byte
					var w addressStreamWriter
					var err error
					switch method {
					case "Serialize":
						wire, err = m.Serialize()
					case "SerializeTo":
						wire = make([]byte, m.Len()+17)
						err = m.SerializeTo(wire)
						wire = wire[:m.Len()]
					case "WriteTo":
						_, err = m.WriteTo(&w)
						wire = w.Bytes()
					case "WriteToStream":
						_, err = m.WriteToStream(&w, 1)
						wire = w.Bytes()
					case "WriteToWithRetry":
						_, err = m.WriteToWithRetry(&w, 1)
						wire = w.Bytes()
					case "WriteToStreamWithRetry":
						_, err = m.WriteToStreamWithRetry(&w, 1, 1)
						wire = w.Bytes()
					}
					if err != nil {
						t.Fatal(err)
					}
					declared := int(uint24to32(wire[1:4]))
					if declared != len(wire) {
						t.Fatalf("header length = %d, actual = %d", declared, len(wire))
					}
					// Serializing reads the message and never writes to it.
					if m.Header.MessageLength != cached {
						t.Fatalf("serializing changed Header.MessageLength from %d to %d", cached, m.Header.MessageLength)
					}
					reader := bytes.NewReader(append(append([]byte(nil), wire...), wire...))
					for range 2 {
						decoded, err := ReadMessage(reader, nil)
						if err != nil {
							t.Fatal(err)
						}
						got, err := decoded.FindAVP(avp.HostIPAddress, 0)
						if err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(got.Data.Serialize(), a.Data.Serialize()) {
							t.Fatal("Address changed on readback")
						}
					}
					if reader.Len() != 0 {
						t.Fatal("frame length left unread bytes")
					}
				}
			})
		}
	}
}

func TestGroupedSerializeInvalidAddress(t *testing.T) {
	for _, addr := range []datatype.Address{{}, {Family: 65535, Value: []byte{1}}, {Family: datatype.AddressFamilyIPv4, Value: make([]byte, 16)}, {Family: datatype.AddressFamilyIPv6, Value: []byte{1, 2, 3, 4}}} {
		for _, depth := range []int{0, 2} {
			t.Run(fmt.Sprintf("%d/%d/%d", addr.Family, len(addr.Value), depth), func(t *testing.T) {
				child := NewAVP(avp.HostIPAddress, avp.Mbit, 0, addr)
				raw := make([]byte, child.Len())
				binary.BigEndian.PutUint32(raw, avp.HostIPAddress)
				raw[4] = avp.Mbit
				putUint24(raw[5:8], uint32(8+addr.Len()))
				copy(raw[8:], addr.Serialize())
				for range depth {
					child = NewAVP(avp.ProxyInfo, avp.Mbit, 0, &GroupedAVP{AVP: []*AVP{child}})
					parent := make([]byte, 8+len(raw))
					binary.BigEndian.PutUint32(parent, avp.ProxyInfo)
					parent[4] = avp.Mbit
					putUint24(parent[5:8], uint32(len(parent)))
					copy(parent[8:], raw)
					raw = parent
				}
				group := &GroupedAVP{AVP: []*AVP{child}}
				if got := group.Serialize(); !bytes.Equal(got, raw) {
					t.Fatalf("raw group = %x, want %x", got, raw)
				}
				m := NewRequest(CapabilitiesExchange, 0, nil)
				m.AddAVP(NewAVP(avp.ProxyInfo, avp.Mbit, 0, group))
				if _, err := m.Serialize(); err == nil {
					t.Fatal("raw group bypassed message Address validation")
				}
			})
		}
	}
}

func TestPrettyDumpNilAVP(t *testing.T) {
	m := NewRequest(CapabilitiesExchange, 0, nil)
	m.AVP = []*AVP{nil, {Code: avp.ProxyInfo, Data: &GroupedAVP{AVP: []*AVP{nil, NewAVP(avp.OriginHost, 0, 0, datatype.DiameterIdentity("after-nil.example"))}}}}
	got := m.PrettyDump()
	if strings.Count(got, "<nil AVP>") != 2 || !strings.Contains(got, "after-nil.example") {
		t.Fatalf("dump skipped nil AVPs or following data: %s", got)
	}
}

// TestSerializeConcurrentAfterAVPMutation serializes and prints one message
// from several goroutines after an AVP changed length through a pointer.
// Serializing must not write to the message, or this races (go test -race).
func TestSerializeConcurrentAfterAVPMutation(t *testing.T) {
	m := NewRequest(CapabilitiesExchange, 0, nil)
	m.AddAVP(NewAVP(avp.HostIPAddress, avp.Mbit, 0, datatype.AddressFromIP(netip.MustParseAddr("192.0.2.1"))))
	a, err := m.FindAVP(avp.HostIPAddress, 0)
	if err != nil {
		t.Fatal(err)
	}
	a.Data = datatype.AddressFromIP(netip.MustParseAddr("2001:db8::1"))
	want := m.Len()
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(3)
		go func() {
			defer wg.Done()
			var w bytes.Buffer
			if _, err := m.WriteTo(&w); err != nil || w.Len() != want || int(uint24to32(w.Bytes()[1:4])) != want {
				t.Errorf("WriteTo: err %v, %d bytes", err, w.Len())
			}
		}()
		go func() {
			defer wg.Done()
			if b, err := m.Serialize(); err != nil || int(uint24to32(b[1:4])) != want {
				t.Errorf("Serialize: err %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			_ = m.String()
		}()
	}
	wg.Wait()
}
