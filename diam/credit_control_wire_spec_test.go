package diam

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

type creditControlWireRule struct {
	Name string `json:"name"`
	Min  int    `json:"min"`
}
type creditControlWireAVP struct {
	Name, Type, Must string
	Code             uint32
	Rules            []creditControlWireRule
}
type creditControlWireCommand struct {
	Section            string
	Code               uint32
	Request, Proxiable bool
	Rules              []creditControlWireRule
}
type creditControlWireSpec struct {
	AVPs     []creditControlWireAVP
	Commands []creditControlWireCommand
}

func loadCreditControlWireSpec(t *testing.T) creditControlWireSpec {
	t.Helper()
	b, err := os.ReadFile("dict/testdata/credit_control_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec creditControlWireSpec
	if err := json.Unmarshal(b, &spec); err != nil {
		t.Fatal(err)
	}
	if len(spec.AVPs) != 68 || len(spec.Commands) != 2 {
		t.Fatalf("incomplete RFC 8506 fixture: %d/%d", len(spec.AVPs), len(spec.Commands))
	}
	return spec
}

func creditControlWireData(t *testing.T, a creditControlWireAVP, lookup map[string]creditControlWireAVP, depth int) datatype.Type {
	t.Helper()
	if depth > 12 {
		t.Fatalf("grouped recursion at %s", a.Name)
	}
	if a.Type != "Grouped" {
		def, err := dict.Default.FindAVP(4, a.Code, 0)
		if err != nil {
			t.Fatal(err)
		}
		return gxSampleData(t, def, depth)
	}
	g := &GroupedAVP{}
	for _, rule := range a.Rules {
		if rule.Min == 0 {
			continue
		}
		child, ok := lookup[rule.Name]
		if !ok {
			t.Fatalf("fixture lacks required child %s of %s", rule.Name, a.Name)
		}
		for i := 0; i < rule.Min; i++ {
			g.AVP = append(g.AVP, NewAVP(child.Code, gxWireFlags(child.Must), 0, creditControlWireData(t, child, lookup, depth+1)))
		}
	}
	return g
}

// RFC 8506 §8: each application-4 AVP is serialized and decoded with
// flags and payload independently specified by the RFC/IANA fixture.
func TestCreditControlAVPWireRoundTrip(t *testing.T) {
	spec := loadCreditControlWireSpec(t)
	lookup := make(map[string]creditControlWireAVP, len(spec.AVPs))
	for _, a := range spec.AVPs {
		lookup[a.Name] = a
	}
	for _, want := range spec.AVPs {
		t.Run(want.Name, func(t *testing.T) {
			def, err := dict.Default.FindAVP(4, want.Code, 0)
			if err != nil {
				t.Fatal(err)
			}
			data := creditControlWireData(t, want, lookup, 0)
			m := NewRequest(272, 4, dict.Default)
			if _, err := m.NewAVPByName(def.Name, gxWireFlags(def.Must), data); err != nil {
				t.Fatal(err)
			}
			assertRefreshWire(t, m, want.Code, gxWireFlags(want.Must), 0, data)
		})
	}
}

func creditControlCommandMessage(t *testing.T, spec creditControlWireCommand) *Message {
	t.Helper()
	flags := uint8(ProxiableFlag)
	if spec.Request {
		flags |= RequestFlag
	}
	m := NewMessage(272, flags, 4, 0x12345678, 0x87654321, dict.Default)
	for _, r := range spec.Rules {
		if r.Min == 0 {
			continue
		}
		def, err := dict.Default.FindAVPByName(4, r.Name)
		if err != nil {
			t.Fatal(err)
		}
		var data datatype.Type
		switch r.Name {
		case "Session-Id":
			data = datatype.UTF8String("cc;123")
		case "Auth-Application-Id":
			data = datatype.Unsigned32(4)
		case "Result-Code":
			data = datatype.Unsigned32(2001)
		case "CC-Request-Type":
			data = datatype.Enumerated(1)
		case "CC-Request-Number":
			data = datatype.Unsigned32(0)
		default:
			data = gxSampleData(t, def, 0)
		}
		m.AddAVP(NewAVP(def.Code, gxWireFlags(def.Must), def.VendorID, data))
	}
	return m
}

// RFC 8506 §§3.1–3.2: CCR/CCA command flags, fixed Session-Id, required
// members and extension cardinality survive a message wire round trip.
func TestCreditControlCommandWireRoundTrip(t *testing.T) {
	for _, spec := range loadCreditControlWireSpec(t).Commands {
		t.Run(spec.Section, func(t *testing.T) {
			m := creditControlCommandMessage(t, spec)
			if err := m.Validate(); err != nil {
				t.Fatalf("minimal command: %v", err)
			}
			m.AddAVP(NewAVP(avp.HostIPAddress, avp.Mbit, 0, datatype.Address{Family: 1, Value: []byte{192, 0, 2, 1}}))
			m.AddAVP(NewAVP(avp.HostIPAddress, avp.Mbit, 0, datatype.Address{Family: 1, Value: []byte{192, 0, 2, 2}}))
			if err := m.Validate(); err != nil {
				t.Fatalf("repeatable extension: %v", err)
			}
			wire, err := m.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			got, err := ReadMessage(bytes.NewReader(wire), dict.Default)
			if err != nil || got.DecodeErr != nil {
				t.Fatalf("read: %v, decode: %v", err, got.DecodeErr)
			}
			if err := got.Validate(); err != nil {
				t.Fatal(err)
			}
			again, err := got.Serialize()
			if err != nil || !bytes.Equal(wire, again) {
				t.Fatalf("round trip differs: %v", err)
			}
			m.Header.CommandFlags &^= ProxiableFlag
			if err := m.Validate(); err == nil || err.ResultCode != InvalidHDRBits {
				t.Fatalf("missing PXY: %v", err)
			}
			m.Header.CommandFlags |= ProxiableFlag
			m.AVP[0], m.AVP[1] = m.AVP[1], m.AVP[0]
			if err := m.Validate(); err == nil || err.ResultCode != AVPNotAllowed {
				t.Fatalf("Session-Id not first: %v", err)
			}
		})
	}
}

// RFC 8506 §§8.17–8.19, 8.16, 8.58, 8.64, 8.68. The latter two
// explicitly permit only one extension, unlike the five repeatable groups.
func TestCreditControlGroupedExtensions(t *testing.T) {
	spec := loadCreditControlWireSpec(t)
	lookup := make(map[string]creditControlWireAVP, len(spec.AVPs))
	for _, a := range spec.AVPs {
		lookup[a.Name] = a
	}
	for _, name := range []string{"Granted-Service-Unit", "Requested-Service-Unit", "Used-Service-Unit", "Multiple-Services-Credit-Control", "QoS-Final-Unit-Indication", "Subscription-Id-Extension", "Redirect-Server-Extension"} {
		t.Run(name, func(t *testing.T) {
			a := lookup[name]
			data := creditControlWireData(t, a, lookup, 0).(*GroupedAVP)
			for i := 0; i < 2; i++ {
				if i == 0 {
					data.AVP = append(data.AVP, NewAVP(411, 0, 0, datatype.OctetString("extension")))
				} else {
					data.AVP = append(data.AVP, NewAVP(424, avp.Mbit, 0, datatype.UTF8String("extension-2")))
				}
				m := creditControlCommandMessage(t, spec.Commands[0])
				m.AddAVP(NewAVP(a.Code, gxWireFlags(a.Must), 0, data))
				err := m.Validate()
				if name == "Subscription-Id-Extension" || name == "Redirect-Server-Extension" {
					if i == 0 && err != nil {
						t.Fatalf("single extension: %v", err)
					}
					if i == 1 && (err == nil || err.ResultCode != AVPOccursTooManyTimes) {
						t.Fatalf("second extension: %v", err)
					}
				} else if err != nil {
					t.Fatalf("repeatable extension %d: %v", i+1, err)
				}
			}
		})
	}
}
