package diam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

type nasreqWireRule struct {
	Name string `json:"name"`
	Min  int    `json:"min"`
}
type nasreqWireAVP struct {
	Name, Type, Must string
	Code, Vendor     uint32
	Rules            []nasreqWireRule
}
type nasreqWireCommand struct {
	Section            string
	Code               uint32
	Request, Proxiable bool
	Rules              []nasreqWireRule
}
type nasreqWireSpec struct {
	AVPs         []nasreqWireAVP
	Commands     []nasreqWireCommand
	Supplemental []nasreqWireAVP
}

func loadNASREQWireSpec(t *testing.T) nasreqWireSpec {
	t.Helper()
	b, err := os.ReadFile("dict/testdata/nasreq_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var s nasreqWireSpec
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.AVPs) != 78 || len(s.Commands) != 10 || len(s.Supplemental) != 4 {
		t.Fatalf("incomplete NASREQ fixture: %d/%d", len(s.AVPs), len(s.Commands))
	}
	return s
}
func nasreqWireData(t *testing.T, a nasreqWireAVP, lookup map[string]nasreqWireAVP) datatype.Type {
	t.Helper()
	if a.Type == "QoSFilterRule" {
		return datatype.QoSFilterRule("tag in ip from any to any DSCP 0")
	}
	if a.Type != "Grouped" {
		def, err := dict.Default.FindAVP(1, a.Code, a.Vendor)
		if err != nil {
			t.Fatal(err)
		}
		return gxSampleData(t, def, 0)
	}
	g := &GroupedAVP{}
	for _, rule := range a.Rules {
		if rule.Min == 0 {
			continue
		}
		name := rule.Name
		if name == "AVP" {
			// RFC 6733 §§3.2, 7.5: a required wildcard accepts arbitrary
			// evidence; use a concrete source-defined User-Name instance.
			name = "User-Name"
		}
		child, ok := lookup[name]
		if !ok {
			t.Fatalf("missing independent fixture for %s child %s", a.Name, rule.Name)
		}
		g.AVP = append(g.AVP, NewAVP(child.Code, gxWireFlags(child.Must), child.Vendor, nasreqWireData(t, child, lookup)))
	}
	return g
}

// RFC 7155 §§4.2–4.6 and Verified Errata 6119: every defined AVP is
// serialized, decoded, and compared with specification-derived wire flags.
func TestNASREQAVPWireRoundTrip(t *testing.T) {
	s := loadNASREQWireSpec(t)
	lookup := map[string]nasreqWireAVP{}
	for _, a := range s.AVPs {
		lookup[a.Name] = a
	}
	for _, want := range append(s.AVPs, s.Supplemental...) {
		t.Run(want.Name, func(t *testing.T) {
			def, err := dict.Default.FindAVP(1, want.Code, want.Vendor)
			if err != nil {
				t.Fatal(err)
			}
			data := nasreqWireData(t, want, lookup)
			m := NewRequest(265, 1, dict.Default)
			if _, err := m.NewAVPByName(def.Name, gxWireFlags(def.Must), data); err != nil {
				t.Fatal(err)
			}
			assertRefreshWire(t, m, want.Code, gxWireFlags(want.Must), want.Vendor, data)
		})
	}
}

func nasreqCommandMessage(t *testing.T, c nasreqWireCommand) *Message {
	t.Helper()
	flags := uint8(ProxiableFlag)
	if c.Request {
		flags |= RequestFlag
	}
	m := NewMessage(c.Code, flags, 1, 0x12345678, 0x87654321, dict.Default)
	for _, r := range c.Rules {
		if r.Min == 0 {
			continue
		}
		def, err := dict.Default.FindAVPByName(1, r.Name)
		if err != nil {
			t.Fatal(err)
		}
		var data datatype.Type
		switch r.Name {
		case "Session-Id":
			data = datatype.UTF8String("nasreq;123")
		case "Auth-Application-Id", "Acct-Application-Id":
			data = datatype.Unsigned32(1)
		case "Result-Code":
			data = datatype.Unsigned32(2001)
		default:
			data = gxSampleData(t, def, 0)
		}
		m.AddAVP(NewAVP(def.Code, gxWireFlags(def.Must), def.VendorID, data))
	}
	return m
}

// RFC 7155 §§3.1–3.10: every command has PXY, fixed Session-Id, required
// members, and a repeatable extension point.
func TestNASREQCommandWireRoundTrip(t *testing.T) {
	for _, c := range loadNASREQWireSpec(t).Commands {
		t.Run(c.Section, func(t *testing.T) {
			m := nasreqCommandMessage(t, c)
			if err := m.Validate(); err != nil {
				t.Fatalf("minimal command: %v", err)
			}
			m.AddAVP(NewAVP(avp.HostIPAddress, avp.Mbit, 0, datatype.Address{Family: 1, Value: []byte{192, 0, 2, 1}}))
			if err := m.Validate(); err != nil {
				t.Fatalf("extension: %v", err)
			}
			wire, err := m.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			got, err := ReadMessage(bytes.NewReader(wire), dict.Default)
			if err != nil {
				t.Fatal(err)
			}
			if got.DecodeErr != nil {
				t.Fatal(got.DecodeErr)
			}
			if err := got.Validate(); err != nil {
				t.Fatal(err)
			}
			again, err := got.Serialize()
			if err != nil || !bytes.Equal(wire, again) {
				t.Fatalf("wire round trip: %v", err)
			}
			m.Header.CommandFlags &^= ProxiableFlag
			if err := m.Validate(); err == nil || err.ResultCode != InvalidHDRBits {
				t.Fatalf("PXY missing: %v", err)
			}
			m.Header.CommandFlags |= ProxiableFlag
			m.AVP[0], m.AVP[1] = m.AVP[1], m.AVP[0]
			if err := m.Validate(); err == nil || err.ResultCode != AVPNotAllowed {
				t.Fatalf("Session-Id not first: %v", err)
			}
		})
	}
}

// RFC 7155 §4.3.4 makes CHAP-Response optional in the grammar. Section
// 4.3.5 separately requires it when CHAP-Algorithm is MD5 (5). The no-response
// case below asserts grammar acceptance only, not a compliant MD5 sender.
func TestNASREQCHAPAuthBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name         string
		withResponse bool
	}{{"grammar-only/no-response", false}, {"md5/with-response", true}} {
		t.Run(tc.name, func(t *testing.T) {
			withResponse := tc.withResponse
			g := &GroupedAVP{AVP: []*AVP{
				NewAVP(403, avp.Mbit, 0, datatype.Enumerated(5)),
				NewAVP(404, avp.Mbit, 0, datatype.OctetString("i")),
			}}
			if withResponse {
				g.AVP = append(g.AVP, NewAVP(405, avp.Mbit, 0, datatype.OctetString("0123456789abcdef")))
			}
			g.AVP = append(g.AVP, NewAVP(avp.HostIPAddress, avp.Mbit, 0, datatype.Address{Family: 1, Value: []byte{192, 0, 2, 1}}))
			m := nasreqCommandMessage(t, loadNASREQWireSpec(t).Commands[0])
			m.AddAVP(NewAVP(402, avp.Mbit, 0, g))
			m.AddAVP(NewAVP(60, avp.Mbit, 0, datatype.OctetString("challenge")))
			if err := m.ValidateOutgoing(); err != nil {
				t.Fatalf("grammar acceptance response=%t: %v", withResponse, err)
			}
			wire, err := m.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := ReadMessage(bytes.NewReader(wire), dict.Default)
			if err != nil {
				t.Fatal(err)
			}
			if err := decoded.ValidateOutgoing(); err != nil {
				t.Fatalf("decoded grammar acceptance response=%t: %v", withResponse, err)
			}
		})
	}
}

// RFC 7155 supplies no Diameter M-bit rule for these four RADIUS AVPs.
// Both choices are allowed; RFC 6733 §4.1 still prohibits a vendor-zero V bit.
func TestNASREQSupplementalOutgoingFlags(t *testing.T) {
	for _, a := range loadNASREQWireSpec(t).Supplemental {
		for _, flags := range []uint8{0, avp.Mbit} {
			t.Run(fmt.Sprintf("%s/M=%t", a.Name, flags&avp.Mbit != 0), func(t *testing.T) {
				m := nasreqCommandMessage(t, loadNASREQWireSpec(t).Commands[0])
				value := NewAVP(a.Code, flags, 0, nasreqWireData(t, a, nil))
				m.AddAVP(value)
				if err := m.ValidateOutgoing(); err != nil {
					t.Fatalf("permitted M flag: %v", err)
				}
				wire, err := m.Serialize()
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := ReadMessage(bytes.NewReader(wire), dict.Default)
				if err != nil {
					t.Fatal(err)
				}
				if err := decoded.ValidateOutgoing(); err != nil {
					t.Fatalf("decoded M flag: %v", err)
				}
				value.Flags |= avp.Vbit // Constructors normalize V; corrupt it deliberately.
				if err := m.ValidateOutgoing(); err == nil || err.ResultCode != InvalidAVPBits {
					t.Fatalf("vendor-zero V set: %v", err)
				}
			})
		}
	}
}
