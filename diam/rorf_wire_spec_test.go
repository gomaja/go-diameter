package diam

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

const roRfWireAppID = 4

func roRfWireSpec(t *testing.T) []rxWireAVPSpec {
	t.Helper()
	b, err := os.ReadFile("dict/testdata/rorf_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct{ AVPs []rxWireAVPSpec }
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.AVPs) != 744 {
		t.Fatalf("incomplete Ro/Rf fixture: %d", len(s.AVPs))
	}
	return s.AVPs
}

func roRfWireFlags(t *testing.T, must string) uint8 {
	t.Helper()
	var flags uint8
	for _, part := range strings.Split(must, ",") {
		part = strings.TrimSpace(part)
		if part == "" || part == "-" {
			continue
		}
		for _, c := range part {
			switch c {
			case 'M':
				flags |= avp.Mbit
			case 'V':
				flags |= avp.Vbit
			case 'P':
				flags |= avp.Pbit
			default:
				t.Fatalf("invalid flag set %q", must)
			}
		}
	}
	return flags
}

func roRfFindAVP(t *testing.T, name string) *dict.AVP {
	t.Helper()
	a, err := dict.Default.FindAVPByName(roRfWireAppID, name)
	if err == nil {
		return a
	}
	normalize := func(s string) string {
		s = strings.ToUpper(strings.ReplaceAll(s, "3GPP", "TGPP"))
		return strings.NewReplacer("-", "", "_", "", " ", "").Replace(s)
	}
	for _, app := range dict.Default.Apps() {
		for _, candidate := range app.AVP {
			if normalize(candidate.Name) == normalize(name) {
				if a, err = dict.Default.FindAVPByName(roRfWireAppID, candidate.Name); err == nil {
					return a
				}
			}
		}
	}
	t.Fatalf("RoRf AVP %s: %v", name, err)
	return nil
}

func roRfSampleData(t *testing.T, a *dict.AVP, depth int) datatype.Type {
	t.Helper()
	if depth > 12 {
		t.Fatalf("unexpected grouped recursion at %s", a.Name)
	}
	switch a.Data.TypeName {
	case "Grouped":
		g := &GroupedAVP{}
		if a.Name == "Failed-AVP" {
			// RFC 6733 §7.5: include the offending AVP in 1*{AVP}.
			g.AVP = append(g.AVP, NewAVP(avp.UserName, avp.Mbit, 0, datatype.UTF8String("user")))
			return g
		}
		for _, r := range a.Data.Rule {
			if r.AVP == "AVP" || r.MaxSet && r.Max == 0 {
				continue
			}
			// RFC 6733 §6.11: select accounting, never both application IDs.
			if a.Name == "Vendor-Specific-Application-Id" && r.AVP == "Auth-Application-Id" {
				continue
			}
			if a.Name == "User-Equipment-Info-Extension" && len(g.AVP) > 0 {
				continue
			}
			count := r.Min
			if count == 0 {
				count = 1
			}
			for i := 0; i < count; i++ {
				child := roRfFindAVP(t, r.AVP)
				g.AVP = append(g.AVP, NewAVP(child.Code, roRfWireFlags(t, child.Must), child.VendorID, roRfSampleData(t, child, depth+1)))
			}
		}
		return g
	case "Enumerated":
		if len(a.Data.Enum) == 0 {
			return datatype.Enumerated(0)
		}
		return datatype.Enumerated(a.Data.Enum[len(a.Data.Enum)-1].Code)
	case "OctetString":
		return datatype.OctetString("\x01\x23\x45\x67\x89")
	case "UTF8String":
		return datatype.UTF8String("roRf-example")
	case "DiameterIdentity":
		return datatype.DiameterIdentity("af.example.net")
	case "DiameterURI":
		return datatype.DiameterURI("aaa://af.example.net")
	case "IPFilterRule":
		return datatype.IPFilterRule("permit out ip from any to any")
	case "Unsigned32":
		return datatype.Unsigned32(17)
	case "Unsigned64":
		return datatype.Unsigned64(0x123456789abcdef0)
	case "Integer32":
		return datatype.Integer32(-17)
	case "Integer64":
		return datatype.Integer64(-17)
	case "Float32":
		return datatype.Float32(0.125)
	case "Float64":
		return datatype.Float64(0.125)
	case "Time":
		return datatype.Time(time.Unix(1700000000, 0))
	case "Address":
		return datatype.Address{Family: 1, Value: []byte{192, 0, 2, 1}}
	default:
		t.Fatalf("no RoRf wire sample for %s (%s)", a.Name, a.Data.TypeName)
		return nil
	}
}

// TS 32.299 V19.0.0 Table 7.2.0.1: all RoRf-local AVPs and
// recursively copied registry definitions have independent wire identities.
func TestRoRfAVPWireRoundTrip(t *testing.T) {
	definitions := roRfWireSpec(t)
	for _, want := range definitions {
		t.Run(want.Name, func(t *testing.T) {
			a, err := dict.Default.FindAVP(roRfWireAppID, want.Code, want.Vendor)
			if err != nil {
				t.Fatal(err)
			}
			if a.Data.TypeName != want.Type {
				t.Fatalf("type %s, want %s", a.Data.TypeName, want.Type)
			}
			data := roRfSampleData(t, a, 0)
			m := NewRequest(272, roRfWireAppID, dict.Default)
			if _, err := m.NewAVPByName(a.Name, roRfWireFlags(t, a.Must), data); err != nil {
				t.Fatal(err)
			}
			assertRefreshWire(t, m, want.Code, roRfWireFlags(t, want.Must), want.Vendor, data)
		})
	}
}

// TS 32.299 V19.0.0 §§6.2.2–6.2.3, 6.4.2–6.4.5. The required
// command prefix is common to the current RFCs and the charging CCF.
// RFC 6733 §3.2, Verified Erratum 4803, defines the CCF header literal.
// Each optional RFC and charging member is exercised separately, including
// cardinality boundaries and a known non-member through the RFC wildcard.
func TestRoRfCommandWire(t *testing.T) {
	b, err := os.ReadFile("dict/testdata/rorf_commands_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Commands []struct {
			Application        uint32
			Section            string
			Code               uint32
			Request, Proxiable bool
			Rules              []rxWireRuleSpec
			Effective          []rxWireRuleSpec `json:"effective_rules"`
		}
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.Commands) != 6 {
		t.Fatal("incomplete charging command fixture")
	}
	for _, c := range s.Commands {
		t.Run(c.Section, func(t *testing.T) {
			flags := uint8(0)
			if c.Request {
				flags |= RequestFlag
			}
			if c.Proxiable {
				flags |= ProxiableFlag
			}
			m := NewMessage(c.Code, flags, c.Application, 0x12345678, 0x87654321, dict.Default)
			for _, r := range c.Rules {
				if r.Name == "AVP" {
					continue
				}
				for i := 0; i < r.Min; i++ {
					a := roRfFindAVP(t, r.Name)
					m.AddAVP(NewAVP(a.Code, roRfWireFlags(t, a.Must), a.VendorID, roRfSampleData(t, a, 0)))
				}
			}
			if err := m.ValidateOutgoing(); err != nil {
				t.Fatalf("source command: %v", err)
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
				t.Fatalf("command round trip: %v", err)
			}
			if got.Header.CommandFlags != flags || got.Header.ApplicationID != c.Application {
				t.Fatal("command header differs")
			}
			m.Header.CommandFlags ^= ProxiableFlag
			if err := m.Validate(); err == nil || err.ResultCode != InvalidHDRBits {
				t.Fatalf("wrong P bit: %v", err)
			}
			m.Header.CommandFlags ^= ProxiableFlag
			prefix := append([]*AVP(nil), m.AVP...)
			for _, r := range c.Effective {
				if r.Min > 0 {
					continue
				}
				name := r.Name
				if name == "AVP" {
					name = "Host-IP-Address"
				}
				a, err := dict.Default.FindAVPByName(c.Application, name)
				if err != nil {
					t.Fatalf("application %d cannot resolve %s: %v", c.Application, name, err)
				}
				member := NewAVP(a.Code, roRfWireFlags(t, a.Must), a.VendorID, roRfSampleData(t, a, 0))
				m.AVP = append(append([]*AVP(nil), prefix...), member)
				if err := m.ValidateOutgoing(); err != nil {
					t.Fatalf("optional %s: %v", name, err)
				}
				wire, err := m.Serialize()
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := ReadMessage(bytes.NewReader(wire), dict.Default)
				if err != nil {
					t.Fatal(err)
				}
				if decoded.DecodeErr != nil || decoded.Validate() != nil {
					t.Fatalf("optional %s did not decode/validate: %v", name, decoded.DecodeErr)
				}
				roundTrip, err := decoded.Serialize()
				if err != nil || !bytes.Equal(wire, roundTrip) {
					t.Fatalf("optional %s round trip: %v", name, err)
				}
				m.AddAVP(member)
				if r.Max != nil && *r.Max == 1 {
					if err := m.ValidateOutgoing(); err == nil {
						t.Fatalf("duplicate singleton %s accepted", name)
					}
				} else if err := m.ValidateOutgoing(); err != nil {
					t.Fatalf("repeated %s: %v", name, err)
				}
			}
			m.AVP = prefix
			original := append([]*AVP(nil), m.AVP...)
			for i := range original {
				m.AVP = append(append([]*AVP(nil), original[:i]...), original[i+1:]...)
				if err := m.Validate(); err == nil {
					t.Fatalf("missing required AVP %d accepted", original[i].Code)
				}
			}
			m.AVP = original
			m.AVP[0], m.AVP[1] = m.AVP[1], m.AVP[0]
			if err := m.Validate(); err == nil {
				t.Fatal("displaced fixed Session-Id accepted")
			}
		})
	}
}
