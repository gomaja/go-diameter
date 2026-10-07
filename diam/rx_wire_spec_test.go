package diam

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

const rxWireAppID = 16777236

type rxWireAVPSpec struct {
	Name, Type, Must string
	Code, Vendor     uint32
}

type rxWireRuleSpec struct {
	Name  string `json:"name"`
	Min   int    `json:"min"`
	Max   *int   `json:"max"`
	Fixed bool   `json:"fixed"`
}

type rxWireCommandSpec struct {
	Section            string
	Code               uint32
	Request, Proxiable bool
	Rules              []rxWireRuleSpec
}

func rxWireSpec(t *testing.T) ([]rxWireAVPSpec, []rxWireCommandSpec) {
	t.Helper()
	b, err := os.ReadFile("dict/testdata/rx_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		AVPs     []rxWireAVPSpec
		Commands []rxWireCommandSpec
		Reused   []struct {
			Name     string
			Metadata *rxWireAVPSpec
		}
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.AVPs) != 84 || len(s.Commands) != 8 || len(s.Reused) != 39 {
		t.Fatalf("incomplete Rx wire fixture: %d AVPs, %d commands, %d reused", len(s.AVPs), len(s.Commands), len(s.Reused))
	}
	b, err = os.ReadFile("dict/testdata/rx_copied_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var copied struct{ AVPs []rxWireAVPSpec }
	if err := json.Unmarshal(b, &copied); err != nil {
		t.Fatal(err)
	}
	if len(copied.AVPs) == 0 {
		t.Fatal("empty Rx copied fixture")
	}
	type key struct{ code, vendor uint32 }
	seen := map[key]bool{}
	var out []rxWireAVPSpec
	all := append(s.AVPs, copied.AVPs...)
	for _, reused := range s.Reused {
		if reused.Metadata == nil {
			t.Fatalf("reused AVP %s lacks wire metadata", reused.Name)
		}
		a := *reused.Metadata
		a.Name = reused.Name
		all = append(all, a)
	}
	for _, a := range all {
		k := key{a.Code, a.Vendor}
		if !seen[k] {
			out = append(out, a)
			seen[k] = true
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Vendor != out[j].Vendor {
			return out[i].Vendor < out[j].Vendor
		}
		return out[i].Code < out[j].Code
	})
	return out, s.Commands
}

func rxWireFlags(t *testing.T, must string) uint8 {
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

func rxFindAVP(t *testing.T, name string) *dict.AVP {
	t.Helper()
	a, err := dict.Default.FindAVPByName(rxWireAppID, name)
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
				if a, err = dict.Default.FindAVPByName(rxWireAppID, candidate.Name); err == nil {
					return a
				}
			}
		}
	}
	t.Fatalf("Rx AVP %s: %v", name, err)
	return nil
}

func rxSampleData(t *testing.T, a *dict.AVP, depth int) datatype.Type {
	t.Helper()
	// RFC 6733 §7.5: one unknown AVP is valid Failed-AVP evidence.
	if a.Code == avp.FailedAVP && a.VendorID == 0 {
		return &GroupedAVP{AVP: []*AVP{NewAVP(999999, avp.Mbit, 0, datatype.OctetString("unsupported"))}}
	}
	if depth > 12 {
		t.Fatalf("unexpected grouped recursion at %s", a.Name)
	}
	switch a.Data.TypeName {
	case "Grouped":
		g := &GroupedAVP{}
		for _, r := range a.Data.Rule {
			if r.AVP == "AVP" || r.MaxSet && r.Max == 0 {
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
				child := rxFindAVP(t, r.AVP)
				g.AVP = append(g.AVP, NewAVP(child.Code, rxWireFlags(t, child.Must), child.VendorID, rxSampleData(t, child, depth+1)))
			}
		}
		return g
	case "Enumerated":
		if len(a.Data.Enum) == 0 {
			t.Fatalf("empty enum %s", a.Name)
		}
		return datatype.Enumerated(a.Data.Enum[len(a.Data.Enum)-1].Code)
	case "OctetString":
		return datatype.OctetString("\x01\x23\x45\x67\x89")
	case "UTF8String":
		return datatype.UTF8String("rx-example")
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
		t.Fatalf("no Rx wire sample for %s (%s)", a.Name, a.Data.TypeName)
		return nil
	}
}

// TS 29.214 V20.0.0 Tables 5.3.0.1 and 5.4.0.1: all Rx-local AVPs and
// recursively copied registry definitions have independent wire identities.
func TestRxAVPWireRoundTrip(t *testing.T) {
	definitions, _ := rxWireSpec(t)
	for _, want := range definitions {
		t.Run(want.Name, func(t *testing.T) {
			a, err := dict.Default.FindAVP(rxWireAppID, want.Code, want.Vendor)
			if err != nil {
				t.Fatal(err)
			}
			if a.Data.TypeName != want.Type {
				t.Fatalf("type %s, want %s", a.Data.TypeName, want.Type)
			}
			data := rxSampleData(t, a, 0)
			m := NewRequest(265, rxWireAppID, dict.Default)
			if _, err := m.NewAVPByName(a.Name, rxWireFlags(t, a.Must), data); err != nil {
				t.Fatal(err)
			}
			assertRefreshWire(t, m, want.Code, rxWireFlags(t, want.Must), want.Vendor, data)
		})
	}
}

func rxCommandMessage(t *testing.T, spec rxWireCommandSpec) *Message {
	t.Helper()
	flags := uint8(0)
	if spec.Proxiable {
		flags |= ProxiableFlag
	}
	if spec.Request {
		flags |= RequestFlag
	}
	m := NewMessage(spec.Code, flags, rxWireAppID, 0x12345678, 0x87654321, dict.Default)
	for _, rule := range spec.Rules {
		if rule.Name == "AVP" {
			continue
		}
		for i := 0; i < rule.Min; i++ {
			a := rxFindAVP(t, rule.Name)
			m.AddAVP(NewAVP(a.Code, rxWireFlags(t, a.Must), a.VendorID, rxSampleData(t, a, 0)))
		}
	}
	return m
}

// TS 29.214 V20.0.0 §§5.6.1–5.6.8: the four Rx command pairs use the
// source CCF's required AVPs, fixed placement, and P bit on actual bytes.
func TestRxCommandWireAndBoundaries(t *testing.T) {
	_, commands := rxWireSpec(t)
	for _, spec := range commands {
		t.Run(spec.Section, func(t *testing.T) {
			m := rxCommandMessage(t, spec)
			if err := m.ValidateOutgoing(); err != nil {
				t.Fatalf("valid command: %v", err)
			}
			wire, err := m.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			got, err := ReadMessage(bytes.NewReader(wire), dict.Default)
			if err != nil || got.DecodeErr != nil {
				t.Fatalf("decode: %v / %v", err, got.DecodeErr)
			}
			if err := got.Validate(); err != nil {
				t.Fatalf("received command: %v", err)
			}
			again, err := got.Serialize()
			if err != nil || !bytes.Equal(wire, again) {
				t.Fatalf("command wire mismatch: %v", err)
			}
			m.Header.CommandFlags ^= ProxiableFlag
			if err := m.Validate(); err == nil || err.ResultCode != InvalidHDRBits {
				t.Fatalf("wrong P bit: %v", err)
			}
			m.Header.CommandFlags ^= ProxiableFlag
			if len(m.AVP) > 1 {
				m.AVP[0], m.AVP[1] = m.AVP[1], m.AVP[0]
				if err := m.Validate(); err == nil || err.ResultCode != AVPNotAllowed {
					t.Fatalf("fixed Session-Id displaced: %v", err)
				}
			}
			for _, rule := range spec.Rules {
				if rule.Name == "AVP" || rule.Min == 0 {
					continue
				}
				m := rxCommandMessage(t, spec)
				a := rxFindAVP(t, rule.Name)
				for i, item := range m.AVP {
					if item.Code == a.Code && item.VendorID == a.VendorID {
						m.AVP = append(m.AVP[:i], m.AVP[i+1:]...)
						break
					}
				}
				wantCode := uint32(MissingAVP)
				if err := m.Validate(); err == nil || err.ResultCode != wantCode {
					t.Errorf("missing %s: %v", rule.Name, err)
				}
			}
			for _, rule := range spec.Rules {
				if rule.Name == "AVP" || rule.Fixed || rule.Max == nil {
					continue
				}
				m := rxCommandMessage(t, spec)
				a := rxFindAVP(t, rule.Name)
				count := 0
				for _, item := range m.AVP {
					if item.Code == a.Code && item.VendorID == a.VendorID {
						count++
					}
				}
				for ; count <= *rule.Max; count++ {
					m.AddAVP(NewAVP(a.Code, rxWireFlags(t, a.Must), a.VendorID, rxSampleData(t, a, 0)))
				}
				if err := m.Validate(); err == nil || err.ResultCode != AVPOccursTooManyTimes {
					t.Errorf("too many %s (max %d): %v", rule.Name, *rule.Max, err)
				}
			}
		})
	}
}
