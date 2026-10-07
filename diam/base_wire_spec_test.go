package diam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

func baseWireSpec(t *testing.T) ([]rxWireAVPSpec, []rxWireCommandSpec) {
	t.Helper()
	b, err := os.ReadFile("dict/testdata/base_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		AVPs     []rxWireAVPSpec
		Commands []rxWireCommandSpec
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.AVPs) != 63 || len(s.Commands) != 14 {
		t.Fatal("incomplete base fixture")
	}
	return s.AVPs, s.Commands
}

func baseFindAVP(t *testing.T, name string) *dict.AVP {
	t.Helper()
	a, err := dict.Default.FindAVPByName(0, name)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// RFC 6733 §4.5 and companion tables: every base AVP and enum value,
// including nested Grouped encodings, in both effective application views.
func TestBaseAVPWireRoundTrip(t *testing.T) {
	definitions, _ := baseWireSpec(t)
	for _, app := range []uint32{0, 3} {
		for _, want := range definitions {
			t.Run(fmt.Sprintf("%d/%s", app, want.Name), func(t *testing.T) {
				a, err := dict.Default.FindAVP(app, want.Code, want.Vendor)
				if err != nil {
					t.Fatal(err)
				}
				if a.Data.TypeName != want.Type {
					t.Fatalf("type %s, want %s", a.Data.TypeName, want.Type)
				}
				samples := []datatype.Type{baseSampleData(t, a, 0)}
				for _, e := range a.Data.Enum {
					samples = append(samples, datatype.Enumerated(e.Code))
				}
				for _, data := range samples {
					m := NewRequest(271, app, dict.Default)
					if _, err := m.NewAVPByName(a.Name, rxWireFlags(t, a.Must), data); err != nil {
						t.Fatal(err)
					}
					assertRefreshWire(t, m, want.Code, rxWireFlags(t, want.Must), want.Vendor, data)
				}
			})
		}
	}
}

func baseSampleData(t *testing.T, a *dict.AVP, depth int) datatype.Type {
	t.Helper()
	if depth > 12 {
		t.Fatalf("unexpected grouped recursion at %s", a.Name)
	}
	switch a.Data.TypeName {
	case "Grouped":
		g := &GroupedAVP{}
		if a.Name == "Failed-AVP" {
			g.AVP = []*AVP{NewAVP(1, avp.Mbit, 0, datatype.UTF8String("invalid-user"))}
			return g
		}
		for _, r := range a.Data.Rule {
			if r.AVP == "AVP" || r.MaxSet && r.Max == 0 {
				continue
			}
			if a.Name == "Vendor-Specific-Application-Id" && r.AVP == "Acct-Application-Id" {
				continue
			}
			count := r.Min
			if count == 0 {
				count = 1
			}
			for i := 0; i < count; i++ {
				child := baseFindAVP(t, r.AVP)
				g.AVP = append(g.AVP, NewAVP(child.Code, rxWireFlags(t, child.Must), child.VendorID, baseSampleData(t, child, depth+1)))
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
		t.Fatalf("no base wire sample for %s (%s)", a.Name, a.Data.TypeName)
		return nil
	}
}

func baseCommandMessage(t *testing.T, app uint32, spec rxWireCommandSpec) *Message {
	t.Helper()
	flags := uint8(0)
	if spec.Proxiable {
		flags |= ProxiableFlag
	}
	if spec.Request {
		flags |= RequestFlag
	}
	m := NewMessage(spec.Code, flags, app, 0x12345678, 0x87654321, dict.Default)
	for _, rule := range spec.Rules {
		if rule.Name == "AVP" {
			continue
		}
		for i := 0; i < rule.Min; i++ {
			a := baseFindAVP(t, rule.Name)
			m.AddAVP(NewAVP(a.Code, rxWireFlags(t, a.Must), a.VendorID, baseSampleData(t, a, 0)))
		}
	}
	return m
}

// RFC 6733 command CCF, with Verified Errata 4803 and 4808.
func TestBaseCommandWireAndBoundaries(t *testing.T) {
	_, commands := baseWireSpec(t)
	for _, app := range []uint32{0, 3} {
		for _, spec := range commands {
			t.Run(fmt.Sprintf("%d/%s", app, spec.Section), func(t *testing.T) {
				m := baseCommandMessage(t, app, spec)
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
				if spec.Rules[0].Fixed {
					m.AVP[0], m.AVP[1] = m.AVP[1], m.AVP[0]
					if err := m.Validate(); err == nil || err.ResultCode != AVPNotAllowed {
						t.Fatalf("fixed Session-Id displaced: %v", err)
					}
				}
				for _, rule := range spec.Rules {
					if rule.Name == "AVP" || rule.Min == 0 {
						continue
					}
					m := baseCommandMessage(t, app, spec)
					a := baseFindAVP(t, rule.Name)
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
					m := baseCommandMessage(t, app, spec)
					a := baseFindAVP(t, rule.Name)
					count := 0
					for _, item := range m.AVP {
						if item.Code == a.Code && item.VendorID == a.VendorID {
							count++
						}
					}
					for ; count <= *rule.Max; count++ {
						m.AddAVP(NewAVP(a.Code, rxWireFlags(t, a.Must), a.VendorID, baseSampleData(t, a, 0)))
					}
					if err := m.Validate(); err == nil || err.ResultCode != AVPOccursTooManyTimes {
						t.Errorf("too many %s (max %d): %v", rule.Name, *rule.Max, err)
					}
				}
			})
		}
	}

}

// RFC 6733 §§6.7.2, 7.5 and RFCs 8581 §§7.1–7.2, 8583 §7.1.
// Exercise extension points with understood AVPs, so deleting the wildcard
// cannot pass merely because an unknown optional AVP is ignored.
func TestBaseGroupedExtensions(t *testing.T) {
	for _, name := range []string{"Proxy-Info", "OC-Supported-Features", "OC-OLR", "Load"} {
		t.Run(name, func(t *testing.T) {
			a := baseFindAVP(t, name)
			g := baseSampleData(t, a, 0).(*GroupedAVP)
			for i := 0; i < 2; i++ {
				g.AVP = append(g.AVP, NewAVP(avp.UserName, avp.Mbit, 0, datatype.UTF8String("extension")))
			}
			for _, app := range []uint32{0, 3} {
				if err := validateAVPs(g.AVP, a.Data.Rule, app, dict.Default.Snapshot()); err != nil {
					t.Fatalf("extensions: %v", err)
				}
				m := NewRequest(271, app, dict.Default)
				m.AddAVP(NewAVP(a.Code, rxWireFlags(t, a.Must), 0, g))
				assertRefreshWire(t, m, a.Code, rxWireFlags(t, a.Must), 0, g)
			}
		})
	}
	// Failed-AVP's dictionary shape is pinned even though normal validation
	// deliberately preserves malformed peer evidence under RFC 6733 §7.5.
	a := baseFindAVP(t, "Failed-AVP")

	for _, n := range []int{1, 2, 4} {
		items := make([]*AVP, n)
		for i := range items {
			items[i] = NewAVP(avp.UserName, avp.Mbit, 0, datatype.UTF8String("evidence"))
		}
		if err := validateAVPs(items, a.Data.Rule, 0, dict.Default.Snapshot()); err != nil {
			t.Fatalf("%d evidence AVPs: %v", n, err)
		}
	}
}

// Every command retains the unbounded *[ AVP ] from RFC 6733's CCF.
func TestBaseCommandExtensions(t *testing.T) {
	_, commands := baseWireSpec(t)
	for _, app := range []uint32{0, 3} {
		for _, spec := range commands {
			t.Run(fmt.Sprintf("%d/%d/%t", app, spec.Code, spec.Request), func(t *testing.T) {
				m := baseCommandMessage(t, app, spec)
				for i := 0; i < 2; i++ {
					m.AddAVP(NewAVP(avp.DRMP, 0, 0, datatype.Enumerated(i)))
				}
				if err := m.ValidateOutgoing(); err != nil {
					t.Fatalf("extensions: %v", err)
				}
				wire, err := m.Serialize()
				if err != nil {
					t.Fatal(err)
				}
				got, err := ReadMessage(bytes.NewReader(wire), dict.Default)
				if err != nil {
					t.Fatal(err)
				}
				if err := got.Validate(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
