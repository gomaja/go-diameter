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

type gxWireSpecAVP struct {
	Name, Type, Must string
	Code, Vendor     uint32
}

func gxWireDefinitions(t *testing.T) []gxWireSpecAVP {
	t.Helper()
	b, err := os.ReadFile("dict/testdata/gx_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		AVPs   []gxWireSpecAVP
		Reused []struct {
			Name     string
			Metadata *gxWireSpecAVP
		}
	}
	if err := json.Unmarshal(b, &spec); err != nil {
		t.Fatal(err)
	}
	if len(spec.AVPs) != 130 {
		t.Fatal("incomplete Gx wire fixture")
	}
	type key struct{ code, vendor uint32 }
	seen := map[key]bool{}
	out := append([]gxWireSpecAVP(nil), spec.AVPs...)
	for _, a := range out {
		seen[key{a.Code, a.Vendor}] = true
	}
	for _, r := range spec.Reused {
		if r.Metadata == nil {
			continue
		}
		a := *r.Metadata
		a.Name = r.Name
		if !seen[key{a.Code, a.Vendor}] {
			out = append(out, a)
			seen[key{a.Code, a.Vendor}] = true
		}
	}
	// Add source-pinned descendants before local definitions so their wire
	// expectations remain independent of the XML under test.
	copiedBytes, err := os.ReadFile("dict/testdata/gx_copied_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var copied struct{ AVPs []gxWireSpecAVP }
	if err := json.Unmarshal(copiedBytes, &copied); err != nil {
		t.Fatal(err)
	}
	for _, a := range copied.AVPs {
		if !seen[key{a.Code, a.Vendor}] {
			out = append(out, a)
			seen[key{a.Code, a.Vendor}] = true
		}
	}
	// Exercise every local definition too, including all nested Trace-Data
	// overrides required by TS 29.212 V20.0.0 Table 5.4.0.1 Note 5.
	app, err := dict.Default.App(16777238)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range app.AVP {
		if !seen[key{a.Code, a.VendorID}] {
			out = append(out, gxWireSpecAVP{Name: a.Name, Type: a.Data.TypeName, Must: a.Must, Code: a.Code, Vendor: a.VendorID})
			seen[key{a.Code, a.VendorID}] = true
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Vendor != out[j].Vendor {
			return out[i].Vendor < out[j].Vendor
		}
		return out[i].Code < out[j].Code
	})
	return out
}
func gxWireFlags(must string) uint8 {
	var f uint8
	if strings.Contains(must, "M") {
		f |= avp.Mbit
	}
	if strings.Contains(must, "V") {
		f |= avp.Vbit
	}
	return f
}
func gxSampleData(t *testing.T, a *dict.AVP, depth int) datatype.Type {
	t.Helper()
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
			child, err := dict.Default.FindAVPByName(16777238, r.AVP)
			if err != nil {
				t.Fatal(err)
			}
			count := r.Min
			if count == 0 {
				count = 1
			}
			for i := 0; i < count; i++ {
				g.AVP = append(g.AVP, NewAVP(child.Code, gxWireFlags(child.Must), child.VendorID, gxSampleData(t, child, depth+1)))
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
		return datatype.UTF8String("gx-example")
	case "DiameterIdentity":
		return datatype.DiameterIdentity("pcef.example.net")
	case "DiameterURI":
		return datatype.DiameterURI("aaa://pcef.example.net")
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
		t.Fatalf("no wire sample for %s (%s)", a.Name, a.Data.TypeName)
		return nil
	}
}

// TS 29.212 V20.0.0 Tables 5.3.0.1/5.4.0.1: all 130 Gx AVPs, reused
// definitions with source metadata, and every local nested flag override.
func TestGxAVPWireRoundTrip(t *testing.T) {
	for _, want := range gxWireDefinitions(t) {
		t.Run(want.Name, func(t *testing.T) {
			a, err := dict.Default.FindAVP(16777238, want.Code, want.Vendor)
			if err != nil {
				t.Fatal(err)
			}
			if want.Type != "" && a.Data.TypeName != want.Type {
				t.Fatalf("type %s, want %s", a.Data.TypeName, want.Type)
			}
			data := gxSampleData(t, a, 0)
			m := NewRequest(272, 16777238, dict.Default)
			// Metadata supplies outgoing flags; the expected wire bits come from the
			// independent specification fixture, rather than the created AVP.
			if _, err := m.NewAVPByName(a.Name, gxWireFlags(a.Must), data); err != nil {
				t.Fatal(err)
			}
			assertRefreshWire(t, m, want.Code, gxWireFlags(want.Must), want.Vendor, data)
		})
	}
}
func gxCommandMessage(t *testing.T, code uint32, request bool) *Message {
	t.Helper()
	flags := uint8(ProxiableFlag)
	if request {
		flags |= RequestFlag
	}
	m := NewMessage(code, flags, 16777238, 0x12345678, 0x87654321, dict.Default)
	m.AddAVP(NewAVP(263, avp.Mbit, 0, datatype.UTF8String("gx;123")))
	m.AddAVP(NewAVP(258, avp.Mbit, 0, datatype.Unsigned32(16777238)))
	m.AddAVP(NewAVP(264, avp.Mbit, 0, datatype.DiameterIdentity("pcef.example.net")))
	m.AddAVP(NewAVP(296, avp.Mbit, 0, datatype.DiameterIdentity("example.net")))
	if request {
		m.AddAVP(NewAVP(283, avp.Mbit, 0, datatype.DiameterIdentity("example.net")))
		if code == 258 {
			m.AddAVP(NewAVP(293, avp.Mbit, 0, datatype.DiameterIdentity("pcrf.example.net")))
			m.AddAVP(NewAVP(285, avp.Mbit, 0, datatype.Enumerated(0)))
		}
	}
	if code == 272 {
		m.AddAVP(NewAVP(416, avp.Mbit, 0, datatype.Enumerated(1)))
		m.AddAVP(NewAVP(415, avp.Mbit, 0, datatype.Unsigned32(0)))
	}
	return m
}

// TS 29.212 V20.0.0 §§5.6.2–5.6.5: fixed Session-Id, PXY, and both
// optional answer result alternatives. These bodies are independent of XML.
func TestGxCommandWireRoundTrip(t *testing.T) {
	for _, code := range []uint32{272, 258} {
		for _, request := range []bool{true, false} {
			m := gxCommandMessage(t, code, request)
			if err := m.Validate(); err != nil {
				t.Fatalf("command %d request=%t: %v", code, request, err)
			}
			b, err := m.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			got, err := ReadMessage(bytes.NewReader(b), dict.Default)
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
			if err != nil || !bytes.Equal(b, again) {
				t.Fatalf("command wire mismatch: %v", err)
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
		}
	}
}
func TestGxCommandCardinality(t *testing.T) {
	t.Run("subscription_and_proxy_repeat", func(t *testing.T) {
		m := gxCommandMessage(t, 272, true)
		for _, name := range []string{"Subscription-Id", "Proxy-Info", "Route-Record"} {
			a, err := dict.Default.FindAVPByName(16777238, name)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				m.AddAVP(NewAVP(a.Code, gxWireFlags(a.Must), a.VendorID, gxSampleData(t, a, 0)))
			}
		}
		if err := m.Validate(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("two_gateway_addresses", func(t *testing.T) {
		m := gxCommandMessage(t, 272, true)
		for i := 0; i < 3; i++ {
			m.AddAVP(NewAVP(1050, avp.Vbit, 10415, datatype.Address{Family: 1, Value: []byte{192, 0, 2, byte(i + 1)}}))
			err := m.Validate()
			if i < 2 && err != nil {
				t.Fatal(err)
			}
			if i == 2 && (err == nil || err.ResultCode != AVPOccursTooManyTimes) {
				t.Fatalf("third AN-GW-Address: %v", err)
			}
		}
	})
	t.Run("required_application_id", func(t *testing.T) {
		m := gxCommandMessage(t, 272, false)
		m.AVP = append(m.AVP[:1], m.AVP[2:]...)
		if err := m.Validate(); err == nil || err.ResultCode != MissingAVP {
			t.Fatalf("missing Auth-Application-Id: %v", err)
		}
	})
}

// TS 29.212 V20.0.0 §5.3.36 permits length-only tunnel information.
// Its printed "2 [ Tunnel-Header-Filter ]" means 0..2 occurrences under
// RFC 5234 §§3.7–3.8 (updated by RFC 7405): two optional elements.
func TestGxTunnelFilterCardinality(t *testing.T) {
	for count := 0; count <= 3; count++ {
		m := gxCommandMessage(t, 272, true)
		g := &GroupedAVP{AVP: []*AVP{NewAVP(1037, avp.Vbit, 10415, datatype.Unsigned32(20))}}
		for i := 0; i < count; i++ {
			g.AVP = append(g.AVP, NewAVP(1036, avp.Vbit, 10415, datatype.IPFilterRule("permit out ip from any to any")))
		}
		m.AddAVP(NewAVP(1038, avp.Vbit, 10415, g))
		err := m.Validate()
		if count < 3 && err != nil {
			t.Fatalf("%d filters: %v", count, err)
		}
		if count == 3 && (err == nil || err.ResultCode != AVPOccursTooManyTimes) {
			t.Fatalf("three filters: %v", err)
		}
	}
}
