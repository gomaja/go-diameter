package diam

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

type smsWireRule struct {
	Name    string `json:"name"`
	Min     int    `json:"min"`
	Max     *int   `json:"max"`
	Fixed   bool   `json:"fixed"`
	MustNot string `json:"must_not"`
}

type smsWireDef struct {
	SharedGap *struct{ Rules *[]smsWireRule } `json:"shared_dictionary_gap"`
	Name      string                          `json:"name"`
	Code      uint32                          `json:"code"`
	Vendor    uint32                          `json:"vendor"`
	Type      string                          `json:"type"`
	Must      string                          `json:"must"`
	MustNot   string                          `json:"must_not"`
	Items     map[string]string               `json:"items"`
	Rules     []smsWireRule                   `json:"rules"`
}

type smsWireCommand struct {
	Section     string        `json:"section"`
	Code        uint32        `json:"code"`
	Request     bool          `json:"request"`
	Proxiable   bool          `json:"proxiable"`
	Application uint32        `json:"application"`
	Rules       []smsWireRule `json:"rules"`
}

type smsWireFixture struct {
	Application uint32           `json:"application"`
	Definitions []smsWireDef     `json:"definitions"`
	Commands    []smsWireCommand `json:"commands"`
}

func smsLoadWireFixtures(t testing.TB) []smsWireFixture {
	t.Helper()
	var out []smsWireFixture
	for _, name := range []string{"s6c_spec.json", "sgd_spec.json"} {
		b, err := os.ReadFile("dict/testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		var f smsWireFixture
		if err := json.Unmarshal(b, &f); err != nil {
			t.Fatal(err)
		}
		if len(f.Definitions) == 0 || len(f.Commands) == 0 {
			t.Fatalf("incomplete %s wire fixture", name)
		}
		// Normalize only documented source typography; wire lookups use the
		// established dictionary spelling.
		aliases := map[string]string{"MME-Location Information": "MME-Location-Information", "eNodeB-Id": "eNodeB-ID", "Extended-eNodeB-Id": "Extended-eNodeB-ID"}
		for i := range f.Definitions {
			if name, ok := aliases[f.Definitions[i].Name]; ok {
				f.Definitions[i].Name = name
			}
		}
		out = append(out, f)
	}
	if out[0].Application != 16777312 || out[1].Application != 16777313 || len(out[0].Commands) != 6 || len(out[1].Commands) != 4 {
		t.Fatal("incomplete S6c/SGd command coverage")
	}
	return out
}

func smsWireFlags(must, mustNot string) uint8 {
	var flags uint8
	if strings.Contains(must, "M") {
		flags |= avp.Mbit
	}
	if strings.Contains(must, "V") {
		flags |= avp.Vbit
	}
	if strings.Contains(mustNot, "M") {
		flags &^= avp.Mbit
	}
	if strings.Contains(mustNot, "V") {
		flags &^= avp.Vbit
	}
	return flags
}

func smsDefIndex(t testing.TB, f smsWireFixture) map[string]smsWireDef {
	t.Helper()
	defs := make(map[string]smsWireDef, len(f.Definitions))
	for _, def := range f.Definitions {
		if _, exists := defs[def.Name]; exists {
			t.Fatalf("duplicate definition %s", def.Name)
		}
		defs[def.Name] = def
	}
	return defs
}

func smsSample(t testing.TB, defs map[string]smsWireDef, def smsWireDef, depth int) datatype.Type {
	t.Helper()
	if depth > 16 {
		t.Fatalf("group recursion at %s", def.Name)
	}
	switch def.Type {
	case "Grouped":
		g := &GroupedAVP{}
		for _, rule := range def.Rules {
			if rule.Name == "AVP" || def.Name == "Vendor-Specific-Application-Id" && rule.Name == "Acct-Application-Id" {
				continue
			}
			child, ok := defs[rule.Name]
			if !ok {
				t.Fatalf("no fixture definition for %s child %s", def.Name, rule.Name)
			}
			count := rule.Min
			if count == 0 && (rule.Max == nil || *rule.Max > 0) {
				count = 1
			} // exercise every optional member
			for i := 0; i < count; i++ {
				flags := smsWireFlags(child.Must, child.MustNot+rule.MustNot)
				if def.Name == "Vendor-Specific-Application-Id" && child.Name == "Acct-Application-Id" {
					g.AVP = append(g.AVP, NewAVP(child.Code, smsWireFlags(child.Must, child.MustNot), child.Vendor, smsSample(t, defs, child, 1)))
				}
				g.AVP = append(g.AVP, NewAVP(child.Code, flags, child.Vendor, smsSample(t, defs, child, depth+1)))
			}
		}
		return g
	case "Enumerated":
		// TS 29.338 V19.3.0 §4.5 requires NO_STATE_MAINTAINED.
		if def.Name == "Auth-Session-State" {
			return datatype.Enumerated(1)
		}
		if len(def.Items) == 0 {
			t.Fatalf("empty enum %s", def.Name)
		}
		var codes []int
		for raw := range def.Items {
			var code int
			if _, err := fmt.Sscanf(raw, "%d", &code); err != nil {
				t.Fatal(err)
			}
			codes = append(codes, code)
		}
		sort.Ints(codes)
		return datatype.Enumerated(codes[0])
	case "OctetString":
		return datatype.OctetString("\x01\x23\x45\x67")
	case "UTF8String":
		return datatype.UTF8String("sms.example")
	case "DiameterIdentity":
		return datatype.DiameterIdentity("sms.example.net")
	case "DiameterURI":
		return datatype.DiameterURI("aaa://sms.example.net")
	case "Unsigned32":
		return datatype.Unsigned32(17)
	case "Unsigned64":
		return datatype.Unsigned64(17)
	case "Integer32":
		return datatype.Integer32(17)
	case "Integer64":
		return datatype.Integer64(17)
	case "Time":
		return datatype.Time(time.Unix(1700000000, 0))
	case "Address":
		return datatype.Address{Family: 1, Value: []byte{192, 0, 2, 1}}
	case "IPFilterRule":
		return datatype.IPFilterRule("permit out ip from any to any")
	default:
		t.Fatalf("no sample for %s (%s)", def.Name, def.Type)
		return nil
	}
}

func smsAssertTree(t *testing.T, got, want *AVP) {
	t.Helper()
	if got.Code != want.Code || got.VendorID != want.VendorID || got.Flags != want.Flags || got.Data.Type() != want.Data.Type() {
		t.Fatalf("AVP header/type: got %d/%d/%02x/%v, want %d/%d/%02x/%v", got.Code, got.VendorID, got.Flags, got.Data.Type(), want.Code, want.VendorID, want.Flags, want.Data.Type())
	}
	if !bytes.Equal(got.Data.Serialize(), want.Data.Serialize()) {
		t.Fatalf("AVP %d payload differs", want.Code)
	}
	wg, grouped := want.Data.(*GroupedAVP)
	if !grouped {
		return
	}
	gg, ok := got.Data.(*GroupedAVP)
	if !ok || len(gg.AVP) != len(wg.AVP) {
		t.Fatalf("AVP %d grouped children differ", want.Code)
	}
	for i := range wg.AVP {
		smsAssertTree(t, gg.AVP[i], wg.AVP[i])
	}
}

// TS 29.338 V19.3.0 Tables 5.3.3.1/1 and 6.3.3.1/1, and each Grouped
// AVP clause: exercise every fixture definition and every named group member.
func TestSMSAVPWireSpec(t *testing.T) {
	for _, f := range smsLoadWireFixtures(t) {
		defs := smsDefIndex(t, f)
		for _, def := range f.Definitions {
			t.Run(fmt.Sprintf("%d/%s", f.Application, def.Name), func(t *testing.T) {
				data := smsSample(t, defs, def, 0)
				m := NewRequest(f.Commands[0].Code, f.Application, dict.Default)
				flags := smsWireFlags(def.Must, def.MustNot)
				if _, err := m.NewAVPByName(def.Name, flags, data); err != nil {
					t.Fatal(err)
				}
				wire, err := m.Serialize()
				if err != nil {
					t.Fatal(err)
				}
				if len(wire) < 28 || binary.BigEndian.Uint32(wire[20:24]) != def.Code || wire[24] != flags {
					t.Fatalf("wire AVP header differs for %s", def.Name)
				}
				if def.Vendor != 0 && (len(wire) < 32 || binary.BigEndian.Uint32(wire[28:32]) != def.Vendor) {
					t.Fatalf("wire vendor differs for %s", def.Name)
				}
				got, err := ReadMessage(bytes.NewReader(wire), dict.Default)
				if err != nil {
					t.Fatal(err)
				}
				if got.DecodeErr != nil {
					t.Fatalf("decode %s: %v", def.Name, got.DecodeErr)
				}
				if len(got.AVP) != 1 {
					t.Fatalf("decoded %d AVPs", len(got.AVP))
				}
				want := NewAVP(def.Code, flags, def.Vendor, data)
				smsAssertTree(t, got.AVP[0], want)
				again, err := got.Serialize()
				if err != nil || !bytes.Equal(wire, again) {
					t.Fatalf("wire round trip %s: %v", def.Name, err)
				}
			})
		}
	}
}

func smsCommandSample(t testing.TB, f smsWireFixture, defs map[string]smsWireDef, command smsWireCommand) *Message {
	t.Helper()
	flags := uint8(0)
	if command.Request {
		flags |= RequestFlag
	}
	if command.Proxiable {
		flags |= ProxiableFlag
	}
	m := NewMessage(command.Code, flags, command.Application, 0x12345678, 0x87654321, dict.Default)
	for _, rule := range command.Rules {
		if rule.Name == "AVP" {
			continue
		}
		def, ok := defs[rule.Name]
		if !ok {
			t.Fatalf("no fixture definition for command member %s", rule.Name)
		}
		for i := 0; i < rule.Min; i++ {
			if _, err := m.NewAVPByName(def.Name, smsWireFlags(def.Must, def.MustNot+rule.MustNot), smsSample(t, defs, def, 0)); err != nil {
				t.Fatal(err)
			}
		}
	}
	return m
}

// TS 29.338 V19.3.0 §§5.3.2.3–5.3.2.8 and 6.3.2.3–6.3.2.6:
// ten exact CCFs, fixed Session-Id, PXY, mandatory members, and singleton bounds.
func TestSMSCommandWireSpec(t *testing.T) {
	for _, f := range smsLoadWireFixtures(t) {
		defs := smsDefIndex(t, f)
		for _, command := range f.Commands {
			t.Run(command.Section, func(t *testing.T) {
				m := smsCommandSample(t, f, defs, command)
				if len(command.Rules) == 0 || command.Rules[0].Name != "Session-Id" || !command.Rules[0].Fixed {
					t.Fatal("missing fixed Session-Id fixture rule")
				}
				if err := m.Validate(); err != nil {
					t.Fatalf("valid command: %v", err)
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
					t.Fatalf("command decode: %v", got.DecodeErr)
				}
				if err := got.Validate(); err != nil {
					t.Fatalf("decoded command: %v", err)
				}
				again, err := got.Serialize()
				if err != nil || !bytes.Equal(wire, again) {
					t.Fatalf("command round trip: %v", err)
				}
				m.Header.CommandFlags &^= ProxiableFlag
				if err := m.Validate(); err == nil {
					t.Fatal("missing PXY accepted")
				}
				m.Header.CommandFlags |= ProxiableFlag
				if len(m.AVP) > 1 {
					m.AVP[0], m.AVP[1] = m.AVP[1], m.AVP[0]
					if err := m.Validate(); err == nil {
						t.Fatal("misplaced fixed Session-Id accepted")
					}
				}
				for _, rule := range command.Rules {
					if rule.Name == "AVP" {
						continue
					}
					def := defs[rule.Name]
					if rule.Min > 0 {
						missing := smsCommandSample(t, f, defs, command)
						for i, a := range missing.AVP {
							if a.Code == def.Code && a.VendorID == def.Vendor {
								missing.AVP = append(missing.AVP[:i], missing.AVP[i+1:]...)
								break
							}
						}
						if err := missing.Validate(); err == nil {
							t.Errorf("missing required %s accepted", rule.Name)
						}
					}
					if rule.Max != nil && *rule.Max == 1 {
						tooMany := smsCommandSample(t, f, defs, command)
						for i := 0; i < 2-rule.Min; i++ {
							tooMany.AddAVP(NewAVP(def.Code, smsWireFlags(def.Must, def.MustNot+rule.MustNot), def.Vendor, smsSample(t, defs, def, 0)))
						}
						if err := tooMany.Validate(); err == nil {
							t.Errorf("duplicate singleton %s accepted", rule.Name)
						}
					}
				}
			})
		}
	}
}

// TS 29.338 V19.3.0 §§5.3.3.6–5.3.3.7, 5.3.3.14–5.3.3.18,
// 5.3.3.27–5.3.3.28, 5.3.3.35–5.3.3.36, 6.3.3.5, 6.3.3.13:
// each printed *[AVP] is an extension point; groups without it are closed.
func TestSMSGroupedGrammarBoundaries(t *testing.T) {
	for _, f := range smsLoadWireFixtures(t) {
		defs := smsDefIndex(t, f)
		for _, def := range f.Definitions {
			if def.Type != "Grouped" || def.Name == "Failed-AVP" {
				continue
			}
			t.Run(fmt.Sprintf("%d/%s", f.Application, def.Name), func(t *testing.T) {
				// Pin acknowledged shared grammar gaps without attributing their
				// incomplete behavior to the normative fixture.
				if def.SharedGap != nil && def.SharedGap.Rules != nil {
					def.Rules = *def.SharedGap.Rules
				}
				var wildcard bool
				for _, rule := range def.Rules {
					if rule.Name == "AVP" {
						wildcard = true
					}
				}
				base := NewRequest(f.Commands[0].Code, f.Application, dict.Default)
				group := smsSample(t, defs, def, 0).(*GroupedAVP)
				group.AVP = append(group.AVP, NewAVP(263, avp.Mbit, 0, datatype.UTF8String("extension")))
				base.AddAVP(NewAVP(def.Code, smsWireFlags(def.Must, def.MustNot), def.Vendor, group))
				err := validateAVPs(base.AVP, []*dict.Rule{{AVP: "AVP"}}, f.Application, dict.Default.Snapshot())
				if wildcard && err != nil {
					t.Fatalf("allowed group extension rejected: %v", err)
				}
				if !wildcard && err == nil {
					t.Fatal("closed group accepted unknown child")
				}
				for _, rule := range def.Rules {
					if rule.Name == "AVP" || rule.Max == nil || *rule.Max != 1 {
						continue
					}
					child := defs[rule.Name]
					m := NewRequest(f.Commands[0].Code, f.Application, dict.Default)
					g := smsSample(t, defs, def, 0).(*GroupedAVP)
					if def.Name == "Vendor-Specific-Application-Id" && child.Name == "Acct-Application-Id" {
						g.AVP = append(g.AVP, NewAVP(child.Code, smsWireFlags(child.Must, child.MustNot), child.Vendor, smsSample(t, defs, child, 1)))
					}
					g.AVP = append(g.AVP, NewAVP(child.Code, smsWireFlags(child.Must, child.MustNot+rule.MustNot), child.Vendor, smsSample(t, defs, child, 1)))
					m.AddAVP(NewAVP(def.Code, smsWireFlags(def.Must, def.MustNot), def.Vendor, g))
					if err := validateAVPs(m.AVP, []*dict.Rule{{AVP: "AVP"}}, f.Application, dict.Default.Snapshot()); err == nil {
						t.Errorf("duplicate group member %s accepted", rule.Name)
					}
				}
			})
		}
	}
}

// TS 29.338 V19.3.0: seed decoding with every specific/reused definition
// and all ten command bodies, including the recursive location grammars.
func FuzzSMSDictionaryMessages(f *testing.F) {
	for _, fixture := range smsLoadWireFixtures(f) {
		defs := smsDefIndex(f, fixture)
		var messages []*Message
		for _, def := range fixture.Definitions {
			m := NewRequest(fixture.Commands[0].Code, fixture.Application, dict.Default)
			if _, err := m.NewAVPByName(def.Name, smsWireFlags(def.Must, def.MustNot), smsSample(f, defs, def, 0)); err != nil {
				f.Fatal(err)
			}
			messages = append(messages, m)
		}
		for _, command := range fixture.Commands {
			messages = append(messages, smsCommandSample(f, fixture, defs, command))
		}
		for _, m := range messages {
			wire, err := m.Serialize()
			if err != nil {
				f.Fatal(err)
			}
			f.Add(wire)
		}
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		m, err := ReadMessage(bytes.NewReader(wire), dict.Default)
		if err != nil || m.DecodeErr != nil {
			return
		}
		_ = m.Validate()
		encoded, err := m.Serialize()
		if err != nil {
			return
		}
		again, err := ReadMessage(bytes.NewReader(encoded), dict.Default)
		if err != nil {
			t.Fatal(err)
		}
		if again.DecodeErr != nil {
			t.Fatal(again.DecodeErr)
		}
	})
}
