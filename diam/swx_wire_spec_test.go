package diam

import (
	"bytes"
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

const swxWireAppID = 16777265

type swxWireAVPSpec struct {
	Name, Type, Must string
	Code, Vendor     uint32
	Rules            []swxWireRuleSpec
	Items            map[string]string
}

type swxWireRuleSpec struct {
	Name    string `json:"name"`
	Min     int    `json:"min"`
	Max     *int   `json:"max"`
	Fixed   bool   `json:"fixed"`
	MustNot string `json:"must_not"`
}

type swxWireCommandSpec struct {
	Section            string
	Code               uint32
	Request, Proxiable bool
	Rules              []swxWireRuleSpec
}

func swxWireSpec(t *testing.T) ([]swxWireAVPSpec, []swxWireCommandSpec) {
	t.Helper()
	b, err := os.ReadFile("dict/testdata/swx_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		AVPs     []swxWireAVPSpec
		Commands []swxWireCommandSpec
		Reused   []struct {
			Name     string
			Metadata *swxWireAVPSpec
		}
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.AVPs) != 16 || len(s.Commands) != 8 || len(s.Reused) != 43 {
		t.Fatalf("incomplete SWx wire fixture: %d AVPs, %d commands, %d reused", len(s.AVPs), len(s.Commands), len(s.Reused))
	}
	b, err = os.ReadFile("dict/testdata/swx_copied_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var copied struct{ AVPs []swxWireAVPSpec }
	if err := json.Unmarshal(b, &copied); err != nil {
		t.Fatal(err)
	}
	if len(copied.AVPs) == 0 {
		t.Fatal("empty SWx copied fixture")
	}
	type key struct{ code, vendor uint32 }
	seen := map[key]int{}
	var out []swxWireAVPSpec
	all := append(s.AVPs, copied.AVPs...)
	for _, reused := range s.Reused {
		if reused.Metadata == nil {
			for _, candidate := range copied.AVPs {
				if swxWireName(candidate.Name) == swxWireName(reused.Name) {
					value := candidate
					reused.Metadata = &value
					break
				}
			}
			if reused.Metadata == nil {
				t.Fatalf("reused AVP %s lacks wire metadata", reused.Name)
			}
		}
		a := *reused.Metadata
		a.Name = reused.Name
		all = append(all, a)
	}
	for _, a := range all {
		k := key{a.Code, a.Vendor}
		if index, ok := seen[k]; ok {
			if out[index].Rules == nil && a.Rules != nil {
				out[index].Rules = a.Rules
			}
			if out[index].Items == nil && a.Items != nil {
				out[index].Items = a.Items
			}
		} else {
			seen[k] = len(out)
			out = append(out, a)
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

func swxWireFlags(t *testing.T, must string) uint8 {
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

func swxFindAVP(t *testing.T, name string) *dict.AVP {
	t.Helper()
	a, err := dict.Default.FindAVPByName(swxWireAppID, name)
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
				if a, err = dict.Default.FindAVPByName(swxWireAppID, candidate.Name); err == nil {
					return a
				}
			}
		}
	}
	t.Fatalf("SWx AVP %s: %v", name, err)
	return nil
}

func swxSampleData(t *testing.T, a *dict.AVP, depth int) datatype.Type {
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
			if a.Name == "Vendor-Specific-Application-Id" && r.AVP == "Acct-Application-Id" {
				continue
			}
			count := r.Min
			if count == 0 {
				count = 1
			}
			for i := 0; i < count; i++ {
				child := swxFindAVP(t, r.AVP)
				g.AVP = append(g.AVP, NewAVP(child.Code, swxWireFlags(t, child.Must)&^swxWireFlags(t, r.MustNot), child.VendorID, swxSampleData(t, child, depth+1)))
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
		return datatype.UTF8String("swx-example")
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
		t.Fatalf("no SWx wire sample for %s (%s)", a.Name, a.Data.TypeName)
		return nil
	}
}

// TS 29.273 V19.2.0 Tables 8.2.3.0/1 and 8.2.3.0/2: all SWx-local AVPs and
// recursively copied registry definitions have independent wire identities.
func TestSWxAVPWireRoundTrip(t *testing.T) {
	definitions, _ := swxWireSpec(t)
	for _, want := range definitions {
		t.Run(want.Name, func(t *testing.T) {
			a, err := dict.Default.FindAVP(swxWireAppID, want.Code, want.Vendor)
			if err != nil {
				t.Fatal(err)
			}
			if a.Data.TypeName != want.Type {
				t.Fatalf("type %s, want %s", a.Data.TypeName, want.Type)
			}
			data := swxSampleData(t, a, 0)
			m := NewRequest(303, swxWireAppID, dict.Default)
			if _, err := m.NewAVPByName(a.Name, swxWireFlags(t, a.Must), data); err != nil {
				t.Fatal(err)
			}
			assertRefreshWire(t, m, want.Code, swxWireFlags(t, want.Must), want.Vendor, data)
			wire, err := m.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			received, err := ReadMessage(bytes.NewReader(wire), dict.Default)
			if err != nil {
				t.Fatal(err)
			}
			if received.DecodeErr != nil {
				t.Fatal(received.DecodeErr)
			}
			swxAssertMemberWire(t, received.AVP[0], want, definitions, 0)
		})
	}
}

func swxCommandMessage(t *testing.T, spec swxWireCommandSpec) *Message {
	t.Helper()
	flags := uint8(0)
	if spec.Proxiable {
		flags |= ProxiableFlag
	}
	if spec.Request {
		flags |= RequestFlag
	}
	m := NewMessage(spec.Code, flags, swxWireAppID, 0x12345678, 0x87654321, dict.Default)
	for _, rule := range spec.Rules {
		if rule.Name == "AVP" {
			continue
		}
		for i := 0; i < rule.Min; i++ {
			a := swxFindAVP(t, rule.Name)
			m.AddAVP(NewAVP(a.Code, swxWireFlags(t, a.Must)&^swxWireFlags(t, rule.MustNot), a.VendorID, swxSampleData(t, a, 0)))
		}
	}
	return m
}

// TS 29.273 V19.2.0 §§8.2.2.1–8.2.2.4: the four SWx command pairs use the
// source CCF's required AVPs, fixed placement, and P bit on actual bytes.
func TestSWxCommandWireAndBoundaries(t *testing.T) {
	_, commands := swxWireSpec(t)
	for _, spec := range commands {
		t.Run(fmt.Sprintf("%s/request=%t", spec.Section, spec.Request), func(t *testing.T) {
			m := swxCommandMessage(t, spec)
			if err := m.ValidateOutgoing(); err != nil {
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
				t.Fatal(got.DecodeErr)
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
				m := swxCommandMessage(t, spec)
				a := swxFindAVP(t, rule.Name)
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
				m := swxCommandMessage(t, spec)
				a := swxFindAVP(t, rule.Name)
				count := 0
				for _, item := range m.AVP {
					if item.Code == a.Code && item.VendorID == a.VendorID {
						count++
					}
				}
				for ; count < *rule.Max; count++ {
					m.AddAVP(NewAVP(a.Code, swxWireFlags(t, a.Must)&^swxWireFlags(t, rule.MustNot), a.VendorID, swxSampleData(t, a, 0)))
				}
				if err := m.ValidateOutgoing(); err != nil {
					t.Fatalf("%s at maximum %d: %v", rule.Name, *rule.Max, err)
				}
				for ; count <= *rule.Max; count++ {
					m.AddAVP(NewAVP(a.Code, swxWireFlags(t, a.Must)&^swxWireFlags(t, rule.MustNot), a.VendorID, swxSampleData(t, a, 0)))
				}
				if err := m.Validate(); err == nil || err.ResultCode != AVPOccursTooManyTimes {
					t.Errorf("too many %s (max %d): %v", rule.Name, *rule.Max, err)
				}
			}
		})
	}
}

// Every grouped descendant is compared with the independent source fixtures;
// member prohibitions apply only within the parent whose grammar lists them.
func swxAssertMemberWire(t *testing.T, got *AVP, want swxWireAVPSpec, definitions []swxWireAVPSpec, forbidden uint8) {
	t.Helper()
	if flags := swxWireFlags(t, want.Must) &^ forbidden; got.Flags != flags {
		t.Errorf("%s flags = %#x, want %#x", want.Name, got.Flags, flags)
	}
	group, ok := got.Data.(*GroupedAVP)
	if !ok {
		return
	}
	if len(want.Rules) == 0 {
		t.Fatalf("grouped %s lacks source grammar", want.Name)
	}
	for _, child := range group.AVP {
		var expected *swxWireAVPSpec
		for i := range definitions {
			if definitions[i].Code == child.Code && definitions[i].Vendor == child.VendorID {
				expected = &definitions[i]
				break
			}
		}
		if expected == nil {
			t.Fatalf("%s child %d/%d lacks independent wire metadata", want.Name, child.Code, child.VendorID)
		}
		var scoped uint8
		for _, rule := range want.Rules {
			if rule.Name == "AVP" || swxWireName(rule.Name) == swxWireName(expected.Name) {
				scoped |= swxWireFlags(t, rule.MustNot)
			}
		}
		swxAssertMemberWire(t, child, *expected, definitions, scoped)
	}
}

func swxWireName(name string) string {
	return strings.NewReplacer("3GPP", "TGPP", "-", "", "_", "", " ", "").Replace(strings.ToUpper(name))
}

// TS 29.273 V19.2.0 §8.2.3 and the source clauses recorded in the
// copied fixture govern required, optional, repeated, and extension members.
func TestSWxGroupedBoundaries(t *testing.T) {
	definitions, _ := swxWireSpec(t)
	for _, spec := range definitions {
		if spec.Type != "Grouped" {
			continue
		}
		t.Run(spec.Name, func(t *testing.T) {
			definition, err := dict.Default.FindAVP(swxWireAppID, spec.Code, spec.Vendor)
			if err != nil {
				t.Fatal(err)
			}
			check := func(items []*AVP) *ValidationError {
				return validateAVPs(items, definition.Data.Rule, swxWireAppID, dict.Default.Snapshot())
			}
			fresh := func() []*AVP {
				return swxSampleData(t, definition, 0).(*GroupedAVP).AVP
			}
			if err := check(fresh()); err != nil {
				t.Fatalf("valid group: %v", err)
			}
			for _, rule := range spec.Rules {
				if rule.Name == "AVP" {
					// A known, unlisted AVP distinguishes a retained extension point
					// from permissive unknown-AVP handling in RFC 6733 §4.1.
					items := fresh()
					for i := 0; i < 2; i++ {
						items = append(items, NewAVP(263, avp.Mbit, 0, datatype.UTF8String("extension")))
					}
					if rule.Max == nil {
						if err := check(items); err != nil {
							t.Errorf("extension point: %v", err)
						}
					}
					continue
				}
				child := swxFindAVP(t, rule.Name)
				withCount := func(count int) []*AVP {
					var items []*AVP
					inserted := false
					insert := func() {
						for i := 0; i < count; i++ {
							items = append(items, NewAVP(child.Code, swxWireFlags(t, child.Must)&^swxWireFlags(t, rule.MustNot), child.VendorID, swxSampleData(t, child, 0)))
						}
						inserted = true
					}
					for _, item := range fresh() {
						if item.Code == child.Code && item.VendorID == child.VendorID {
							if !inserted {
								insert()
							}
						} else {
							items = append(items, item)
						}
					}
					if !inserted {
						insert()
					}
					return items
				}
				if rule.Min > 0 {
					want := uint32(MissingAVP)
					if err := check(withCount(rule.Min - 1)); err == nil || err.ResultCode != want {
						t.Errorf("missing %s: %v", rule.Name, err)
					}
				} else {
					if err := check(withCount(0)); err != nil {
						t.Errorf("optional %s absent: %v", rule.Name, err)
					}
				}
				if rule.Max != nil {
					if err := check(withCount(*rule.Max)); err != nil {
						t.Errorf("%s at maximum %d: %v", rule.Name, *rule.Max, err)
					}
					want := uint32(AVPOccursTooManyTimes)
					if *rule.Max == 0 {
						want = AVPNotAllowed
					}
					if err := check(withCount(*rule.Max + 1)); err == nil || err.ResultCode != want {
						t.Errorf("too many %s: %v", rule.Name, err)
					}
				} else {
					if err := check(withCount(rule.Min + 2)); err != nil {
						t.Errorf("repeated %s: %v", rule.Name, err)
					}
				}
			}
		})
	}
}

// Sender-only parent restrictions must reject each prohibited member flag,
// while the permitted form remains valid under the effective SWx dictionary.
func TestSWxScopedMemberFlags(t *testing.T) {
	_, commands := swxWireSpec(t)
	for _, command := range commands {
		for _, rule := range command.Rules {
			if rule.MustNot == "" || rule.Name == "AVP" {
				continue
			}
			for _, bit := range []uint8{avp.Mbit, avp.Pbit} {
				if swxWireFlags(t, rule.MustNot)&bit == 0 {
					continue
				}
				m := swxCommandMessage(t, command)
				definition := swxFindAVP(t, rule.Name)
				child := NewAVP(definition.Code, swxWireFlags(t, definition.Must)&^swxWireFlags(t, rule.MustNot), definition.VendorID, swxSampleData(t, definition, 0))
				m.AddAVP(child)
				if err := m.ValidateOutgoing(); err != nil {
					t.Fatalf("%s permitted %s: %v", command.Section, rule.Name, err)
				}
				child.Flags |= bit
				if err := m.ValidateOutgoing(); err == nil || err.ResultCode != InvalidAVPBits {
					t.Errorf("%s prohibited %s flag %#x: %v", command.Section, rule.Name, bit, err)
				}
			}
		}
	}
}

// TS 29.229 V19.1.0 §7.2.1 requires Supported-Features to clear M in
// answers; TS 29.273 V19.2.0 Table 8.2.3.0/2 reuses that definition.
func TestSWxSupportedFeaturesFlagScope(t *testing.T) {
	_, commands := swxWireSpec(t)
	for _, command := range commands {
		for _, rule := range command.Rules {
			if rule.Name != "Supported-Features" {
				continue
			}
			for _, bit := range []uint8{0, avp.Mbit} {
				m := swxCommandMessage(t, command)
				definition := swxFindAVP(t, rule.Name)
				m.AddAVP(NewAVP(definition.Code, swxWireFlags(t, definition.Must)|bit, definition.VendorID, swxSampleData(t, definition, 0)))
				err := m.ValidateOutgoing()
				if !command.Request && bit != 0 {
					if err == nil || err.ResultCode != InvalidAVPBits {
						t.Errorf("answer %d with M: %v", command.Code, err)
					}
				} else if err != nil {
					t.Errorf("command %d request=%t M=%#x: %v", command.Code, command.Request, bit, err)
				}
				wire, wireErr := m.Serialize()
				if wireErr != nil {
					t.Fatal(wireErr)
				}
				received, readErr := ReadMessage(bytes.NewReader(wire), dict.Default)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if received.DecodeErr != nil {
					t.Fatal(received.DecodeErr)
				}
				got, findErr := received.FindAVP(628, 10415)
				if findErr != nil {
					t.Fatal(findErr)
				}
				if got.Flags != avp.Vbit|bit {
					t.Fatalf("command %d request=%t Supported-Features wire flags %#x, want %#x", command.Code, command.Request, got.Flags, avp.Vbit|bit)
				}
				decodedErr := received.ValidateOutgoing()
				if !command.Request && bit != 0 {
					if decodedErr == nil || decodedErr.ResultCode != InvalidAVPBits {
						t.Errorf("decoded answer %d with M: %v", command.Code, decodedErr)
					}
				} else {
					if decodedErr != nil {
						t.Errorf("decoded command %d request=%t M=%#x: %v", command.Code, command.Request, bit, decodedErr)
					}
					if err := received.Validate(); err != nil {
						t.Errorf("received permitted command: %v", err)
					}
				}
				again, serializeErr := received.Serialize()
				if serializeErr != nil || !bytes.Equal(wire, again) {
					t.Fatalf("Supported-Features wire round trip differs: %v", serializeErr)
				}

			}
		}
	}
}

// TS 29.336 V20.0.0 Table 8.4.1-1 and §8.4.5 require M,V on SCEF-ID.
// TS 29.273 V19.2.0 Table 8.2.3.0/2 does not import S6a's M-bit override.
func TestSWxSCEFIDSAAOutgoing(t *testing.T) {
	_, commands := swxWireSpec(t)
	var saa swxWireCommandSpec
	for _, command := range commands {
		if command.Code == 301 && !command.Request {
			saa = command
		}
	}
	if saa.Code == 0 {
		t.Fatal("missing SAA fixture")
	}
	for _, tc := range []struct {
		name  string
		flags uint8
		valid bool
	}{
		{"mandatory", avp.Mbit | avp.Vbit, true},
		{"missing_M", avp.Vbit, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := swxCommandMessage(t, saa)
			scef := NewAVP(avp.SCEFID, tc.flags, 10415, datatype.DiameterIdentity("scef.example.net"))
			apn := NewAVP(avp.APNConfiguration, avp.Mbit|avp.Vbit, 10415, &GroupedAVP{AVP: []*AVP{
				NewAVP(avp.ContextIdentifier, avp.Mbit|avp.Vbit, 10415, datatype.Unsigned32(1)),
				NewAVP(avp.PDNType, avp.Mbit|avp.Vbit, 10415, datatype.Enumerated(0)),
				NewAVP(avp.ServiceSelection, avp.Mbit, 0, datatype.UTF8String("internet")),
				scef,
			}})
			m.AddAVP(NewAVP(avp.Non3GPPUserData, avp.Mbit|avp.Vbit, 10415, &GroupedAVP{AVP: []*AVP{apn}}))
			check := func(message *Message) {
				t.Helper()
				err := message.ValidateOutgoing()
				if tc.valid && err != nil {
					t.Errorf("SAA with SCEF-ID M,V: %v", err)
				}
				if !tc.valid && (err == nil || err.ResultCode != InvalidAVPBits) {
					t.Errorf("SAA with V-only SCEF-ID: %v, want InvalidAVPBits", err)
				}
			}
			check(m)
			wire, err := m.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			received, err := ReadMessage(bytes.NewReader(wire), dict.Default)
			if err != nil {
				t.Fatal(err)
			}
			if received.DecodeErr != nil {
				t.Fatal(received.DecodeErr)
			}
			profile := received.AVP[len(received.AVP)-1].Data.(*GroupedAVP)
			configuration := profile.AVP[0].Data.(*GroupedAVP)
			got := configuration.AVP[len(configuration.AVP)-1]
			if got.Code != 3125 || got.VendorID != 10415 || got.Flags != tc.flags {
				t.Fatalf("decoded SCEF-ID = %d/%d/%#x", got.Code, got.VendorID, got.Flags)
			}
			check(received)
		})
	}
}
