package diam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/gomaja/go-diameter/diam/dict/sy"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

type syWireRule struct {
	Name    string
	Min     int
	Max     *int
	Fixed   bool
	MustNot string `json:"must_not"`
}
type syWireCommand struct {
	Code               uint32
	Request, Proxiable bool
	Rules              []syWireRule
}
type syWireFixture struct {
	AVPs     []gxWireSpecAVP
	Commands []syWireCommand
}

func syWireSpec(t *testing.T) syWireFixture {
	t.Helper()
	var spec syWireFixture
	b, err := os.ReadFile("dict/testdata/sy_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &spec); err != nil {
		t.Fatal(err)
	}
	var reused syWireFixture
	b, err = os.ReadFile("dict/testdata/sy_reused_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &reused); err != nil {
		t.Fatal(err)
	}
	spec.AVPs = append(spec.AVPs, reused.AVPs...)
	if len(spec.AVPs) != 29 || len(spec.Commands) != 6 {
		t.Fatal("incomplete Sy fixture")
	}
	return spec
}
func sySampleData(t *testing.T, a *dict.AVP, depth int, parsers ...*dict.Parser) datatype.Type {
	testDict := newTestDictionary(sy.Dictionary())
	if len(parsers) > 0 {

		// RFC 6733 §7.5: one unknown AVP is valid Failed-AVP evidence.
		testDict = parsers[0]
	}

	t.Helper()

	if a.Code == avp.FailedAVP && a.VendorID == 0 {
		return &GroupedAVP{AVP: []*AVP{NewAVP(999999, avp.Mbit, 0, datatype.OctetString("unsupported"))}}
	}
	if depth > 8 {
		t.Fatalf("unexpected Sy recursion: %s", a.Name)
	}
	if a.Data.TypeName != "Grouped" {
		return gxSampleData(t, a, depth, testDict)
	}
	g := &GroupedAVP{}
	for _, r := range a.Data.Rule {
		if r.AVP == "AVP" {
			continue
		}
		child, err := testDict.FindAVPByName(16777302, r.AVP)
		if err != nil {
			t.Fatal(err)
		}
		g.AVP = append(g.AVP, NewAVP(child.Code, gxWireFlags(child.Must), child.VendorID, sySampleData(t, child, depth+1, testDict)))
	}
	return g
}
func syWireAVP(t *testing.T, name string, parsers ...*dict.Parser) *AVP {
	var testDict *dict.Parser
	if len(parsers) > 0 {
		testDict = parsers[0]
	} else {
		testDict = newTestDictionary(sy.Dictionary())
	}

	t.Helper()
	a, err := testDict.FindAVPByName(16777302, name)
	if err != nil {
		t.Fatal(err)
	}
	return NewAVP(a.Code, gxWireFlags(a.Must), a.VendorID, sySampleData(t, a, 0, testDict))
}
func syCommandMessage(t *testing.T, c syWireCommand, parsers ...*dict.Parser) *Message {
	var testDict *dict.Parser
	if len(parsers) > 0 {
		testDict = parsers[0]
	} else {
		testDict = newTestDictionary(sy.Dictionary())
	}

	t.Helper()
	flags := uint8(ProxiableFlag)
	if c.Request {
		flags |= RequestFlag
	}
	m := NewMessage(c.Code, flags, 16777302, 0x12345678, 0x87654321, testDict)
	for _, r := range c.Rules {
		for i := 0; i < r.Min; i++ {
			a := syWireAVP(t, r.Name, testDict)
			if r.Name == "Auth-Application-Id" {
				a.Data = datatype.Unsigned32(16777302)
			}
			m.AddAVP(a)
		}
	}
	return m
}
func syRoundTrip(t *testing.T, m *Message, parsers ...*dict.Parser) {
	var testDict *dict.Parser
	if len(parsers) > 0 {
		testDict = parsers[0]
	} else {
		testDict = newTestDictionary(sy.Dictionary())
	}

	t.Helper()
	if err := m.ValidateOutgoing(); err != nil {
		t.Fatal(err)
	}
	b, err := m.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadMessage(bytes.NewReader(b), testDict)
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
		t.Fatalf("wire mismatch: %v", err)
	}
}

// TS 29.219 V19.0.0 Tables 5.3.0.1/5.4; all seven Sy AVPs and the
// 22 source-pinned reused definitions, including every named descendant.
func TestSyAVPWireRoundTrip(t *testing.T) {
	testDict := newTestDictionary(sy.Dictionary())

	for _, want := range syWireSpec(t).AVPs {
		t.Run(want.Name, func(t *testing.T) {
			a, err := testDict.FindAVP(16777302, want.Code, want.Vendor)
			if err != nil {
				t.Fatal(err)
			}
			if a.Data.TypeName != want.Type {
				t.Fatalf("type %s, want %s", a.Data.TypeName, want.Type)
			}
			samples := []datatype.Type{sySampleData(t, a, 0, testDict)}
			for _, e := range a.Data.Enum {
				samples = append(samples, datatype.Enumerated(e.Code))
			}
			if want.Code == 2907 {
				samples = []datatype.Type{datatype.Unsigned32(0), datatype.Unsigned32(1), datatype.Unsigned32(2), datatype.Unsigned32(3)}
			}
			for _, data := range samples {
				m := NewRequest(8388635, 16777302, testDict)
				if _, err := m.NewAVPByName(a.Name, gxWireFlags(a.Must), data); err != nil {
					t.Fatal(err)
				}
				assertRefreshWire(t, m, want.Code, gxWireFlags(want.Must), want.Vendor, data, testDict)
			}
		})
	}
}

// TS 29.219 V19.0.0 §§5.6.2–5.6.7: exercise every required minimum,
// optional singleton, repetition, fixed Session-Id and PXY constraint.
func TestSyCommandWireRoundTrip(t *testing.T) {
	testDict := newTestDictionary(sy.Dictionary())

	for _, c := range syWireSpec(t).Commands {
		t.Run(fmt.Sprintf("%d/%t", c.Code, c.Request), func(t *testing.T) {
			m := syCommandMessage(t, c, testDict)
			syRoundTrip(t, m, testDict)
			m.Header.CommandFlags &^= ProxiableFlag
			if err := m.Validate(); err == nil || err.ResultCode != InvalidHDRBits {
				t.Fatalf("PXY: %v", err)
			}
			m = syCommandMessage(t, c, testDict)
			m.AVP[0], m.AVP[1] = m.AVP[1], m.AVP[0]
			if err := m.Validate(); err == nil || err.ResultCode != AVPNotAllowed {
				t.Fatalf("fixed Session-Id: %v", err)
			}
			for _, r := range c.Rules {
				t.Run(r.Name, func(t *testing.T) {
					m := syCommandMessage(t, c, testDict)
					if r.Name == "AVP" {
						m.AddAVP(NewAVP(999999, 0, 0, datatype.OctetString("extension")))
						syRoundTrip(t, m, testDict)
						return
					}
					if r.Min > 0 {
						a := syWireAVP(t, r.Name, testDict)
						for i, v := range m.AVP {
							if v.Code == a.Code && v.VendorID == a.VendorID {
								m.AVP = append(m.AVP[:i], m.AVP[i+1:]...)
								break
							}
						}
						wantCode := uint32(MissingAVP)
						if err := m.Validate(); err == nil || err.ResultCode != wantCode {
							t.Fatalf("missing %s: %v", r.Name, err)
						}
						m = syCommandMessage(t, c, testDict)
					} else {
						m.AddAVP(syWireAVP(t, r.Name, testDict))
						syRoundTrip(t, m, testDict)
					}
					m.AddAVP(syWireAVP(t, r.Name, testDict))
					if r.Fixed {
						m.AVP[1], m.AVP[len(m.AVP)-1] = m.AVP[len(m.AVP)-1], m.AVP[1]
					}
					if r.Max == nil {
						syRoundTrip(t, m, testDict)
					} else if err := m.Validate(); err == nil || err.ResultCode != AVPOccursTooManyTimes {
						t.Fatalf("duplicate %s: %v", r.Name, err)
					}
				})
			}
		})
	}
}

// RFC 8581 §7.4 and RFC 8583 §§7.1–7.5, with TS 29.219 V19.0.0
// Table 5.4: M is prohibited on all Load members, including extensions.
func TestSyMemberFlags(t *testing.T) {
	testDict := newTestDictionary(sy.Dictionary())

	answer := syWireSpec(t).Commands[1]
	for _, parent := range []uint32{621, 623, 650} {
		for _, code := range []uint32{649, 651, 652, 999999} {
			if parent != 650 && code != 649 {
				continue
			}
			for _, flag := range []uint8{0, avp.Mbit} {
				m := syCommandMessage(t, answer, testDict)
				g := &GroupedAVP{}
				if parent == 623 {
					g.AVP = append(g.AVP, NewAVP(624, 0, 0, datatype.Unsigned64(1)), NewAVP(626, 0, 0, datatype.Enumerated(0)))
				}
				var data datatype.Type = datatype.OctetString("extension")
				switch code {
				case 649:
					data = datatype.DiameterIdentity("source.example")
				case 651:
					data = datatype.Enumerated(1)
				case 652:
					data = datatype.Unsigned64(0x100000001)
				}
				g.AVP = append(g.AVP, NewAVP(code, flag, 0, data))
				m.AddAVP(NewAVP(parent, 0, 0, g))
				err := m.ValidateOutgoing()
				if parent == 650 && flag != 0 {
					if err == nil || err.ResultCode != InvalidAVPBits {
						t.Errorf("Load member %d flags %x: %v", code, flag, err)
					}
				} else if err != nil {
					t.Errorf("parent %d flags %x: %v", parent, flag, err)
				}
			}
		}
	}
}

// TS 29.219 V19.0.0 §5.1.6 overrides Supported-Features flags only in
// the initial SLR; intermediate SLRs retain TS 29.229 V19.1.0 §7.2.1.
func TestSySupportedFeaturesContext(t *testing.T) {
	testDict := newTestDictionary(sy.Dictionary())

	c := syWireSpec(t).Commands[0]
	for _, initial := range []bool{true, false} {
		m := syCommandMessage(t, c, testDict)
		for _, a := range m.AVP {
			if a.Code == 2904 {
				if initial {
					a.Data = datatype.Enumerated(0)
				} else {
					a.Data = datatype.Enumerated(1)
				}
			}
		}
		a := syWireAVP(t, "Supported-Features", testDict)
		if !initial {
			a.Flags |= avp.Mbit
		}
		m.AddAVP(a)
		syRoundTrip(t, m, testDict)
	}
}

// TS 29.219 V19.0.0 §5.1.6 imports TS 29.229 V19.1.0 §7.2.1:
// Supported-Features must never set M in an answer.
func TestSyAnswerFeatureFlags(t *testing.T) {
	testDict := newTestDictionary(sy.Dictionary())

	c := syWireSpec(t).Commands[1]
	for _, bit := range []uint8{0, avp.Mbit} {
		m := syCommandMessage(t, c, testDict)
		a := syWireAVP(t, "Supported-Features", testDict)
		a.Flags |= bit
		m.AddAVP(a)
		if bit == 0 {
			syRoundTrip(t, m, testDict)
			continue
		}
		if err := m.ValidateOutgoing(); err == nil || err.ResultCode != InvalidAVPBits {
			t.Fatalf("SLA Supported-Features M: %v", err)
		}
	}
}
