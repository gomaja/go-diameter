package diam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

type rfc5777WireRule struct {
	Name string
	Min  int
	Max  *int
}
type rfc5777WireAVP struct {
	Name, Type, Must string
	Code             uint32
	Items            map[string]string
	Rules            []rfc5777WireRule
}

func rfc5777WireSpec(t *testing.T) ([]rfc5777WireAVP, map[string]rfc5777WireAVP) {
	t.Helper()
	b, err := os.ReadFile("dict/testdata/rfc5777_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct{ AVPs []rfc5777WireAVP }
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.AVPs) != 71 {
		t.Fatalf("fixture has %d AVPs", len(s.AVPs))
	}
	lookup := map[string]rfc5777WireAVP{}
	for _, a := range s.AVPs {
		lookup[a.Name] = a
	}
	// RFC 6733 §5.3.3 and §4.5: the only external named member.
	lookup["Vendor-Id"] = rfc5777WireAVP{Name: "Vendor-Id", Code: 266, Type: "Unsigned32", Must: "M"}
	return s.AVPs, lookup
}

func rfc5777Data(t *testing.T, a rfc5777WireAVP, lookup map[string]rfc5777WireAVP) datatype.Type {
	t.Helper()
	switch a.Type {
	case "Grouped":
		g := &GroupedAVP{}
		for _, r := range a.Rules {
			for i := 0; i < r.Min; i++ {
				g.AVP = append(g.AVP, rfc5777Member(t, r.Name, lookup))
			}
		}
		return g
	case "Enumerated":
		value := int64(0)
		if len(a.Items) > 0 {
			value = 1<<31 - 1
			for s := range a.Items {
				n, err := strconv.ParseInt(s, 10, 32)
				if err != nil {
					t.Fatal(err)
				}
				if n < value {
					value = n
				}
			}
		}
		return datatype.Enumerated(value)
	case "Unsigned32":
		return datatype.Unsigned32(1)
	case "Integer32":
		if a.Code == 571 {
			return datatype.Integer32(-3600)
		}
		return datatype.Integer32(443)
	case "Time":
		return datatype.Time(time.Unix(1700000000, 0))
	case "Address":
		return datatype.Address{Family: 1, Value: []byte{192, 0, 2, 1}}
	case "OctetString":
		switch a.Code {
		case 524, 526:
			return datatype.OctetString("\x00\x10\xa4\x23\x00\x00")
		case 527, 529:
			return datatype.OctetString("\x00\x10\xa4\xff\xfe\x23\x00\x00")
		case 550, 551:
			return datatype.OctetString("\x08\x00")
		default:
			return datatype.OctetString("classifier")
		}
	default:
		t.Fatalf("unsupported source datatype %s", a.Type)
		return nil
	}
}
func rfc5777Member(t *testing.T, name string, lookup map[string]rfc5777WireAVP) *AVP {
	t.Helper()
	a, ok := lookup[name]
	if !ok {
		t.Fatalf("fixture lacks %s", name)
	}
	return NewAVP(a.Code, gxWireFlags(a.Must), 0, rfc5777Data(t, a, lookup))
}

func rfc5777Message(t *testing.T, a *AVP) *Message {
	t.Helper()
	m := creditControlCommandMessage(t, loadCreditControlWireSpec(t).Commands[0])
	m.AddAVP(a)
	return m
}

func rfc5777ValidateWire(t *testing.T, m *Message, want uint32) {
	t.Helper()
	check := func(m *Message) {
		err := m.ValidateOutgoing()
		if want == 0 {
			if err != nil {
				t.Fatal(err)
			}
		} else if err == nil || err.ResultCode != want {
			t.Fatalf("validation %v, want %d", err, want)
		}
	}
	check(m)
	b, err := m.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadMessage(bytes.NewReader(b), dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.DecodeErr != nil {
		t.Fatal(decoded.DecodeErr)
	}
	check(decoded)
	again, err := decoded.Serialize()
	if err != nil || !bytes.Equal(b, again) {
		t.Fatalf("wire round trip differs: %v", err)
	}
}

// RFC 5777 §§3–6, Verified Errata 2333–2336: every AVP and enum value
// is built from the source fixture, encoded and decoded through the product.
func TestRFC5777AVPWireRoundTrip(t *testing.T) {
	specs, lookup := rfc5777WireSpec(t)
	for _, a := range specs {
		t.Run(a.Name, func(t *testing.T) {
			data := rfc5777Data(t, a, lookup)
			for _, flags := range []uint8{0, avp.Mbit} {
				m := rfc5777Message(t, NewAVP(a.Code, flags, 0, data))
				wireMessage := NewRequest(272, 4, dict.Default)
				wireMessage.AddAVP(NewAVP(a.Code, flags, 0, data))
				assertRefreshWire(t, wireMessage, a.Code, flags, 0, data)
				rfc5777ValidateWire(t, m, 0)
			}
			for value := range a.Items {
				n, err := strconv.ParseInt(value, 10, 32)
				if err != nil {
					t.Fatal(err)
				}
				data := datatype.Enumerated(n)
				m := rfc5777Message(t, NewAVP(a.Code, 0, 0, data))
				wireMessage := NewRequest(272, 4, dict.Default)
				wireMessage.AddAVP(NewAVP(a.Code, 0, 0, data))
				assertRefreshWire(t, wireMessage, a.Code, 0, 0, data)
				rfc5777ValidateWire(t, m, 0)
			}
		})
	}
}

// RFC 6733 §3.2/Erratum 4803: braces require a member, square brackets
// permit omission, and * permits repetitions. Wildcards use known non-members
// so deleting an extension point cannot silently pass as an unknown AVP.
func TestRFC5777GroupedMemberBoundaries(t *testing.T) {
	specs, lookup := rfc5777WireSpec(t)
	for _, a := range specs {
		if a.Type != "Grouped" {
			continue
		}
		t.Run(a.Name, func(t *testing.T) {
			for _, rule := range a.Rules {
				t.Run(rule.Name, func(t *testing.T) {
					for count := 0; count <= 2; count++ {
						t.Run(fmt.Sprint(count), func(t *testing.T) {
							g := rfc5777Data(t, a, lookup).(*GroupedAVP)
							// Remove the target's required instances before testing its boundary.
							kept := g.AVP[:0]
							for _, child := range g.AVP {
								if rule.Name == "AVP" || child.Code != lookup[rule.Name].Code {
									kept = append(kept, child)
								}
							}
							g.AVP = kept
							for i := 0; i < count; i++ {
								if rule.Name == "AVP" {
									g.AVP = append(g.AVP, NewAVP(avp.HostIPAddress, avp.Mbit, 0, datatype.Address{Family: 1, Value: []byte{192, 0, 2, 1}}))
								} else {
									g.AVP = append(g.AVP, rfc5777Member(t, rule.Name, lookup))
								}
							}
							want := uint32(0)
							if count < rule.Min {
								want = MissingAVP
							} else if rule.Max != nil && count > *rule.Max {
								want = AVPOccursTooManyTimes
							}
							rfc5777ValidateWire(t, rfc5777Message(t, NewAVP(a.Code, 0, 0, g)), want)
						})
					}
				})
			}
		})
	}
}

// RFC 8506 §8.68 reaches the complete RFC 5777 §3.2 condition/action tree.
func TestRFC5777FinalUnitClosure(t *testing.T) {
	_, lookup := rfc5777WireSpec(t)
	classifier := rfc5777Member(t, "Classifier", lookup)
	rule := NewAVP(509, 0, 0, &GroupedAVP{AVP: []*AVP{classifier, rfc5777Member(t, "Time-Of-Day-Condition", lookup), rfc5777Member(t, "Excess-Treatment", lookup)}})
	final := NewAVP(669, 0, 0, &GroupedAVP{AVP: []*AVP{NewAVP(449, avp.Mbit, 0, datatype.Enumerated(2)), rule}})
	m := creditControlCommandMessage(t, loadCreditControlWireSpec(t).Commands[1])
	m.AddAVP(final)
	rfc5777ValidateWire(t, m, 0)
	classifier.Data.(*GroupedAVP).AVP = nil
	rfc5777ValidateWire(t, m, MissingAVP)
}
