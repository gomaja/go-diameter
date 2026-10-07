package diam

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// RFC 8581 §7.4 permits M on SourceID; TS 29.212 V20.0.0 Table 5.4.0.1 clears M inside Load.
func TestGxSourceIDContext(t *testing.T) {
	for _, parent := range []uint32{621, 623, 650} {
		for _, mBit := range []uint8{0, avp.Mbit} {
			m := gxCommandMessage(t, 272, false)
			group := &GroupedAVP{}
			if parent == 623 {
				group.AVP = append(group.AVP, NewAVP(624, 0, 0, datatype.Unsigned64(1)), NewAVP(626, 0, 0, datatype.Enumerated(0)))
			}
			group.AVP = append(group.AVP, NewAVP(649, mBit, 0, datatype.DiameterIdentity("source.example")))
			m.AddAVP(NewAVP(parent, 0, 0, group))
			err := m.ValidateOutgoing()
			if parent == 650 && mBit != 0 {
				if err == nil || err.ResultCode != InvalidAVPBits {
					t.Errorf("Load SourceID M: %v", err)
				}
			} else if err != nil {
				t.Errorf("parent %d M=%x: %v", parent, mBit, err)
			}
		}
	}
}
func TestFlagListedRejectsMalformedSet(t *testing.T) {
	for _, list := range []string{"M.V", "MANDATORY", "M,X", "MV?", "M V", "V,M.X"} {
		for _, flag := range []string{"M", "V", "P"} {
			if flagListed(list, flag) {
				t.Errorf("flagListed(%q,%q) accepted malformed set", list, flag)
			}
		}
	}
}

// TS 29.212 V20.0.0 §§5.3.138–139 and CR 1665r2; TS 29.214
// V20.0.0 §5.3.49; RFC 8583 §7.3. Values expose float and 32-bit mistakes.
func TestGxScalarTypesOnWire(t *testing.T) {
	for _, app := range []uint32{16777238, 16777236} {
		for _, code := range []uint32{2852, 2853} {
			for _, value := range []uint32{0, 1, 1000} {
				m := NewRequest(272, app, dict.Default)
				a, err := dict.Default.FindAVP(app, code, 10415)
				if err != nil {
					t.Fatal(err)
				}
				data := datatype.Unsigned32(value)
				m.AddAVP(NewAVP(code, gxWireFlags(a.Must), 10415, data))
				assertRefreshWire(t, m, code, gxWireFlags(a.Must), 10415, data)
			}
		}
		for _, tc := range []struct{ code, vendor uint32 }{{552, 10415}, {652, 0}} {
			m := NewRequest(272, app, dict.Default)
			a, err := dict.Default.FindAVP(app, tc.code, tc.vendor)
			if err != nil {
				t.Fatal(err)
			}
			data := datatype.Unsigned64(0x100000001)
			m.AddAVP(NewAVP(tc.code, gxWireFlags(a.Must), tc.vendor, data))
			assertRefreshWire(t, m, tc.code, gxWireFlags(a.Must), tc.vendor, data)
		}
	}
}

// A child application can shadow an inherited AVP name with another vendor's
// identity. Member restrictions must follow the resolved code/vendor pair.
func TestMemberFlagsUseResolvedIdentity(t *testing.T) {
	p := dict.New(dict.Base)
	if err := p.Load(strings.NewReader(`<diameter><application id="42"><avp name="SourceID" code="70000" vendor-id="777" must="V"><data type="DiameterIdentity"/></avp><avp name="Scope" code="70001" vendor-id="777" must="V"><data type="Grouped"><rule avp="SourceID" must-not="M"/><rule avp="AVP"/></data></avp></application></diameter>`)); err != nil {
		t.Fatal(err)
	}

	for _, foreign := range []bool{false, true} {
		child := NewAVP(649, avp.Mbit, 0, datatype.DiameterIdentity("source.example"))
		if foreign {
			child = NewAVP(70000, avp.Vbit|avp.Mbit, 777, datatype.DiameterIdentity("source.example"))
		}
		a := NewAVP(70001, avp.Vbit, 777, &GroupedAVP{AVP: []*AVP{child}})
		err := walkOutgoingFlags([]*AVP{a}, 42, p.Snapshot(), make(map[*GroupedAVP]bool), nil)
		if foreign {
			if err == nil || err.ResultCode != InvalidAVPBits {
				t.Errorf("scoped vendor identity: %v", err)
			}
		} else if err != nil {
			t.Errorf("unrelated inherited identity restricted: %v", err)
		}
	}
}

func TestMemberFlagsUseSameCodeDifferentVendors(t *testing.T) {
	p := dict.New(dict.Base)
	if err := p.Load(strings.NewReader(`<diameter><application id="42"><avp name="SourceID" code="649" vendor-id="777" must="V"><data type="DiameterIdentity"/></avp><avp name="Scope" code="70001" vendor-id="777" must="V"><data type="Grouped"><rule avp="SourceID" must-not="M"/><rule avp="AVP"/></data></avp></application></diameter>`)); err != nil {
		t.Fatal(err)
	}

	for _, foreign := range []bool{false, true} {
		child := NewAVP(649, avp.Mbit, 0, datatype.DiameterIdentity("source.example"))
		if foreign {
			child = NewAVP(649, avp.Vbit|avp.Mbit, 777, datatype.DiameterIdentity("source.example"))
		}
		a := NewAVP(70001, avp.Vbit, 777, &GroupedAVP{AVP: []*AVP{child}})
		err := walkOutgoingFlags([]*AVP{a}, 42, p.Snapshot(), make(map[*GroupedAVP]bool), nil)
		if foreign {
			if err == nil || err.ResultCode != InvalidAVPBits {
				t.Errorf("scoped vendor identity: %v", err)
			}
		} else if err != nil {
			t.Errorf("unrelated inherited identity restricted: %v", err)
		}
	}
}

// TS 29.212 and TS 29.214 V20.0.0 Table 5.4.0.1 clear M on every
// member of Gx/Rx Load, including extensions. RFC 8583 §7.5 leaves M
// policy to each application.
func TestGxLoadWildcardFlags(t *testing.T) {
	for _, app := range []uint32{16777238, 0, 16777236} {
		for _, code := range []uint32{649, 651, 652, 70000} {
			for _, mBit := range []uint8{0, avp.Mbit} {
				p := dict.New(dict.Gx, dict.Rx)
				if err := p.RegisterAVP(app, &dict.AVP{Name: "Load-Extension", Code: 70000, Data: dict.Data{TypeName: "Unsigned32"}}); err != nil {
					t.Fatal(err)
				}
				m := NewMessage(70000, RequestFlag, app, 1, 2, p)
				if err := p.Load(strings.NewReader(fmt.Sprintf(`<diameter><application id="%d"><command code="70000" name="Load-Test"><request><rule avp="Load"/></request></command></application></diameter>`, app))); err != nil {
					t.Fatal(err)
				}
				var data datatype.Type = datatype.Unsigned32(17)
				switch code {
				case 649:
					data = datatype.DiameterIdentity("source.example")
				case 651:
					data = datatype.Enumerated(0)
				case 652:
					data = datatype.Unsigned64(17)
				}
				m.AddAVP(NewAVP(650, 0, 0, &GroupedAVP{AVP: []*AVP{NewAVP(code, mBit, 0, data)}}))
				outgoing := m.ValidateOutgoing()
				if (app == 16777238 || app == 16777236) && mBit != 0 {
					if outgoing == nil || outgoing.ResultCode != InvalidAVPBits {
						t.Errorf("app %d member %d M: %v", app, code, outgoing)
					}
				} else if outgoing != nil {
					t.Errorf("app %d member %d M=%x: %v", app, code, mBit, outgoing)
				}
				b, err := m.Serialize()
				if err != nil {
					t.Fatal(err)
				}
				received, err := ReadMessage(bytes.NewReader(b), p)
				if err != nil {
					t.Fatal(err)
				}
				if err := received.Validate(); err != nil {
					t.Errorf("received app %d member %d M=%x: %v", app, code, mBit, err)
				}
			}
		}
	}
}

func TestCommandMemberProhibitions(t *testing.T) {
	for _, request := range []bool{false, true} {
		for _, wildcard := range []bool{false, true} {
			for _, bit := range []uint8{0, avp.Mbit, avp.Pbit} {
				p := dict.New()
				rule := `<rule avp="Leaf" must-not="M,P"/>`
				if wildcard {
					rule = `<rule avp="Leaf"/><rule avp="AVP" must-not="M,P"/>`
				}
				src := `<diameter><application id="42"><avp name="Leaf" code="70000"><data type="Unsigned32"/></avp><command code="70000" name="Example"><request>` + rule + `</request><answer>` + rule + `</answer></command></application></diameter>`
				if err := p.Load(strings.NewReader(src)); err != nil {
					t.Fatal(err)
				}
				var flags uint8
				if request {
					flags = RequestFlag
				}
				m := NewMessage(70000, flags, 42, 1, 2, p)
				m.AddAVP(NewAVP(70000, bit, 0, datatype.Unsigned32(17)))
				err := m.ValidateOutgoing()
				if bit == 0 {
					if err != nil {
						t.Error(err)
					}
				} else if err == nil || err.ResultCode != InvalidAVPBits {
					t.Errorf("request=%t wildcard=%t bit=%x: %v", request, wildcard, bit, err)
				}
				if err := m.Validate(); err != nil {
					t.Errorf("receive validation: %v", err)
				}
			}
		}
	}
}
