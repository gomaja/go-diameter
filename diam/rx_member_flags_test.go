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

// RFC 8506 §8.52 ends with [ AVP ], allowing one optional extension.
// A small command isolates that grouped grammar in each effective application.
func TestRxUserEquipmentInfoExtensionWire(t *testing.T) {
	for _, app := range []uint32{4, 16777236, 16777238} {
		for _, count := range []int{1, 2} {
			t.Run(fmt.Sprintf("%d/extensions-%d", app, count), func(t *testing.T) {
				p := dict.New(dict.Rx, dict.Gx)
				xml := fmt.Sprintf(`<diameter><application id="%d" name="Extension-Test">
<command code="70000" name="Extension-Test" short="EXT"><request>
<rule avp="User-Equipment-Info-Extension" required="true" max="1"/>
</request></command>
<avp name="Equipment-Extension" code="70001" must-not="M,V"><data type="OctetString"/></avp>
</application></diameter>`, app)
				if err := p.Load(strings.NewReader(xml)); err != nil {
					t.Fatal(err)
				}
				g := &GroupedAVP{}
				for i := 0; i < count; i++ {
					g.AVP = append(g.AVP, NewAVP(70001, 0, 0, datatype.OctetString("equipment")))
				}
				m := NewMessage(70000, RequestFlag, app, 1, 2, p)
				m.AddAVP(NewAVP(653, 0, 0, g))
				check := func(stage string, err *ValidationError) {
					t.Helper()
					if count == 1 {
						if err != nil {
							t.Errorf("%s: one extension rejected: %v", stage, err)
						}
					} else if err == nil || err.ResultCode != AVPOccursTooManyTimes {
						t.Errorf("%s: two extensions: %v, want AVPOccursTooManyTimes", stage, err)
					}
				}
				check("outgoing", m.ValidateOutgoing())
				wire, err := m.Serialize()
				if err != nil {
					t.Fatal(err)
				}
				received, err := ReadMessage(bytes.NewReader(wire), p)
				if err != nil {
					t.Fatal(err)
				}
				if received.DecodeErr != nil {
					t.Fatal(received.DecodeErr)
				}
				check("received", received.Validate())
				got := received.AVP[0].Data.(*GroupedAVP).AVP
				if len(got) != count {
					t.Fatalf("decoded %d extension AVPs, want %d", len(got), count)
				}
				for _, a := range got {
					if a.Code != 70001 || a.Flags != 0 || a.VendorID != 0 || string(a.Data.(datatype.OctetString)) != "equipment" {
						t.Errorf("decoded extension changed: %v", a)
					}
				}
			})
		}
	}
}

// TS 29.214 V20.0.0 Table 5.4.0.1 clears M in Rx Load. The same SourceID
// remains legal with M inside overload groups, where that restriction is absent.
func TestRxSourceIDMemberScope(t *testing.T) {
	_, commands := rxWireSpec(t)
	var answer rxWireCommandSpec
	for _, c := range commands {
		if c.Code == 265 && !c.Request {
			answer = c
			break
		}
	}
	if answer.Code == 0 {
		t.Fatal("missing AAA fixture")
	}
	for _, parent := range []uint32{621, 623, 650} {
		for _, mBit := range []uint8{0, avp.Mbit} {
			m := rxCommandMessage(t, answer)
			g := &GroupedAVP{}
			if parent == 623 {
				g.AVP = append(g.AVP,
					NewAVP(624, 0, 0, datatype.Unsigned64(1)),
					NewAVP(626, 0, 0, datatype.Enumerated(0)))
			}
			g.AVP = append(g.AVP, NewAVP(649, mBit, 0, datatype.DiameterIdentity("source.example")))
			m.AddAVP(NewAVP(parent, 0, 0, g))
			err := m.ValidateOutgoing()
			if parent == 650 && mBit != 0 {
				if err == nil || err.ResultCode != InvalidAVPBits {
					t.Errorf("Load SourceID M: %v", err)
				}
			} else if err != nil {
				t.Errorf("parent %d SourceID M=%x: %v", parent, mBit, err)
			}
		}
	}
}

// TS 29.214 V20.0.0 Table 5.4.0.1 selects four defined counters while
// retaining RFC 8506 §§8.17/8.19 extensions. Section 5.4.1 allows new
// optional AVPs with M cleared; the defined counters retain their source flags.
func TestRxUsageUnitSubset(t *testing.T) {
	_, commands := rxWireSpec(t)
	var request rxWireCommandSpec
	for _, c := range commands {
		if c.Code == 265 && c.Request {
			request = c
			break
		}
	}
	if request.Code == 0 {
		t.Fatal("missing AAR fixture")
	}
	p := dict.New(dict.Rx)
	if err := p.RegisterAVP(rxWireAppID, &dict.AVP{Name: "Usage-Extension", Code: 70000, VendorID: 10415, Must: "V", Data: dict.Data{TypeName: "Unsigned32"}}); err != nil {
		t.Fatal(err)
	}
	type member struct {
		name   string
		code   uint32
		vendor uint32
		flags  uint8
		valid  bool
	}
	members := []member{
		{"CC-Time", 420, 0, avp.Mbit, true},
		{"CC-Total-Octets", 421, 0, avp.Mbit, true},
		{"CC-Input-Octets", 412, 0, avp.Mbit, true},
		{"CC-Output-Octets", 414, 0, avp.Mbit, true},
		{"Usage-Extension", 70000, 10415, avp.Vbit, true},
	}
	for _, unit := range []struct {
		name string
		code uint32
	}{{"Granted-Service-Unit", 431}, {"Used-Service-Unit", 446}} {
		for _, item := range members {
			t.Run(fmt.Sprintf("%s/%s", unit.name, item.name), func(t *testing.T) {
				definition, err := p.FindAVP(rxWireAppID, item.code, item.vendor)
				if err != nil {
					t.Fatal(err)
				}
				m := rxCommandMessage(t, request)
				m.dictionary = p
				child := NewAVP(item.code, item.flags, item.vendor, rxSampleData(t, definition, 0))
				usage := NewAVP(unit.code, 0, 0, &GroupedAVP{AVP: []*AVP{child}})
				m.AddAVP(NewAVP(530, avp.Vbit, 10415, &GroupedAVP{AVP: []*AVP{usage}}))
				outgoing := m.ValidateOutgoing()
				if item.valid {
					if outgoing != nil {
						t.Fatalf("permitted counter: %v", outgoing)
					}
				} else if outgoing == nil || outgoing.ResultCode != AVPNotAllowed {
					t.Fatalf("excluded counter: %v", outgoing)
				}
				wire, err := m.Serialize()
				if err != nil {
					t.Fatal(err)
				}
				received, err := ReadMessage(bytes.NewReader(wire), p)
				if err != nil || received == nil {
					t.Fatalf("receive: %v", err)
				}
				if received.DecodeErr != nil {
					t.Fatal(received.DecodeErr)
				}
				sponsored, err := received.FindAVP(530, 10415)
				if err != nil {
					t.Fatal(err)
				}
				got := sponsored.Data.(*GroupedAVP).AVP[0].Data.(*GroupedAVP).AVP[0]
				if got.Code != item.code || got.VendorID != item.vendor || got.Flags != item.flags {
					t.Fatalf("received counter code/vendor/flags %d/%d/%x, want %d/%d/%x", got.Code, got.VendorID, got.Flags, item.code, item.vendor, item.flags)
				}
				receiveErr := received.Validate()
				if item.valid {
					if receiveErr != nil {
						t.Fatalf("permitted received counter: %v", receiveErr)
					}
				} else if receiveErr == nil || receiveErr.ResultCode != AVPNotAllowed {
					t.Fatalf("excluded received counter: %v", receiveErr)
				}
			})
		}
	}
}

// TS 29.214 V20.0.0 Table 5.4.0.1 applies the Load restriction to each
// listed child and the extension wildcard, not just SourceID.
func TestRxLoadAllMemberFlags(t *testing.T) {
	for _, child := range []struct {
		code uint32
		data datatype.Type
	}{
		{649, datatype.DiameterIdentity("source.example")},
		{651, datatype.Enumerated(0)},
		{652, datatype.Unsigned64(17)},
		{70000, datatype.Unsigned32(17)},
	} {
		for _, mBit := range []uint8{0, avp.Mbit} {
			p := dict.New(dict.Rx)
			if err := p.RegisterAVP(rxWireAppID, &dict.AVP{Name: "Load-Extension", Code: 70000, Data: dict.Data{TypeName: "Unsigned32"}}); err != nil {
				t.Fatal(err)
			}
			g := NewAVP(650, 0, 0, &GroupedAVP{AVP: []*AVP{NewAVP(child.code, mBit, 0, child.data)}})
			// This isolates the grouped member flag policy from unrelated
			// required command AVPs.
			err := walkOutgoingFlags([]*AVP{g}, rxWireAppID, p.Snapshot(), make(map[*GroupedAVP]bool), nil)
			if mBit != 0 {
				if err == nil || err.ResultCode != InvalidAVPBits {
					t.Errorf("Load child %d with M: %v", child.code, err)
				}
			} else if err != nil {
				t.Errorf("Load child %d without M: %v", child.code, err)
			}
		}
	}
}
