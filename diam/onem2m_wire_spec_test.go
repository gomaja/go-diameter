package diam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

type oneM2MWireAVPSpec struct {
	rxWireAVPSpec
	Rules []rxWireRuleSpec
}

func oneM2MWireSpec(t *testing.T) []oneM2MWireAVPSpec {
	t.Helper()
	b, err := os.ReadFile("dict/testdata/onem2m_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct{ AVPs []oneM2MWireAVPSpec }
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.AVPs) != 23 {
		t.Fatalf("incomplete oneM2M fixture: %d", len(s.AVPs))
	}
	return s.AVPs
}

// oneM2M TS-0004 V5.2.0 Table A.4-1; TS 32.299 V19.0.0 §7.5.
// Source identities and flags must survive serialization in both Ro and Rf.
func TestOneM2MAVPWireRoundTrip(t *testing.T) {
	for _, want := range oneM2MWireSpec(t) {
		for _, app := range []uint32{3, 4} {
			t.Run(fmt.Sprintf("%d/%s", app, want.Name), func(t *testing.T) {
				a, err := dict.Default.FindAVP(app, want.Code, want.Vendor)
				if err != nil {
					t.Fatal(err)
				}
				if a.Data.TypeName != want.Type {
					t.Fatalf("type %s, want %s", a.Data.TypeName, want.Type)
				}
				data := roRfSampleData(t, a, 0)
				code := uint32(271)
				if app == 4 {
					code = 272
				}
				m := NewRequest(code, app, dict.Default)
				if _, err := m.NewAVPByName(a.Name, roRfWireFlags(t, a.Must), data); err != nil {
					t.Fatal(err)
				}
				assertRefreshWire(t, m, want.Code, roRfWireFlags(t, want.Must), want.Vendor, data)
			})
		}
	}
}

func oneM2MACR(t *testing.T, group *GroupedAVP) *Message {
	t.Helper()
	m := NewRequest(271, 3, dict.Default)
	// TS 32.299 V19.0.0 §6.2.2 required ACR prefix.
	for _, name := range []string{"Session-Id", "Origin-Host", "Origin-Realm", "Destination-Realm", "Accounting-Record-Type", "Accounting-Record-Number"} {
		a := roRfFindAVP(t, name)
		data := roRfSampleData(t, a, 0)
		if name == "Accounting-Record-Type" {
			data = datatype.Enumerated(1)
		} // TS-0004 §A.5.3 EVENT_RECORD.
		m.AddAVP(NewAVP(a.Code, roRfWireFlags(t, a.Must), a.VendorID, data))
	}
	m.AddAVP(NewAVP(873, avp.Mbit|avp.Vbit, 10415, &GroupedAVP{AVP: []*AVP{
		NewAVP(1011, avp.Mbit|avp.Vbit, 45687, group),
	}}))
	return m
}

func checkOneM2MACR(t *testing.T, group *GroupedAVP) {
	t.Helper()
	m := oneM2MACR(t, group)
	if err := m.ValidateOutgoing(); err != nil {
		t.Fatalf("ACR with M2M-Information: %v", err)
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
		t.Fatalf("ACR round trip: %v", err)
	}
}

// TS-0004 V5.2.0 §A.5.14: each named member is optional and singleton;
// the trailing *[AVP] admits extensions. TS 32.299 §7.2.192 admits the group.
func TestOneM2MACR(t *testing.T) {
	t.Run("empty", func(t *testing.T) { checkOneM2MACR(t, &GroupedAVP{}) })
	for _, source := range oneM2MWireSpec(t) {
		if source.Code != 1011 {
			continue
		}
		all := &GroupedAVP{}
		for _, r := range source.Rules {
			t.Run(r.Name, func(t *testing.T) {
				name := r.Name
				if name == "AVP" {
					name = "User-Name"
				}
				a := roRfFindAVP(t, name)
				child := NewAVP(a.Code, roRfWireFlags(t, a.Must), a.VendorID, roRfSampleData(t, a, 0))
				checkOneM2MACR(t, &GroupedAVP{AVP: []*AVP{child}})
				pair := &GroupedAVP{AVP: []*AVP{child, child}}
				if r.Name == "AVP" {
					checkOneM2MACR(t, pair)
				} else {
					if err := oneM2MACR(t, pair).ValidateOutgoing(); err == nil {
						t.Fatalf("duplicate singleton %s accepted", name)
					}
					all.AVP = append(all.AVP, child)
				}
			})
		}
		t.Run("all", func(t *testing.T) { checkOneM2MACR(t, all) })
	}
}
