package diam

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// TestMarshalUnmarshalRegisteredGroupedAVP covers the struct helpers with AVPs
// registered at run time: Marshal and Unmarshal resolve `avp` tags by name in
// the message's application, so a registered vendor Grouped AVP must round
// trip, and a vendor-0 AVP sharing its code must not be picked instead.
func TestMarshalUnmarshalRegisteredGroupedAVP(t *testing.T) {
	p := dict.New(dict.Base)
	if err := p.Load(strings.NewReader(`<diameter><application id="16777999" type="auth" name="Registered">
		<vendor id="10415" name="TGPP"/>
	</application></diameter>`)); err != nil {
		t.Fatal(err)
	}
	if err := p.RegisterAVP(16777999,
		&dict.AVP{Name: "Registered-Member", Code: 70103, VendorID: 10415, Must: "V", MustNot: "M", Data: dict.Data{TypeName: "Unsigned32"}},
		&dict.AVP{Name: "Registered-Group", Code: 70102, VendorID: 10415, Must: "V", MustNot: "M", Data: dict.Data{TypeName: "Grouped", Rule: []*dict.Rule{{AVP: "Registered-Member", Max: 1, MaxSet: true}}}},
		&dict.AVP{Name: "Registered-Vendor0", Code: 70102, Must: "M", MustNot: "V", Data: dict.Data{TypeName: "OctetString"}},
	); err != nil {
		t.Fatal(err)
	}
	type group struct {
		Member datatype.Unsigned32 `avp:"Registered-Member"`
	}
	type body struct {
		Group group `avp:"Registered-Group"`
	}

	m := NewRequest(300, 16777999, p)
	if err := m.Marshal(&body{Group: group{Member: 7}}); err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var wire bytes.Buffer
	if _, err := m.WriteTo(&wire); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMessage(&wire, p)
	if err != nil {
		t.Fatal(err)
	}
	if a := got.AVP[0]; a.Code != 70102 || a.VendorID != 10415 {
		t.Fatalf("encoded AVP = %d/%d, want 70102/10415", a.Code, a.VendorID)
	}
	var out body
	if err := got.Unmarshal(&out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.Group.Member != 7 {
		t.Fatalf("round trip = %+v, want member 7", out)
	}
}
