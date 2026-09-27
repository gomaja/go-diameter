package diam

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

func TestReadMessageUnknownMandatoryAVPs(t *testing.T) {
	unknown := NewAVP(0xfedc, avp.Mbit|avp.Vbit, 10415, datatype.OctetString("bad"))
	optional := NewAVP(0xfedd, avp.Vbit, 10415, datatype.OctetString("okay"))
	group := NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &GroupedAVP{AVP: []*AVP{optional, unknown}})
	m := NewRequest(ReAuth, 0, dict.Default)
	m.AddAVP(optional)
	m.AddAVP(unknown)
	m.AddAVP(group)
	var wire bytes.Buffer
	if _, err := m.WriteTo(&wire); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadMessage(&wire, dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	if got := decoded.UnknownMandatoryAVPs(); len(got) != 2 {
		t.Fatalf("unknown mandatory roots = %d, want 2", len(got))
	} else {
		if got[0].Code != unknown.Code || got[0].VendorID != unknown.VendorID || string(got[0].Data.(datatype.Unknown)) != "bad" {
			t.Fatalf("top-level unknown = %+v", got[0])
		}
		if got[1].Code != group.Code {
			t.Fatalf("nested parent = %d, want %d", got[1].Code, group.Code)
		}
		children := got[1].Data.(*GroupedAVP).AVP
		if len(children) != 1 || children[0].Code != unknown.Code || children[0].VendorID != unknown.VendorID {
			t.Fatalf("nested failed hierarchy = %+v", children)
		}
	}
	decoded.UnknownMandatoryAVPs()[0] = nil
	if decoded.UnknownMandatoryAVPs()[0] == nil {
		t.Fatal("caller mutated internal unknown-AVP list")
	}
}
