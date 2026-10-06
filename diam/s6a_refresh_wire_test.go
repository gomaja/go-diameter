package diam

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// TS 29.272 V19.6.0 §§7.3.151, 7.3.162, 7.3.175, 7.3.177,
// 7.3.186, 7.3.201–7.3.202 and Table 7.3.1/1.
func TestS6aRefreshAVPWireRoundTrip(t *testing.T) {
	plmns := func() datatype.Type {
		return &GroupedAVP{AVP: []*AVP{
			NewAVP(1407, avp.Mbit|avp.Vbit, 10415, datatype.OctetString("\x21\xf3\x54")),
			NewAVP(1407, avp.Mbit|avp.Vbit, 10415, datatype.OctetString("\x13\xf0\x62")),
		}}
	}
	for _, tc := range []struct {
		name string
		code uint32
		data datatype.Type
	}{
		{"AIR-Flags", 1679, datatype.Unsigned32(1)},
		{"UE-Usage-Type", 1680, datatype.Unsigned32(255)},
		{"Equivalent-PLMN-List", 1637, plmns()},
		{"SMS-Register-Request", 1648, datatype.Enumerated(2)},
		{"SGs-MME-Identity", 1664, datatype.UTF8String("mme.example.net")},
		{"Coupled-Node-Diameter-ID", 1666, datatype.DiameterIdentity("sgsn.example.net")},
		{"Adjacent-PLMNs", 1672, plmns()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := dict.Default.FindAVPWithVendor(16777251, tc.name, 10415)
			if err != nil {
				t.Fatal(err)
			}
			typ := tc.data.Type()
			if typ == GroupedAVPType {
				typ = datatype.GroupedType
			}
			if d.Code != tc.code || d.Must != "V" || d.MustNot != "M" || d.MayEncrypt != "N" || d.Data.Type != typ {
				t.Fatalf("definition differs from TS 29.272: %+v", d)
			}
			m := NewRequest(316, 16777251, dict.Default)
			if _, err := m.NewAVP(tc.name, avp.Vbit, 10415, tc.data); err != nil {
				t.Fatal(err)
			}
			assertRefreshWire(t, m, tc.code, avp.Vbit, 10415, tc.data)
		})
	}
}

// TS 29.272 V19.6.0 Table 7.3.1/2 overrides the reused definitions' M bit.
func TestS6aS13RefreshMBitWire(t *testing.T) {
	for _, tc := range []struct {
		name    string
		app     uint32
		code    uint32
		vendor  uint32
		flags   uint8
		mustNot string
		data    datatype.Type
	}{
		{"RAT-Type", 16777251, 1032, 10415, avp.Mbit | avp.Vbit, "", datatype.Enumerated(1004)},
		{"GMLC-Address", 16777251, 2405, 10415, avp.Vbit, "M", datatype.Address{Family: 1, Value: []byte{127, 0, 0, 1}}},
		{"DRMP", 16777251, 301, 0, 0, "M,V", datatype.Enumerated(1)},
		{"DRMP", 16777252, 301, 0, 0, "M,V", datatype.Enumerated(1)},
		{"OC-Supported-Features", 16777251, 621, 0, 0, "M,V", &GroupedAVP{AVP: []*AVP{NewAVP(622, 0, 0, datatype.Unsigned64(1))}}},
		{"OC-OLR", 16777251, 623, 0, 0, "M,V", &GroupedAVP{AVP: []*AVP{NewAVP(624, 0, 0, datatype.Unsigned64(1)), NewAVP(626, 0, 0, datatype.Enumerated(0))}}},
		{"Load", 16777251, 650, 0, 0, "M,V", s6aLoadAVP(0, 37).Data},
	} {
		t.Run(tc.name+"/"+strconv.FormatUint(uint64(tc.app), 10), func(t *testing.T) {
			d, err := dict.Default.FindAVPWithVendor(tc.app, tc.name, tc.vendor)
			if err != nil {
				t.Fatal(err)
			}
			var flags uint8
			if strings.Contains(d.Must, "M") {
				flags |= avp.Mbit
			}
			if strings.Contains(d.Must, "V") {
				flags |= avp.Vbit
			}
			if flags != tc.flags || d.MustNot != tc.mustNot {
				t.Fatalf("Table 7.3.1/2 flags = %#x forbidden=%q, want %#x/%q", flags, d.MustNot, tc.flags, tc.mustNot)
			}
			// Carry each AVP in a command of its application: ULR (316) for
			// S6a, ECR (324) for S13 (TS 29.272 V19.6.0 Tables 7.2.2/1-2).
			code := uint32(316)
			if tc.app == 16777252 {
				code = 324
			}
			if _, err := dict.Default.FindCommand(tc.app, code); err != nil {
				t.Fatal(err)
			}
			m := NewRequest(code, tc.app, dict.Default)
			if _, err := m.NewAVP(tc.name, flags, tc.vendor, tc.data); err != nil {
				t.Fatal(err)
			}
			assertRefreshWire(t, m, tc.code, tc.flags, tc.vendor, tc.data)
		})
	}
}

func assertRefreshWire(t *testing.T, m *Message, code uint32, flags uint8, vendor uint32, data datatype.Type) {
	t.Helper()
	wire, err := m.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) < 28 || binary.BigEndian.Uint32(wire[20:24]) != code || wire[24] != flags {
		t.Fatalf("wire AVP code/flags: %x", wire)
	}
	if vendor != 0 && (len(wire) < 32 || binary.BigEndian.Uint32(wire[28:32]) != vendor) {
		t.Fatalf("wire vendor: %x", wire)
	}
	decoded, err := ReadMessage(bytes.NewReader(wire), dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	a, err := decoded.FindAVP(code, vendor)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.DecodeErr != nil || a.Flags != flags || a.Data.Type() != data.Type() {
		t.Fatalf("decoded AVP: %+v error=%v", a, decoded.DecodeErr)
	}
	payload := a.Data.Serialize()
	want := data.Serialize()
	if !bytes.Equal(payload, want) {
		t.Fatalf("payload=%x, want %x", payload, want)
	}
	if g, ok := a.Data.(*GroupedAVP); ok {
		for _, child := range g.AVP {
			if child.Data.Type() == datatype.UnknownType {
				t.Fatalf("unresolved grouped child: %+v", child)
			}
		}
	}
	again, err := decoded.Serialize()
	if err != nil || !bytes.Equal(wire, again) {
		t.Fatalf("round trip differs: %x, err=%v", again, err)
	}
}
