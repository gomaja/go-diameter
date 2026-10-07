package diam

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

func TestValidateOutgoingFlags(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Message) *AVP
		code   uint32
	}{
		{"mandatory M clear", func(m *Message) *AVP { m.AVP[0].Flags &^= avp.Mbit; return m.AVP[0] }, InvalidAVPBits},
		{"forbidden M set", func(m *Message) *AVP {
			a := NewAVP(avp.FirmwareRevision, avp.Mbit, 0, datatype.Unsigned32(1))
			m.AddAVP(a)
			return a
		}, InvalidAVPBits},
		{"known V clear", func(m *Message) *AVP {
			a := NewAVP(avp.ULRFlags, avp.Mbit, 10415, datatype.Unsigned32(0))
			a.Flags &^= avp.Vbit
			m.AVP[7] = a
			return a
		}, InvalidAVPBits},
		{"unknown V clear", func(m *Message) *AVP {
			a := NewAVP(0xfedc, 0, 42, datatype.OctetString("unknown"))
			a.Flags = 0
			m.AddAVP(a)
			return a
		}, InvalidAVPBits},
		{"unknown V set without vendor", func(m *Message) *AVP {
			a := NewAVP(0xfedc, 0, 0, datatype.OctetString("unknown"))
			a.Flags |= avp.Vbit // Deliberately corrupt the normalized constructor output.
			m.AddAVP(a)
			return a
		}, InvalidAVPBits},
		{"reserved AVP bits", func(m *Message) *AVP { m.AVP[0].Flags |= 1; return m.AVP[0] }, InvalidAVPBits},
		{"unknown reserved AVP bits", func(m *Message) *AVP {
			a := NewAVP(0xfedc, 1, 0, datatype.OctetString("unknown"))
			m.AddAVP(a)
			return a
		}, InvalidAVPBits},
		{"reserved command bits", func(m *Message) *AVP { m.Header.CommandFlags |= 1; return nil }, InvalidHDRBits},
		{"unknown M set", func(m *Message) *AVP {
			m.AddAVP(NewAVP(0xfedc, avp.Mbit, 0, datatype.OctetString("unknown")))
			return nil
		}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := validationULR(t)
			failed := tc.change(m)
			got := m.ValidateOutgoing()
			if tc.code == 0 {
				if got != nil {
					t.Fatal(got)
				}
				return
			}
			if got == nil || got.ResultCode != tc.code || got.FailedAVP != failed {
				t.Fatalf("outgoing check = %v, want %d for %v", got, tc.code, failed)
			}
		})
	}
}

func TestValidateOutgoingGroupedFlags(t *testing.T) {
	for _, tc := range []struct {
		name         string
		code, vendor uint32
		flags        uint8
		exempt       bool
	}{
		{"known group", avp.VendorSpecificApplicationID, 0, avp.Mbit, false},
		{"unknown group", 0xfedc, 42, avp.Vbit, false},
		{"vendor code 279", avp.FailedAVP, 42, avp.Vbit, false},
		{"Failed-AVP evidence", avp.FailedAVP, 0, avp.Mbit, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := validationULR(t)
			child := NewAVP(avp.VendorID, 0, 0, datatype.Unsigned32(10415))
			parent := NewAVP(tc.code, tc.flags, tc.vendor, &GroupedAVP{AVP: []*AVP{child, NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(TGPP_S6A_APP_ID))}})
			m.AddAVP(parent)
			got := m.ValidateOutgoing()
			if tc.exempt {
				if got != nil {
					t.Fatal(got)
				}
				return
			}
			if got == nil || got.ResultCode != InvalidAVPBits || got.FailedAVP.Code != tc.code {
				t.Fatalf("nested missing M: %v", got)
			}
			group, ok := got.FailedAVP.Data.(*GroupedAVP)
			if !ok || len(group.AVP) != 1 || group.AVP[0] != child {
				t.Fatalf("lost offending child: %v", got.FailedAVP)
			}
		})
	}
}

func TestValidateOutgoingFailedAVPEvidence(t *testing.T) {
	m := validationULR(t)
	bad := NewAVP(avp.VendorSpecificApplicationID, avp.Vbit|avp.Pbit|0x1f, 0, &GroupedAVP{AVP: []*AVP{
		NewAVP(avp.VendorID, 0, 0, datatype.Unsigned32(10415)),
	}})
	failed := NewAVP(avp.FailedAVP, avp.Mbit, 0, &GroupedAVP{AVP: []*AVP{bad}})
	m.AddAVP(failed)
	before, err := m.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ValidateOutgoing(); err != nil {
		t.Fatal(err)
	}
	after, err := m.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("outgoing check changed Failed-AVP evidence")
	}
	failed.Flags = 0
	if err := m.ValidateOutgoing(); err == nil || err.ResultCode != InvalidAVPBits || err.FailedAVP != failed {
		t.Fatalf("Failed-AVP container missing M: %v", err)
	}
}

func TestValidateOutgoingApplicationPRestriction(t *testing.T) {
	// TS 29.273 V19.2.0, Tables 5.2.3.1/1 and 8.2.3.0/1 prohibit P.
	for _, a := range []*AVP{
		NewAVP(318, avp.Mbit|avp.Vbit, 10415, datatype.DiameterIdentity("aaa.example")),
		NewAVP(1524, avp.Vbit, 10415, datatype.OctetString("ssid")),
	} {
		snapshot := dict.Default.Snapshot()
		if err := validateOutgoingFlags([]*AVP{a}, CHARGING_CONTROL_APP_ID, snapshot); err != nil {
			t.Fatal(err)
		}
		a.Flags |= avp.Pbit
		if err := validateOutgoingFlags([]*AVP{a}, CHARGING_CONTROL_APP_ID, snapshot); err == nil || err.ResultCode != InvalidAVPBits || err.FailedAVP != a {
			t.Fatalf("application P restriction: %v", err)
		}
	}
}

func TestValidateOutgoingUnruledGroup(t *testing.T) {
	d := dict.New(dict.Base, dict.NASREQ, dict.CreditControl, dict.RoRf, dict.S6c, dict.S6a)
	if err := d.Load(bytes.NewBufferString(`<diameter><application id="16777251" name="test"><avp name="Unruled" code="65000"><data type="Grouped"/></avp></application></diameter>`)); err != nil {
		t.Fatal(err)
	}
	child := NewAVP(avp.OriginHost, 0, 0, datatype.DiameterIdentity("host.example"))
	parent := NewAVP(65000, 0, 0, &GroupedAVP{AVP: []*AVP{child}})
	if err := validateOutgoingFlags([]*AVP{parent}, TGPP_S6A_APP_ID, d.Snapshot()); err == nil || err.ResultCode != InvalidAVPBits {
		t.Fatalf("unruled Grouped AVP skipped: %v", err)
	}
}

func TestValidateOutgoingInvalidGroups(t *testing.T) {
	for _, children := range [][]*AVP{
		{nil},
		{{Code: 65000, Data: (*GroupedAVP)(nil)}},
	} {
		parent := &AVP{Code: 65001, Data: &GroupedAVP{AVP: children}}
		if err := validateOutgoingFlags([]*AVP{parent}, 0, dict.Default.Snapshot()); err == nil {
			t.Fatal("accepted invalid outgoing group")
		}
	}
}

func TestValidateOutgoingGroupCycles(t *testing.T) {
	m := validationULR(t)
	group := &GroupedAVP{}
	a := NewAVP(65000, 0, 0, group)
	group.AVP = []*AVP{a}
	m.AVP = append(m.AVP, a)
	if err := m.ValidateOutgoing(); err == nil || err.ResultCode != InvalidAVPValue {
		t.Fatalf("cyclic group: %v", err)
	}
	// Sharing an acyclic group across siblings is valid.
	group.AVP = []*AVP{NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("host.example"))}
	m.AddAVP(a)
	if err := m.ValidateOutgoing(); err != nil {
		t.Fatalf("shared acyclic group: %v", err)
	}
}
