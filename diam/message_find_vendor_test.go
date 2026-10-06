package diam

import (
	"bytes"
	"slices"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

const vendor3GPP = 10415

// sameCodeAVPs returns two AVPs of application 4 that share code 9 in two
// vendors' spaces (RFC 6733 §4.1): Framed-IP-Netmask (IETF, RFC 7155
// §4.4.10.5.2) and TGPP-GGSN-MCC-MNC (3GPP).
func sameCodeAVPs() (ietf, tgpp *AVP) {
	return NewAVP(avp.FramedIPNetmask, avp.Mbit, 0, datatype.OctetString("\xff\xff\xff\x00")),
		NewAVP(avp.TGPPGGSNMCCMNC, avp.Vbit, vendor3GPP, datatype.UTF8String("00101"))
}

func psInformation(members ...*AVP) *AVP {
	return NewAVP(avp.PSInformation, avp.Mbit|avp.Vbit, vendor3GPP, &GroupedAVP{AVP: members})
}

// sameCodeLayouts places the two AVPs in a message of application 4, each
// before the other, at the top level and inside a Grouped AVP.
func sameCodeLayouts(t *testing.T) []struct {
	name       string
	m          *Message
	ietf, tgpp *AVP
} {
	t.Helper()
	type layout = struct {
		name       string
		m          *Message
		ietf, tgpp *AVP
	}
	var layouts []layout
	for _, tc := range []struct {
		name  string
		place func(ietf, tgpp *AVP) []*AVP
	}{
		{"top level, IETF first", func(ietf, tgpp *AVP) []*AVP { return []*AVP{ietf, tgpp} }},
		{"top level, 3GPP first", func(ietf, tgpp *AVP) []*AVP { return []*AVP{tgpp, ietf} }},
		{"grouped, IETF first", func(ietf, tgpp *AVP) []*AVP { return []*AVP{psInformation(ietf, tgpp)} }},
		{"grouped, 3GPP first", func(ietf, tgpp *AVP) []*AVP { return []*AVP{psInformation(tgpp, ietf)} }},
		{"IETF at top level, 3GPP grouped", func(ietf, tgpp *AVP) []*AVP { return []*AVP{ietf, psInformation(tgpp)} }},
		{"3GPP at top level, IETF grouped", func(ietf, tgpp *AVP) []*AVP { return []*AVP{tgpp, psInformation(ietf)} }},
	} {
		ietf, tgpp := sameCodeAVPs()
		m := NewMessage(CreditControl, RequestFlag|ProxiableFlag, 4, 1, 2, dict.Default)
		for _, a := range tc.place(ietf, tgpp) {
			m.AddAVP(a)
		}
		layouts = append(layouts, layout{tc.name, m, ietf, tgpp})

		// The same message decoded from the wire.
		b, err := m.Serialize()
		if err != nil {
			t.Fatalf("%s: serialize: %v", tc.name, err)
		}
		decoded, err := ReadMessage(bytes.NewReader(b), dict.Default)
		if err != nil {
			t.Fatalf("%s: decode: %v", tc.name, err)
		}
		var dietf, dtgpp *AVP
		walkAVPs(decoded.AVP, func(a *AVP) {
			if a.Code == 9 && a.VendorID == 0 {
				dietf = a
			}
			if a.Code == 9 && a.VendorID == vendor3GPP {
				dtgpp = a
			}
		})
		if dietf == nil || dtgpp == nil {
			t.Fatalf("%s: decoded message lost an AVP: %s", tc.name, decoded)
		}
		layouts = append(layouts, layout{tc.name + ", decoded", decoded, dietf, dtgpp})
	}
	return layouts
}

func walkAVPs(avps []*AVP, visit func(*AVP)) {
	for _, a := range avps {
		visit(a)
		if group, ok := a.Data.(*GroupedAVP); ok {
			walkAVPs(group.AVP, visit)
		}
	}
}

// TestFindAVPMatchesCodeAndVendor guards that FindAVP and FindAVPs identify
// an AVP by its code and Vendor-Id together (RFC 6733 §4.1), at the top
// level and inside Grouped AVPs, whether the AVP is named by code or by
// dictionary name: a code reused by another vendor never matches.
func TestFindAVPMatchesCodeAndVendor(t *testing.T) {
	for _, l := range sameCodeLayouts(t) {
		t.Run(l.name, func(t *testing.T) {
			for _, q := range []struct {
				code   any
				vendor uint32
				want   *AVP
			}{
				{avp.FramedIPNetmask, 0, l.ietf},
				{uint32(avp.FramedIPNetmask), 0, l.ietf},
				{"Framed-IP-Netmask", 0, l.ietf},
				{avp.TGPPGGSNMCCMNC, vendor3GPP, l.tgpp},
				{uint32(avp.TGPPGGSNMCCMNC), vendor3GPP, l.tgpp},
				{"TGPP-GGSN-MCC-MNC", vendor3GPP, l.tgpp},
			} {
				got, err := l.m.FindAVP(q.code, q.vendor)
				if err != nil {
					t.Fatalf("FindAVP(%#v, %d): %v", q.code, q.vendor, err)
				}
				if got != q.want {
					t.Errorf("FindAVP(%#v, %d) = %v, want %v", q.code, q.vendor, got, q.want)
				}
				all, err := l.m.FindAVPs(q.code, q.vendor)
				if err != nil {
					t.Fatalf("FindAVPs(%#v, %d): %v", q.code, q.vendor, err)
				}
				if !slices.Equal(all, []*AVP{q.want}) {
					t.Errorf("FindAVPs(%#v, %d) = %v, want [%v]", q.code, q.vendor, all, q.want)
				}
			}
		})
	}
}

// TestFindAVPRejectsAnotherVendorsName guards that a name is resolved in
// the vendor's space the caller gives, never in another vendor's.
func TestFindAVPRejectsAnotherVendorsName(t *testing.T) {
	ietf, tgpp := sameCodeAVPs()
	m := NewMessage(CreditControl, RequestFlag|ProxiableFlag, 4, 1, 2, dict.Default)
	m.AddAVP(ietf)
	m.AddAVP(tgpp)
	for _, q := range []struct {
		name   string
		vendor uint32
	}{
		{"TGPP-GGSN-MCC-MNC", 0},
		{"Framed-IP-Netmask", vendor3GPP},
		{"Framed-IP-Netmask", dict.UndefinedVendorID},
	} {
		if a, err := m.FindAVP(q.name, q.vendor); err == nil {
			t.Errorf("FindAVP(%q, %d) = %v, want an error", q.name, q.vendor, a)
		}
		if avps, err := m.FindAVPs(q.name, q.vendor); err == nil {
			t.Errorf("FindAVPs(%q, %d) = %v, want an error", q.name, q.vendor, avps)
		}
		if avps, err := m.FindAVPsWithPath(AVPRef{q.name, q.vendor}); err == nil {
			t.Errorf("FindAVPsWithPath(%q, %d) = %v, want an error", q.name, q.vendor, avps)
		}
	}
}

// TestFindAVPByCodeNeedsNoDictionary guards that an AVP named by code and
// Vendor-Id is found whether or not the dictionary defines it: the pair is
// the AVP's identity on the wire.
func TestFindAVPByCodeNeedsNoDictionary(t *testing.T) {
	m := NewMessage(CreditControl, RequestFlag|ProxiableFlag, 4, 1, 2, dict.Default)
	unknown := NewAVP(4242, avp.Vbit, 99999, datatype.Unknown{1, 2, 3, 4})
	m.AddAVP(psInformation(unknown))
	got, err := m.FindAVP(4242, 99999)
	if err != nil || got != unknown {
		t.Fatalf("FindAVP(4242, 99999) = %v, %v; want %v", got, err, unknown)
	}
	if got, err := m.FindAVP(4242, 0); err == nil {
		t.Fatalf("FindAVP(4242, 0) = %v, want an error", got)
	}
	for _, code := range []any{-1, int64(4242), 1.5} {
		if got, err := m.FindAVP(code, 99999); err == nil {
			t.Errorf("FindAVP(%#v, 99999) = %v, want an error", code, got)
		}
	}
}

// TestFindAVPsWithPathMatchesEachElementsVendor guards that each element of
// a path is matched by its own code and Vendor-Id: a 3GPP Grouped AVP can
// hold IETF members, and its members can reuse codes of other vendors.
func TestFindAVPsWithPathMatchesEachElementsVendor(t *testing.T) {
	for _, l := range sameCodeLayouts(t) {
		t.Run(l.name, func(t *testing.T) {
			var group *AVP
			var top []*AVP
			for _, a := range l.m.AVP {
				if a.Code == avp.PSInformation {
					group = a
				} else {
					top = append(top, a)
				}
			}
			var grouped []*AVP
			if group != nil {
				grouped = group.Data.(*GroupedAVP).AVP
			}
			in := func(want *AVP, avps []*AVP) []*AVP {
				if slices.Contains(avps, want) {
					return []*AVP{want}
				}
				return nil
			}
			for _, q := range []struct {
				path []AVPRef
				want []*AVP
			}{
				{[]AVPRef{{avp.FramedIPNetmask, 0}}, in(l.ietf, top)},
				{[]AVPRef{{avp.TGPPGGSNMCCMNC, vendor3GPP}}, in(l.tgpp, top)},
				{[]AVPRef{{"Framed-IP-Netmask", 0}}, in(l.ietf, top)},
				{[]AVPRef{{"TGPP-GGSN-MCC-MNC", vendor3GPP}}, in(l.tgpp, top)},
				{[]AVPRef{{avp.PSInformation, vendor3GPP}, {avp.FramedIPNetmask, 0}}, in(l.ietf, grouped)},
				{[]AVPRef{{avp.PSInformation, vendor3GPP}, {avp.TGPPGGSNMCCMNC, vendor3GPP}}, in(l.tgpp, grouped)},
				{[]AVPRef{{"PS-Information", vendor3GPP}, {"Framed-IP-Netmask", 0}}, in(l.ietf, grouped)},
				{[]AVPRef{{"PS-Information", vendor3GPP}, {"TGPP-GGSN-MCC-MNC", vendor3GPP}}, in(l.tgpp, grouped)},
				// The Grouped AVP is 3GPP's; code 874 in the IETF space is another AVP.
				{[]AVPRef{{avp.PSInformation, 0}, {avp.FramedIPNetmask, 0}}, nil},
				{[]AVPRef{{avp.PSInformation, 0}, {avp.TGPPGGSNMCCMNC, vendor3GPP}}, nil},
			} {
				got, err := l.m.FindAVPsWithPath(q.path...)
				if err != nil {
					t.Fatalf("FindAVPsWithPath(%v): %v", q.path, err)
				}
				if !slices.Equal(got, q.want) {
					t.Errorf("FindAVPsWithPath(%v) = %v, want %v", q.path, got, q.want)
				}
			}
		})
	}
}

// TestFindAVPsWithPathCrossesVendorSpaces guards the documented S6a path:
// Service-Selection, an IETF AVP (RFC 5778 §6.2), inside 3GPP Grouped AVPs
// (3GPP TS 29.272 §7.3.2), named by code and by name.
func TestFindAVPsWithPathCrossesVendorSpaces(t *testing.T) {
	m := NewMessage(UpdateLocation, ProxiableFlag, TGPP_S6A_APP_ID, 1, 2, dict.Default)
	selection := NewAVP(avp.ServiceSelection, avp.Mbit, 0, datatype.UTF8String("internet"))
	m.AddAVP(NewAVP(avp.SubscriptionData, avp.Mbit, vendor3GPP, &GroupedAVP{AVP: []*AVP{
		NewAVP(avp.APNConfigurationProfile, avp.Mbit, vendor3GPP, &GroupedAVP{AVP: []*AVP{
			NewAVP(avp.ContextIdentifier, avp.Mbit, vendor3GPP, datatype.Unsigned32(1)),
			NewAVP(avp.APNConfiguration, avp.Mbit, vendor3GPP, &GroupedAVP{AVP: []*AVP{
				NewAVP(avp.ContextIdentifier, avp.Mbit, vendor3GPP, datatype.Unsigned32(1)),
				// Same code in the 3GPP space: never matched as Service-Selection.
				NewAVP(avp.ServiceSelection, avp.Mbit, vendor3GPP, datatype.UTF8String("decoy")),
				selection,
			}}),
		}}),
	}}))
	for _, path := range [][]AVPRef{
		{{avp.SubscriptionData, vendor3GPP}, {avp.APNConfigurationProfile, vendor3GPP}, {avp.APNConfiguration, vendor3GPP}, {avp.ServiceSelection, 0}},
		{{"Subscription-Data", vendor3GPP}, {"APN-Configuration-Profile", vendor3GPP}, {"APN-Configuration", vendor3GPP}, {"Service-Selection", 0}},
	} {
		got, err := m.FindAVPsWithPath(path...)
		if err != nil {
			t.Fatalf("FindAVPsWithPath(%v): %v", path, err)
		}
		if !slices.Equal(got, []*AVP{selection}) {
			t.Errorf("FindAVPsWithPath(%v) = %v, want [%v]", path, got, selection)
		}
	}
}

// TestFindAVPToleratesNilGroupedData guards that a Grouped AVP whose Data is
// a nil *GroupedAVP is searched as one without members, at the top level
// and nested, by FindAVP, FindAVPs and FindAVPsWithPath.
func TestFindAVPToleratesNilGroupedData(t *testing.T) {
	for _, tc := range []struct {
		name   string
		nested bool
	}{{"top level", false}, {"nested", true}} {
		t.Run(tc.name, func(t *testing.T) {
			empty := &AVP{Code: avp.PSInformation, Flags: avp.Mbit | avp.Vbit, VendorID: vendor3GPP, Data: (*GroupedAVP)(nil)}
			_, target := sameCodeAVPs()
			m := NewMessage(CreditControl, RequestFlag|ProxiableFlag, 4, 1, 2, dict.Default)
			path := []AVPRef{{avp.PSInformation, vendor3GPP}, {avp.TGPPGGSNMCCMNC, vendor3GPP}}
			if tc.nested {
				// A literal: NewAVP would measure the nil group.
				outer := &AVP{Code: avp.ServiceInformation, Flags: avp.Mbit | avp.Vbit, VendorID: vendor3GPP, Data: &GroupedAVP{AVP: []*AVP{empty}}}
				m.AVP = []*AVP{outer, target}
				path = append([]AVPRef{{avp.ServiceInformation, vendor3GPP}}, path...)
			} else {
				m.AVP = []*AVP{empty, target}
			}
			if got, err := m.FindAVP(avp.TGPPGGSNMCCMNC, vendor3GPP); err != nil || got != target {
				t.Errorf("FindAVP(TGPP-GGSN-MCC-MNC) = %v, %v; want %v", got, err, target)
			}
			if got, err := m.FindAVPs(avp.TGPPGGSNMCCMNC, vendor3GPP); err != nil || !slices.Equal(got, []*AVP{target}) {
				t.Errorf("FindAVPs(TGPP-GGSN-MCC-MNC) = %v, %v; want [%v]", got, err, target)
			}
			if got, err := m.FindAVPs(avp.PSInformation, vendor3GPP); err != nil || !slices.Equal(got, []*AVP{empty}) {
				t.Errorf("FindAVPs(PS-Information) = %v, %v; want [%v]", got, err, empty)
			}
			if got, err := m.FindAVP(avp.FramedIPNetmask, 0); err == nil {
				t.Errorf("FindAVP(Framed-IP-Netmask) = %v, want an error", got)
			}
			if got, err := m.FindAVPsWithPath(path...); err != nil || len(got) != 0 {
				t.Errorf("FindAVPsWithPath(%v) = %v, %v; want none", path, got, err)
			}
			if got, err := m.FindAVPsWithPath(path[:len(path)-1]...); err != nil || !slices.Equal(got, []*AVP{empty}) {
				t.Errorf("FindAVPsWithPath(%v) = %v, %v; want [%v]", path[:len(path)-1], got, err, empty)
			}
		})
	}
}

// TestNilGroupedAVPHasNoMembers checks that a nil *GroupedAVP behaves as an
// empty Grouped AVP: it has no length, serializes to nothing and prints.
func TestNilGroupedAVPHasNoMembers(t *testing.T) {
	var g *GroupedAVP
	if g.Len() != 0 || len(g.Serialize()) != 0 || g.String() != "" {
		t.Fatalf("nil group: Len %d, Serialize %x, String %q", g.Len(), g.Serialize(), g.String())
	}
	a := NewAVP(avp.ProxyInfo, avp.Mbit, 0, g)
	m := NewRequest(CapabilitiesExchange, 0, nil)
	m.AddAVP(a)
	b, err := m.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != HeaderLength+8 {
		t.Fatalf("message with an empty Grouped AVP = %d bytes, want %d", len(b), HeaderLength+8)
	}
}
