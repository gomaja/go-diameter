package diam

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// TestFlagListedAcceptsCompactRules checks that the compact flag-rule form
// ("MV") is read like the comma form ("M,V"), so a dictionary written either
// way is validated the same.
func TestFlagListedAcceptsCompactRules(t *testing.T) {
	for _, tc := range []struct {
		list, flag string
		want       bool
	}{
		{"M,V", "M", true}, {"V,M", "V", true}, {"M", "M", true},
		{"MV", "M", true}, {"MV", "V", true}, {"VM", "M", true},
		{"MV", "P", false}, {"V", "M", false}, {"", "M", false}, {"-", "M", false},
	} {
		if got := flagListed(tc.list, tc.flag); got != tc.want {
			t.Errorf("flagListed(%q, %q) = %t, want %t", tc.list, tc.flag, got, tc.want)
		}
	}
}

func TestValidateUnderstoodAVPFlags(t *testing.T) {
	for _, tc := range []struct {
		name   string
		code   uint32
		vendor uint32
		flags  uint8
		data   datatype.Type
		mRule  string
	}{
		{"base must-not M", avp.FirmwareRevision, 0, avp.Mbit, datatype.Unsigned32(1), "must-not"},
		{"S6a must-not M", avp.UESRVCCCapability, 10415, avp.Vbit | avp.Mbit, datatype.Enumerated(0), "must-not"},
		{"S6a must M", avp.ULRFlags, 10415, avp.Vbit, datatype.Unsigned32(0), "must"},
		{"base reserved P", avp.FirmwareRevision, 0, avp.Pbit, datatype.Unsigned32(1), ""},
		{"reserved bits", avp.FirmwareRevision, 0, 0x1f, datatype.Unsigned32(1), ""},
		{"OC-Supported-Features M", avp.OCSupportedFeatures, 0, avp.Mbit, &GroupedAVP{}, ""},
		{"DRMP M", avp.DRMP, 0, avp.Mbit, datatype.Enumerated(0), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := validationULR(t)
			definition, err := m.Dictionary().FindAVP(m.Header.ApplicationID, tc.code, tc.vendor)
			if err != nil {
				t.Fatal(err)
			}
			if tc.mRule == "must" && !flagListed(definition.Must, "M") || tc.mRule == "must-not" && !flagListed(definition.MustNot, "M") {
				t.Fatalf("regression fixture no longer has %s M: %+v", tc.mRule, definition)
			}
			a := NewAVP(tc.code, tc.flags, tc.vendor, tc.data)
			replaced := false
			for i, existing := range m.AVP {
				if existing.Code == a.Code && existing.VendorID == a.VendorID {
					m.AVP[i], replaced = a, true
					break
				}
			}
			if !replaced {
				m.AddAVP(a)
			}
			wire, err := m.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := ReadMessage(bytes.NewReader(wire), m.Dictionary())
			if err != nil {
				t.Fatal(err)
			}
			if got := decoded.Validate(); got != nil {
				t.Fatalf("understood AVP rejected: %v", got)
			}
			after, err := decoded.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(wire, after) {
				t.Fatal("validation changed received AVPs")
			}
		})
	}
}

func validationULR(t *testing.T) *Message {
	t.Helper()
	m := NewMessage(UpdateLocation, RequestFlag|ProxiableFlag, TGPP_S6A_APP_ID, 1, 2, dict.Default)
	if err := m.Marshal(&struct {
		SessionID        string                    `avp:"Session-Id"`
		AuthSessionState datatype.Enumerated       `avp:"Auth-Session-State"`
		OriginHost       datatype.DiameterIdentity `avp:"Origin-Host"`
		OriginRealm      datatype.DiameterIdentity `avp:"Origin-Realm"`
		DestinationRealm datatype.DiameterIdentity `avp:"Destination-Realm"`
		UserName         string                    `avp:"User-Name"`
		RATType          datatype.Enumerated       `avp:"RAT-Type"`
		ULRFlags         datatype.Unsigned32       `avp:"ULR-Flags"`
		VisitedPLMNID    datatype.OctetString      `avp:"Visited-PLMN-Id"`
	}{"session", 1, "mme.example", "example", "example", "001010000000001", 1004, 0, "\x00\xf1\x10"}); err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("invalid ULR fixture: %v", err)
	}
	return m
}

func TestValidateGroupedAVPFlags(t *testing.T) {
	for _, flags := range []uint8{avp.Vbit, avp.Vbit | avp.Pbit, avp.Vbit | 0x1f, avp.Mbit} {
		m, _ := validationFixture(t)
		child := NewAVP(4, avp.Vbit, 42, datatype.Unsigned32(1))
		child.Flags = flags // NewAVP normally supplies V for a nonzero Vendor-Id.
		m.AddAVP(NewAVP(3, 0, 0, &GroupedAVP{AVP: []*AVP{child}}))
		got := m.Validate()
		if flags&avp.Vbit != 0 {
			if got != nil {
				t.Fatalf("flags %#x: %v", flags, got)
			}
		} else if got == nil || got.ResultCode != InvalidAVPBits || got.FailedAVP.Code != 3 || got.FailedAVP.Data.(*GroupedAVP).AVP[0] != child {
			t.Fatalf("missing V must retain 3009 and Grouped hierarchy: %v", got)
		}
	}
}

func TestInvalidAVPFlagsReceiveRules(t *testing.T) {
	for _, definition := range []*dict.AVP{
		{Must: "M", MustNot: "V,P"},
		{MustNot: "M,V,P"},
		{VendorID: 10415, Must: "MV", MustNot: "P"},
		{VendorID: 10415, Must: "V", MustNot: "M,P"},
		{},
		{VendorID: 10415},
		{Must: "P", MustNot: "V"},
	} {
		for flags := 0; flags <= 255; flags++ {
			want := (uint8(flags)&avp.Vbit != 0) != (definition.VendorID != 0)
			if got := invalidAVPFlags(uint8(flags), definition); got != want {
				t.Fatalf("definition %+v flags %#x: invalid = %t, want %t", definition, flags, got, want)
			}
		}
	}
}

func TestMarshalDictionaryFlags(t *testing.T) {
	m := NewRequest(UpdateLocation, TGPP_S6A_APP_ID, nil)
	if err := m.Marshal(&struct {
		Host     datatype.DiameterIdentity `avp:"Origin-Host"`
		Firmware datatype.Unsigned32       `avp:"Firmware-Revision"`
		SRVCC    datatype.Enumerated       `avp:"UE-SRVCC-Capability"`
	}{"mme.example", 1, 0}); err != nil {
		t.Fatal(err)
	}
	if err := walkOutgoingFlags(m.AVP, m.Header.ApplicationID, m.Dictionary().Snapshot(), make(map[*GroupedAVP]bool), nil); err != nil {
		t.Fatal(err)
	}
}

func TestValidateReservedCommandBits(t *testing.T) {
	for flags := uint8(1); flags <= 0x0f; flags++ {
		for _, request := range []bool{true, false} {
			m, d := validationFixture(t)
			if !request {
				m = NewMessage(999, ProxiableFlag, 0, 1, 2, d)
				m.AddAVP(NewAVP(5, avp.Mbit, 0, datatype.Unsigned32(2001)))
			}
			m.Header.CommandFlags |= flags
			if err := m.Validate(); err != nil {
				t.Errorf("receive reserved command bits %#x request=%t: %v", flags, request, err)
			}
		}
	}
}

func TestValidateDefinedCommandBits(t *testing.T) {
	for _, flags := range []uint8{RequestFlag | ProxiableFlag | ErrorFlag, ProxiableFlag | RetransmittedFlag, RequestFlag} {
		m, _ := validationFixture(t)
		m.Header.CommandFlags = flags | 0x0f
		if err := m.Validate(); err == nil || err.ResultCode != InvalidHDRBits {
			t.Fatalf("forbidden defined command flags %#x: %v", flags, err)
		}
	}
}

func TestAnswerClearsReservedCommandBits(t *testing.T) {
	m, _ := validationFixture(t)
	m.Header.CommandFlags |= RetransmittedFlag | 0x0f
	if got := m.Answer(Success).Header.CommandFlags; got != ProxiableFlag {
		t.Fatalf("answer flags = %#x, want %#x", got, ProxiableFlag)
	}
}

func TestValidateErrorCommandBits(t *testing.T) {
	for _, flags := range []uint8{ErrorFlag, ErrorFlag | RequestFlag, ErrorFlag | RetransmittedFlag} {
		m := NewMessage(0xfedc, flags|0x0f, 0, 1, 2, nil)
		m.AddAVP(NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(CommandUnsupported)))
		m.AddAVP(NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("host.example")))
		m.AddAVP(NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
		got := m.Validate()
		if flags == ErrorFlag {
			if got != nil {
				t.Fatal(got)
			}
		} else if got == nil || got.ResultCode != InvalidHDRBits {
			t.Fatalf("forbidden error flags %#x: %v", flags, got)
		}
	}
}
