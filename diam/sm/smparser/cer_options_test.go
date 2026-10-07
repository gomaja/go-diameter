package smparser

import (
	"errors"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

func TestCERParseOptions(t *testing.T) {
	baseOnly := dict.New(dict.Base)
	for _, tc := range []struct {
		name     string
		options  ParseOptions
		app      uint32
		security bool
		want     error
	}{
		{"message dictionary", ParseOptions{Role: Server}, 4, false, nil},
		{"dictionary override", ParseOptions{Role: Server, Dictionary: baseOnly}, 4, false, ErrNoCommonApplication},
		{"explicit applications", ParseOptions{Role: Server, Dictionary: baseOnly, LocalApplications: []uint32{4}}, 4, false, nil},
		{"empty applications", ParseOptions{Role: Server, LocalApplications: []uint32{}}, 4, false, ErrNoCommonApplication},
		{"base is not an application", ParseOptions{Role: Server}, 0, false, ErrNoCommonApplication},
		{"relay with empty local offer", ParseOptions{Role: Server, LocalApplications: []uint32{}}, 0xffffffff, false, nil},
		{"TLS", ParseOptions{Role: Server, TLS: true}, 4, true, nil},
		{"plaintext", ParseOptions{Role: Server}, 4, true, ErrNoCommonSecurity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := diam.NewRequest(diam.CapabilitiesExchange, 0, dict.New(dict.Base, dict.CreditControl))
			mustCERAVP(t, m, avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example"))
			mustCERAVP(t, m, avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example"))
			mustCERAVP(t, m, avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(tc.app))
			if tc.security {
				mustCERAVP(t, m, avp.InbandSecurityID, avp.Mbit, 0, datatype.Unsigned32(1))
			}
			_, err := new(CER).Parse(m, tc.options)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Parse=%v, want %v", err, tc.want)
			}
		})
	}
	for _, role := range []Role{Client, Server} {
		m := diam.NewRequest(diam.CapabilitiesExchange, 0, dict.Default)
		mustCERAVP(t, m, avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example"))
		mustCERAVP(t, m, avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example"))
		want := ErrNoCommonApplication
		if role == Client {
			want = ErrMissingApplication
		}
		_, err := new(CER).Parse(m, ParseOptions{Role: role})
		if !errors.Is(err, want) {
			t.Fatalf("role %d: %v, want %v", role, err, want)
		}
	}
}

func TestCEAParseOptions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options ParseOptions
		want    error
	}{
		{"message dictionary", ParseOptions{Role: Client}, nil},
		{"dictionary override", ParseOptions{Role: Client, Dictionary: dict.New(dict.Base)}, ErrNoCommonApplication},
		{"explicit applications", ParseOptions{Role: Client, Dictionary: dict.New(dict.Base), LocalApplications: []uint32{4}}, nil},
		{"empty applications", ParseOptions{Role: Client, LocalApplications: []uint32{}}, ErrNoCommonApplication},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := diam.NewMessage(diam.CapabilitiesExchange, 0, 0, 1, 2, dict.New(dict.Base, dict.CreditControl))
			m.AddAVP(diam.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.Success)))
			m.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
			m.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
			m.AddAVP(diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)))
			if err := new(CEA).Parse(m, tc.options); !errors.Is(err, tc.want) {
				t.Fatalf("Parse=%v want %v", err, tc.want)
			}
		})
	}
}

func TestCapabilityParserHeader(t *testing.T) {
	for _, answer := range []bool{false, true} {
		m := diam.NewRequest(diam.CapabilitiesExchange, 4, dict.Default)
		m.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
		m.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
		m.AddAVP(diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)))
		var err error
		if answer {
			m.Header.CommandFlags = 0
			m.AddAVP(diam.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.Success)))
			err = new(CEA).Parse(m, ParseOptions{Role: Client})
		} else {
			_, err = new(CER).Parse(m, ParseOptions{Role: Server})
		}
		var me *diam.MessageError
		if !errors.As(err, &me) || me.ResultCode != diam.InvalidHDRBits {
			t.Fatalf("answer=%t error=%v", answer, err)
		}
	}
}
