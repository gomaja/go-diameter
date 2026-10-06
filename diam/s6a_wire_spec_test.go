package diam

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// TS 29.272 V19.6.0 §§7.2.3–7.2.20: nine S6a/S6d and S13 command pairs.
// The AVP codes and minimum command bodies are transcribed independently of
// the dictionary's command rules. The values exercise real AVP decoding.
var s6aS13WireCommands = []struct {
	name          string
	code, app     uint32
	requestExtras []*AVP
}{
	{"UL", 316, 16777251, []*AVP{
		s6aBase(283, datatype.DiameterIdentity("example.net")),
		s6aBase(1, datatype.UTF8String("001010123456789")),
		s6a3GPP(1032, datatype.Enumerated(1004)),                              // RAT-Type: EUTRAN
		s6a3GPP(1405, datatype.Unsigned32(0)),                                 // ULR-Flags
		s6a3GPP(1407, datatype.OctetString(string([]byte{0x21, 0xf3, 0x54}))), // Visited-PLMN-Id
	}},
	{"CL", 317, 16777251, []*AVP{
		s6aBase(293, datatype.DiameterIdentity("mme.example.net")),
		s6aBase(283, datatype.DiameterIdentity("example.net")),
		s6aBase(1, datatype.UTF8String("001010123456789")),
		s6a3GPP(1420, datatype.Enumerated(0)), // Cancellation-Type
	}},
	{"AI", 318, 16777251, []*AVP{
		s6aBase(283, datatype.DiameterIdentity("example.net")),
		s6aBase(1, datatype.UTF8String("001010123456789")),
		s6a3GPP(1407, datatype.OctetString(string([]byte{0x21, 0xf3, 0x54}))),
	}},
	{"ID", 319, 16777251, []*AVP{
		s6aBase(293, datatype.DiameterIdentity("mme.example.net")),
		s6aBase(283, datatype.DiameterIdentity("example.net")),
		s6aBase(1, datatype.UTF8String("001010123456789")),
		s6a3GPP(1400, &GroupedAVP{AVP: []*AVP{s6a3GPP(1424, datatype.Enumerated(0))}}), // Subscription-Data
	}},
	{"DS", 320, 16777251, []*AVP{
		s6aBase(293, datatype.DiameterIdentity("mme.example.net")),
		s6aBase(283, datatype.DiameterIdentity("example.net")),
		s6aBase(1, datatype.UTF8String("001010123456789")),
		s6a3GPP(1421, datatype.Unsigned32(0)), // DSR-Flags
	}},
	{"PU", 321, 16777251, []*AVP{
		s6aBase(283, datatype.DiameterIdentity("example.net")),
		s6aBase(1, datatype.UTF8String("001010123456789")),
	}},
	{"RS", 322, 16777251, []*AVP{
		s6aBase(293, datatype.DiameterIdentity("mme.example.net")),
		s6aBase(283, datatype.DiameterIdentity("example.net")),
	}},
	{"NO", 323, 16777251, []*AVP{
		s6aBase(283, datatype.DiameterIdentity("example.net")),
		s6aBase(1, datatype.UTF8String("001010123456789")),
	}},
	{"EC", 324, 16777252, []*AVP{
		s6aBase(283, datatype.DiameterIdentity("example.net")),
		s6a3GPP(1401, &GroupedAVP{AVP: []*AVP{s6a3GPP(1402, datatype.UTF8String("490154203237518"))}}), // Terminal-Information
	}},
}

func s6aBase(code uint32, data datatype.Type) *AVP {
	return NewAVP(code, avp.Mbit, 0, data)
}

func s6a3GPP(code uint32, data datatype.Type) *AVP {
	return NewAVP(code, avp.Mbit|avp.Vbit, 10415, data)
}

func s6aWireMessage(code, app uint32, request bool, extras []*AVP) *Message {
	flags := uint8(ProxiableFlag)
	if request {
		flags |= RequestFlag
	}
	m := NewMessage(code, flags, app, 0x12345678, 0x87654321, dict.Default)
	m.AddAVP(s6aBase(263, datatype.UTF8String("session;123")))
	if !request {
		m.AddAVP(s6aBase(268, datatype.Unsigned32(2001)))
	}
	m.AddAVP(s6aBase(277, datatype.Enumerated(1)))
	m.AddAVP(s6aBase(264, datatype.DiameterIdentity("host.example.net")))
	m.AddAVP(s6aBase(296, datatype.DiameterIdentity("example.net")))
	for _, extra := range extras {
		m.AddAVP(extra)
	}
	return m
}

// RFC 8583 §§6.1.1–6.1.2, 7.1–7.5 Load grammar; TS 29.272 V19.6.0 §§7.2.4, 7.2.6,
// 7.2.14, and 7.2.18 permit multiple Load AVPs in these answers.
func s6aLoadAVP(loadType, loadValue uint32) *AVP {
	return NewAVP(650, 0, 0, &GroupedAVP{AVP: []*AVP{
		NewAVP(651, 0, 0, datatype.Enumerated(loadType)),
		NewAVP(652, 0, 0, datatype.Unsigned64(loadValue)),
		NewAVP(649, 0, 0, datatype.DiameterIdentity("host.example.net")),
	}})
}

func TestS6aS13CommandWireRoundTrip(t *testing.T) {
	for _, tc := range s6aS13WireCommands {
		for _, request := range []bool{true, false} {
			direction := "answer"
			if request {
				direction = "request"
			}
			t.Run(tc.name+"/"+direction, func(t *testing.T) {
				var extras []*AVP
				if request {
					extras = tc.requestExtras
				} else if tc.app == 16777251 && (tc.code == 316 || tc.code == 318 || tc.code == 321 || tc.code == 323) {
					extras = []*AVP{s6aLoadAVP(0, 37), s6aLoadAVP(1, 52)}
				}
				original := s6aWireMessage(tc.code, tc.app, request, extras)
				if err := original.Validate(); err != nil {
					t.Fatalf("constructed message: %v", err)
				}
				wire, err := original.Serialize()
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := ReadMessage(bytes.NewReader(wire), dict.Default)
				if err != nil {
					t.Fatal(err)
				}
				if decoded.DecodeErr != nil {
					t.Fatal(decoded.DecodeErr)
				}
				if err := decoded.Validate(); err != nil {
					t.Fatalf("decoded message: %v", err)
				}
				if decoded.Header.CommandCode != tc.code || decoded.Header.ApplicationID != tc.app || len(decoded.AVP) != len(original.AVP) {
					t.Fatalf("decoded command or AVP count differs: %+v", decoded.Header)
				}
				for i := range decoded.AVP {
					got, want := decoded.AVP[i], original.AVP[i]
					if got.Code != want.Code || got.VendorID != want.VendorID || got.Flags != want.Flags || got.Data.Type() != want.Data.Type() {
						t.Errorf("AVP %d: got %v, want %v", i, got, want)
					}
				}
			})
		}
	}
}

// TS 29.272 V19.6.0 §§7.2.3 and 7.2.19: Session-Id is fixed first,
// Terminal-Information is required in ECR, and User-Name is optional with max 1.
func TestS6aS13CommandValidationBoundaries(t *testing.T) {
	t.Run("required_terminal_information", func(t *testing.T) {
		m := s6aWireMessage(324, 16777252, true, []*AVP{s6aBase(283, datatype.DiameterIdentity("example.net"))})
		if err := m.Validate(); err == nil || err.ResultCode != MissingAVP {
			t.Fatalf("got %v, want MissingAVP", err)
		}
	})
	t.Run("optional_user_name", func(t *testing.T) {
		m := s6aWireMessage(324, 16777252, true, s6aS13WireCommands[8].requestExtras)
		if err := m.Validate(); err != nil {
			t.Fatal(err)
		}
		m.AddAVP(s6aBase(1, datatype.UTF8String("001010123456789")))
		if err := m.Validate(); err != nil {
			t.Fatal(err)
		}
		m.AddAVP(s6aBase(1, datatype.UTF8String("001010987654321")))
		if err := m.Validate(); err == nil || err.ResultCode != AVPOccursTooManyTimes {
			t.Fatalf("got %v, want AVPOccursTooManyTimes", err)
		}
	})
	t.Run("fixed_session_id", func(t *testing.T) {
		m := s6aWireMessage(324, 16777252, true, s6aS13WireCommands[8].requestExtras)
		m.AVP[0], m.AVP[1] = m.AVP[1], m.AVP[0]
		if err := m.Validate(); err == nil || err.ResultCode != AVPNotAllowed {
			t.Fatalf("got %v, want AVPNotAllowed", err)
		}
	})
	t.Run("proxiable_header", func(t *testing.T) {
		m := s6aWireMessage(324, 16777252, true, s6aS13WireCommands[8].requestExtras)
		m.Header.CommandFlags &^= ProxiableFlag
		if err := m.Validate(); err == nil || err.ResultCode != InvalidHDRBits {
			t.Fatalf("got %v, want InvalidHDRBits", err)
		}
	})
}
