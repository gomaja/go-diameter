package base

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

func valueMessage(command uint32, flags uint8) *diam.Message {
	m := diam.NewMessage(command, flags, 0, 1, 2, dict.Default)
	m.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example.net")))
	m.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example.net")))
	if flags&diam.RequestFlag == 0 {
		result := uint32(diam.Success)
		if flags&diam.ErrorFlag != 0 {
			result = diam.TooBusy
		}
		m.AddAVP(diam.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(result)))
	}
	if command == diam.CapabilitiesExchange {
		m.AddAVP(diam.NewAVP(avp.HostIPAddress, avp.Mbit, 0, datatype.AddressFromIP(netip.MustParseAddr("127.0.0.1"))))
		m.AddAVP(diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(0)))
		m.AddAVP(diam.NewAVP(avp.ProductName, 0, 0, datatype.UTF8String("validation")))
	}
	if command == diam.DisconnectPeer && flags&diam.RequestFlag != 0 {
		m.AddAVP(diam.NewAVP(avp.DisconnectCause, avp.Mbit, 0, datatype.Enumerated(0)))
	}
	return m
}

func TestBaseAnswerDestinationAVPs(t *testing.T) {
	for _, command := range []uint32{diam.CapabilitiesExchange, diam.DeviceWatchdog, diam.DisconnectPeer} {
		for _, flags := range []uint8{0, diam.ErrorFlag} {
			for _, code := range []uint32{avp.DestinationHost, avp.DestinationRealm} {
				t.Run(fmt.Sprintf("%d/%d/%d", command, flags, code), func(t *testing.T) {
					m := valueMessage(command, flags)
					a := diam.NewAVP(code, avp.Mbit, 0, datatype.DiameterIdentity("destination.example.net"))
					m.AddAVP(a)
					if err := ValidateMessage(m); err == nil || err.ResultCode != diam.AVPNotAllowed || err.FailedAVP != a {
						t.Fatalf("answer accepted prohibited destination AVP %d: %v", code, err)
					}
				})
			}
			// The wildcard still permits extensions, including vendor code collisions
			// and destination evidence inside Failed-AVP (RFC 6733 §§6.2, 7.5).
			t.Run(fmt.Sprintf("extensions/%d/%d", command, flags), func(t *testing.T) {
				m := valueMessage(command, flags)
				if flags == 0 {
					a, err := m.FindAVP(avp.ResultCode, 0)
					if err != nil {
						t.Fatal(err)
					}
					a.Data = datatype.Unsigned32(diam.UnableToComply)
				}
				m.AddAVP(diam.NewAVP(avp.DestinationHost, avp.Vbit, 10415, datatype.OctetString("opaque")))
				m.AddAVP(diam.NewAVP(0x00fedcba, 0, 0, datatype.OctetString("extension")))
				m.AddAVP(diam.NewAVP(avp.FailedAVP, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{
					diam.NewAVP(avp.DestinationHost, avp.Mbit, 0, datatype.DiameterIdentity("destination.example.net")),
					diam.NewAVP(avp.DestinationRealm, avp.Mbit, 0, datatype.DiameterIdentity("example.net")),
					diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("\xff")),
					diam.NewAVP(avp.SupportedVendorID, avp.Mbit, 0, datatype.Unsigned32(0)),
				}}))
				if err := ValidateMessage(m); err != nil {
					t.Fatalf("permitted extension rejected: %v", err)
				}
			})
		}
	}
}

func TestBaseIdentitySyntax(t *testing.T) {
	maxName := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	values := []struct {
		name, value string
		valid       bool
	}{
		{"fqdn", "Peer-1.Example.NET", true}, {"absolute", "peer.example.net.", true},
		{"single label", "localhost", true}, {"numeric label", "123.example.net", true},
		{"punycode", "xn--bcher-kva.example", true}, {"label limit", strings.Repeat("a", 63), true},
		{"name limit", maxName, true}, {"absolute limit", maxName + ".", true},
		{"empty", "", false}, {"high octet", "peer\xff.example", false}, {"nul", "peer\x00.example", false},
		{"space", "peer .example", false}, {"newline", "peer\n.example", false}, {"unicode", "bücher.example", false},
		{"empty label", "peer..example", false}, {"leading dot", ".example", false}, {"root", ".", false},
		{"leading hyphen", "-peer.example", false}, {"trailing hyphen", "peer-.example", false},
		{"underscore", "peer_name.example", false}, {"slash", "peer/example", false}, {"port", "peer.example:3868", false},
		{"long label", strings.Repeat("a", 64) + ".example", false}, {"long name", maxName + "e", false},
	}
	for _, command := range []uint32{diam.CapabilitiesExchange, diam.DeviceWatchdog, diam.DisconnectPeer} {
		for _, flags := range []uint8{diam.RequestFlag, 0, diam.ErrorFlag} {
			for _, field := range []uint32{avp.OriginHost, avp.OriginRealm} {
				for _, tc := range values {
					t.Run(fmt.Sprintf("%d/%d/%d/%s", command, flags, field, tc.name), func(t *testing.T) {
						m := valueMessage(command, flags)
						a, err := m.FindAVP(field, 0)
						if err != nil {
							t.Fatal(err)
						}
						a.Data = datatype.DiameterIdentity(tc.value)
						got := ValidateMessage(m)
						if tc.valid {
							if got != nil {
								t.Fatalf("valid identity rejected: %v", got)
							}
						} else if got == nil || got.ResultCode != diam.InvalidAVPValue || got.FailedAVP != a {
							t.Fatalf("invalid identity %q accepted or wrong evidence: %v", tc.value, got)
						}
					})
				}
			}
		}
	}
}

func TestBaseSupportedVendorValue(t *testing.T) {
	for _, flags := range []uint8{diam.RequestFlag, 0, diam.ErrorFlag} {
		for _, value := range []uint32{0, 1, 10415, 0xffffffff} {
			t.Run(fmt.Sprintf("%d/%d", flags, value), func(t *testing.T) {
				m := valueMessage(diam.CapabilitiesExchange, flags)
				a := diam.NewAVP(avp.SupportedVendorID, avp.Mbit, 0, datatype.Unsigned32(value))
				m.AddAVP(a)
				got := ValidateMessage(m)
				if value == 0 {
					if got == nil || got.ResultCode != diam.InvalidAVPValue || got.FailedAVP != a {
						t.Fatalf("zero Supported-Vendor-Id accepted: %v", got)
					}
				} else if got != nil {
					t.Fatalf("valid Supported-Vendor-Id rejected: %v", got)
				}
			})
		}
	}
}
