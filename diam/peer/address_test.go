package peer

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-sctp"
)

type addressLocalConn struct {
	*fakeConn
	local net.Addr
}

func (c *addressLocalConn) LocalAddr() net.Addr { return c.local }

func TestPeerLocalAddresses(t *testing.T) {
	v4 := datatype.Address{Family: datatype.AddressFamilyIPv4, Value: []byte{192, 0, 2, 7}}
	v6 := datatype.Address{Family: datatype.AddressFamilyIPv6, Value: []byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}}
	loopback := datatype.AddressFromIP(netip.MustParseAddr("127.0.0.1"))
	for _, tc := range []struct {
		name  string
		local net.Addr
		want  []datatype.Address
	}{
		{"TCP IPv4", &net.TCPAddr{IP: net.IP{192, 0, 2, 7}}, []datatype.Address{v4}},
		{"TCP IPv6", &net.TCPAddr{IP: net.IP(v6.Value)}, []datatype.Address{v6}},
		{"SCTP multihomed", &sctp.Addr{IPs: []netip.Addr{netip.MustParseAddr("192.0.2.7"), netip.MustParseAddr("2001:db8::7")}}, []datatype.Address{v4, v6}},
		{"SCTP mixed loopback", &sctp.Addr{IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.0.2.7"), netip.MustParseAddr("2001:db8::7")}}, []datatype.Address{loopback, v4, v6}},
		{"SCTP empty", &sctp.Addr{}, nil},
		{"SCTP nil", (*sctp.Addr)(nil), nil},
		{"TCP nil", (*net.TCPAddr)(nil), nil},
		{"TCP empty", &net.TCPAddr{}, nil},
		{"TCP unspecified", &net.TCPAddr{IP: net.IPv4zero}, nil},
		{"SCTP unspecified", &sctp.Addr{IPs: []netip.Addr{netip.IPv6Unspecified()}}, nil},
		{"SCTP invalid", &sctp.Addr{IPs: []netip.Addr{{}}}, nil},
		{"nil address", nil, nil},
		{"custom address", &net.UnixAddr{Name: "diameter", Net: "unix"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := testSettings("local.example.net")
			settings.HostIPAddresses = nil
			m := &Manager{cfg: Config{Settings: settings}}
			cfg := m.baseSettings(&addressLocalConn{local: tc.local})
			assertPeerAddresses(t, cfg.HostIPAddresses, tc.want)
			if len(tc.want) != 0 {
				cer, err := base.BuildCER(m.dictionary(), cfg)
				if err != nil {
					t.Fatal(err)
				}
				cea, err := base.BuildCEA(cer, cfg, diam.Success)
				if err != nil {
					t.Fatal(err)
				}
				assertPeerEncodedAddresses(t, cer, tc.want)
				assertPeerEncodedAddresses(t, cea, tc.want)
			}
		})
	}
	settings := testSettings("local.example.net")
	settings.HostIPAddresses = nil
	m := &Manager{cfg: Config{Settings: settings}}
	assertPeerAddresses(t, m.baseSettings(nil).HostIPAddresses, nil)
}

func assertPeerAddresses(t *testing.T, got, want []datatype.Address) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("Host-IP-Address count = %d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Family != want[i].Family || !bytes.Equal(got[i].Value, want[i].Value) {
			t.Fatalf("Host-IP-Address[%d] = family %d value %x, want family %d value %x", i, got[i].Family, got[i].Value, want[i].Family, want[i].Value)
		}
	}
}

func TestPeerAddressConfigOwnership(t *testing.T) {
	configured := datatype.Address{Family: datatype.AddressFamilyIPv6, Value: netip.MustParseAddr("2001:db8::7").AsSlice()}
	settings := testSettings("local.example.net")
	settings.HostIPAddresses = []datatype.Address{configured.Clone()}
	m, err := New(Config{Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	defer closeManager(t, m, nil)
	settings.HostIPAddresses[0].Value[0] = 99
	settings.HostIPAddresses[0].Family = datatype.AddressFamilyIPv4
	assertPeerAddresses(t, m.cfg.Settings.HostIPAddresses, []datatype.Address{configured})
	// Explicit settings override transport discovery and each builder gets owned values.
	cfg := m.baseSettings(&addressLocalConn{local: &net.UnixAddr{Name: "unresolvable", Net: "unix"}})
	assertPeerAddresses(t, cfg.HostIPAddresses, []datatype.Address{configured})
	cer, err := base.BuildCER(m.dictionary(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	cea, err := base.BuildCEA(cer, cfg, diam.Success)
	if err != nil {
		t.Fatal(err)
	}
	assertPeerEncodedAddresses(t, cer, []datatype.Address{configured})
	assertPeerEncodedAddresses(t, cea, []datatype.Address{configured})
	cfg.HostIPAddresses[0].Value[0] = 88
	cfg.HostIPAddresses[0].Family = datatype.AddressFamilyIPv4
	assertPeerAddresses(t, m.cfg.Settings.HostIPAddresses, []datatype.Address{configured})
}

func TestPeerRejectsInvalidAddressSettings(t *testing.T) {
	for _, addr := range []datatype.Address{{}, {Family: datatype.AddressFamilyIPv4, Value: make([]byte, 16)}, {Value: []byte{192, 0, 2, 1}}} {
		settings := testSettings("local.example.net")
		settings.HostIPAddresses = []datatype.Address{addr}
		m, err := New(Config{Settings: settings})
		if m != nil {
			closeManager(t, m, nil)
		}
		if err == nil || m != nil {
			t.Errorf("peer.New accepted invalid Address %v", addr)
		}
	}
}

var _ diam.Conn = (*addressLocalConn)(nil)

// RFC 6733 §§5.3.1, 5.3.2 and 5.3.5 require real local addresses in CER/CEA.
func TestPeerCapabilityAddressResolutionFailure(t *testing.T) {
	for _, local := range []net.Addr{nil, &net.UnixAddr{Name: "diameter", Net: "unix"}, &net.TCPAddr{}, &sctp.Addr{}} {
		settings := testSettings("local.example.net")
		settings.HostIPAddresses = nil
		m := &Manager{cfg: Config{Settings: settings}}
		cfg := m.baseSettings(&addressLocalConn{local: local})
		request := diam.NewRequest(diam.CapabilitiesExchange, 0, m.dictionary())
		builders := []struct {
			name  string
			build func() (*diam.Message, error)
		}{
			{"CER", func() (*diam.Message, error) { return base.BuildCER(m.dictionary(), cfg) }},
			{"CEA", func() (*diam.Message, error) { return base.BuildCEA(request, cfg, diam.Success) }},
			{"error CEA", func() (*diam.Message, error) {
				return base.BuildErrorAnswer(request, cfg, diam.AVPUnsupported, nil, false)
			}},
		}
		for _, builder := range builders {
			t.Run(builder.name+"/"+fmt.Sprint(local), func(t *testing.T) {
				msg, err := builder.build()
				if msg != nil || err == nil || !strings.Contains(err.Error(), "HostIPAddresses") || !strings.Contains(err.Error(), "custom transport") {
					t.Fatalf("build = (%v, %v), want explicit HostIPAddresses advice for custom transport", msg, err)
				}
			})
		}
	}
}

func assertPeerEncodedAddresses(t *testing.T, message *diam.Message, want []datatype.Address) {
	t.Helper()
	data, err := message.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := diam.ReadMessage(bytes.NewReader(data), message.Dictionary())
	if err != nil {
		t.Fatal(err)
	}
	var got []datatype.Address
	for _, a := range decoded.FindAVPsWithPath(diam.AVPRef{Code: avp.HostIPAddress}) {
		value, ok := a.Data.(datatype.Address)
		if !ok {
			t.Fatalf("Host-IP-Address type = %T", a.Data)
		}
		got = append(got, value)
	}
	assertPeerAddresses(t, got, want)
}
