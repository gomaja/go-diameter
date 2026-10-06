package peer

import (
	"bytes"
	"net"
	"net/netip"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
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
	fallback := datatype.Address{Family: datatype.AddressFamilyIPv4, Value: []byte{127, 0, 0, 1}}
	for _, tc := range []struct {
		name  string
		local net.Addr
		want  []datatype.Address
	}{
		{"TCP IPv4", &net.TCPAddr{IP: net.IP{192, 0, 2, 7}}, []datatype.Address{v4}},
		{"TCP IPv6", &net.TCPAddr{IP: net.IP(v6.Value)}, []datatype.Address{v6}},
		{"SCTP multihomed", &sctp.Addr{IPs: []netip.Addr{netip.MustParseAddr("192.0.2.7"), netip.MustParseAddr("2001:db8::7")}}, []datatype.Address{v4, v6}},
		{"SCTP empty", &sctp.Addr{}, []datatype.Address{fallback}},
		{"SCTP nil", (*sctp.Addr)(nil), []datatype.Address{fallback}},
		{"TCP nil", (*net.TCPAddr)(nil), []datatype.Address{fallback}},
		{"TCP empty", &net.TCPAddr{}, []datatype.Address{fallback}},
		{"nil address", nil, []datatype.Address{fallback}},
		{"custom address", &net.UnixAddr{Name: "diameter", Net: "unix"}, []datatype.Address{fallback}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &Manager{cfg: Config{Settings: testSettings("local.example.net")}}
			cfg := m.baseSettings(&addressLocalConn{local: tc.local})
			assertPeerAddresses(t, cfg.HostIPAddresses, tc.want)
		})
	}
	m := &Manager{cfg: Config{Settings: testSettings("local.example.net")}}
	assertPeerAddresses(t, m.baseSettings(nil).HostIPAddresses, []datatype.Address{fallback})
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
	cfg := m.baseSettings(&addressLocalConn{local: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 9)}})
	assertPeerAddresses(t, cfg.HostIPAddresses, []datatype.Address{configured})
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
