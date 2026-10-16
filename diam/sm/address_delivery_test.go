package sm

import (
	"bytes"
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-sctp"
)

// RFC 6733 §5.3.5: every usable SCTP source is advertised, including loopback.
func TestDiscoveredAddressesEncodedInCERAndCEA(t *testing.T) {
	cases := []struct {
		name  string
		local net.Addr
		want  []string
	}{
		{"IPv4", &net.TCPAddr{IP: net.IP{192, 0, 2, 7}, Port: 3868}, []string{"192.0.2.7"}},
		{"IPv6", &net.TCPAddr{IP: net.ParseIP("2001:db8::7"), Port: 3868}, []string{"2001:db8::7"}},
		{"multihomed", &sctp.Addr{IPs: []netip.Addr{netip.MustParseAddr("192.0.2.7"), netip.MustParseAddr("2001:db8::7")}}, []string{"192.0.2.7", "2001:db8::7"}},
		{"mixed loopback", &sctp.Addr{IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.0.2.7"), netip.MustParseAddr("::1")}}, []string{"127.0.0.1", "192.0.2.7", "::1"}},
		{"custom literal", testLocalAddr{value: "127.0.0.1/[::1]/192.0.2.7:3868"}, []string{"127.0.0.1", "::1", "192.0.2.7"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dictionary := newSMTestDictionary(dict.Base())
			cfg := cloneTestSettings(clientSettings, dictionary)
			cfg.HostIPAddresses = nil
			sm := mustNewStateMachine(t, cfg, dictionary)
			conn := &testLocalAddrDiamConn{localAddr: tc.local}
			addresses, err := getLocalAddresses(conn)
			if err != nil {
				t.Fatal(err)
			}
			cli := &Client{Handler: sm, Dict: dictionary}
			cer, err := cli.makeCER(addresses)
			if err != nil {
				t.Fatal(err)
			}
			cea, err := buildTestCEA(sm, conn, cer)
			if err != nil {
				t.Fatal(err)
			}
			for _, message := range []*diam.Message{cer, cea} {
				data, err := message.Serialize()
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := diam.ReadMessage(bytes.NewReader(data), dictionary)
				if err != nil {
					t.Fatal(err)
				}
				var got []string
				for _, address := range decoded.FindAVPsWithPath(diam.AVPRef{Code: avp.HostIPAddress}) {
					value, ok := address.Data.(datatype.Address)
					if !ok {
						t.Fatalf("address type = %T", address.Data)
					}
					ip, ok := value.IP()
					if !ok {
						t.Fatalf("invalid IP address: %v", value)
					}
					got = append(got, ip.String())
				}
				if !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("flags %x decoded addresses = %v, want %v", decoded.Header.CommandFlags, got, tc.want)
				}
			}
		})
	}
}

func TestUnspecifiedLocalAddressesAreNotAdvertised(t *testing.T) {
	for _, local := range []net.Addr{&net.TCPAddr{IP: net.IPv4zero}, &sctp.Addr{IPs: []netip.Addr{netip.IPv6Unspecified()}}} {
		got, err := getLocalAddresses(&testLocalAddrDiamConn{localAddr: local})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("unspecified source addresses advertised: %v", got)
		}
	}
}
