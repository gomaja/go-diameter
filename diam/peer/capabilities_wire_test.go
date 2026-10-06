package peer

import (
	"context"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

// Capture the actor's outgoing CER and the manager's answer to an incoming
// CER over real TCP connections. This exercises the production send paths.
func peerCapabilitiesOnWire(t *testing.T, dictionary *dict.Parser) (*diam.Message, *diam.Message) {
	t.Helper()
	remoteListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = remoteListener.Close() }()
	if err := remoteListener.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	settings := testSettings("local.example.net")
	settings.Dict = dictionary
	settings.VendorID = 10415
	settings.HostIPAddresses = []datatype.Address{datatype.AddressFromIP(netip.MustParseAddr("127.0.0.1"))}
	manager, err := New(Config{Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.AddPeer(PeerConfig{Host: "remote.example.net", Endpoints: []Endpoint{{Network: "tcp", Address: remoteListener.Addr().String()}}, NoAutoReconnect: true}); err != nil {
		t.Fatal(err)
	}
	localListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = localListener.Close() }()
	server := &diam.Server{Dict: dictionary}
	defer closeManager(t, manager, server)
	if err := manager.BindServer(server); err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(localListener) }()
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	remote, err := remoteListener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = remote.Close() }()
	request := read(t, remote)
	if request.Header.CommandCode != diam.CapabilitiesExchange || request.Header.CommandFlags&diam.RequestFlag == 0 {
		t.Fatalf("outgoing message is not CER: %v", request.Header)
	}
	_ = remote.Close()
	awaitState(t, manager, Closed)
	inbound, err := net.DialTimeout("tcp", localListener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inbound.Close() }()
	cfg := manager.baseSettings(nil)
	cfg.OriginHost = "remote.example.net"
	incoming, err := base.BuildCER(dictionary, cfg)
	if err != nil {
		t.Fatal(err)
	}
	write(t, inbound, incoming)
	answer := read(t, inbound)
	if answer.Header.CommandCode != diam.CapabilitiesExchange || answer.Header.CommandFlags&diam.RequestFlag != 0 || code(t, answer) != diam.Success {
		t.Fatalf("incoming response is not success CEA: %v", answer)
	}
	_ = inbound.Close()
	awaitState(t, manager, Closed)
	return request, answer
}

func TestPeerCapabilitiesOnWire(t *testing.T) {
	for _, tc := range []struct {
		name                string
		dictionary          *dict.Parser
		auth, vendors, apps []uint32
	}{
		{"Default", dict.Default, []uint32{1, 4}, []uint32{5535, 10415, 13019}, []uint32{16777216, 16777217, 16777236, 16777238, 16777251, 16777252, 16777265, 16777302, 16777312, 16777313}},
		{"S6a", dict.New(dict.Base, dict.S6a), nil, []uint32{10415}, []uint32{16777251}},
		{"Cx", dict.New(dict.Base, dict.NASREQ, dict.Cx), []uint32{1}, []uint32{10415, 13019}, []uint32{16777216}},
		{"CreditControl-RoRf", dict.New(dict.Base, dict.NASREQ, dict.CreditControl, dict.RoRf), []uint32{1, 4}, []uint32{5535, 13019}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request, answer := peerCapabilitiesOnWire(t, tc.dictionary)
			for _, message := range []*diam.Message{request, answer} {
				got := readPeerCapabilities(t, message, tc.dictionary)
				if !reflect.DeepEqual(got.auth, tc.auth) || !reflect.DeepEqual(got.acct, []uint32{3}) || !reflect.DeepEqual(got.supported, tc.vendors) {
					t.Errorf("wire capabilities=%+v; want auth=%v acct=[3] suppliers=%v", got, tc.auth, tc.vendors)
				}
				if len(got.groups) != len(tc.apps) {
					t.Fatalf("wire VSAI count=%d, want %d", len(got.groups), len(tc.apps))
				}
				for _, id := range tc.apps {
					if countPeerGroup(got.groups, id, 10415, avp.AuthApplicationID) != 1 {
						t.Errorf("wire VSAI must contain exactly one author10415/app%d: %+v", id, got.groups)
					}
				}
			}
		})
	}
}
