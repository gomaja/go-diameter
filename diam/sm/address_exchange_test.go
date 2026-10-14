// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// RFC 6733 §§5.3.1–5.3.5: CER and CEA carry each advertised host address.
func TestAddressCapabilitiesExchangeTCP(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())
	serverSettings := cloneTestSettings(serverSettings,
		testDict)
	clientSettings := cloneTestSettings(clientSettings,
		testDict)

	addresses := []datatype.Address{
		datatype.AddressFromIP(netip.MustParseAddr("192.0.2.1")),
		datatype.AddressFromIP(netip.MustParseAddr("2001:db8::1")),
	}
	serverCfg := *serverSettings
	serverCfg.HostIPAddresses = addresses
	server := mustNewStateMachine(t, &serverCfg, testDict)
	serverHandshakes := testHandshakeNotifications(server)
	srv := diamtest.NewServer(server, testDict)
	defer srv.Close()
	clientCfg := *clientSettings
	clientCfg.HostIPAddresses = addresses
	client := &Client{Handler: mustNewStateMachine(t, &clientCfg, testDict), AuthApplicationID: []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4))}, Dict: testDict}
	clientHandshakes := testHandshakeNotifications(client.Handler)
	conn, err := client.Dial(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, notifications := range []<-chan diam.Conn{serverHandshakes, clientHandshakes} {
		select {
		case c := <-notifications:
			metadata, ok := smpeer.FromContext(c.Context())
			if !ok {
				t.Fatal("handshake lacks peer metadata")
			}
			var got []datatype.Address
			if notifications == serverHandshakes {
				got = metadata.CER.HostIPAddresses
			} else {
				got = metadata.CEA.HostIPAddresses
			}
			if !reflect.DeepEqual(got, addresses) {
				t.Fatalf("Host-IP-Address = %v, want %v", got, addresses)
			}
			cloned := metadata.Clone()
			if cloned.CER != nil {
				cloned.CER.HostIPAddresses[0].Value[0] = 99
			} else {
				cloned.CEA.HostIPAddresses[0].Value[0] = 99
			}
			if !reflect.DeepEqual(got, addresses) {
				t.Fatal("metadata clone aliases addresses")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("handshake timeout")
		}
	}
}
