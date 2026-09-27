package peer

import (
	"testing"

	"github.com/gomaja/go-diameter/diam/datatype"
)

func TestSetRoutesValidatesAndSwapsAtomically(t *testing.T) {
	m, err := New(Config{Settings: testSettings("local.example.net")})
	if err != nil {
		t.Fatal(err)
	}
	defer closeManager(t, m, nil)
	for _, host := range []datatype.DiameterIdentity{"a.example.net", "b.example.net"} {
		if err := m.AddPeer(PeerConfig{Host: host}); err != nil {
			t.Fatal(err)
		}
	}
	routes := []Route{{Realm: "EXAMPLE.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"A.EXAMPLE.net", "b.example.net"}}}
	if err := m.SetRoutes(routes); err != nil {
		t.Fatal(err)
	}
	routes[0].PeerHosts[0] = "changed.example.net"
	got := m.routes.Load().entries[routeKey{realm: "example.net", app: 4}]
	if len(got) != 2 || got[0] != "a.example.net" || got[1] != "b.example.net" {
		t.Fatalf("route snapshot = %v", got)
	}
	bad := []Route{{Realm: "example.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"missing.example.net"}}}
	if err := m.SetRoutes(bad); err == nil {
		t.Fatal("unknown peer accepted")
	}
	if got := m.routes.Load().entries[routeKey{realm: "example.net", app: 4}]; len(got) != 2 {
		t.Fatalf("failed update changed snapshot: %v", got)
	}
	for _, routes := range [][]Route{
		{{Realm: "", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"a.example.net"}}},
		{{Realm: "example.net", ApplicationID: 4}},
		{{Realm: "example.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"a.example.net", "A.example.net"}}},
		{{Realm: "example.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"a.example.net"}}, {Realm: "EXAMPLE.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"b.example.net"}}},
	} {
		if err := m.SetRoutes(routes); err == nil {
			t.Fatalf("accepted invalid routes %+v", routes)
		}
	}
	if err := m.SetRoutes(nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.routes.Load().entries[routeKey{realm: "example.net", app: 4}]; ok {
		t.Fatal("clear retained route")
	}
}
