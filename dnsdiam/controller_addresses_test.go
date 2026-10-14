package dnsdiam

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/peer"
)

type addressOrderResolver struct {
	base    *controllerResolver
	mu      sync.Mutex
	reverse bool
}

func (r *addressOrderResolver) Lookup(ctx context.Context, name string, typ RRType) (Answer, error) {
	if typ != TypeA && typ != TypeAAAA {
		return r.base.Lookup(ctx, name, typ)
	}
	ips := []string{"127.0.0.1", "127.0.0.2"}
	if typ == TypeAAAA {
		ips = []string{"::1", "::2"}
	}
	r.mu.Lock()
	reverse := r.reverse
	r.mu.Unlock()
	if reverse {
		slices.Reverse(ips)
	}
	a := Answer{ReceivedAt: r.base.now()}
	for _, ip := range ips {
		a.Records = append(a.Records, address(name, ip, r.base.ttl))
	}
	return a, nil
}

func TestControllerPermutedAddresses(t *testing.T) {
	for _, shared := range []bool{false, true} {
		name := "refresh"
		if shared {
			name = "shared acquisition"
		}
		t.Run(name, func(t *testing.T) {
			target := controllerPeer(t, "shared.example.net", "example.net")
			m := controllerManager(t, time.Now, nil, nil)
			r := &addressOrderResolver{base: &controllerResolver{targets: []controllerTarget{target}, ttl: 60, now: time.Now}}
			d, err := New(Config{Resolver: r, RandIntn: func(int) int { return 0 }})
			if err != nil {
				t.Fatal(err)
			}
			c, err := NewController(d, m, Policy{AllowPlaintext: true, Authorize: authorizeFixture})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				if err := c.Close(ctx); err != nil {
					t.Error(err)
				}
			})
			if err := c.Ensure(context.Background(), "example.net", 4); err != nil {
				t.Fatal(err)
			}
			old := c.owned[target.host].lease
			attempts := slices.Clone(c.owned[target.host].spec.Peer.Endpoints)
			r.mu.Lock()
			r.reverse = true
			r.mu.Unlock()
			if shared {
				err = c.Ensure(context.Background(), "example.net", 1)
			} else {
				err = controllerRefresh(t, c, 4)
			}
			if err != nil {
				t.Fatalf("permuted address set rejected: %v", err)
			}
			if c.owned[target.host].lease != old {
				t.Fatal("same address set replaced the connected lease")
			}
			for i, endpoint := range c.owned[target.host].spec.Peer.Endpoints {
				if endpoint.Address != attempts[i].Address {
					t.Fatal("refresh changed the retained connection's attempt order")
				}
			}
			if shared && (!m.HasRoute("example.net", 1) || !m.HasRoute("example.net", 4)) {
				t.Fatal("shared bindings did not retain both routes")
			}
		})
	}
}

func TestControllerAddressSetEquality(t *testing.T) {
	a := Candidate{Realm: "example.net", Host: "peer.example.net", ApplicationID: 4, Transport: TCP, Port: 3868, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}, Names: []string{"example.net"}}
	b := a
	b.Addresses = []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("::ffff:192.0.2.1"), netip.MustParseAddr("192.0.2.1")}
	if !sameProof(a, b) {
		t.Fatal("normalized address sets differ")
	}
	x := peer.PeerConfig{Host: "peer.example.net", Endpoints: []peer.Endpoint{{Network: "tcp", Address: "192.0.2.1:3868"}, {Network: "tcp", Address: "[2001:db8::1]:3868"}}}
	y := peer.PeerConfig{Host: x.Host, Endpoints: []peer.Endpoint{{Network: "tcp", Address: "[2001:db8::1]:3868"}, {Network: "tcp", Address: "[::ffff:192.0.2.1]:3868"}}}
	if !sameEndpoint(x, y) {
		t.Fatal("normalized endpoint sets differ")
	}
	b.Addresses = []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::1")}
	if sameProof(a, b) {
		t.Fatal("changed address set accepted")
	}
	y.Endpoints[1].Address = "192.0.2.1:5868"
	if sameEndpoint(x, y) {
		t.Fatal("changed port accepted")
	}
}
