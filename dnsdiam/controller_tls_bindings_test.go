package dnsdiam

import (
	"context"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/peer"
	"github.com/gomaja/go-diameter/diam/sm"
)

func TestControllerTLSSharedNamingChainsRefresh(t *testing.T) {
	serverTLS, clientTLS := fixtureTLS(t, []string{"example.net", "_diameters._tcp.example.net", "_alternate._tcp.example.net", "peer.example.net"})
	addr := fixturePeer(t, controllerSettings("peer.example.net", "example.net"), serverTLS, nil)
	d := liveDiscovery(t, addr, TLS)
	r := d.cfg.Resolver.(*fakeResolver)
	key := lookupKey{"example.net.", TypeNAPTR}
	answer := r.answers[key]
	answer.Records = append(answer.Records, nap(key.name, "aaa+ap1:diameter.tls.tcp", "s", "_alternate._tcp.example.net.", 600))
	r.answers[key] = answer
	answer = r.answers[lookupKey{"_diameters._tcp.example.net.", TypeSRV}]
	answer.Records = append([]Record(nil), answer.Records...)
	for i := range answer.Records {
		answer.Records[i].Name = "_alternate._tcp.example.net."
	}
	r.answers[lookupKey{"_alternate._tcp.example.net.", TypeSRV}] = answer
	m, err := peer.New(peer.Config{Settings: controllerSettings("client.example.net", "example.net"), Timers: peer.Timers{Closing: 50 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := m.Close(ctx, sm.DisconnectRebooting); err != nil {
			t.Error(err)
		}
	})
	c, err := NewController(d, m, Policy{TLSConfig: clientTLS, Authorize: authorizeFixture})
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
	for _, app := range []uint32{4, 1} {
		if err := c.Ensure(context.Background(), "example.net", app); err != nil {
			t.Fatal(err)
		}
	}
	for _, binding := range c.owned["peer.example.net"].bindings {
		if binding.evidence.config != c.owned["peer.example.net"].spec.Peer.Endpoints[0].TLSConfig {
			t.Fatal("shared binding uses a different configuration's TLS evidence")
		}
	}
	old := c.owned["peer.example.net"].lease
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.lock(ctx); err != nil {
		t.Fatal(err)
	}
	err = c.ensureLocked(ctx, Request{Realm: "example.net", ApplicationID: 4, Transports: []Transport{TLS}}, bindingKey{"example.net", 4}, true)
	c.unlock()
	if err != nil {
		t.Fatal(err)
	}
	if c.owned["peer.example.net"].lease != old {
		t.Fatal("unchanged shared binding replaced the authenticated connection")
	}
}
