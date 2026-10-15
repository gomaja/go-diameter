package dnsdiam

import (
	"context"
	"testing"
	"time"
)

func TestControllerPreservesDiscoveryOrderPerApplication(t *testing.T) {
	a := controllerPeer(t, "a.example.net", "example.net")
	b := controllerPeer(t, "b.example.net", "example.net")
	m := controllerManager(t, time.Now, nil, nil)
	r := &controllerResolver{targets: []controllerTarget{b, a}, ttl: 60, now: time.Now}
	c := controllerFixture(t, m, r, nil)
	if err := c.Ensure(context.Background(), "example.net", 4); err != nil {
		t.Fatal(err)
	}
	first, second := c.owned[b.host], c.owned[a.host]
	assertRanks := func(app uint32, preferred, backup string) {
		t.Helper()
		if c.owned[preferred].spec.RouteOrder[app] != 1 || c.owned[backup].spec.RouteOrder[app] != 2 {
			t.Fatalf("application %d lost ordered discovery ranks: %v / %v", app, c.owned[preferred].spec.RouteOrder, c.owned[backup].spec.RouteOrder)
		}
	}
	assertRanks(4, b.host, a.host)
	r.mu.Lock()
	r.targets = []controllerTarget{a, b}
	r.mu.Unlock()
	if err := c.Ensure(context.Background(), "example.net", 1); err != nil {
		t.Fatal(err)
	}
	assertRanks(1, a.host, b.host)
	assertRanks(4, b.host, a.host)
	if err := controllerRefresh(t, c, 4); err != nil {
		t.Fatal(err)
	}
	assertRanks(4, a.host, b.host)
	assertRanks(1, a.host, b.host)
	if c.owned[b.host].lease != first.lease || c.owned[a.host].lease != second.lease {
		t.Fatal("rank changes replaced admitted connections")
	}
}
