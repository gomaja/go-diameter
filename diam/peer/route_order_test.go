package peer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/datatype"
)

func TestDiscoveryRouteOrder(t *testing.T) {
	m, actors, sessions := outboundTestManager(t)
	m.cfg.Clock = &fakeClock{}
	specs := make([]Discovery, len(actors))
	for i, a := range actors {
		spec := discoverySpec()
		spec.Peer = a.cfg
		// Publish the backup first; arrival order must not override DNS ranking.
		spec.RouteOrder = map[uint32]uint64{4: uint64(2 - i)}
		specs[i] = spec
		a.discovery.Store(&discoveryState{spec: spec, expires: spec.ExpiresAt})
		sessions[i].meta = a.meta
		a.publish(nil)
	}
	request := outboundRequest("", "example.net")
	choose := func(want *actor, excluded map[*actor]bool) {
		t.Helper()
		for range 256 {
			got, _, err := m.selectPeer(request, excluded)
			if err != nil || got != want {
				t.Fatalf("selected actor %p (%v), want %s", got, err, want.cfg.Host)
			}
		}
	}
	choose(actors[1], nil)
	choose(actors[0], map[*actor]bool{actors[1]: true})
	fixtureSetHealth(actors[1], WatchdogSuspect)
	actors[1].publish(nil)
	choose(actors[0], nil)
	fixtureSetHealth(actors[1], WatchdogOkay)
	actors[1].publish(nil)
	choose(actors[1], nil)
	// Refresh changes ranking while retaining the admitted session.
	specs[0].RouteOrder = map[uint32]uint64{4: 0}
	specs[0].ExpiresAt = specs[0].ExpiresAt.Add(time.Minute)
	if err := actors[0].refreshDiscovery(context.Background(), specs[0]); err != nil {
		t.Fatal(err)
	}
	if actors[0].activeSession.Load() != sessions[0] {
		t.Fatal("rank refresh replaced session")
	}
	choose(actors[0], nil)
	// Static routes retain their explicit order and take precedence.
	if err := m.SetRoutes([]Route{{Realm: "example.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{actors[1].cfg.Host, actors[0].cfg.Host}}}); err != nil {
		t.Fatal(err)
	}
	choose(actors[1], nil)
	if err := m.SetRoutes(nil); err != nil {
		t.Fatal(err)
	}
	choose(actors[0], nil)
	// Omitted ranks are zero; equal ranks have a stable identity tie-break.
	specs[1].RouteOrder = nil
	if err := actors[1].refreshDiscovery(context.Background(), specs[1]); err != nil {
		t.Fatal(err)
	}
	choose(actors[0], nil)
	actors[0].publish(nil)
	choose(actors[0], nil)
	actors[0].revokeDiscovery()
	choose(actors[1], nil)
}

func TestDiscoveryRouteOrderCloned(t *testing.T) {
	m, _, _ := outboundTestManager(t)
	spec := discoverySpec()
	spec.RouteOrder = map[uint32]uint64{4: 2}
	cloned, err := m.cloneDiscovery(spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.RouteOrder[4] = 100
	if cloned.RouteOrder[4] != 2 {
		t.Fatal("caller mutation changed cloned route order")
	}
	cloned.RouteOrder[4] = 3
	if spec.RouteOrder[4] != 100 {
		t.Fatal("clone mutation changed caller route order")
	}
}

func TestDiscoveryRouteOrderPerApplicationAndExpiry(t *testing.T) {
	m, actors, _ := outboundTestManager(t)
	now := time.Now()
	m.cfg.Now = func() time.Time { return now }
	m.localApps[1] = struct{}{}
	for i, a := range actors {
		spec := discoverySpec()
		spec.Peer = a.cfg
		spec.ApplicationIDs = []uint32{1, 4, 4}
		spec.RouteOrder = map[uint32]uint64{1: uint64(i), 4: uint64(1 - i)}
		spec.ExpiresAt = now.Add(time.Duration(i+1) * time.Minute)
		a.discovery.Store(&discoveryState{spec: spec, expires: spec.ExpiresAt})
		a.meta.Applications = []uint32{1, 4}
		a.publish(nil)
	}
	for _, app := range []uint32{1, 4} {
		if len(m.dynamicRoutes[routeKey{"example.net", app}]) != 2 {
			t.Fatal("duplicate app produced duplicate routes")
		}
		request := outboundRequest("", "example.net")
		request.Header.ApplicationID = app
		want := actors[0]
		if app == 4 {
			want = actors[1]
		}
		got, _, err := m.selectPeer(request, nil)
		if err != nil || got != want {
			t.Fatalf("app %d: got %p (%v), want %p", app, got, err, want)
		}
	}
	now = actors[0].discovery.Load().expires
	request := outboundRequest("", "example.net")
	request.Header.ApplicationID = 1
	got, _, err := m.selectPeer(request, nil)
	if err != nil || got != actors[1] {
		t.Fatal("expired preferred peer prevented fallback")
	}
	if !m.HasRoute("example.net", 1) {
		t.Fatal("backup missing from HasRoute")
	}
	now = actors[1].discovery.Load().expires
	if _, _, err := m.selectPeer(request, nil); !errors.Is(err, ErrUnableToDeliver) {
		t.Fatalf("expired routes selected: %v", err)
	}
	if m.HasRoute("example.net", 1) {
		t.Fatal("expired backup remains eligible")
	}
}
