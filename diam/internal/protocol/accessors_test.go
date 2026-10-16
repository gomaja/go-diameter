package protocol

import "testing"

func TestAdmissionStateReadsFollowTransitions(t *testing.T) {
	check := func(t *testing.T, c *Core, phase Phase, ready bool) {
		t.Helper()
		snapshot := c.Snapshot()
		if c.Phase() != phase || c.Ready() != ready || c.Phase() != snapshot.Phase() || c.Ready() != snapshot.Ready() {
			t.Fatalf("state reads: phase=%v ready=%t; snapshot phase=%v ready=%t; want phase=%v ready=%t", c.Phase(), c.Ready(), snapshot.Phase(), snapshot.Ready(), phase, ready)
		}
	}
	t.Run("Accepted", func(t *testing.T) {
		c := machine(t)
		check(t, c, PreCER, false)
		sent := find(t, accept(t, c), Send)
		check(t, c, Open, false)
		ready := find(t, c.Handle(complete(sent)), HandshakeReady)
		check(t, c, Open, false)
		release := event(ReleaseAdmission)
		release.Token = ready.Token
		c.Handle(release)
		check(t, c, Open, true)
		c.Handle(event(Disconnect))
		check(t, c, Closing, false)
		c.Handle(event(TransportLost))
		check(t, c, Closed, false)
	})
	t.Run("Dialed", func(t *testing.T) {
		c := machine(t, func(cfg *Config) { cfg.Role = Initiator })
		check(t, c, PreCER, false)
		c.Handle(event(Start))
		check(t, c, WaitCEA, false)
		c.Handle(event(Retire))
		check(t, c, Retired, false)
	})
	t.Run("ExternalAdmission", func(t *testing.T) {
		c := admitted(t, false)
		check(t, c, Open, true)
		c.RefreshAdmission(nil)
		check(t, c, PreCER, false)
		c.RefreshAdmission(&PeerClaims{Host: "remote.example", Realm: "example"})
		check(t, c, Open, true)
	})
}
