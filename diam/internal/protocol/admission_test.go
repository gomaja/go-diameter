package protocol

import (
	"slices"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/watchdog"
)

func admitted(t *testing.T, cer bool) *Core {
	t.Helper()
	cfg := configuration(t)
	cfg.Watchdog, cfg.WatchdogInterval = true, watchdog.MinimumTw
	c, err := NewAdmitted(cfg, PeerClaims{Host: "remote.example", Realm: "example", RemoteApplications: []uint32{4}, CER: cer})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestExternalAdmissionStartsWithoutExchange(t *testing.T) {
	c := admitted(t, true)
	if s := c.Snapshot(); s.Phase() != Open || !s.Ready() || !c.PassiveResponder() || !c.started || c.handshakePending {
		t.Fatalf("external admission did not start Open: %+v", s)
	}
	wantKinds(t, c.Handle(event(Start)))
	for kind := HandshakeTimer; kind < timerCount; kind++ {
		if c.Snapshot().Timer(kind).Token != 0 {
			t.Fatalf("external admission armed %v", kind)
		}
	}
	if c.cfg.Watchdog || len(c.Snapshot().Capabilities().LocalApplications) != 0 {
		t.Fatal("external admission derived capabilities or enabled supervision")
	}
	m := diam.NewMessage(999, 0, 0, 10, 20, c.cfg.Dictionary)
	in := receive(m)
	in.HasHandler = true
	wantKinds(t, c.Handle(in), Admit)
	wantKinds(t, c.Handle(receive(cer(t))), Discard)
	other := admitted(t, false)
	wantKinds(t, other.Handle(receive(cer(t))), Discard, Notify)
}

func TestExternalAdmissionClaimsAreCopiedAndRefreshed(t *testing.T) {
	c := admitted(t, true)
	peer := PeerClaims{Host: "new.example", Realm: "new.realm", LocalApplications: []uint32{4}, RemoteApplications: []uint32{4, 1001}}
	c.RefreshAdmission(&peer)
	peer.LocalApplications[0], peer.RemoteApplications[0] = 99, 99
	caps := c.Snapshot().Capabilities()
	if caps.Host != "new.example" || caps.Realm != "new.realm" || !slices.Equal(caps.LocalApplications, []uint32{4}) || !slices.Equal(caps.RemoteApplications, []uint32{4, 1001}) || !slices.Equal(caps.CommonApplications, []uint32{4}) {
		t.Fatalf("claims alias or stale identity: %+v", caps)
	}
	c.RefreshAdmission(nil)
	if s := c.Snapshot(); s.Phase() != PreCER || s.Ready() || s.Capabilities().Host != "" || !c.cfg.Watchdog {
		t.Fatalf("metadata removal did not restore CER gating: %+v", s)
	}
	// A real exchange resumes configured capabilities and supervision, and ends
	// trust in mutable frontend metadata (RFC 6733 §§5.3, 5.6).
	activated := accept(t, c)
	sent := find(t, activated, Send)
	ready := find(t, c.Handle(complete(sent)), HandshakeReady)
	release := event(ReleaseAdmission)
	release.Token, release.Interval = ready.Token, time.Minute
	c.Handle(release)
	if c.PassiveResponder() || c.Snapshot().Timer(WatchdogTimer).Token == 0 {
		t.Fatal("genuine CER did not resume ordinary responder ownership")
	}
	c.RefreshAdmission(&PeerClaims{Host: "forged.example"})
	if c.Snapshot().Capabilities().Host != "remote.example" {
		t.Fatal("frontend metadata replaced the genuinely admitted identity")
	}
}

func TestExternalAdmissionCannotReopenGeneration(t *testing.T) {
	for _, terminal := range []InputKind{Disconnect, TransportLost, Retire} {
		t.Run(map[InputKind]string{Disconnect: "closing", TransportLost: "closed", Retire: "retired"}[terminal], func(t *testing.T) {
			c := admitted(t, true)
			in := event(terminal)
			in.Timeout = time.Second
			c.Handle(in)
			phase := c.Snapshot().Phase()
			c.RefreshAdmission(nil)
			c.RefreshAdmission(&PeerClaims{Host: "forged.example"})
			if c.Snapshot().Phase() != phase || c.Snapshot().Ready() {
				t.Fatal("external metadata reopened a generation")
			}
		})
	}
	normal := opened(t)
	normal.RefreshAdmission(&PeerClaims{Host: "forged.example"})
	if normal.Snapshot().Capabilities().Host != "remote.example" {
		t.Fatal("external metadata changed an ordinary responder")
	}
}

func TestExternalAdmissionRefreshesClaimsDuringClosing(t *testing.T) {
	c := admitted(t, true)
	in := event(Disconnect)
	in.Timeout = time.Second
	c.Handle(in)
	c.RefreshAdmission(&PeerClaims{Host: "updated.example", Realm: "example"})
	if c.Snapshot().Phase() != Closing || c.Snapshot().Capabilities().Host != "updated.example" || c.Snapshot().Ready() {
		t.Fatal("Closing did not retain live claims without reopening")
	}
	c.RefreshAdmission(nil)
	if c.Snapshot().Phase() != Closing || c.Snapshot().Capabilities().Host != "" || c.Snapshot().Ready() {
		t.Fatal("Closing retained revoked claims or reopened")
	}
}

func TestGenuineCERHookRetainsResponderOwnership(t *testing.T) {
	c := admitted(t, false)
	c.cfg.Hooks = true
	c.RefreshAdmission(nil)
	hook := find(t, c.Handle(receive(cer(t))), RunHook)
	if c.PassiveResponder() {
		t.Fatal("genuine CER hook retained external ownership")
	}
	// Claims arriving during the hook cannot replace the pending exchange.
	c.RefreshAdmission(&PeerClaims{Host: "forged.example", CER: true})
	if c.Snapshot().Phase() != PreCER || c.Snapshot().Ready() {
		t.Fatal("external claims bypassed the pending CER hook")
	}
	in := event(Continue)
	in.Token, in.Message = hook.Token, hook.Message
	candidate := find(t, c.Handle(in), ValidatedCER)
	in = event(Activate)
	in.Token = candidate.Token
	sent := find(t, c.Handle(in), Send)
	ready := find(t, c.Handle(complete(sent)), HandshakeReady)
	in = event(ReleaseAdmission)
	in.Token, in.Interval = ready.Token, time.Minute
	c.Handle(in)
	c.RefreshAdmission(&PeerClaims{Host: "forged.example", CER: true})
	s := c.Snapshot()
	if c.PassiveResponder() || !s.Ready() || s.Capabilities().Host != "remote.example" || s.Timer(WatchdogTimer).Token == 0 {
		t.Fatal("genuine admission lost its identity, admission barrier or supervision")
	}
}
