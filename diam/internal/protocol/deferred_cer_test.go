package protocol

import (
	"testing"
	"time"
)

func TestDeferredCERStartsResponseWindowAtPeerCommit(t *testing.T) {
	c := machine(t, func(cfg *Config) { cfg.Role = Initiator })
	in := event(Start)
	in.DeferCER = true
	wantKinds(t, c.Handle(in))
	if c.Phase() != WaitCEA || c.Snapshot().Timer(HandshakeTimer).Token != 0 {
		t.Fatal("deferred startup did not commit without starting the response deadline")
	}
	in = event(BeginCER)
	in.At = epoch.Add(10 * time.Second)
	es := c.Handle(in)
	timer := find(t, es, ArmTimer)
	find(t, es, ReserveIDs)
	if timer.Deadline != epoch.Add(40*time.Second) {
		t.Fatalf("CER response deadline=%v", timer.Deadline)
	}
	wantKinds(t, c.Handle(in))
}

func TestDeferredCERClosureCompletesBeforePeerCommit(t *testing.T) {
	c := machine(t, func(cfg *Config) { cfg.Role = Initiator })
	in := event(Start)
	in.DeferCER = true
	c.Handle(in)
	es := c.Handle(event(TransportLost))
	n := find(t, es, Notify).Notification
	if n.Kind != HandshakeNotice || n.Outcome != ConnectionClosed {
		t.Fatal("closure lost the unstarted CER completion")
	}
	wantKinds(t, c.Handle(event(BeginCER)))
}
