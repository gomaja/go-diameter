package peer

import (
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

func TestSuccessfulAutomaticReplyCompletesWithoutActorEvent(t *testing.T) {
	m, err := New(Config{Settings: testSettings("local.example.net"), Clock: &fakeClock{}})
	if err != nil {
		t.Fatal(err)
	}
	a := &actor{m: m, cfg: PeerConfig{Host: "known.example.net", NoAutoReconnect: true}, state: ROpen, watchdog: WatchdogOkay}
	s := &session{m: m, c: newFakeConn(), actor: a, gen: 3, requests: new(diam.PendingRequests)}
	if err := bootstrapSessionProtocol(s); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.close(); closeManager(t, m, nil) })
	s.applyProtocol(protocol.Input{Kind: protocol.Receive, Message: watchdogRequest(t)}, nil)
	var w writeRequest
	select {
	case w = <-s.writes:
	default:
		t.Fatal("DWR did not select DWA")
	}
	if len(a.events) != 0 {
		t.Fatal("reply queue acceptance posted an actor event")
	}
	if s.writeProtocol(w) {
		t.Fatal("successful reply closed connection")
	}
	if len(a.events) != 0 {
		t.Fatal("successful automatic reply woke the actor")
	}
	s.coreMu.Lock()
	writes, headers := len(s.coreWrites), len(s.coreHeaders)
	s.coreMu.Unlock()
	if writes != 0 || headers != 0 {
		t.Fatal("successful reply retained writer ownership")
	}
	if s.protocolSnapshot().Phase() != protocol.Open {
		t.Fatal("successful reply changed connection phase")
	}
}
