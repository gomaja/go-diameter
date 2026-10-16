package peer

import (
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

// A CER selected by a session not yet attached to either actor leg still owns
// its handshake, native publication and core writer completion during shutdown.
func TestActorShutdownSettlesUnattachedCoreCompletion(t *testing.T) {
	for _, observed := range []bool{false, true} {
		for _, late := range []bool{false, true} {
			t.Run(map[bool]string{false: "local close/", true: "observed close/"}[observed]+map[bool]string{false: "queued completion", true: "completion after actor exit"}[late], func(t *testing.T) {
				m, err := New(Config{Settings: testSettings("local.example.net"), Clock: &fakeClock{}, Timers: Timers{Closing: time.Second}})
				if err != nil {
					t.Fatal(err)
				}
				a := &actor{m: m, cfg: PeerConfig{Host: "known.example.net", NoAutoReconnect: true}, state: Closed, events: make(chan event, 8), done: make(chan struct{})}
				a.publish(nil)
				s := &session{m: m, c: newFakeConn(), actor: a, gen: 11, writes: make(chan writeRequest, 8), closed: make(chan struct{}), requests: new(diam.PendingRequests)}
				m.sessions[s.c] = s
				renewalCoreSession(t, s, false, false, "example.net")
				s.runProtocol(protocol.Input{Kind: protocol.Start}, s.takeStartup(), nil)
				w := renewalCoreWrite(t, s, diam.CapabilitiesExchange)
				wire, err := w.msg.Serialize()
				if err != nil {
					t.Fatal(err)
				}
				nativeDone := s.requests.BeginWrite(wire)
				nativeDone(true)
				if !s.requests.HasPending() {
					t.Fatal("fixture CER did not acquire native answer ownership")
				}
				if !late {
					s.finishProtocolWriter(w, protocol.WrittenStage, int64(len(wire)), nil)
				}
				if observed {
					s.closeObserved()
					if s.protocolSnapshot().Phase() != protocol.WaitCEA {
						t.Fatal("observed close prematurely terminalized core before decoded-message drain")
					}
				}
				a.closeOwnedSessions()
				close(a.done)
				if got := s.protocolSnapshot().Phase(); got != protocol.Closed {
					t.Errorf("shutdown left core phase %v", got)
				}
				if s.requests.HasPending() {
					t.Error("shutdown retained native CER answer ownership")
				}
				if late {
					s.finishProtocolWriter(w, protocol.WrittenStage, int64(len(wire)), nil)
				}
				snapshot := s.protocolSnapshot()
				if controls := snapshot.Controls(); len(controls) != 0 {
					t.Errorf("shutdown lost writer completion: controls=%+v", controls)
				}
				s.coreMu.Lock()
				pendingWrites := len(s.coreWrites)
				s.coreMu.Unlock()
				if pendingWrites != 0 {
					t.Errorf("shutdown retained %d selected native writer tickets", pendingWrites)
				}
				if timer := snapshot.Timer(protocol.HandshakeTimer); timer.Token != 0 {
					t.Errorf("shutdown left handshake timer armed: %+v", timer)
				}
				closeManager(t, m, nil)
			})
		}
	}
}
