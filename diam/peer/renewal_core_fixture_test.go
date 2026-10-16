package peer

import (
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

// renewalCoreSession stages a real connection core before publishing its actor.
// A private setup actor executes the normal admission/election effects so a
// candidate stays unadmitted and an initiator retains its deferred Start effects.
func renewalCoreSession(t *testing.T, s *session, started, admitted bool, realm string) {
	t.Helper()
	owner := s.actor
	setup := &actor{m: s.m, cfg: owner.cfg, state: Closed, watchdog: WatchdogInitial,
		events: make(chan event, 64), done: make(chan struct{}), nextGen: s.gen - 1, pendingGen: s.gen}
	setup.publish(nil)
	s.actor = setup
	defer func() { s.actor = owner }()
	if err := s.initProtocol(); err != nil {
		t.Fatal(err)
	}
	if !s.inbound && !started {
		return
	}
	remote := testBase(string(owner.cfg.Host))
	remote.OriginRealm = datatype.DiameterIdentity(realm)
	if s.inbound {
		s.runProtocol(protocol.Input{Kind: protocol.Start}, s.takeStartup(), nil)
		if !admitted {
			setup.state = WaitConnAck
		}
		cer, err := base.BuildCER(s.m.dictionary(), remote)
		if err != nil {
			t.Fatal(err)
		}
		s.applyProtocol(protocol.Input{Kind: protocol.Receive, Message: cer}, nil)
		if admitted {
			w := renewalCoreWrite(t, s, diam.CapabilitiesExchange)
			fixtureCompleteWrite(s, w)
		}
	} else {
		setup.state = WaitConnAck
		setup.onDial(event{gen: s.gen, s: s})
		w := renewalCoreWrite(t, s, diam.CapabilitiesExchange)
		s.cerRequest = w.msg
		s.cerHop, s.cerEnd = w.msg.Header.HopByHopID, w.msg.Header.EndToEndID
		fixtureCompleteWrite(s, w)
		if admitted {
			cea, err := base.BuildCEA(w.msg, remote, diam.Success)
			if err != nil {
				t.Fatal(err)
			}
			s.applyProtocol(protocol.Input{Kind: protocol.Receive, Message: cea}, nil)
		}
	}
}

func renewalCoreWrite(t *testing.T, s *session, command uint32) writeRequest {
	t.Helper()
	select {
	case w := <-s.writes:
		if w.msg.Header.CommandCode != command {
			t.Fatalf("fixture queued %d, want %d", w.msg.Header.CommandCode, command)
		}
		return w
	default:
		t.Fatalf("fixture did not queue %d", command)
		return writeRequest{}
	}
}
