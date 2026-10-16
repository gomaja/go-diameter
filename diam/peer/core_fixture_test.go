package peer

import (
	"errors"
	"fmt"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

// bootstrapSessionProtocol admits a fixture through the production responder
// handshake. The session keeps the original Manager's allocator and executor;
// setup-only actor notifications go to a private queue. Call before starting
// any session worker or actor loop.
func bootstrapSessionProtocol(s *session) error {
	if s == nil || s.actor == nil {
		return errors.New("fixture requires an actor-bound session")
	}
	if s.core != nil {
		return nil
	}
	a, manager := s.actor, s.actor.m
	health, pending, num, peerState, failures := a.watchdog, a.pendingWatchdog, a.numDWA, a.state, a.failures
	if a.events == nil {
		a.events = make(chan event, 64)
	}
	if a.done == nil {
		a.done = make(chan struct{})
	}
	if s.writes == nil {
		s.writes = make(chan writeRequest, 64)
	}
	if s.closed == nil {
		s.closed = make(chan struct{})
	}
	if manager.controls == nil {
		manager.controls = make(map[*session]map[uint32]struct{})
	}
	// Only actor publication is muted. s.m remains manager throughout startup.
	a.m = &Manager{cfg: manager.cfg, callbackQ: make(chan PeerEvent, 128)}
	defer func() { a.m = manager; a.failures = failures }()
	a.state = Closed
	a.active, a.r, a.i = nil, nil, nil
	a.nextGen = s.gen
	if a.nextGen > 0 {
		a.nextGen--
	}
	if health == WatchdogDown || health == WatchdogReopen {
		a.watchdog = WatchdogDown
	} else {
		a.watchdog = WatchdogInitial
	}
	a.publish(nil)
	s.inbound = true
	if err := s.initProtocol(); err != nil {
		return err
	}
	s.runProtocol(protocol.Input{Kind: protocol.Start}, s.takeStartup(), nil)
	remote := testBase(string(a.cfg.Host))
	cer, err := base.BuildCER(s.m.dictionary(), remote)
	if err != nil {
		return err
	}
	s.applyProtocol(protocol.Input{Kind: protocol.Receive, Message: cer}, nil)
	if s.core.Snapshot().Phase() != protocol.Open {
		return fmt.Errorf("fixture handshake phase=%v", s.core.Snapshot().Phase())
	}
	select {
	case w := <-s.writes:
		if w.msg == nil || w.msg.Header.CommandCode != diam.CapabilitiesExchange || w.msg.Header.CommandFlags&diam.RequestFlag != 0 {
			return errors.New("fixture handshake selected no CEA")
		}
		fixtureCompleteWrite(s, w)
	default:
		return errors.New("fixture handshake did not queue CEA")
	}
	if peerState == IOpen {
		a.state = IOpen
		a.i = s
		a.r = nil
	} else {
		a.state = ROpen
		a.r = s
		a.i = nil
	}
	a.active = s
	if health == WatchdogSuspect {
		fixtureExpireWatchdog(a)
		fixtureConsumeProbe(s)
		fixtureExpireWatchdog(a)
	} else if health == WatchdogReopen || health == WatchdogDown {
		// REOPEN starts with a real queued recovery probe. Credit earlier rounds
		// using the same peer identity and allocator reservation as normal traffic.
		for i := 0; i < num; i++ {
			request := fixtureConsumeProbe(s)
			answer, err := base.BuildDWA(request, testBase(string(a.cfg.Host)))
			if err != nil {
				return err
			}
			s.applyProtocol(protocol.Input{Kind: protocol.Receive, Message: answer}, nil)
			if i+1 < num || pending {
				fixtureExpireWatchdog(a)
			}
		}
		if num == 0 && !pending && health == WatchdogReopen {
			fixtureConsumeProbe(s)
		}
	} else if pending {
		fixtureExpireWatchdog(a)
		fixtureConsumeProbe(s)
	}
	a.publish(nil)
	return nil
}

func ensureSessionProtocol(s *session) {
	if err := bootstrapSessionProtocol(s); err != nil {
		panic(err)
	}
}

func fixtureCompleteWrite(s *session, w writeRequest) {
	s.writeProtocol(w)
	for len(s.actor.events) > 0 {
		s.actor.handle(<-s.actor.events)
	}
}

func fixtureConsumeProbe(s *session) *diam.Message {
	select {
	case w := <-s.writes:
		if w.msg == nil || w.msg.Header.CommandCode != diam.DeviceWatchdog || w.msg.Header.CommandFlags&diam.RequestFlag == 0 {
			panic("fixture expected DWR")
		}
		fixtureCompleteWrite(s, w)
		return w.msg
	default:
		panic("fixture has no selected DWR")
	}
}

func fixtureExpireWatchdog(a *actor) {
	s := a.active
	if s == nil {
		return
	}
	ensureSessionProtocol(s)
	timer := s.protocolSnapshot().Timer(protocol.WatchdogTimer)
	s.applyProtocol(protocol.Input{Kind: protocol.TimerExpired, Timer: protocol.WatchdogTimer, Token: timer.Token, At: timer.Deadline}, nil)
}

// Compatibility names are test-only executors, never alternate protocol logic.
func (a *actor) watchdogTick() {
	fixtureExpireWatchdog(a)
}

func (a *actor) sendWatchdog() {
	fixtureExpireWatchdog(a)
}

func (a *actor) watchdogReceive(msg *diam.Message) bool {
	return a.watchdogReceiveAt(msg, a.m.now())
}

func (a *actor) watchdogReceiveAt(msg *diam.Message, at time.Time) bool {
	if a.active == nil {
		return false
	}
	ensureSessionProtocol(a.active)
	s := a.active
	before := s.protocolSnapshot().Watchdog()
	s.applyProtocol(protocol.Input{Kind: protocol.Receive, Message: msg, At: at}, nil)
	after := s.protocolSnapshot().Watchdog()
	if msg.Header.CommandCode == diam.DeviceWatchdog && msg.Header.CommandFlags&diam.RequestFlag == 0 {
		return before.Pending && !after.Pending
	}
	return true
}

func (a *actor) onOpen() {
	s := a.active
	if s == nil {
		s = a.r
	}
	if s == nil {
		s = a.i
	}
	ensureSessionProtocol(s)
}

func (a *actor) answerDPR(s *session, msg *diam.Message) {
	ensureSessionProtocol(s)
	a.onWire(event{s: s, msg: msg})
}
