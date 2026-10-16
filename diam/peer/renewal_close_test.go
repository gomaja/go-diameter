package peer

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// Close waits at the generation write gate. RetirementReason exposes the
// Server's intervening lifecycle latch, and stale Close cannot close its owner.
type renewalCloseRaceConn struct {
	*fakeConn
	reason                  atomic.Uint32
	closeStarted            atomic.Bool
	ordinary                chan struct{}
	ordinaryGate            chan struct{}
	closeEntered, closeGate chan struct{}
	ordinaryOnce            sync.Once
	closeOnce               sync.Once
	gateOnce                sync.Once
}

func (*renewalCloseRaceConn) Generation() uint64 { return 1 }
func (c *renewalCloseRaceConn) RetirementReason() diam.RetirementReason {
	reason := diam.RetirementReason(c.reason.Load())
	if reason == 0 && c.closeStarted.Load() {
		c.ordinaryOnce.Do(func() { close(c.ordinary) })
		<-c.ordinaryGate
	}
	return reason
}
func (c *renewalCloseRaceConn) Close() {
	c.closeStarted.Store(true)
	c.closeOnce.Do(func() { close(c.closeEntered) })
	<-c.closeGate
	if c.reason.Load() == 0 {
		c.fakeConn.Close()
	}
}
func (c *renewalCloseRaceConn) Closed() bool {
	return c.reason.Load() != 0 || c.fakeConn.Closed()
}
func (c *renewalCloseRaceConn) unblock() { c.gateOnce.Do(func() { close(c.closeGate) }) }

func TestManagerRenewalCloseWatcherJoinsInterveningRetirement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m, err := New(Config{Settings: testSettings("local.example.net"), Clock: &fakeClock{}})
		if err != nil {
			t.Fatal(err)
		}
		c := &renewalCloseRaceConn{fakeConn: newFakeConn(), ordinary: make(chan struct{}), ordinaryGate: make(chan struct{}), closeEntered: make(chan struct{}), closeGate: make(chan struct{})}
		defer c.unblock()
		a := &actor{m: m, cfg: PeerConfig{Host: "known.example.net", NoAutoReconnect: true}, state: ROpen, snapshotValue: fixtureHealth(WatchdogOkay), everOpen: true, events: make(chan event, 8), done: make(chan struct{})}
		s := &session{m: m, c: c, actor: a, gen: 1, inbound: true, closed: make(chan struct{}), ingress: make(chan incoming, 4), writes: make(chan writeRequest, 4)}
		s.admitted.Store(true)
		a.r, a.active = s, s
		a.meta = &smpeer.Metadata{OriginHost: "known.example.net", OriginRealm: "example.net", Applications: []uint32{4}}
		renewalCoreSession(t, s, true, true, "example.net")
		a.syncProtocol(s, protocol.Input{Kind: protocol.ReleaseAdmission})
		a.publish(nil)
		m.peers[identity(a.cfg.Host)] = a
		m.sessions[c] = s
		watched, closing := make(chan struct{}), make(chan struct{})
		go func() { s.close(); close(closing) }()
		renewalScriptReceive(t, c.closeEntered, "local close waiting at the write gate")
		m.wg.Add(1)
		go func() { s.watch(); close(watched) }()
		renewalScriptReceive(t, c.ordinary, "watcher choosing ordinary closure")
		synctest.Wait() // Watcher's first check read ordinary closure; Close is held.
		// Server retires while old Close waits; dispatch's connGone cannot
		// rescue this path because retired session events are discarded.
		c.reason.Store(uint32(diam.SCTPAssociationRestart))
		close(c.ordinaryGate) // Complete the first check with its already-read zero.
		a.events <- event{kind: connGone, s: s, gen: 1}
		m.wg.Add(1)
		go a.run()
		t.Cleanup(func() {
			c.unblock()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := m.Close(ctx, 0); err != nil {
				t.Error(err)
			}
		})
		c.unblock()
		renewalScriptReceive(t, closing, "fenced old Close completion")
		renewalScriptReceive(t, watched, "close watcher completion")
		// This lookup follows the watcher, as in the reported interleaving.
		_ = m.HandleRetire(c, diam.SCTPAssociationRestart)
		synctest.Wait()
		if p := a.snapshot(); p.State != Closed || p.Watchdog != WatchdogDown {
			t.Fatalf("watcher bypassed retirement acknowledgement: peer=%+v", p)
		}
		if a.active != nil || a.r != nil || m.getSession(c) != nil {
			t.Fatal("retired session retained actor or registration ownership")
		}
	})
}

func TestManagerRenewalTerminalDecisionVetoesRenewal(t *testing.T) {
	for _, immediate := range []bool{false, true} {
		t.Run(fmt.Sprintf("immediate=%t", immediate), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				m, err := New(Config{Settings: testSettings("local.example.net"), Clock: &fakeClock{}})
				if err != nil {
					t.Fatal(err)
				}
				c := &renewalCloseRaceConn{fakeConn: newFakeConn(), ordinary: make(chan struct{}), ordinaryGate: make(chan struct{}), closeEntered: make(chan struct{}), closeGate: make(chan struct{})}
				close(c.ordinaryGate)
				defer c.unblock()
				a := &actor{m: m, cfg: PeerConfig{Host: "known.example.net", NoAutoReconnect: true}, state: ROpen, snapshotValue: fixtureHealth(WatchdogOkay), everOpen: true, events: make(chan event, 4), done: make(chan struct{})}
				s := &session{m: m, c: c, actor: a, gen: 1, inbound: true, closed: make(chan struct{}), ingress: make(chan incoming, 4), writes: make(chan writeRequest, 4)}
				s.admitted.Store(true)
				a.r, a.active = s, s
				renewalCoreSession(t, s, true, true, "example.net")
				a.syncProtocol(s, protocol.Input{Kind: protocol.ReleaseAdmission})
				a.publish(nil)
				m.peers[identity(a.cfg.Host)] = a
				m.sessions[c] = s
				m.wg.Add(1)
				go a.run()
				t.Cleanup(func() {
					c.unblock()
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					if err := m.Close(ctx, 0); err != nil {
						t.Error(err)
					}
				})
				if !m.CanRenewAcceptedCER(c) {
					t.Fatal("live admitted responder was not initially renewable")
				}
				var closing chan struct{}
				if immediate {
					closing = make(chan struct{})
					go func() { s.close(); close(closing) }()
					renewalScriptReceive(t, c.closeEntered, "terminal Close blocked at transport")
				} else if err := s.send(capabilitiesExchangeRequest(t).Answer(diam.InvalidHDRBits), true); err != nil {
					t.Fatal(err)
				}
				if c.Closed() {
					t.Fatal("test did not hold the physical close")
				}
				if m.CanRenewAcceptedCER(c) {
					t.Error("terminal session decision remained eligible before physical close")
				}
				c.unblock()
				if closing != nil {
					renewalScriptReceive(t, closing, "terminal Close completion")
				}
				if err := m.HandleRetire(c, diam.SCTPAssociationRestart); err == nil {
					t.Error("retirement accepted a terminal session decision")
				}
				synctest.Wait()
				if a.snapshot().State != Closed || a.active != nil {
					t.Error("vetoing renewal bypassed actor retirement")
				}
			})
		})
	}
}

func TestManagerRenewalCommittedTerminalAnswerWins(t *testing.T) {
	for _, mode := range []int{0, 1, 2, -1} {
		for _, restart := range []bool{false, true} {
			t.Run(fmt.Sprintf("dispatch=%d/restart=%t", mode, restart), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					h := renewalScriptNew(t, mode, true, true, nil)
					h.open(t)
					s := h.m.getSession(h.initial)
					hold := &renewalScriptWriterHold{Conn: s.c, entered: make(chan struct{}), release: make(chan struct{})}
					defer hold.unblock()
					s.c = hold
					sentinel := outboundRequest("known.example.net", "example.net")
					if err := s.send(sentinel, false); err != nil {
						t.Fatal(err)
					}
					h.message(t)
					renewalScriptReceive(t, hold.entered, "held old writer")
					invalid := renewalScriptCER(t, "known.example.net", "example.net", 4, 111)
					invalid.Header.ApplicationID = 4
					h.feed(t, invalid)
					e := renewalScriptReceive(t, h.protocol, "committed invalid-CER rejection")
					if e.Err.Kind() != diam.ProtocolInvalidHeader || e.Err.ResultCode() != diam.InvalidHDRBits || !e.Closing || e.Reply != diam.ProtocolReplyQueued {
						t.Fatalf("terminal notification=%+v", e)
					}
					if len(s.writes) != 1 {
						t.Fatal("terminal answer was not queued behind the held writer")
					}
					if h.m.CanRenewAcceptedCER(h.initial) {
						t.Error("committed terminal answer remained eligible for CER renewal")
					}
					if restart {
						h.restart()
					} else {
						h.feed(t, renewalScriptCER(t, "known.example.net", "fresh.example.net", 5, 222))
					}
					synctest.Wait()
					if len(h.pairs) != 0 {
						t.Error("renewal discarded a committed terminal rejection")
					}
					hold.unblock()
					if !restart {
						h.answer(t, diam.CapabilitiesExchange, diam.InvalidHDRBits)
					}
					synctest.Wait()
					select {
					case <-h.transport.closed:
					default:
						t.Error("terminal protocol decision did not close the physical connection")
					}
				})
			})
		}
	}
}
