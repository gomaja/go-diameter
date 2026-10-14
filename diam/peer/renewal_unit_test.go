package peer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// A missing per-generation hook leaves restart closing the accepted socket.
func TestManagerRenewalInterfaces(t *testing.T) {
	m, err := New(Config{Settings: testSettings("local.example.net")})
	if err != nil {
		t.Fatal(err)
	}
	defer closeManager(t, m, nil)
	for _, check := range []struct {
		name string
		ok   bool
	}{
		{"accept", func() bool { _, ok := diam.HandlerAs[diam.AcceptHandler](m); return ok }()},
		{"retire", func() bool { _, ok := diam.HandlerAs[diam.RetireHandler](m); return ok }()},
		{"CER eligibility", func() bool { _, ok := diam.HandlerAs[diam.AcceptedCERHandler](m); return ok }()},
	} {
		if !check.ok {
			t.Errorf("Manager missing %s hook", check.name)
		}
	}
}

func renewalCompositionActor(t *testing.T, state PeerState, local string, responder, activeR, activeI bool) (*Manager, *actor, *session, *session, *fakeClock) {
	testDict := newTestDictionary(creditcontrol.Dictionary())

	t.Helper()
	clock := &fakeClock{}
	settings := testSettings(local, testDict)
	settings.AuthApplicationID = []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)), diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(5))}
	m, err := New(Config{Settings: settings, Clock: clock, Logger: logtest.New().Logger()})
	if err != nil {
		t.Fatal(err)
	}
	a := &actor{m: m, cfg: PeerConfig{Host: "known.example.net", NoAutoReconnect: true}, state: state, watchdog: WatchdogInitial, nextGen: 17, pendingGen: 11, dialing: state == WaitConnAck || state == WaitConnAckElect, events: make(chan event, 16), done: make(chan struct{})}
	i := &session{m: m, c: newFakeConn(testDict), actor: a, gen: 11, writes: make(chan writeRequest, 16), closed: make(chan struct{}), meta: &smpeer.Metadata{OriginHost: "known.example.net", OriginRealm: "initiator.example.net", Applications: []uint32{4}}}
	r := &session{m: m, c: newFakeConn(testDict), actor: a, gen: 7, inbound: true, writes: make(chan writeRequest, 16), ingress: make(chan incoming, 16), closed: make(chan struct{}), cerRequest: reviewCER(t), meta: &smpeer.Metadata{OriginHost: "known.example.net", OriginRealm: "old.example.net", Applications: []uint32{4}}}
	if state == WaitICEA || state == WaitReturns || activeI {
		a.i = i
	}
	if responder {
		a.r = r
	}
	if activeR {
		a.active = r
		a.meta = r.meta.Clone()
		a.watchdog = WatchdogOkay
		a.everOpen = true
		r.admitted.Store(true)
	}
	if activeI {
		a.active = i
		a.meta = i.meta.Clone()
		a.watchdog = WatchdogOkay
		a.everOpen = true
		if state == IOpen {
			a.armWatchdog()
		}
	}
	if state == WaitICEA || state == WaitReturns {
		request, err := base.BuildCER(testDict, m.baseSettings(i.c))
		if err != nil {
			t.Fatal(err)
		}
		i.cerRequest = request
		i.cerHop = request.Header.HopByHopID
		i.cerEnd = request.Header.EndToEndID
	}
	a.publish(nil)
	m.peers[identity(a.cfg.Host)] = a
	m.sessions[r.c] = r
	if a.i != nil {
		m.sessions[i.c] = i
	}
	m.wg.Add(1)
	go a.run()
	t.Cleanup(func() {
		i.close()
		a.post(event{kind: connGone, s: i})
		m.closeSessions()
		a.post(event{kind: timeout})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := m.Close(ctx, 0); err != nil {
			t.Error(err)
		}
	})
	synctest.Wait()
	return m, a, i, r, clock
}

func renewalCompositionCommit(a *actor, e event) {
	d := newProtocolDelivery()
	a.commit(e, d)
}

func renewalCompositionCEA(t *testing.T, m *Manager, a *actor, i *session) {
	t.Helper()
	request := i.cerRequest
	if request == nil {
		select {
		case write := <-i.writes:
			request = write.msg
		default:
			t.Fatal("initiator CER not queued")
		}
	}
	request.Header.HopByHopID = i.cerHop
	request.Header.EndToEndID = i.cerEnd
	cfg := testBase("known.example.net")
	cfg.OriginRealm = "initiator.example.net"
	cfg.AuthApplicationID = []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4))}
	answer, err := base.BuildCEA(request, cfg, diam.Success)
	if err != nil {
		t.Fatal(err)
	}
	renewalCompositionCommit(a, event{kind: wireEvent, s: i, msg: answer})
	synctest.Wait()
	if p := m.Peers()[0]; p.State != IOpen || p.Realm != "initiator.example.net" || !reflect.DeepEqual(p.Applications, []uint32{4}) {
		t.Fatalf("surviving initiator CEA=%+v", p)
	}
}

func TestManagerRenewalReplacementCERStateTable(t *testing.T) {
	testDict := newTestDictionary(creditcontrol.Dictionary())

	for _, tc := range []struct {
		state, wantRetired, wantReplacement PeerState
		responder, activeR, activeI         bool
	}{
		{Closed, Closed, ROpen, false, false, false},
		{WaitConnAck, WaitConnAck, WaitConnAckElect, false, false, false},
		{WaitICEA, WaitICEA, WaitReturns, false, false, false},
		{WaitConnAckElect, WaitConnAck, WaitConnAckElect, true, false, false},
		{WaitReturns, WaitICEA, WaitReturns, true, false, false},
		{ROpen, Closed, ROpen, true, true, false},
		{IOpen, IOpen, IOpen, false, false, true},
		{Closing, Closed, ROpen, true, true, false},
		{Closing, Closing, Closing, false, false, true},
	} {
		for _, win := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/activeR=%t/activeI=%t/win=%t", tc.state, tc.activeR, tc.activeI, win), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					local := "a.example.net"
					if win {
						local = "z.example.net"
					}
					m, a, i, old, _ := renewalCompositionActor(t, tc.state, local, tc.responder, tc.activeR, tc.activeI)
					oldWatchdogTimer, oldWatchdogToken := a.wdTimer, a.wdToken
					if err := m.HandleRetire(old.c, diam.SCTPAssociationRestart); err != nil {
						t.Fatal(err)
					}
					synctest.Wait()
					if p := a.snapshot(); p.State != tc.wantRetired {
						t.Fatalf("retirement=%s want%s", p.State, tc.wantRetired)
					}
					freshConn := &capabilityWireConn{fakeConn: newFakeConn(testDict), wire: make(chan []byte, 16)}
					cleanup := m.HandleAccept(freshConn)
					defer cleanup()
					fresh := m.getSession(freshConn)
					if fresh == nil {
						t.Fatal("replacement not registered")
					}
					cer := renewalScriptCER(t, "known.example.net", "fresh.example.net", 5, 222)
					m.ServeDIAM(freshConn, cer)
					synctest.Wait()
					want := tc.wantReplacement
					if win && want == WaitReturns {
						want = ROpen
					}
					if p := a.snapshot(); p.State != want {
						t.Fatalf("replacement first CER=%+v want%s", p, want)
					}
					if tc.activeI {
						if !freshConn.Closed() || i.c.Closed() || a.active != i || a.meta.OriginRealm != "initiator.example.net" {
							t.Fatal("replacement candidate disturbed surviving initiator")
						}
						if a.wdTimer != oldWatchdogTimer || a.wdToken != oldWatchdogToken {
							t.Fatal("candidate retirement changed surviving initiator watchdog timer")
						}
						return
					}
					if freshConn.Closed() || a.r != fresh || fresh.meta == nil || fresh.meta.OriginRealm != "fresh.example.net" || !reflect.DeepEqual(fresh.meta.Applications, []uint32{5}) || fresh.gen == old.gen {
						t.Fatal("replacement reused retired session identity or capabilities")
					}
					if want == WaitConnAckElect {
						if len(freshConn.wire) != 0 || !a.dialing || a.pendingGen != 11 {
							t.Fatal("replacement prematurely answered or discarded pending dial")
						}
						renewalCompositionCommit(a, event{kind: dialDone, s: i, gen: 11})
						synctest.Wait()
						want = WaitReturns
						if win {
							want = ROpen
						}
						if p := a.snapshot(); p.State != want {
							t.Fatalf("pending dial completion=%+v want%s", p, want)
						}
					}
					if want == WaitReturns {
						if i.c.Closed() || len(freshConn.wire) != 0 {
							t.Fatal("losing election closed I or answered R before I CEA")
						}
						renewalCompositionCEA(t, m, a, i)
						if !freshConn.Closed() || a.active != i {
							t.Fatal("losing replacement survived initiator admission")
						}
					} else {
						wire := renewalScriptReceive(t, freshConn.wire, "replacement CEA")
						answer, err := diam.ReadMessage(bytes.NewReader(wire), testDict)
						if err != nil {
							t.Fatal(err)
						}
						if answer.Header.CommandCode != diam.CapabilitiesExchange || answer.Header.HopByHopID != cer.Header.HopByHopID || code(t, answer) != diam.Success {
							t.Fatal("winning replacement CEA did not match fresh CER")
						}
						if a.active != fresh || (win && (tc.wantReplacement == WaitReturns || tc.wantReplacement == WaitConnAckElect) && !i.c.Closed()) {
							t.Fatal("winning replacement did not select R and discard I")
						}
					}
				})
			})
		}
	}
}

func TestManagerRenewalWatchdogStatesEligibilityAndRetirement(t *testing.T) {
	for _, health := range []WatchdogState{WatchdogInitial, WatchdogOkay, WatchdogSuspect, WatchdogReopen, WatchdogDown} {
		t.Run(string(health), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				m, a, _, old, clock := renewalCompositionActor(t, ROpen, "z.example.net", true, true, false)
				a.watchdog = health
				a.pendingWatchdog = true
				a.watchdogHop = 41
				a.watchdogEnd = 42
				a.watchdogGen = old.gen
				a.numDWA = 2
				a.armWatchdog()
				oldToken, oldTimer := a.wdToken, a.wdTimer
				a.publish(nil)
				if !m.CanRenewAcceptedCER(old.c) {
					t.Fatalf("admitted active R with %s was ineligible", health)
				}
				if err := m.HandleRetire(old.c, diam.AcceptedCERRenewal); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				if m.CanRenewAcceptedCER(old.c) || a.watchdog != WatchdogDown || a.wdTimer != nil || a.wdToken == oldToken || a.pendingWatchdog || a.watchdogHop != 0 || a.watchdogEnd != 0 || a.watchdogGen != 0 || a.numDWA != 0 {
					t.Fatalf("retired %s retained health/control ownership", health)
				}
				oldTimer.(*fakeTimer).mu.Lock()
				active := oldTimer.(*fakeTimer).active
				oldTimer.(*fakeTimer).mu.Unlock()
				if active {
					t.Fatal("retirement left old watchdog timer armed")
				}
				freshConn := &capabilityWireConn{fakeConn: newFakeConn(), wire: make(chan []byte, 16)}
				cleanup := m.HandleAccept(freshConn)
				defer cleanup()
				m.ServeDIAM(freshConn, renewalScriptCER(t, "known.example.net", "fresh.example.net", 5, 222))
				synctest.Wait()
				fresh := m.getSession(freshConn)
				if a.watchdog != WatchdogReopen || a.snapshot().Eligible || !m.CanRenewAcceptedCER(freshConn) {
					t.Fatalf("replacement of %s did not enter renewable REOPEN", health)
				}
				renewalCompositionCommit(a, event{kind: watchdogTimeout, gen: old.gen, token: oldToken})
				clock.mu.Lock()
				timers := len(clock.timers)
				clock.mu.Unlock()
				if a.active != fresh || fresh.isRetired() || a.watchdog != WatchdogReopen || timers == 0 {
					t.Fatal("old watchdog callback changed replacement")
				}
			})
		})
	}
}

func TestManagerRenewalReplacementProcessesCurrentActorState(t *testing.T) {
	for _, changed := range []string{"dial ack", "dial nack", "initiator CEA"} {
		for _, win := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/win=%t", changed, win), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					local := "a.example.net"
					if win {
						local = "z.example.net"
					}
					state := WaitConnAckElect
					if changed == "initiator CEA" {
						state = WaitReturns
					}
					m, a, i, old, _ := renewalCompositionActor(t, state, local, true, false, false)
					if err := m.HandleRetire(old.c, diam.SCTPAssociationRestart); err != nil {
						t.Fatal(err)
					}
					freshConn := &capabilityWireConn{fakeConn: newFakeConn(), wire: make(chan []byte, 16)}
					cleanup := m.HandleAccept(freshConn)
					defer cleanup()
					// The replacement is registered but has not sent its first CER.
					// The surviving outbound exchange commits during that interval.
					switch changed {
					case "dial ack":
						renewalCompositionCommit(a, event{kind: dialDone, s: i, gen: 11})
					case "dial nack":
						renewalCompositionCommit(a, event{kind: dialDone, gen: 11, err: errors.New("synthetic dial failure")})
					case "initiator CEA":
						renewalCompositionCEA(t, m, a, i)
					}
					synctest.Wait()
					cer := renewalScriptCER(t, "known.example.net", "fresh.example.net", 5, 222)
					m.ServeDIAM(freshConn, cer)
					synctest.Wait()
					switch changed {
					case "initiator CEA":
						if a.snapshot().State != IOpen || a.active != i || i.c.Closed() || !freshConn.Closed() || a.meta.OriginRealm != "initiator.example.net" {
							t.Fatal("replacement ignored the initiator CEA committed before its CER")
						}
					case "dial ack":
						if win {
							if a.snapshot().State != ROpen || a.active.c != freshConn || !i.c.Closed() {
								t.Fatal("completed dial did not participate in winning replacement election")
							}
						} else {
							if a.snapshot().State != WaitReturns || i.c.Closed() || len(freshConn.wire) != 0 {
								t.Fatal("completed dial did not survive losing replacement election")
							}
							renewalCompositionCEA(t, m, a, i)
							if !freshConn.Closed() {
								t.Fatal("losing replacement remained after I CEA")
							}
						}
					case "dial nack":
						if a.snapshot().State != ROpen || a.active.c != freshConn || a.dialing {
							t.Fatal("replacement CER did not admit after dial failure committed Closed")
						}
					}
				})
			})
		}
	}
}

func TestManagerRenewalPendingAnswerRetirementBoundary(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(fmt.Sprintf("answerCommitted=%t", committed), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				m, a, _, old, _ := renewalCompositionActor(t, ROpen, "z.example.net", true, true, false)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				result := sendAsync(m, ctx, requestWithoutOrigins("known.example.net", "old.example.net"))
				request := renewalScriptReceive(t, old.writes, "pending old request").msg
				answer := request.Answer(diam.Success)
				if committed {
					renewalCompositionCommit(a, event{kind: wireEvent, s: old, msg: answer})
				}
				if err := m.HandleRetire(old.c, diam.SCTPAssociationRestart); err != nil {
					t.Fatal(err)
				}
				if !committed {
					renewalCompositionCommit(a, event{kind: wireEvent, s: old, msg: answer})
				}
				got := renewalScriptReceive(t, result, "pending completion at retirement boundary")
				if committed {
					if got.err != nil || got.answer != answer {
						t.Fatalf("retirement replaced committed answer=%+v", got)
					}
				} else if got.err == nil || got.answer != nil {
					t.Fatalf("queued retired answer completed request=%+v", got)
				}
				synctest.Wait()
				m.pendingMu.Lock()
				remaining := len(m.pending[old])
				controls := len(m.controls[old])
				m.pendingMu.Unlock()
				if remaining != 0 || controls != 0 {
					t.Fatal("completed retirement left old pending or control ownership")
				}
				if a.snapshot().State != Closed || a.snapshot().Eligible {
					t.Fatal("old answer reopened retired actor")
				}
			})
		})
	}
}

// A committed first-CER rejection wins even when its queued CEA/close has not
// reached the transport writer before the restart boundary.
func TestManagerRenewalRejectedAdmissionWins(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown peer", true: "malformed CER"}[malformed], func(t *testing.T) {
			m, err := New(Config{Settings: testSettings("local.example.net")})
			if err != nil {
				t.Fatal(err)
			}
			c := newFakeConn()
			s := &session{m: m, c: c, inbound: true, writes: make(chan writeRequest, 4), ingress: make(chan incoming, 4), closed: make(chan struct{})}
			m.sessions[c] = s
			if malformed {
				_ = m.answerMessageError(s, reviewCER(t), &diam.MessageError{ResultCode: diam.InvalidAVPLength})
			} else {
				m.processDIAM(s, reviewCER(t))
			}
			if len(s.writes) != 1 {
				t.Fatal("rejection did not queue its CEA")
			}
			if err = m.HandleRetire(c, diam.SCTPAssociationRestart); err == nil {
				t.Error("committed rejection allowed restart renewal")
			}
			closeManager(t, m, nil)
		})
	}
}

// Server timeout cleanup can run while the actor acknowledgement is pending;
// the eventual retirement must not recreate an already-cleaned tombstone.
func TestManagerRenewalCleanupBeforeAcknowledgement(t *testing.T) {
	m, err := New(Config{Settings: testSettings("local.example.net"), Clock: &fakeClock{}})
	if err != nil {
		t.Fatal(err)
	}
	c := newFakeConn()
	cleanup := m.HandleAccept(c)
	s := m.getSession(c)
	a := &actor{m: m, cfg: PeerConfig{Host: "known.example.net", NoAutoReconnect: true}, state: ROpen, watchdog: WatchdogOkay, everOpen: true, events: make(chan event, 1), done: make(chan struct{})}
	s.bind(a, 7)
	a.r, a.active = s, s
	a.publish(nil)
	m.peers[identity(a.cfg.Host)] = a
	retired := make(chan error, 1)
	go func() { retired <- m.HandleRetire(c, diam.SCTPAssociationRestart) }()
	<-s.closed
	cleanup()
	m.wg.Add(1)
	go a.run()
	select {
	case err := <-retired:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("late acknowledgement stalled")
	}
	m.mu.RLock()
	remaining := len(m.retiredSessions)
	m.mu.RUnlock()
	if remaining != 0 {
		t.Errorf("retirement recreated %d tombstones after cleanup", remaining)
	}
	closeManager(t, m, nil)
}

// The old token must be rejected while the new handshake/disconnect still has
// a timeout transition; checking only an already Closed peer misses this race.
func TestManagerRenewalStaleStateTimer(t *testing.T) {
	for _, state := range []PeerState{WaitICEA, Closing} {
		t.Run(string(state), func(t *testing.T) {
			a, s, _ := newWatchdogTestActor(t, WatchdogOkay)
			a.state = state
			if state == WaitICEA {
				a.i = s
				a.r = nil
				a.active = nil
			}
			notifications := make(chan diam.ProtocolErrorEvent, 2)
			a.m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { notifications <- e }
			a.arm(time.Second)
			oldToken := a.token
			a.arm(time.Second)
			a.handle(event{kind: timeout, token: oldToken})
			if a.state != state || s.c.Closed() {
				t.Errorf("stale timer ended new %s exchange: state=%s closed=%t", state, a.state, s.c.Closed())
			}
			if len(notifications) != 0 {
				t.Error("stale timer emitted a protocol notification")
			}
			a.stopTimer()
		})
	}
}

// Losing R before election must leave an established I available for its CEA.
func TestManagerRenewalRetirementDuringInitiatorCER(t *testing.T) {
	m, err := New(Config{Settings: testSettings("z.example.net"), Clock: &fakeClock{}})
	if err != nil {
		t.Fatal(err)
	}
	a := &actor{m: m, cfg: PeerConfig{Host: "known.example.net", NoAutoReconnect: true}, state: WaitConnAckElect, watchdog: WatchdogInitial, events: make(chan event, 4), done: make(chan struct{}), pendingGen: 7, nextGen: 7, dialing: true}
	r := &session{m: m, c: newFakeConn(), actor: a, gen: 6, inbound: true, closed: make(chan struct{}), writes: make(chan writeRequest, 4), cerRequest: reviewCER(t)}
	i := &session{m: m, c: newFakeConn(), actor: a, gen: 7, closed: make(chan struct{}), writes: make(chan writeRequest, 4)}
	a.r = r
	a.meta = &smpeer.Metadata{OriginHost: "known.example.net", OriginRealm: "example.net", Applications: []uint32{4}}
	a.publish(nil)
	m.peers[identity(a.cfg.Host)] = a
	m.sessions[r.c] = r
	entered, release := make(chan struct{}), make(chan struct{})
	i.beforeAdmission = func() { close(entered); <-release }
	m.wg.Add(1)
	go a.run()
	a.post(event{kind: dialDone, s: i, gen: 7})
	<-entered
	retired := make(chan struct{})
	go func() { _ = m.HandleRetire(r.c, diam.SCTPAssociationRestart); close(retired) }()
	select {
	case <-r.closed:
	case <-time.After(time.Second):
		t.Fatal("retirement latch did not seal responder")
	}
	close(release)
	select {
	case <-retired:
	case <-time.After(time.Second):
		t.Fatal("retirement did not acknowledge")
	}
	if i.c.Closed() || a.snapshot().State != WaitICEA || a.i != i {
		t.Errorf("retired candidate discarded initiator: closed=%t state=%s", i.c.Closed(), a.snapshot().State)
	}
	a.post(event{kind: timeout})
	awaitState(t, m, Closed)
	i.close()
	closeManager(t, m, nil)
}

// A retry paused after reservation still owns the logical request when that
// alternate retires; deleting its entry must not strand the next failover.
func TestManagerRenewalRetirementDuringFailover(t *testing.T) {
	m, _, sessions := outboundTestManager(t)
	third := &actor{m: m, cfg: PeerConfig{Host: "c.example.net"}, done: make(chan struct{}), events: make(chan event, 4), state: IOpen, watchdog: WatchdogOkay, meta: &smpeer.Metadata{OriginHost: "c.example.net", OriginRealm: "example.net", Applications: []uint32{4}}}
	c := &session{m: m, c: newFakeConn(), actor: third, gen: 3, writes: make(chan writeRequest, 4), closed: make(chan struct{})}
	third.i, third.active = c, c
	third.publish(nil)
	close(third.done)
	m.peers[identity(third.cfg.Host)] = third
	t.Cleanup(c.close)
	if err := m.SetRoutes([]Route{{Realm: "example.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"a.example.net", "b.example.net", "c.example.net"}}}); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	b := sessions[1]
	b.beforeAdmission = func() { close(entered); <-release }
	m.sessions[b.c] = b
	result := sendAsync(m, context.Background(), outboundRequest("", "example.net"))
	original := nextWrite(t, sessions[0])
	failed := make(chan struct{})
	go func() { sessions[0].close(); close(failed) }()
	<-entered
	if err := m.HandleRetire(b.c, diam.SCTPAssociationRestart); err != nil {
		t.Fatal(err)
	}
	close(release)
	select {
	case <-failed:
	case <-time.After(time.Second):
		t.Fatal("first failover stalled")
	}
	select {
	case w := <-c.writes:
		if w.msg.Header.HopByHopID == original.Header.HopByHopID || w.msg.Header.EndToEndID != original.Header.EndToEndID || w.msg.Header.CommandFlags&diam.RetransmittedFlag == 0 {
			t.Fatal("second failover identifiers changed")
		}
		answer := w.msg.Answer(diam.Success)
		m.receiveAnswer(c, answer)
	case <-time.After(time.Second):
		t.Error("retirement stranded an in-progress failover instead of trying the next peer")
		m.pendingMu.Lock()
		var p *pendingRequest
		for _, entry := range m.pending[sessions[0]] {
			p = entry
			break
		}
		m.pendingMu.Unlock()
		if p != nil {
			m.complete(p, nil, ErrFailover)
		}
	}
	select {
	case got := <-result:
		if got.err != nil && !errors.Is(got.err, ErrFailover) {
			t.Fatal(got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("request completion stranded")
	}
}

// Raw session deadlines bypass retirement; Server must own their bound.
func TestManagerRenewalWriteTimeout(t *testing.T) {
	for _, configured := range []time.Duration{0, -time.Second, time.Second, time.Minute} {
		t.Run(configured.String(), func(t *testing.T) {
			m, err := New(Config{Settings: testSettings("local.example.net"), Timers: Timers{Closing: 5 * time.Second}})
			if err != nil {
				t.Fatal(err)
			}
			srv := &diam.Server{WriteTimeout: configured}
			srv.Dict = m.cfg.Settings.Dict
			if err = m.BindServer(srv); err != nil {
				t.Fatal(err)
			}
			defer closeManager(t, m, srv)
			want := 5 * time.Second
			if configured > 0 && configured < want {
				want = configured
			}
			if srv.WriteTimeout != want {
				t.Fatalf("WriteTimeout=%v want %v", srv.WriteTimeout, want)
			}
		})
	}
}

// Retirement uses the R-disconnect rows, never a wholesale peer failure. The
// full normal event queue cannot prevent the reserved retirement command.
func TestManagerRenewalRetirementStateTable(t *testing.T) {
	for _, tc := range []struct {
		state, want                 PeerState
		responder, activeR, activeI bool
		watchdog, wantWatchdog      WatchdogState
	}{
		{Closed, Closed, false, false, false, WatchdogInitial, WatchdogInitial},
		{WaitConnAck, WaitConnAck, false, false, false, WatchdogInitial, WatchdogInitial},
		{WaitICEA, WaitICEA, false, false, false, WatchdogInitial, WatchdogInitial},
		{WaitConnAckElect, WaitConnAck, true, false, false, WatchdogInitial, WatchdogInitial},
		{WaitReturns, WaitICEA, true, false, false, WatchdogInitial, WatchdogInitial},
		{ROpen, Closed, true, true, false, WatchdogOkay, WatchdogDown},
		{IOpen, IOpen, false, false, true, WatchdogOkay, WatchdogOkay},
		{Closing, Closed, true, true, false, WatchdogOkay, WatchdogDown},
		{Closing, Closing, false, false, true, WatchdogSuspect, WatchdogSuspect},
	} {
		t.Run(string(tc.state)+"/"+string(tc.watchdog)+"/"+map[bool]string{false: "candidate", true: "activeR"}[tc.activeR], func(t *testing.T) {
			m, err := New(Config{Settings: testSettings("local.example.net"), Clock: &fakeClock{}, Limits: Limits{Events: 1}})
			if err != nil {
				t.Fatal(err)
			}
			a := &actor{m: m, cfg: PeerConfig{Host: "known.example.net", NoAutoReconnect: true}, state: tc.state, watchdog: tc.watchdog, everOpen: tc.activeR || tc.activeI, nextGen: 17, pendingGen: 11, dialing: tc.state == WaitConnAckElect, events: make(chan event, 1), done: make(chan struct{}), pendingDPR: 41, pendingDPREnd: 42, pendingWatchdog: true, watchdogHop: 43, watchdogEnd: 44, watchdogGen: 7, numDWA: 2}
			i := &session{m: m, c: newFakeConn(), actor: a, gen: 11, closed: make(chan struct{}), writes: make(chan writeRequest, 4)}
			r := &session{m: m, c: newFakeConn(), actor: a, gen: 7, inbound: true, closed: make(chan struct{}), writes: make(chan writeRequest, 4), cerRequest: reviewCER(t), cerHop: 31, cerEnd: 32}
			a.i = i
			if tc.responder {
				a.r = r
			}
			if tc.activeR {
				a.active = r
			}
			if tc.activeI {
				a.active = i
			}
			a.meta = &smpeer.Metadata{OriginHost: a.cfg.Host, OriginRealm: "example.net", Applications: []uint32{4}}
			a.publish(nil)
			m.peers[identity(a.cfg.Host)] = a
			m.sessions[r.c] = r
			m.nextHop = 88
			oldEnd := m.endToEnd.next.Load()
			a.events <- event{kind: wireEvent, s: r, msg: reviewCER(t)}
			retired := make(chan error, 1)
			go func() { retired <- m.HandleRetire(r.c, diam.SCTPAssociationRestart) }()
			select {
			case <-r.closed:
			case <-time.After(time.Second):
				t.Fatal("full actor queue prevented sealing")
			}
			m.wg.Add(1)
			go a.run()
			select {
			case err := <-retired:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("full actor queue prevented acknowledgement")
			}
			if p := a.snapshot(); p.State != tc.want || p.Watchdog != tc.wantWatchdog {
				t.Errorf("retired state=%+v want %s/%s", p, tc.want, tc.wantWatchdog)
			}
			if a.i != i || i.c.Closed() {
				t.Error("retirement discarded surviving I")
			}
			if a.r == r || m.getSession(r.c) != nil || !r.c.Closed() {
				t.Error("retired R retained ownership")
			}
			if a.nextGen != 17 || a.pendingGen != 11 || m.nextHop != 88 || m.endToEnd.next.Load() != oldEnd {
				t.Error("retirement reset peer or request identifiers")
			}
			if tc.activeR && (a.pendingWatchdog || a.watchdogHop != 0 || a.pendingDPR != 0 || a.numDWA != 0) {
				t.Error("retirement retained watchdog/disconnect identifiers")
			}
			if tc.activeI && (a.watchdogHop != 43 || a.pendingDPR != 41 || a.numDWA != 2) {
				t.Error("candidate retirement reset surviving initiator identifiers")
			}
			if r.cerRequest != nil || r.cerHop != 0 || r.cerEnd != 0 {
				t.Error("retired CER identifiers retained")
			}
			if err := m.HandleRetire(r.c, diam.SCTPAssociationRestart); err != nil {
				t.Fatal(err)
			}
			if tc.state == IOpen {
				a.post(event{kind: connGone, s: i})
			} else {
				a.post(event{kind: timeout})
			}
			awaitState(t, m, Closed)
			i.close()
			closeManager(t, m, nil)
		})
	}
}

// Exercise stale callbacks in states where a current callback changes state.
func TestManagerRenewalStaleTimerTokens(t *testing.T) {
	for _, state := range []PeerState{WaitICEA, Closing} {
		t.Run(string(state), func(t *testing.T) {
			a, s, _ := failureReportingActor(t)
			a.state, a.i, a.active, a.token = state, s, s, 20
			a.publish(nil)
			a.handle(event{kind: timeout, token: 19})
			if a.state != state || s.c.Closed() {
				t.Fatalf("stale timer closed current session: state=%s closed=%t", a.state, s.c.Closed())
			}
			a.handle(event{kind: timeout, token: 20})
			if a.state != Closed || !s.c.Closed() {
				t.Fatal("current timer did not close waiting session")
			}
		})
	}
	t.Run("watchdog", func(t *testing.T) {
		a, s, _ := failureReportingActor(t)
		a.state, a.r, a.active, a.watchdog, a.wdToken = ROpen, s, s, WatchdogOkay, 20
		a.publish(nil)
		a.handle(event{kind: watchdogTimeout, token: 19, gen: s.gen})
		if len(s.writes) != 0 || a.pendingWatchdog {
			t.Fatal("stale watchdog timer sent current-generation probe")
		}
		a.handle(event{kind: watchdogTimeout, token: 20, gen: s.gen})
		if len(s.writes) != 1 || !a.pendingWatchdog {
			t.Fatal("current watchdog timer did not send probe")
		}
		if w := <-s.writes; w.msg.Header.CommandCode != diam.DeviceWatchdog {
			t.Fatal("current watchdog timer sent wrong command")
		}
	})
	t.Run("reconnect", func(t *testing.T) {
		a, _, _ := failureReportingActor(t)
		a.tcToken = 20
		timer := a.m.cfg.Clock.AfterFunc(time.Minute, func() {})
		a.tcTimer = timer
		a.handle(event{kind: reconnectTimeout, token: 19})
		if a.tcTimer != timer {
			t.Fatal("stale reconnect timer cleared current timer")
		}
		a.handle(event{kind: reconnectTimeout, token: 20})
		if a.tcTimer != nil {
			t.Fatal("current reconnect timer retained expired timer")
		}
	})
}
