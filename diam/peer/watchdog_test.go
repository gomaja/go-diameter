package peer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/sm"
)

func TestWatchdogTwMinimum(t *testing.T) {
	for _, tc := range []struct {
		name string
		tw   time.Duration
		fail bool
	}{
		{"default", 0, false},
		{"below minimum", 6*time.Second - time.Nanosecond, true},
		{"minimum", 6 * time.Second, false},
		{"negative", -time.Second, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := New(Config{Settings: testSettings("local.example.net"), Timers: Timers{TwInit: tc.tw}})
			if tc.fail {
				if err == nil || !strings.Contains(err.Error(), "TwInit") {
					t.Fatalf("New error = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if m.cfg.Timers.TwInit == 0 {
				t.Fatal("TwInit not defaulted")
			}
			closeManager(t, m, nil)
		})
	}
}

func newWatchdogTestActor(t *testing.T, state WatchdogState) (*actor, *session, *fakeClock) {
	t.Helper()
	clock := &fakeClock{}
	m, err := New(Config{Settings: testSettings("local.example.net"), Clock: clock, Timers: Timers{TwInit: time.Second}, watchdogTiming: &watchdogTiming{floor: time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	a := &actor{m: m, cfg: PeerConfig{Host: "known.example.net"}, state: ROpen, snapshotValue: fixtureHealth(state), everOpen: state != WatchdogInitial, events: make(chan event, 8), done: make(chan struct{})}
	s := &session{m: m, c: newFakeConn(), actor: a, gen: 7, writes: make(chan writeRequest, 8), closed: make(chan struct{})}
	a.r, a.active = s, s
	a.publish(nil)
	if state != WatchdogInitial && state != WatchdogDown {
		if err := bootstrapSessionProtocol(s); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { a.stopReconnect(); s.close(); closeManager(t, m, nil) })
	return a, s, clock
}

func testDWA(t *testing.T, a *actor) *diam.Message {
	t.Helper()
	ensureSessionProtocol(a.active)
	if !a.active.protocolSnapshot().Watchdog().Pending {
		a.sendWatchdog()
	}
	if len(a.active.writes) > 0 {
		fixtureConsumeProbe(a.active)
	}
	for _, control := range a.active.protocolSnapshot().Controls() {
		if control.Command == diam.DeviceWatchdog && control.Logical {
			request := diam.NewMessage(diam.DeviceWatchdog, diam.RequestFlag, 0, control.Reservation.Hop, control.Reservation.End, a.m.dictionary())
			request.Header.HopByHopID, request.Header.EndToEndID = control.Reservation.Hop, control.Reservation.End
			answer, err := base.BuildDWA(request, testBase("known.example.net"))
			if err != nil {
				t.Fatal(err)
			}
			return answer
		}
	}
	t.Fatal("core has no owned DWR")
	return nil
}

func TestValidateDWACommandFlags(t *testing.T) {
	for flags := 0; flags <= 255; flags++ {
		t.Run(fmt.Sprintf("%02x", flags), func(t *testing.T) {
			a, _, _ := newWatchdogTestActor(t, WatchdogOkay)
			answer := testDWA(t, a)
			answer.Header.CommandFlags = uint8(flags)
			a.watchdogReceive(answer)
			valid := !fixtureWatchdog(a).Pending
			// RFC 6733 §§3 and 5.5.2: ignore reserved low bits; successful
			// DWA must have all four defined command flags clear.
			if want := flags&0xf0 == 0; valid != want {
				t.Fatalf("DWA flags %#02x: credit=%t, want %t", flags, valid, want)
			}
		})
	}
}

func TestWatchdogReceiveReservedDWAFlags(t *testing.T) {
	for reserved := uint8(0); reserved <= 0x0f; reserved++ {
		t.Run(fmt.Sprintf("%02x", reserved), func(t *testing.T) {
			a, _, _ := newWatchdogTestActor(t, WatchdogReopen)
			answer := testDWA(t, a)
			answer.Header.CommandFlags = reserved
			if !a.watchdogReceive(answer) || fixtureWatchdog(a).Pending || fixtureWatchdog(a).NumDWA != 1 {
				t.Fatalf("reserved DWA flags %#02x: pending=%t recovery count=%d", reserved, fixtureWatchdog(a).Pending, fixtureWatchdog(a).NumDWA)
			}
		})
	}
}

// RFC 3539 Appendix A admitted rows are exercised through production core
// timers and receipts. INITIAL/DOWN transport admission is covered separately
// by Manager's handshake/reconnect tests rather than fabricated DWA ownership.
func TestRFC3539WatchdogTable(t *testing.T) {
	for _, tc := range []struct {
		name            string
		state           WatchdogState
		pending         bool
		event           string
		want            WatchdogState
		wantPending     bool
		wantNum, writes int
	}{
		{"OKAY/Tw expires no pending", WatchdogOkay, false, "timer", WatchdogOkay, true, 0, 1},
		{"OKAY/Tw expires pending", WatchdogOkay, true, "timer", WatchdogSuspect, true, 0, 0},
		{"OKAY/valid DWA", WatchdogOkay, true, "dwa", WatchdogOkay, false, 0, 0},
		{"OKAY/valid other message", WatchdogOkay, true, "other", WatchdogOkay, true, 0, 1},
		{"SUSPECT/valid DWA", WatchdogSuspect, true, "dwa", WatchdogOkay, false, 0, 0},
		{"SUSPECT/valid other message", WatchdogSuspect, true, "other", WatchdogOkay, true, 0, 1},
		{"SUSPECT/Tw expires", WatchdogSuspect, true, "timer", WatchdogDown, false, 0, 0},
		{"REOPEN/first valid DWA", WatchdogReopen, true, "dwa", WatchdogReopen, false, 1, 0},
		{"REOPEN/valid other message", WatchdogReopen, true, "other", WatchdogReopen, true, 0, 1},
		{"REOPEN/first unanswered expiry", WatchdogReopen, true, "timer", WatchdogReopen, true, -1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, s, _ := newWatchdogTestActor(t, tc.state)
			if tc.pending && !fixtureWatchdog(a).Pending {
				a.sendWatchdog()
				fixtureConsumeProbe(s)
			}
			switch tc.event {
			case "timer":
				a.watchdogTick()
			case "dwa":
				a.watchdogReceive(testDWA(t, a))
			case "other":
				a.watchdogReceive(watchdogRequest(t))
			}
			if a.publishedWatchdog() != tc.want || fixtureWatchdog(a).Pending != tc.wantPending || fixtureWatchdog(a).NumDWA != tc.wantNum {
				t.Fatalf("watchdog=%s pending=%t NumDWA=%d; want %s %t %d", a.publishedWatchdog(), fixtureWatchdog(a).Pending, fixtureWatchdog(a).NumDWA, tc.want, tc.wantPending, tc.wantNum)
			}
			if len(s.writes) != tc.writes {
				t.Fatalf("writes=%d want %d", len(s.writes), tc.writes)
			}
			if got, want := a.snapshot().Eligible, a.state == ROpen && tc.want == WatchdogOkay; got != want {
				t.Fatalf("Eligible=%t want %t", got, want)
			}
		})
	}
}

func TestWatchdogRecoveryCreditAndSecondExpiry(t *testing.T) {
	for _, prior := range []int{1, 2} {
		t.Run(fmt.Sprintf("credited=%d", prior), func(t *testing.T) {
			a, _, _ := newWatchdogTestActor(t, WatchdogReopen)
			for range prior {
				a.watchdogReceive(testDWA(t, a))
			}
			a.watchdogReceive(testDWA(t, a))
			if fixtureWatchdog(a).NumDWA != prior+1 || fixtureWatchdog(a).Pending || a.snapshot().Eligible != (prior == 2) {
				t.Fatalf("recovery credit state=%s NumDWA=%d Pending=%t Eligible=%t", a.publishedWatchdog(), fixtureWatchdog(a).NumDWA, fixtureWatchdog(a).Pending, a.snapshot().Eligible)
			}
		})
	}
	t.Run("second unanswered expiry", func(t *testing.T) {
		a, _, _ := newWatchdogTestActor(t, WatchdogReopen)
		a.watchdogTick()
		if fixtureWatchdog(a).NumDWA != -1 || !fixtureWatchdog(a).Pending {
			t.Fatalf("first unanswered expiry state=%s NumDWA=%d Pending=%t", a.publishedWatchdog(), fixtureWatchdog(a).NumDWA, fixtureWatchdog(a).Pending)
		}
		a.watchdogTick()
		if a.publishedWatchdog() != WatchdogDown || fixtureWatchdog(a).Pending || a.snapshot().Eligible {
			t.Fatalf("second unanswered expiry state=%s Pending=%t Eligible=%t", a.publishedWatchdog(), fixtureWatchdog(a).Pending, a.snapshot().Eligible)
		}
	})
	for _, history := range []WatchdogState{WatchdogInitial, WatchdogDown} {
		t.Run(string(history)+"/connection up", func(t *testing.T) {
			a, s, _ := newWatchdogTestActor(t, history)
			a.onOpen()
			if history == WatchdogInitial {
				if a.publishedWatchdog() != WatchdogOkay || fixtureWatchdog(a).Pending || !a.snapshot().Eligible || len(s.writes) != 0 {
					t.Fatalf("initial admission state=%s Pending=%t writes=%d", a.publishedWatchdog(), fixtureWatchdog(a).Pending, len(s.writes))
				}
			} else if a.publishedWatchdog() != WatchdogReopen || !fixtureWatchdog(a).Pending || fixtureWatchdog(a).NumDWA != 0 || a.snapshot().Eligible || len(s.writes) != 1 {
				t.Fatalf("recovery admission state=%s Pending=%t NumDWA=%d writes=%d", a.publishedWatchdog(), fixtureWatchdog(a).Pending, fixtureWatchdog(a).NumDWA, len(s.writes))
			}
		})
	}
}

func TestWatchdogReconnectAttemptRows(t *testing.T) {
	for _, state := range []WatchdogState{WatchdogInitial, WatchdogDown} {
		t.Run(string(state)+"/Tc expires", func(t *testing.T) {
			a, _, _ := newWatchdogTestActor(t, state)
			a.state = Closed
			a.cfg.Endpoints = []Endpoint{{Address: "127.0.0.1:1"}}
			a.m.cfg.Dial = func(context.Context, Endpoint) (net.Conn, error) { return nil, errors.New("refused") }
			a.m.mu.Lock()
			a.m.started = true
			a.m.mu.Unlock()
			a.reconnectTick()
			if a.state != WaitConnAck || !a.dialing {
				t.Fatalf("retry state=%s dialing=%v", a.state, a.dialing)
			}
		})
	}
}

func TestWatchdogMatchingAndRecovery(t *testing.T) {
	a, s, _ := newWatchdogTestActor(t, WatchdogDown)
	a.onOpen()
	if !fixtureWatchdog(a).Pending || fixtureWatchdog(a).NumDWA != 0 || a.snapshot().Eligible {
		t.Fatal("recovery opened before validation")
	}
	first := fixtureConsumeProbe(s)
	answer := func(request *diam.Message) *diam.Message {
		t.Helper()
		m, err := base.BuildDWA(request, testBase("known.example.net"))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	bad := answer(first)
	bad.Header.HopByHopID++
	a.onWire(event{s: s, msg: bad})
	if fixtureWatchdog(a).NumDWA != 0 || !fixtureWatchdog(a).Pending {
		t.Fatal("mismatched DWA counted")
	}
	a.onWire(event{s: s, msg: answer(first)})
	if fixtureWatchdog(a).NumDWA != 1 || a.snapshot().Eligible {
		t.Fatal("first DWA made peer eligible")
	}
	a.onWire(event{s: s, msg: answer(first)})
	if fixtureWatchdog(a).NumDWA != 1 {
		t.Fatal("duplicate DWA counted")
	}
	for want := 2; want <= 3; want++ {
		a.watchdogTick()
		probe := fixtureConsumeProbe(s)
		a.onWire(event{s: s, msg: answer(probe)})
		if fixtureWatchdog(a).NumDWA != want || a.snapshot().Eligible != (want == 3) {
			t.Fatalf("NumDWA=%d Eligible=%v", fixtureWatchdog(a).NumDWA, a.snapshot().Eligible)
		}
	}
	if a.publishedWatchdog() != WatchdogOkay {
		t.Fatalf("state=%s", a.publishedWatchdog())
	}
}

func TestWatchdogReopenSuppressesApplicationButAnswersDWR(t *testing.T) {
	a, s, clock := newWatchdogTestActor(t, WatchdogReopen)
	tw := clock.timers[len(clock.timers)-1]
	a.onWire(event{s: s, msg: diam.NewRequest(999, 0, a.m.dictionary())})
	if len(s.writes) != 0 {
		t.Fatal("application message dispatched in REOPEN")
	}
	if tw.active {
		t.Fatal("decoded REOPEN traffic did not reset its recovery timer")
	}
	tw = clock.timers[len(clock.timers)-1]
	dwr, err := base.BuildDWR(a.m.dictionary(), testBase("known.example.net"), 0)
	if err != nil {
		t.Fatal(err)
	}
	a.onWire(event{s: s, msg: dwr})
	if tw.active {
		t.Fatal("peer DWR did not reset the recovery timer")
	}
	if len(s.writes) != 1 || (<-s.writes).msg.Header.CommandFlags&diam.RequestFlag != 0 {
		t.Fatal("peer DWR not answered")
	}
}

func TestWatchdogTrafficResetsTwAndJitter(t *testing.T) {
	a, _, clock := newWatchdogTestActor(t, WatchdogOkay)
	first := clock.timers[len(clock.timers)-1]
	a.watchdogReceive(diam.NewRequest(999, 0, a.m.dictionary()))
	if first.active {
		t.Fatal("old Tw not stopped")
	}
	if len(clock.timers) < 2 || !clock.timers[len(clock.timers)-1].active {
		t.Fatal("new Tw not armed")
	}
	a.m.cfg.Timers.TwInit = 6 * time.Second
	a.m.cfg.watchdogTiming = nil
	for i := 0; i < 200; i++ {
		d := a.watchdogInterval()
		if d < 4*time.Second || d > 8*time.Second {
			t.Fatalf("Tw jitter %s outside ±2s", d)
		}
	}
}

func TestReconnectBackoffAndPolicy(t *testing.T) {
	a, s, clock := newWatchdogTestActor(t, WatchdogDown)
	a.state = Closed
	a.cfg.Endpoints = []Endpoint{{Address: "127.0.0.1:1"}}
	a.m.mu.Lock()
	a.m.started = true
	a.m.mu.Unlock()
	for i, baseTc := range []time.Duration{30 * time.Second, 60 * time.Second, 120 * time.Second, 240 * time.Second, 300 * time.Second, 300 * time.Second} {
		a.scheduleReconnect()
		if a.tcTimer == nil {
			t.Fatal("Tc not scheduled")
		}
		d := clock.timers[len(clock.timers)-1].duration
		lower := baseTc * 8 / 10
		upper := baseTc * 12 / 10
		if upper > 5*time.Minute {
			upper = 5 * time.Minute
		}
		if d < lower || d > upper {
			t.Fatalf("failure %d: Tc %s outside %s..%s", i, d, lower, upper)
		}
	}
	a.state = ROpen
	a.r, a.active = s, s
	a.publish(nil)
	for range 3 {
		a.watchdogReceive(testDWA(t, a))
	}
	if a.failures != 0 || !a.snapshot().Eligible {
		t.Fatal("stable OKAY did not reset Tc")
	}
	a.state = Closed
	a.scheduleReconnect()
	d := clock.timers[len(clock.timers)-1].duration
	if d < 24*time.Second || d > 36*time.Second {
		t.Fatalf("reset Tc=%s", d)
	}
	a.cfg.NoAutoReconnect = true
	a.stopReconnect()
	a.scheduleReconnect()
	if a.tcTimer != nil {
		t.Fatal("NoAutoReconnect scheduled Tc")
	}
}

func TestReconnectDPRCausesAndOwnClose(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cause sm.DisconnectCause
		retry bool
	}{
		{"REBOOTING", sm.DisconnectRebooting, true},
		{"BUSY", sm.DisconnectBusy, false},
		{"DO_NOT_WANT_TO_TALK_TO_YOU", sm.DisconnectDoNotWantToTalkToYou, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, s, _ := newWatchdogTestActor(t, WatchdogOkay)
			a.cfg.Endpoints = []Endpoint{{Address: "127.0.0.1:1"}}
			a.m.mu.Lock()
			a.m.started = true
			a.m.mu.Unlock()
			dpr, err := base.BuildDPR(a.m.dictionary(), testBase("known.example.net"), uint32(tc.cause))
			if err != nil {
				t.Fatal(err)
			}
			a.onWire(event{s: s, msg: dpr})
			if a.state != Closing || len(s.writes) != 1 {
				t.Fatalf("DPR state=%s writes=%d", a.state, len(s.writes))
			}
			a.onGone(s)
			if (a.tcTimer != nil) != tc.retry {
				t.Fatalf("Tc scheduled=%v want %v", a.tcTimer != nil, tc.retry)
			}
		})
	}
	t.Run("our Close", func(t *testing.T) {
		a, s, _ := newWatchdogTestActor(t, WatchdogOkay)
		a.cfg.Endpoints = []Endpoint{{Address: "127.0.0.1:1"}}
		a.m.mu.Lock()
		a.m.started = true
		a.m.mu.Unlock()
		a.stop(sm.DisconnectRebooting)
		a.onGone(s)
		if a.tcTimer != nil {
			t.Fatal("our Close scheduled reconnect")
		}
	})
}

// RFC 6733 §5.4.3: a BUSY or DO_NOT_WANT_TO_TALK_TO_YOU DPR received on an
// inbound connection before Start also suppresses the first dial.
func TestStartHonorsEarlierDPRSuppression(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cause sm.DisconnectCause
	}{
		{"BUSY", sm.DisconnectBusy},
		{"DO_NOT_WANT_TO_TALK_TO_YOU", sm.DisconnectDoNotWantToTalkToYou},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, s, _ := newWatchdogTestActor(t, WatchdogOkay)
			a.cfg.Endpoints = []Endpoint{{Address: "127.0.0.1:1"}}
			dpr, err := base.BuildDPR(a.m.dictionary(), testBase("known.example.net"), uint32(tc.cause))
			if err != nil {
				t.Fatal(err)
			}
			a.onWire(event{s: s, msg: dpr})
			a.onGone(s)
			a.handle(event{kind: start})
			if a.state != Closed || a.i != nil {
				t.Fatalf("Start after %s DPR: state=%s dialing=%v", tc.name, a.state, a.i != nil)
			}
		})
	}
}

func TestReconnectAfterDisconnectBeforeCEA(t *testing.T) {
	a, s, _ := newWatchdogTestActor(t, WatchdogInitial)
	a.state, a.i, a.r, a.active = WaitICEA, s, nil, nil
	a.cfg.Endpoints = []Endpoint{{Address: "127.0.0.1:1"}}
	a.m.mu.Lock()
	a.m.started = true
	a.m.mu.Unlock()
	a.onGone(s)
	if a.state != Closed || a.publishedWatchdog() != WatchdogInitial || a.tcTimer == nil {
		t.Fatalf("CEA-stage loss: state=%s watchdog=%s Tc scheduled=%v", a.state, a.publishedWatchdog(), a.tcTimer != nil)
	}
}

func TestWatchdogDWAIdentityAndResult(t *testing.T) {
	for _, mutate := range []struct {
		name   string
		change func(*diam.Message)
	}{
		{"wrong host", func(m *diam.Message) {
			a, _ := m.FindAVP(avp.OriginHost, 0)
			a.Data = datatype.DiameterIdentity("other.example.net")
		}},
		{"failed result", func(m *diam.Message) {
			a, _ := m.FindAVP(avp.ResultCode, 0)
			a.Data = datatype.Unsigned32(diam.UnableToComply)
		}},
		{"wrong application", func(m *diam.Message) { m.Header.ApplicationID = 4 }},
		{"invalid flags", func(m *diam.Message) { m.Header.CommandFlags = diam.ProxiableFlag }},
		{"wrong end-to-end", func(m *diam.Message) { m.Header.EndToEndID++ }},
		{"duplicate host", func(m *diam.Message) {
			m.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("known.example.net")))
		}},
		{"missing result", func(m *diam.Message) {
			for i, a := range m.AVP {
				if a.Code == avp.ResultCode {
					m.AVP = append(m.AVP[:i], m.AVP[i+1:]...)
					break
				}
			}
		}},
		{"missing realm", func(m *diam.Message) {
			for i, a := range m.AVP {
				if a.Code == avp.OriginRealm {
					m.AVP = append(m.AVP[:i], m.AVP[i+1:]...)
					break
				}
			}
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			a, s, _ := newWatchdogTestActor(t, WatchdogReopen)
			m := testDWA(t, a)
			mutate.change(m)
			a.onWire(event{s: s, msg: m})
			if fixtureWatchdog(a).NumDWA != 0 || !fixtureWatchdog(a).Pending || a.snapshot().Eligible {
				t.Fatal("invalid DWA counted")
			}
		})
	}
}

func TestWatchdogStaleGenerationDWA(t *testing.T) {
	a, s, _ := newWatchdogTestActor(t, WatchdogReopen)
	m := testDWA(t, a)
	old := &session{m: a.m, c: newFakeConn(), actor: a, gen: s.gen - 1, writes: make(chan writeRequest, 8), closed: make(chan struct{})}
	t.Cleanup(old.close)
	a.onWire(event{s: old, msg: m})
	if fixtureWatchdog(a).NumDWA != 0 || !fixtureWatchdog(a).Pending {
		t.Fatal("old-generation DWA counted")
	}
}

func TestNoAutoReconnectStillDialsInitially(t *testing.T) {
	clock := &fakeClock{}
	var attempts atomic.Int32
	m, err := New(Config{
		Settings: testSettings("local.example.net"), Clock: clock,
		Dial: func(context.Context, Endpoint) (net.Conn, error) { attempts.Add(1); return nil, errors.New("refused") },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = m.AddPeer(PeerConfig{Host: "known.example.net", NoAutoReconnect: true, Endpoints: []Endpoint{{Address: "127.0.0.1:1"}}}); err != nil {
		t.Fatal(err)
	}
	if err = m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer closeManager(t, m, nil)
	deadline := time.Now().Add(time.Second)
	for (attempts.Load() == 0 || m.Peers()[0].State != Closed) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if attempts.Load() != 1 || m.Peers()[0].State != Closed {
		t.Fatalf("initial dial attempts=%d state=%s", attempts.Load(), m.Peers()[0].State)
	}
	clock.fire()
	if attempts.Load() != 1 {
		t.Fatal("NoAutoReconnect retried")
	}
}

func TestWatchdogTransitionsEmitReasons(t *testing.T) {
	got := make(chan PeerEvent, 8)
	m, err := New(Config{Settings: testSettings("local.example.net"), OnPeerEvent: func(e PeerEvent) { got <- e }})
	if err != nil {
		t.Fatal(err)
	}
	defer closeManager(t, m, nil)
	a := &actor{m: m, cfg: PeerConfig{Host: "known.example.net"}, state: ROpen, snapshotValue: fixtureHealth(WatchdogInitial), events: make(chan event, 8), done: make(chan struct{})}
	a.publish(nil)
	for _, state := range []WatchdogState{WatchdogOkay, WatchdogSuspect, WatchdogDown, WatchdogReopen, WatchdogOkay} {
		a.publishWatchdog(state, errors.New("transition"))
	}
	for _, want := range []WatchdogState{WatchdogOkay, WatchdogSuspect, WatchdogDown, WatchdogReopen, WatchdogOkay} {
		select {
		case event := <-got:
			if event.Peer.Watchdog == WatchdogInitial {
				event = <-got
			}
			if event.Peer.Watchdog != want || event.Reason == nil {
				t.Fatalf("event=%+v want %s with reason", event, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("missing %s event", want)
		}
	}
}

func TestReconnectNeverOverlapsDial(t *testing.T) {
	clock := &fakeClock{}
	release := make(chan struct{})
	var active, maxActive, attempts atomic.Int32
	m, err := New(Config{
		Settings: testSettings("local.example.net"), Clock: clock,
		Dial: func(context.Context, Endpoint) (net.Conn, error) {
			attempts.Add(1)
			n := active.Add(1)
			for {
				old := maxActive.Load()
				if n <= old || maxActive.CompareAndSwap(old, n) {
					break
				}
			}
			<-release
			active.Add(-1)
			return nil, errors.New("refused")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = m.AddPeer(PeerConfig{Host: "known.example.net", Endpoints: []Endpoint{{Address: "127.0.0.1:1"}}}); err != nil {
		t.Fatal(err)
	}
	if err = m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { close(release); closeManager(t, m, nil) }()
	deadline := time.Now().Add(time.Second)
	for attempts.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if attempts.Load() == 0 {
		t.Fatal("initial dial did not start")
	}
	before := clock.timerCount()
	clock.fire() // Connect timeout while Dial is still blocked.
	awaitState(t, m, Closed)
	clock.waitTimers(t, before+1)
	before = clock.timerCount()
	clock.fire() // Tc expires while the first Dial is still in progress.
	clock.waitTimers(t, before+1)
	if got := attempts.Load(); got != 1 {
		t.Fatalf("overlapping attempts=%d", got)
	}
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("maximum simultaneous dials=%d", got)
	}
}
