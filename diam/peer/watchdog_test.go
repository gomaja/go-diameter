package peer

import (
	"context"
	"errors"
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
	a := &actor{m: m, cfg: PeerConfig{Host: "known.example.net"}, state: ROpen, watchdog: state, everOpen: state != WatchdogInitial, events: make(chan event, 8), done: make(chan struct{})}
	s := &session{m: m, c: newFakeConn(), actor: a, gen: 7, writes: make(chan writeRequest, 8), closed: make(chan struct{})}
	a.r, a.active = s, s
	a.publish(nil)
	t.Cleanup(func() { a.stopWatchdog(); a.stopReconnect(); s.close(); closeManager(t, m, nil) })
	return a, s, clock
}

func testDWA(t *testing.T, a *actor) *diam.Message {
	t.Helper()
	request, err := base.BuildDWR(a.m.dictionary(), testBase("local.example.net"), 0)
	if err != nil {
		t.Fatal(err)
	}
	a.pendingWatchdog, a.watchdogHop, a.watchdogEnd, a.watchdogGen = true, request.Header.HopByHopID, request.Header.EndToEndID, a.active.gen
	answer, err := base.BuildDWA(request, testBase("known.example.net"))
	if err != nil {
		t.Fatal(err)
	}
	return answer
}

// Every row is named after the RFC 3539 Appendix A state/event/guard.
func TestRFC3539WatchdogTable(t *testing.T) {
	type row struct {
		name        string
		state       WatchdogState
		event       string
		pending     bool
		num         int
		want        WatchdogState
		wantPending bool
		wantNum     int
		writes      int
	}
	rows := []row{
		{"INITIAL/connection up", WatchdogInitial, "up", false, 0, WatchdogOkay, false, 0, 0},
		{"INITIAL/Tw expires", WatchdogInitial, "timer", false, 0, WatchdogInitial, false, 0, 0},
		{"INITIAL/DWA", WatchdogInitial, "dwa", true, 0, WatchdogInitial, false, 0, 0},
		{"INITIAL/other message", WatchdogInitial, "other", false, 0, WatchdogInitial, false, 0, 0},
		{"OKAY/valid DWA", WatchdogOkay, "dwa", true, 0, WatchdogOkay, false, 0, 0},
		{"OKAY/other message", WatchdogOkay, "other", true, 0, WatchdogOkay, true, 0, 0},
		{"OKAY/Tw expires no pending", WatchdogOkay, "timer", false, 0, WatchdogOkay, true, 0, 1},
		{"OKAY/Tw expires pending", WatchdogOkay, "timer", true, 0, WatchdogSuspect, true, 0, 0},
		{"OKAY/connection down", WatchdogOkay, "down", false, 0, WatchdogDown, false, 0, 0},
		{"SUSPECT/valid DWA", WatchdogSuspect, "dwa", true, 0, WatchdogOkay, false, 0, 0},
		{"SUSPECT/other message", WatchdogSuspect, "other", true, 0, WatchdogOkay, true, 0, 0},
		{"SUSPECT/Tw expires", WatchdogSuspect, "timer", true, 0, WatchdogDown, false, 0, 0},
		{"SUSPECT/connection down", WatchdogSuspect, "down", true, 0, WatchdogDown, false, 0, 0},
		{"DOWN/Tw expires", WatchdogDown, "timer", false, 0, WatchdogDown, false, 0, 0},
		{"DOWN/connection up", WatchdogDown, "up", false, 9, WatchdogReopen, true, 0, 1},
		{"DOWN/DWA", WatchdogDown, "dwa", true, 0, WatchdogDown, false, 0, 0},
		{"DOWN/other message", WatchdogDown, "other", false, 0, WatchdogDown, false, 0, 0},
		{"REOPEN/valid DWA NumDWA 0", WatchdogReopen, "dwa", true, 0, WatchdogReopen, false, 1, 0},
		{"REOPEN/valid DWA NumDWA 1", WatchdogReopen, "dwa", true, 1, WatchdogReopen, false, 2, 0},
		{"REOPEN/valid DWA NumDWA 2", WatchdogReopen, "dwa", true, 2, WatchdogOkay, false, 3, 0},
		{"REOPEN/other message", WatchdogReopen, "other", true, 0, WatchdogReopen, true, 0, 0},
		{"REOPEN/Tw expires no pending", WatchdogReopen, "timer", false, 0, WatchdogReopen, true, 0, 1},
		{"REOPEN/Tw expires pending first", WatchdogReopen, "timer", true, 0, WatchdogReopen, true, -1, 0},
		{"REOPEN/Tw expires pending second", WatchdogReopen, "timer", true, -1, WatchdogDown, false, -1, 0},
		{"REOPEN/connection down", WatchdogReopen, "down", true, 1, WatchdogDown, false, 1, 0},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			a, s, _ := newWatchdogTestActor(t, tc.state)
			a.pendingWatchdog, a.numDWA = tc.pending, tc.num
			switch tc.event {
			case "up":
				a.onOpen()
			case "down":
				a.onGone(s)
			case "timer":
				a.watchdogTick()
			case "dwa":
				a.watchdogReceive(testDWA(t, a))
			case "other":
				a.watchdogReceive(diam.NewRequest(999, 0, a.m.dictionary()))
			}
			if a.watchdog != tc.want || a.pendingWatchdog != tc.wantPending || a.numDWA != tc.wantNum {
				t.Fatalf("watchdog=%s pending=%v NumDWA=%d; want %s %v %d", a.watchdog, a.pendingWatchdog, a.numDWA, tc.want, tc.wantPending, tc.wantNum)
			}
			if len(s.writes) != tc.writes {
				t.Fatalf("writes=%d want %d", len(s.writes), tc.writes)
			}
			if got := a.snapshot().Eligible; got != (a.state == ROpen && tc.want == WatchdogOkay) {
				t.Fatalf("Eligible=%v", got)
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
	if !a.pendingWatchdog || a.numDWA != 0 || a.snapshot().Eligible {
		t.Fatal("recovery opened before validation")
	}
	first := (<-s.writes).msg
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
	if a.numDWA != 0 || !a.pendingWatchdog {
		t.Fatal("mismatched DWA counted")
	}
	a.onWire(event{s: s, msg: answer(first)})
	if a.numDWA != 1 || a.snapshot().Eligible {
		t.Fatal("first DWA made peer eligible")
	}
	a.onWire(event{s: s, msg: answer(first)})
	if a.numDWA != 1 {
		t.Fatal("duplicate DWA counted")
	}
	for want := 2; want <= 3; want++ {
		a.watchdogTick()
		probe := (<-s.writes).msg
		a.onWire(event{s: s, msg: answer(probe)})
		if a.numDWA != want || a.snapshot().Eligible != (want == 3) {
			t.Fatalf("NumDWA=%d Eligible=%v", a.numDWA, a.snapshot().Eligible)
		}
	}
	if a.watchdog != WatchdogOkay {
		t.Fatalf("state=%s", a.watchdog)
	}
}

func TestWatchdogReopenSuppressesApplicationButAnswersDWR(t *testing.T) {
	a, s, clock := newWatchdogTestActor(t, WatchdogReopen)
	a.armWatchdog()
	tw := clock.timers[len(clock.timers)-1]
	a.onWire(event{s: s, msg: diam.NewRequest(999, 0, a.m.dictionary())})
	if len(s.writes) != 0 {
		t.Fatal("application message dispatched in REOPEN")
	}
	if !tw.active {
		t.Fatal("REOPEN traffic postponed the next recovery probe")
	}
	dwr, err := base.BuildDWR(a.m.dictionary(), testBase("known.example.net"), 0)
	if err != nil {
		t.Fatal(err)
	}
	a.onWire(event{s: s, msg: dwr})
	if !tw.active {
		t.Fatal("peer DWR postponed the next recovery probe")
	}
	if len(s.writes) != 1 || (<-s.writes).msg.Header.CommandFlags&diam.RequestFlag != 0 {
		t.Fatal("peer DWR not answered")
	}
}

func TestWatchdogTrafficResetsTwAndJitter(t *testing.T) {
	a, _, clock := newWatchdogTestActor(t, WatchdogOkay)
	a.armWatchdog()
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
		a.armWatchdog()
		d := clock.timers[len(clock.timers)-1].duration
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
	a.watchdog = WatchdogReopen
	a.numDWA = 2
	a.publish(nil)
	a.watchdogReceive(testDWA(t, a))
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
	if a.state != Closed || a.watchdog != WatchdogInitial || a.tcTimer == nil {
		t.Fatalf("CEA-stage loss: state=%s watchdog=%s Tc scheduled=%v", a.state, a.watchdog, a.tcTimer != nil)
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
			if a.numDWA != 0 || !a.pendingWatchdog || a.snapshot().Eligible {
				t.Fatal("invalid DWA counted")
			}
		})
	}
}

func TestWatchdogStaleGenerationDWA(t *testing.T) {
	a, s, _ := newWatchdogTestActor(t, WatchdogReopen)
	m := testDWA(t, a)
	a.watchdogGen = s.gen - 1
	a.onWire(event{s: s, msg: m})
	if a.numDWA != 0 || !a.pendingWatchdog {
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
	a := &actor{m: m, cfg: PeerConfig{Host: "known.example.net"}, state: ROpen, watchdog: WatchdogInitial, events: make(chan event, 8), done: make(chan struct{})}
	a.publish(nil)
	for _, state := range []WatchdogState{WatchdogOkay, WatchdogSuspect, WatchdogDown, WatchdogReopen, WatchdogOkay} {
		a.changeWatchdog(state, errors.New("transition"))
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
	clock.mu.Lock()
	before := len(clock.timers)
	clock.mu.Unlock()
	clock.fire() // Connect timeout while Dial is still blocked.
	awaitState(t, m, Closed)
	deadline = time.Now().Add(time.Second)
	for {
		clock.mu.Lock()
		count := len(clock.timers)
		clock.mu.Unlock()
		if count > before || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	clock.mu.Lock()
	before = len(clock.timers)
	clock.mu.Unlock()
	clock.fire() // Tc expires while the first Dial is still in progress.
	deadline = time.Now().Add(time.Second)
	for {
		clock.mu.Lock()
		count := len(clock.timers)
		clock.mu.Unlock()
		if count > before || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("overlapping attempts=%d", got)
	}
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("maximum simultaneous dials=%d", got)
	}
}
