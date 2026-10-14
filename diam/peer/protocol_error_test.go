package peer

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/sm"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

func protocolErrorReceive(t *testing.T, events <-chan diam.ProtocolErrorEvent) diam.ProtocolErrorEvent {
	t.Helper()
	select {
	case e := <-events:
		return e
	case <-time.After(time.Second):
		t.Fatal("protocol notification missing")
		return diam.ProtocolErrorEvent{}
	}
}

func protocolErrorCheck(t *testing.T, e diam.ProtocolErrorEvent, c diam.Conn, h diam.Header, kind diam.ProtocolErrorKind, result uint32, closing bool, reply diam.ProtocolReplyStatus, replyCode uint32, stream ...uint) {
	t.Helper()
	wantStream := ^uint(0)
	if len(stream) != 0 {
		wantStream = stream[0]
	}
	var classified *diam.ProtocolError
	if e.Conn != c || !e.Message.HasHeader || e.Message.Header != h || e.Message.Stream != wantStream || !errors.As(e.Err, &classified) || !errors.Is(e.Err, kind) || e.Err.Kind() != kind || e.Err.ResultCode() != result || e.Closing != closing || e.Reply != reply || e.ReplyCode != replyCode {
		t.Fatalf("notification=%+v error=%v want conn=%p header=%+v kind=%v result=%d closing=%v reply=%v/%d", e, e.Err, c, h, kind, result, closing, reply, replyCode)
	}
}

// Removing a terminal decision's notification must fail without changing the
// existing answer, connection policy, or protocol log.
func TestProtocolErrorManagerWireDecisions(t *testing.T) {
	testDict := newTestDictionary(creditcontrol.Dictionary())

	for _, tc := range []struct {
		name              string
		message           func(*testing.T) *diam.Message
		kind              diam.ProtocolErrorKind
		result, replyCode uint32
		closing, preCER   bool
	}{
		{"unsupported command", func(t *testing.T) *diam.Message { return diam.NewRequest(999, 0, testDict) }, diam.ProtocolUnsupportedCommand, 3001, 3001, false, false},
		{"unsupported application", func(t *testing.T) *diam.Message { return diam.NewRequest(999, 0x00fffffe, testDict) }, diam.ProtocolUnsupportedApplication, 3007, 3007, false, false},
		{"unmatched answer", func(t *testing.T) *diam.Message { return diam.NewRequest(999, 0, testDict).Answer(diam.Success) }, diam.ProtocolUnexpectedMessage, 0, 0, false, false},
		{"invalid DWR", func(t *testing.T) *diam.Message { return diam.NewRequest(diam.DeviceWatchdog, 0, testDict) }, diam.ProtocolInvalidDWR, 0, 0, false, false},
		{"wrong DWR identity", func(t *testing.T) *diam.Message {
			m, err := base.BuildDWR(testDict, testBase("other.example.net"), 0)
			if err != nil {
				t.Fatal(err)
			}
			return m
		}, diam.ProtocolInvalidDWR, 0, 0, false, false},
		{"invalid DPR", func(t *testing.T) *diam.Message { return diam.NewRequest(diam.DisconnectPeer, 0, testDict) }, diam.ProtocolInvalidDPR, 0, 0, false, false},
		{"unsolicited DWA", func(t *testing.T) *diam.Message {
			m, err := base.BuildDWA(reviewDWR(t), testBase("known.example.net"))
			if err != nil {
				t.Fatal(err)
			}
			return m
		}, diam.ProtocolInvalidDWA, 0, 0, false, false},
		{"invalid base header", func(t *testing.T) *diam.Message { m := reviewDWR(t); m.Header.ApplicationID = 4; return m }, diam.ProtocolInvalidHeader, 3008, 3008, false, false},
		{"invalid answer header", func(t *testing.T) *diam.Message { m := reviewDWR(t).Answer(2001); m.Header.ApplicationID = 4; return m }, diam.ProtocolInvalidHeader, 3008, 0, false, false},
		{"invalid initial CER header", func(t *testing.T) *diam.Message { m := reviewCER(t); m.Header.ApplicationID = 4; return m }, diam.ProtocolInvalidHeader, 3008, 3008, true, true},
		{"unknown CER identity", func(t *testing.T) *diam.Message {
			m := reviewCER(t)
			a, _ := m.FindAVP(avp.OriginHost, 0)
			a.Data = datatype.DiameterIdentity("unknown.example.net")
			return m
		}, diam.ProtocolCERRejected, 3010, 3010, true, true},
		{"malformed AVP payload", func(t *testing.T) *diam.Message {
			m := reviewDWR(t)
			m.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2}))
			return m
		}, diam.ProtocolMalformedMessage, 5014, 5014, false, false},
		{"duplicate CER", reviewCER, diam.ProtocolUnexpectedMessage, 0, 0, false, false},
		{"pre CER traffic", reviewDWR, diam.ProtocolHandshakeState, 0, 0, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := make(chan diam.ProtocolErrorEvent, 8)
			records := logtest.New()
			settings := testSettings("local.example.net", testDict)
			settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
			m, err := New(Config{Settings: settings, Logger: records.Logger()})
			if err != nil {
				t.Fatal(err)
			}
			if err := m.AddPeer(PeerConfig{Host: "known.example.net"}); err != nil {
				t.Fatal(err)
			}
			l, srv := startReceiverWithHandlers(t, m, 8)
			srv.Logger = records.Logger()
			t.Cleanup(func() { closeManager(t, m, srv) })
			c, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = c.Close() })
			if !tc.preCER {
				write(t, c, reviewCER(t))
				if code(t, read(t, c)) != 2001 {
					t.Fatal("handshake failed")
				}
			}
			msg := tc.message(t)
			write(t, c, msg)
			var expectedConn diam.Conn
			e := protocolErrorReceive(t, events)
			m.mu.RLock()
			for conn := range m.sessions {
				if conn.RemoteAddr().String() == c.LocalAddr().String() {
					expectedConn = conn
				}
			}
			m.mu.RUnlock()
			if expectedConn == nil && tc.closing {
				expectedConn = e.Conn
			}
			if expectedConn == nil || e.Conn.RemoteAddr().String() != c.LocalAddr().String() {
				t.Fatal("wrong connection attribution")
			}
			reply := diam.ProtocolReplyNone
			if tc.replyCode != 0 {
				reply = diam.ProtocolReplyQueued
				answer := read(t, c)
				if code(t, answer) != tc.replyCode || answer.Header.HopByHopID != msg.Header.HopByHopID {
					t.Fatalf("answer=%+v", answer.Header)
				}
				protocolError := tc.replyCode >= 3000 && tc.replyCode < 4000
				if (answer.Header.CommandFlags&diam.ErrorFlag != 0) != protocolError {
					t.Errorf("reply code=%d flags=%#02x, want E=%v", tc.replyCode, answer.Header.CommandFlags, protocolError)
				}
				if err := answer.ValidateOutgoing(); err != nil {
					t.Errorf("reply grammar: %v", err)
				}
			}
			protocolErrorCheck(t, e, expectedConn, *msg.Header, tc.kind, tc.result, tc.closing, reply, tc.replyCode, 0)
			if tc.closing {
				if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				var b [1]byte
				if n, err := c.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
					t.Fatalf("connection did not close: read=%d error=%v; want EOF", n, err)
				}
				if !e.Conn.Closed() {
					t.Fatal("closing decision left server connection open")
				}
			} else {
				write(t, c, reviewDWR(t))
				if code(t, read(t, c)) != 2001 {
					t.Fatal("connection not usable")
				}
			}
			select {
			case extra := <-events:
				t.Fatalf("duplicate notification: %+v", extra)
			default:
			}
			logs := records.Records()
			wantLog := "peer: protocol error"
			if tc.kind == diam.ProtocolMalformedMessage {
				wantLog = "diam: malformed message"
			}
			if tc.name == "duplicate CER" {
				wantLog = "peer: ignoring CER on admitted connection; accepted CER renewal is disabled or ineligible"
			}
			if len(logs) != 1 || logs[0].Level != slog.LevelWarn || logs[0].Message != wantLog {
				t.Fatalf("logs changed: %v", logs)
			}
		})
	}
}

func TestProtocolErrorManagerMessageFailures(t *testing.T) {
	for _, full := range []bool{false, true} {
		t.Run(map[bool]string{false: "queued", true: "queue full"}[full], func(t *testing.T) {
			a, s, _ := failureReportingActor(t)
			a.state, a.i, a.active = IOpen, s, s
			events := make(chan diam.ProtocolErrorEvent, 8)
			a.m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
			if full {
				for len(s.writes) < cap(s.writes) {
					s.writes <- writeRequest{}
				}
			}
			msg := reviewDWR(t)
			msg.Header.ApplicationID = 4
			original := *msg.Header
			a.onWire(event{s: s, msg: msg, messageErr: &diam.MessageError{ResultCode: 5014, Fatal: true}})
			e := protocolErrorReceive(t, events)
			reply := diam.ProtocolReplyQueued
			if full {
				reply = diam.ProtocolReplyFailed
			}
			protocolErrorCheck(t, e, s.c, original, diam.ProtocolInvalidHeader, 3008, true, reply, 3008)
			msg.Header.HopByHopID++
			msg.AVP = nil
			if e.Message.Header != original {
				t.Fatal("retained message metadata changed")
			}
			var parserError *diam.MessageError
			if errors.As(e.Err, &parserError) {
				t.Fatal("notification retained mutable parser error")
			}
			select {
			case extra := <-events:
				t.Fatalf("duplicate event: %+v", extra)
			default:
			}
		})
	}
}

func TestProtocolErrorManagerQueuedThenClosed(t *testing.T) {
	testDict := newTestDictionary(creditcontrol.Dictionary())

	a, s, _ := failureReportingActor(t)
	var got diam.ProtocolErrorEvent
	a.m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { got = e; e.Conn.Close() }
	msg := diam.NewRequest(999, 0, testDict)
	a.m.unsupported(s, msg)
	protocolErrorCheck(t, got, s.c, *msg.Header, diam.ProtocolUnsupportedCommand, 3001, false, diam.ProtocolReplyQueued, 3001)
	if !s.c.Closed() || len(s.writes) != 1 {
		t.Fatal("callback did not follow queue admission")
	}
}

func TestProtocolErrorManagerMalformedAndRejectedAnswers(t *testing.T) {
	for _, request := range []bool{false, true} {
		a, s, _ := failureReportingActor(t)
		a.state, a.i, a.active = IOpen, s, s
		var events []diam.ProtocolErrorEvent
		a.m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events = append(events, e) }
		msg := reviewDWR(t)
		if !request {
			msg.Header.CommandFlags = 0
		}
		a.onWire(event{s: s, msg: msg, messageErr: &diam.MessageError{ResultCode: 5014}})
		if len(events) != 1 {
			t.Fatalf("events=%d", len(events))
		}
		reply, replyCode := diam.ProtocolReplyNone, uint32(0)
		if request {
			reply, replyCode = diam.ProtocolReplyQueued, 5014
		}
		protocolErrorCheck(t, events[0], s.c, *msg.Header, diam.ProtocolMalformedMessage, 5014, false, reply, replyCode)
	}
}

func TestProtocolErrorManagerPeerEventOverflow(t *testing.T) {
	testDict := newTestDictionary(creditcontrol.Dictionary())

	a, s, _ := failureReportingActor(t)
	a.state, a.i, a.active = IOpen, s, s
	for len(a.m.callbackQ) < cap(a.m.callbackQ) {
		a.m.callbackQ <- PeerEvent{}
	}
	var calls int
	a.m.cfg.Settings.OnProtocolError = func(diam.ProtocolErrorEvent) { calls++ }
	a.m.unsupported(s, diam.NewRequest(999, 0, testDict))
	if calls != 1 {
		t.Fatalf("protocol callbacks=%d", calls)
	}
}

func TestProtocolErrorManagerDWAAndDPA(t *testing.T) {
	testDict := newTestDictionary(creditcontrol.Dictionary())

	for _, tc := range []struct {
		name    string
		command uint32
		kind    diam.ProtocolErrorKind
		result  uint32
		mutate  func(*diam.Message)
	}{
		{"DWA identifier", diam.DeviceWatchdog, diam.ProtocolInvalidDWA, 0, func(m *diam.Message) { m.Header.EndToEndID++ }},
		{"DWA identity", diam.DeviceWatchdog, diam.ProtocolInvalidDWA, 0, func(m *diam.Message) {
			a, _ := m.FindAVP(avp.OriginHost, 0)
			a.Data = datatype.DiameterIdentity("other.example.net")
		}},
		{"DWA rejected", diam.DeviceWatchdog, diam.ProtocolRejectedDWA, 3002, func(m *diam.Message) { a, _ := m.FindAVP(avp.ResultCode, 0); a.Data = datatype.Unsigned32(3002) }},
		{"DWA identity before rejection", diam.DeviceWatchdog, diam.ProtocolInvalidDWA, 0, func(m *diam.Message) {
			a, _ := m.FindAVP(avp.OriginHost, 0)
			a.Data = datatype.DiameterIdentity("other.example.net")
			for i, field := range m.AVP {
				if field == a {
					m.AVP[0], m.AVP[i] = m.AVP[i], m.AVP[0]
					break
				}
			}
			a, _ = m.FindAVP(avp.ResultCode, 0)
			a.Data = datatype.Unsigned32(3002)
		}},
		{"DPA identifier", diam.DisconnectPeer, diam.ProtocolInvalidDPA, 0, func(m *diam.Message) { m.Header.EndToEndID++ }},
		{"DPA identity", diam.DisconnectPeer, diam.ProtocolInvalidDPA, 0, func(m *diam.Message) {
			a, _ := m.FindAVP(avp.OriginHost, 0)
			a.Data = datatype.DiameterIdentity("other.example.net")
		}},
		{"DPA rejected", diam.DisconnectPeer, diam.ProtocolPeerRejected, 3002, func(m *diam.Message) { a, _ := m.FindAVP(avp.ResultCode, 0); a.Data = datatype.Unsigned32(3002) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, s, _ := failureReportingActor(t)
			a.state, a.i, a.active = IOpen, s, s
			var msg *diam.Message
			var err error
			if tc.command == diam.DeviceWatchdog {
				msg, err = base.BuildDWA(reviewDWR(t), testBase("known.example.net"))
				a.pendingWatchdog = true
				a.watchdogGen = s.gen
				a.watchdogHop, a.watchdogEnd = msg.Header.HopByHopID, msg.Header.EndToEndID
			} else {
				req, buildErr := base.BuildDPR(testDict, testBase("known.example.net"), 0)
				if buildErr != nil {
					t.Fatal(buildErr)
				}
				msg, err = base.BuildDPA(req, testBase("known.example.net"))
				a.state = Closing
				a.pendingDPR, a.pendingDPREnd = msg.Header.HopByHopID, msg.Header.EndToEndID
			}
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(msg)
			var events []diam.ProtocolErrorEvent
			a.m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events = append(events, e) }
			a.onWire(event{s: s, msg: msg})
			if len(events) != 1 {
				t.Fatalf("events=%d", len(events))
			}
			protocolErrorCheck(t, events[0], s.c, *msg.Header, tc.kind, tc.result, false, diam.ProtocolReplyNone, 0)
			if s.c.Closed() || tc.command == diam.DeviceWatchdog && !a.pendingWatchdog || tc.command == diam.DisconnectPeer && a.state != Closing {
				t.Fatal("invalid answer advanced protocol state")
			}
		})
	}
}

func TestProtocolErrorManagerHandshakeDecisions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		kind   diam.ProtocolErrorKind
		result uint32
		run    func(*testing.T, *actor, *session) *diam.Message
	}{
		{"non CEA", diam.ProtocolHandshakeState, 0, func(t *testing.T, a *actor, s *session) *diam.Message {
			a.state, a.i = WaitICEA, s
			msg := reviewDWR(t)
			a.onWire(event{s: s, msg: msg})
			return msg
		}},
		{"CEA identifiers", diam.ProtocolCEARejected, 0, func(t *testing.T, a *actor, s *session) *diam.Message {
			a.state, a.i = WaitICEA, s
			msg, err := base.BuildCEA(reviewCER(t), testBase("known.example.net"), 2001)
			if err != nil {
				t.Fatal(err)
			}
			s.cerHop = msg.Header.HopByHopID + 1
			a.onWire(event{s: s, msg: msg})
			return msg
		}},
		{"CEA rejected", diam.ProtocolCEARejected, 3010, func(t *testing.T, a *actor, s *session) *diam.Message {
			a.state, a.i = WaitICEA, s
			msg, err := base.BuildCEA(reviewCER(t), testBase("known.example.net"), 3010)
			if err != nil {
				t.Fatal(err)
			}
			s.cerHop, s.cerEnd = msg.Header.HopByHopID, msg.Header.EndToEndID
			a.onWire(event{s: s, msg: msg})
			return msg
		}},
		{"CER closing", diam.ProtocolHandshakeState, 0, func(t *testing.T, a *actor, s *session) *diam.Message {
			a.state = Closing
			msg := reviewCER(t)
			a.onCER(event{s: s, msg: msg, meta: smpeer.FromCER(&smparser.CER{OriginHost: "known.example.net"})})
			return msg
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, s, _ := failureReportingActor(t)
			var events []diam.ProtocolErrorEvent
			a.m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events = append(events, e) }
			msg := tc.run(t, a, s)
			if len(events) != 1 {
				t.Fatalf("events=%d", len(events))
			}
			protocolErrorCheck(t, events[0], s.c, *msg.Header, tc.kind, tc.result, true, diam.ProtocolReplyNone, 0)
			if !s.c.Closed() {
				t.Fatal("handshake failure left transport open")
			}
		})
	}
}

func TestProtocolErrorManagerTimersAndRetirement(t *testing.T) {
	testDict := newTestDictionary(creditcontrol.Dictionary())

	for _, tc := range []struct {
		name     string
		state    PeerState
		watchdog WatchdogState
		kind     diam.ProtocolErrorKind
		fire     func(*actor)
	}{
		{"handshake", WaitICEA, WatchdogInitial, diam.ProtocolHandshakeTimeout, func(a *actor) { a.handle(event{kind: timeout}) }},
		{"disconnect", Closing, WatchdogOkay, diam.ProtocolDisconnectTimeout, func(a *actor) { a.handle(event{kind: timeout}) }},
		{"watchdog", IOpen, WatchdogSuspect, diam.ProtocolWatchdogTimeout, func(a *actor) { a.watchdogTick() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, s, _ := failureReportingActor(t)
			a.state, a.i, a.active, a.watchdog = tc.state, s, s, tc.watchdog
			var events []diam.ProtocolErrorEvent
			a.m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events = append(events, e) }
			tc.fire(a)
			if len(events) != 1 || events[0].Conn != s.c || events[0].Message.HasHeader || !events[0].Closing || !errors.Is(events[0].Err, tc.kind) || events[0].Reply != diam.ProtocolReplyNone {
				t.Fatalf("events=%+v", events)
			}
			a.handle(event{kind: timeout, token: a.token - 1})
			if len(events) != 1 {
				t.Fatal("retired timer notified")
			}
		})
	}
	t.Run("retired answer keeps original connection", func(t *testing.T) {
		a, s, _ := failureReportingActor(t)
		var got diam.ProtocolErrorEvent
		a.m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { got = e }
		replacement := newFakeConn(testDict)
		t.Cleanup(replacement.Close)
		a.i = &session{c: replacement, gen: 2}
		msg := diam.NewRequest(999, 4, testDict).Answer(2001)
		a.onWire(event{s: s, msg: msg})
		protocolErrorCheck(t, got, s.c, *msg.Header, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
	})
}

type protocolErrorLoggedConn struct {
	diam.Conn
	logger *slog.Logger
}

func (c protocolErrorLoggedConn) Logger() *slog.Logger { return c.logger }

func TestProtocolErrorManagerCallbackPanic(t *testing.T) {
	testDict := newTestDictionary(creditcontrol.Dictionary())

	a, s, _ := failureReportingActor(t)
	records := logtest.New()
	s.c = protocolErrorLoggedConn{Conn: s.c, logger: records.Logger()}
	var calls int
	a.m.cfg.Settings.OnProtocolError = func(diam.ProtocolErrorEvent) { calls++; panic("callback failure") }
	for range 2 {
		a.m.unsupported(s, diam.NewRequest(999, 0, testDict))
	}
	if calls != 2 || len(s.writes) != 2 || s.c.Closed() {
		t.Fatal("panic changed handling or delivery")
	}
	logs := records.Records()
	if len(logs) != 2 {
		t.Fatalf("panic logs=%v", logs)
	}
	for _, r := range logs {
		if r.Level != slog.LevelError || r.Message != "diam: protocol error callback panicked" || logtest.Attr(r, "stack").String() == "" {
			t.Fatalf("panic record=%v", r)
		}
	}
}

func TestProtocolErrorManagerCallbackBackpressure(t *testing.T) {
	testDict := newTestDictionary(creditcontrol.Dictionary())

	a, s, _ := failureReportingActor(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	a.m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { close(entered); <-release }
	go func() { a.m.unsupported(s, diam.NewRequest(999, 0, testDict)); close(done) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("callback not called")
	}
	if len(s.writes) != 1 {
		t.Fatal("callback preceded answer enqueue")
	}
	select {
	case <-done:
		t.Fatal("callback was asynchronous")
	default:
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("blocked callback did not release worker")
	}
}

func TestProtocolErrorManagerConcurrentCallbacks(t *testing.T) {
	testDict := newTestDictionary(creditcontrol.Dictionary())

	a, s, _ := failureReportingActor(t)
	entered, release, done := make(chan struct{}, 2), make(chan struct{}), make(chan struct{}, 2)
	a.m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) {
		_ = a.m.getSession(s.c)
		_, _ = s.binding()
		entered <- struct{}{}
		<-release
	}
	for range 2 {
		go func() { a.m.unsupported(s, diam.NewRequest(999, 0, testDict)); done <- struct{}{} }()
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			close(release)
			t.Fatal("callbacks serialized or bookkeeping lock held")
		}
	}
	close(release)
	for range 2 {
		<-done
	}
}

func TestProtocolErrorManagerLocalFailuresAreNotProtocolErrors(t *testing.T) {
	for _, tc := range []struct {
		name, operation string
		enqueue         bool
	}{
		{"DWA enqueue", "send DWA", true},
		{"CEA build", "build CEA", false},
		{"DWR enqueue", "send DWR", true},
		{"DPR enqueue", "send DPR", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, s, records := failureReportingActor(t)
			a.state, a.i, a.active = IOpen, s, s
			var events []diam.ProtocolErrorEvent
			a.m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events = append(events, e) }
			var cause error
			wantWrites := 0
			if tc.enqueue {
				for len(s.writes) < cap(s.writes) {
					s.writes <- writeRequest{}
				}
				if len(s.writes) != cap(s.writes) {
					t.Fatal("enqueue failure requires a full write queue")
				}
				cause, wantWrites = errQueueFull, cap(s.writes)
			} else {
				a.m.cfg.Settings.HostIPAddresses = []datatype.Address{{}}
			}
			switch tc.name {
			case "DWA enqueue":
				a.step(iDWR, s, reviewDWR(t))
			case "CEA build":
				s.cerRequest = reviewCER(t)
				if a.sendCEA(s) {
					t.Fatal("invalid CEA settings unexpectedly built an answer")
				}
			case "DWR enqueue":
				a.sendWatchdog()
			case "DPR enqueue":
				a.step(stop, s, nil)
			}
			if !s.c.Closed() || a.state != Closed || a.active != nil {
				t.Fatalf("local failure did not close connection: closed=%v state=%v active=%p writes=%d", s.c.Closed(), a.state, a.active, len(s.writes))
			}
			if len(s.writes) != wantWrites || a.pendingWatchdog || a.pendingDPR != 0 {
				t.Fatalf("failed control message advanced state: writes=%d want=%d watchdog=%v DPR=%d", len(s.writes), wantWrites, a.pendingWatchdog, a.pendingDPR)
			}
			assertFailureRecord(t, records, slog.LevelError, "peer: "+tc.operation+" failed; closing connection", s.c.RemoteAddr().String(), cause)
			assertFailureEvents(t, a, []PeerState{Closed, Closed}, []WatchdogState{WatchdogInitial, WatchdogInitial}, []string{"", "peer: " + tc.operation + ":"})
			if len(events) != 0 {
				t.Fatalf("local failure notified as protocol error: %+v", events)
			}
		})
	}
}

func TestProtocolErrorManagerWirePendingAnswers(t *testing.T) {
	for _, command := range []uint32{diam.DeviceWatchdog, diam.DisconnectPeer} {
		for _, fault := range []string{"identifiers", "identity", "missing AVP", "rejected"} {
			name := map[uint32]string{diam.DeviceWatchdog: "DWA", diam.DisconnectPeer: "DPA"}[command] + "/" + fault
			t.Run(name, func(t *testing.T) {
				events := make(chan diam.ProtocolErrorEvent, 8)
				settings := testSettings("local.example.net")
				settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
				clock, records := &fakeClock{}, logtest.New()
				m, err := New(Config{Settings: settings, Clock: clock, Logger: records.Logger()})
				if err != nil {
					t.Fatal(err)
				}
				if err = m.AddPeer(PeerConfig{Host: "known.example.net"}); err != nil {
					t.Fatal(err)
				}
				l, srv := startReceiverWithHandlers(t, m, 8)
				t.Cleanup(func() { closeManager(t, m, srv) })
				c, err := net.Dial("tcp", l.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = c.Close() })
				write(t, c, reviewCER(t))
				read(t, c)
				clock.waitTimers(t, 2)
				m.mu.RLock()
				var connection diam.Conn
				for conn := range m.sessions {
					connection = conn
				}
				m.mu.RUnlock()
				var closing <-chan error
				if command == diam.DeviceWatchdog {
					clock.fire()
				} else {
					done := make(chan error, 1)
					closing = done
					go func() {
						ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
						defer cancel()
						done <- m.Close(ctx, sm.DisconnectRebooting)
					}()
				}
				request := read(t, c)
				if request.Header.CommandCode != command {
					t.Fatalf("control request=%+v", request.Header)
				}
				var answer *diam.Message
				if command == diam.DeviceWatchdog {
					answer, err = base.BuildDWA(request, testBase("known.example.net"))
				} else {
					answer, err = base.BuildDPA(request, testBase("known.example.net"))
				}
				if err != nil {
					t.Fatal(err)
				}
				valid := *answer.Header
				kind := diam.ProtocolInvalidDWA
				if command == diam.DisconnectPeer {
					kind = diam.ProtocolInvalidDPA
				}
				result := uint32(0)
				switch fault {
				case "identifiers":
					answer.Header.EndToEndID++
				case "identity":
					a, _ := answer.FindAVP(avp.OriginHost, 0)
					a.Data = datatype.DiameterIdentity("other.example.net")
				case "missing AVP":
					for i, a := range answer.AVP {
						if a.Code == avp.OriginRealm {
							answer.AVP = append(answer.AVP[:i], answer.AVP[i+1:]...)
							answer.Header.MessageLength = uint32(answer.Len())
							break
						}
					}
				case "rejected":
					a, _ := answer.FindAVP(avp.ResultCode, 0)
					a.Data = datatype.Unsigned32(3002)
					result = 3002
					if command == diam.DeviceWatchdog {
						kind = diam.ProtocolRejectedDWA
					} else {
						kind = diam.ProtocolPeerRejected
					}
				}
				write(t, c, answer)
				e := protocolErrorReceive(t, events)
				protocolErrorCheck(t, e, connection, *answer.Header, kind, result, false, diam.ProtocolReplyNone, 0, 0)
				if closing != nil {
					select {
					case err := <-closing:
						t.Fatalf("invalid DPA completed close: %v", err)
					default:
					}
				}
				if command == diam.DeviceWatchdog {
					answer, err = base.BuildDWA(request, testBase("known.example.net"))
				} else {
					answer, err = base.BuildDPA(request, testBase("known.example.net"))
				}
				if err != nil {
					t.Fatal(err)
				}
				*answer.Header = valid
				write(t, c, answer)
				if closing != nil {
					select {
					case err := <-closing:
						if err != nil {
							t.Fatal(err)
						}
					case <-time.After(time.Second):
						t.Fatal("valid DPA did not complete close")
					}
				} else {
					write(t, c, reviewDWR(t))
					if code(t, read(t, c)) != 2001 {
						t.Fatal("invalid DWA changed connection")
					}
				}
				select {
				case extra := <-events:
					t.Fatalf("extra event=%+v", extra)
				default:
				}
				logs := records.Records()
				if len(logs) != 1 || logs[0].Level != slog.LevelWarn || logs[0].Message != "peer: protocol error" {
					t.Fatalf("logs changed: %v", logs)
				}
			})
		}
	}
}
