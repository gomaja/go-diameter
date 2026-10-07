package peer

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/sm"
)

type fakeClock struct {
	mu     sync.Mutex
	timers []*fakeTimer
}
type fakeConn struct {
	once              sync.Once
	done              chan struct{}
	underlying, other net.Conn
	ctx               context.Context
}

func newFakeConn() *fakeConn {
	a, b := net.Pipe()
	return &fakeConn{done: make(chan struct{}), underlying: a, other: b, ctx: context.Background()}
}
func (c *fakeConn) Write(b []byte) (int, error)               { return len(b), nil }
func (c *fakeConn) WriteStream(b []byte, _ uint) (int, error) { return c.Write(b) }
func (c *fakeConn) Close() {
	c.once.Do(func() { close(c.done); _ = c.underlying.Close(); _ = c.other.Close() })
}
func (c *fakeConn) CloseNotify() <-chan struct{}   { return c.done }
func (c *fakeConn) LocalAddr() net.Addr            { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3868} }
func (c *fakeConn) RemoteAddr() net.Addr           { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 3868} }
func (c *fakeConn) TLS() *tls.ConnectionState      { return nil }
func (c *fakeConn) Dictionary() *dict.Parser       { return dict.Default }
func (c *fakeConn) Logger() *slog.Logger           { return slog.Default() }
func (c *fakeConn) Context() context.Context       { return c.ctx }
func (c *fakeConn) SetContext(ctx context.Context) { c.ctx = ctx }
func (c *fakeConn) Connection() net.Conn           { return c.underlying }

type fakeTimer struct {
	mu       sync.Mutex
	active   bool
	f        func()
	duration time.Duration
}

func (c *fakeClock) AfterFunc(d time.Duration, f func()) Timer {
	t := &fakeTimer{active: true, f: f, duration: d}
	c.mu.Lock()
	c.timers = append(c.timers, t)
	c.mu.Unlock()
	return t
}
func (t *fakeTimer) Stop() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	was := t.active
	t.active = false
	return was
}
func (c *fakeClock) fire() {
	c.mu.Lock()
	timers := append([]*fakeTimer(nil), c.timers...)
	c.mu.Unlock()
	for _, t := range timers {
		t.mu.Lock()
		active := t.active
		t.active = false
		t.mu.Unlock()
		if active {
			t.f()
		}
	}
}
func testSettings(host string) sm.Settings {
	return sm.Settings{OriginHost: datatype.DiameterIdentity(host), OriginRealm: "example.net", VendorID: 1, ProductName: "test"}
}
func testBase(host string) base.Settings {
	cfg := base.Settings{OriginHost: datatype.DiameterIdentity(host), OriginRealm: "example.net", VendorID: 1, ProductName: "test", HostIPAddresses: []datatype.Address{datatype.AddressFromIP(netip.MustParseAddr("127.0.0.1"))}}
	apps := sm.PrepareSupportedApps(dict.Default)
	for _, a := range apps {
		if a.AppType == "auth" && a.Vendor == 0 {
			cfg.AuthApplicationID = []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(a.ID))}
			break
		}
	}
	return cfg
}
func startReceiver(t *testing.T, m *Manager) (net.Listener, *diam.Server) {
	return startReceiverWithHandlers(t, m, 0)
}
func startReceiverWithHandlers(t *testing.T, m *Manager, concurrent int) (net.Listener, *diam.Server) {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	srv := &diam.Server{MaxConcurrentHandlers: concurrent}
	if e = m.BindServer(srv); e != nil {
		t.Fatal(e)
	}
	go func() { _ = srv.Serve(l) }()
	return l, srv
}

func TestConcurrentDispatchPreservesFirstCER(t *testing.T) {
	m, err := New(Config{Settings: testSettings("local.example.net")})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.AddPeer(PeerConfig{Host: "known.example.net"}); err != nil {
		t.Fatal(err)
	}
	l, srv := startReceiverWithHandlers(t, m, 16)
	defer closeManager(t, m, srv)
	cfg := testBase("known.example.net")
	for run := 0; run < 20; run++ {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		cer, err := base.BuildCER(dict.Default, cfg)
		if err != nil {
			t.Fatal(err)
		}
		dwr, err := base.BuildDWR(dict.Default, cfg, 0)
		if err != nil {
			t.Fatal(err)
		}
		write(t, c, cer)
		write(t, c, dwr)
		cea := read(t, c)
		dwa := read(t, c)
		if dwa.Header.CommandCode == diam.DeviceWatchdog && dwa.Header.CommandFlags&diam.RequestFlag != 0 {
			answer, err := base.BuildDWA(dwa, cfg)
			if err != nil {
				t.Fatal(err)
			}
			write(t, c, answer)
			dwa = read(t, c)
		}
		if cea.Header.CommandCode != diam.CapabilitiesExchange || code(t, cea) != diam.Success || dwa.Header.CommandCode != diam.DeviceWatchdog || code(t, dwa) != diam.Success {
			t.Fatalf("run %d: response order %d/%d", run, cea.Header.CommandCode, dwa.Header.CommandCode)
		}
		dpr, err := base.BuildDPR(dict.Default, cfg, 0)
		if err != nil {
			t.Fatal(err)
		}
		write(t, c, dpr)
		dpa := read(t, c)
		if dpa.Header.CommandCode != diam.DisconnectPeer || code(t, dpa) != diam.Success {
			t.Fatalf("run %d: no DPA", run)
		}
		_ = c.Close()
		awaitState(t, m, Closed)
	}
}

func TestOrderedIngressFIFOWithSingleSlot(t *testing.T) {
	m, err := New(Config{Settings: testSettings("local.example.net"), Limits: Limits{Events: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.AddPeer(PeerConfig{Host: "known.example.net"}); err != nil {
		t.Fatal(err)
	}
	c := &capabilityWireConn{fakeConn: newFakeConn(), wire: make(chan []byte, 2)}
	s := m.newSession(c, nil, 0, true)
	defer func() { s.close(); closeManager(t, m, nil) }()
	cer, err := base.BuildCER(dict.Default, testBase("known.example.net"))
	if err != nil {
		t.Fatal(err)
	}
	dwr, err := base.BuildDWR(dict.Default, testBase("known.example.net"), 0)
	if err != nil {
		t.Fatal(err)
	}
	// The single write slot must be drained before asking for another answer.
	// A wire notification, not actor state or scheduling, proves that happened.
	for _, request := range []*diam.Message{cer, dwr} {
		s.ingress <- incoming{msg: request}
		select {
		case wire := <-c.wire:
			answer, err := diam.ReadMessage(bytes.NewReader(wire), dict.Default)
			if err != nil {
				t.Fatal(err)
			}
			if code(t, answer) != diam.Success || answer.Header.CommandCode != request.Header.CommandCode || answer.Header.HopByHopID != request.Header.HopByHopID {
				t.Fatalf("unexpected answer: %v", answer)
			}
		case <-time.After(time.Second):
			t.Fatal("answer was not written")
		}
	}
	if peers := m.Peers(); len(peers) != 1 || peers[0].State != ROpen {
		t.Fatalf("peer state after DWA: %v", peers)
	}
	select {
	case <-s.closed:
		t.Fatal("FIFO admission closed the connection")
	default:
	}
}
func closeManager(t *testing.T, m *Manager, s *diam.Server) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := m.Close(ctx, sm.DisconnectRebooting); err != nil {
		t.Fatal(err)
	}
	if s != nil {
		_ = s.Close()
	}
}
func read(t *testing.T, c net.Conn) *diam.Message {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	m, e := diam.ReadMessage(c, dict.Default)
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func write(t *testing.T, c net.Conn, m *diam.Message) {
	t.Helper()
	_ = c.SetWriteDeadline(time.Now().Add(time.Second))
	if _, e := m.WriteTo(c); e != nil {
		t.Fatal(e)
	}
}
func code(t *testing.T, m *diam.Message) uint32 {
	t.Helper()
	var r struct {
		ResultCode uint32 `avp:"Result-Code"`
	}
	if e := m.Unmarshal(&r); e != nil {
		t.Fatal(e)
	}
	return r.ResultCode
}
func awaitState(t *testing.T, m *Manager, want PeerState) {
	t.Helper()
	end := time.Now().Add(time.Second)
	for time.Now().Before(end) {
		if m.Peers()[0].State == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("state=%s want %s", m.Peers()[0].State, want)
}

func TestPreCERGateAndUnknownPeer(t *testing.T) {
	for _, name := range []string{"non-CER", "timeout", "unknown-peer", "missing-host", "no-common-application"} {
		t.Run(name, func(t *testing.T) {
			clock := &fakeClock{}
			records := logtest.New()
			m, e := New(Config{Logger: records.Logger(), Settings: testSettings("local.example.net"), Clock: clock})
			if e != nil {
				t.Fatal(e)
			}
			if e = m.AddPeer(PeerConfig{Host: "known.example.net"}); e != nil {
				t.Fatal(e)
			}
			l, srv := startReceiver(t, m)
			defer closeManager(t, m, srv)
			c, e := net.Dial("tcp", l.Addr().String())
			if e != nil {
				t.Fatal(e)
			}
			defer func() { _ = c.Close() }()
			switch name {
			case "non-CER":
				dwr, e := base.BuildDWR(dict.Default, testBase("known.example.net"), 0)
				if e != nil {
					t.Fatal(e)
				}
				write(t, c, dwr)
			case "timeout":
				time.Sleep(10 * time.Millisecond)
				clock.fire()
			default:
				host := "known.example.net"
				if name == "unknown-peer" {
					host = "other.example.net"
				}
				cer, e := base.BuildCER(dict.Default, testBase(host))
				if e != nil {
					t.Fatal(e)
				}
				if name == "missing-host" {
					filtered := cer.AVP[:0]
					for _, a := range cer.AVP {
						if a.Code != avp.OriginHost {
							filtered = append(filtered, a)
						}
					}
					cer.AVP = filtered
					cer.Header.MessageLength = uint32(cer.Len())
				}
				if name == "no-common-application" {
					filtered := cer.AVP[:0]
					for _, a := range cer.AVP {
						if a.Code != avp.AuthApplicationID {
							filtered = append(filtered, a)
						}
					}
					cer.AVP = filtered
					cer.Header.MessageLength = uint32(cer.Len())
				}
				write(t, c, cer)
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				ans, readErr := diam.ReadMessage(c, dict.Default)
				if readErr != nil {
					t.Fatalf("read: %v; state: %+v; records: %v", readErr, m.Peers(), records.Records())
				}
				want := uint32(diam.MissingAVP)
				if name == "unknown-peer" {
					want = diam.UnknownPeer
				}
				if name == "no-common-application" {
					want = diam.NoCommonApplication
				}
				if got := code(t, ans); got != want {
					t.Fatalf("Result-Code=%d want %d", got, want)
				}
			}
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			var b [1]byte
			_, e = c.Read(b[:])
			if e == nil {
				t.Fatal("connection remained open")
			}
			if n, ok := e.(net.Error); ok && n.Timeout() {
				t.Fatal("connection did not close")
			}
			if len(records.Records()) == 0 {
				t.Fatal("peer close decision was not logged before EOF")
			}
		})
	}
}

func TestMalformedFirstMessageCannotAdmitLaterCER(t *testing.T) {
	for _, tc := range []struct {
		name       string
		firstCER   bool
		wantAnswer bool
	}{
		{name: "malformed CER", firstCER: true, wantAnswer: true},
		{name: "malformed non-CER"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := &fakeClock{}
			records := logtest.New()
			m, err := New(Config{Logger: records.Logger(), Settings: testSettings("local.example.net"), Clock: clock})
			if err != nil {
				t.Fatal(err)
			}
			if err := m.AddPeer(PeerConfig{Host: "known.example.net"}); err != nil {
				t.Fatal(err)
			}
			l, srv := startReceiver(t, m)
			defer closeManager(t, m, srv)
			c, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			cfg := testBase("known.example.net")
			cer, err := base.BuildCER(dict.Default, cfg)
			if err != nil {
				t.Fatal(err)
			}
			first := cer
			if !tc.firstCER {
				first, err = base.BuildDWR(dict.Default, cfg, 0)
				if err != nil {
					t.Fatal(err)
				}
			}
			var raw, valid bytes.Buffer
			if _, err := first.WriteTo(&raw); err != nil {
				t.Fatal(err)
			}
			if _, err := cer.WriteTo(&valid); err != nil {
				t.Fatal(err)
			}
			wire := raw.Bytes()
			wire[25], wire[26], wire[27] = 0xff, 0xff, 0xff // First AVP length exceeds this message.
			batch := append(append([]byte(nil), wire...), valid.Bytes()...)
			if n, err := c.Write(batch); err != nil || n != len(batch) {
				t.Fatalf("write %d/%d: %v", n, len(batch), err)
			}
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			if tc.wantAnswer {
				answer, err := diam.ReadMessage(c, dict.Default)
				if err != nil {
					t.Fatalf("missing malformed CER answer: %v", err)
				}
				if got := code(t, answer); got != diam.InvalidAVPLength {
					t.Fatalf("Result-Code=%d want %d", got, diam.InvalidAVPLength)
				}
			}
			if answer, err := diam.ReadMessage(c, dict.Default); err == nil {
				t.Fatalf("admitted later CER: answer command=%d code=%d", answer.Header.CommandCode, code(t, answer))
			} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				t.Fatalf("connection stayed open after malformed first message: %v", err)
			}
			if len(records.Records()) == 0 {
				t.Fatal("malformed first message close was not logged before EOF")
			}
			clock.mu.Lock()
			timers := append([]*fakeTimer(nil), clock.timers...)
			clock.mu.Unlock()
			if len(timers) == 0 {
				t.Fatal("pre-CER timer was not armed")
			}
			timers[0].mu.Lock()
			active := timers[0].active
			timers[0].mu.Unlock()
			if active {
				t.Fatal("pre-CER timer remained active after connection close")
			}
		})
	}
}

func TestFakeTransportPreCERTimer(t *testing.T) {
	clock := &fakeClock{}
	m, err := New(Config{Settings: testSettings("local.example.net"), Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	c := newFakeConn()
	m.acceptConnection(c)
	clock.fire()
	select {
	case <-c.done:
	case <-time.After(time.Second):
		t.Fatal("pre-CER timeout did not close fake transport")
	}
	closeManager(t, m, nil)
}

func TestFakeTransportOpenControl(t *testing.T) {
	clock := &fakeClock{}
	m, err := New(Config{Settings: testSettings("local.example.net"), Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	a := &actor{m: m, cfg: PeerConfig{Host: "known.example.net"}, state: ROpen, events: make(chan event, 8), done: make(chan struct{})}
	s := &session{m: m, c: newFakeConn(), actor: a, gen: 1, writes: make(chan writeRequest, 8), closed: make(chan struct{})}
	a.r = s
	a.active = s
	a.publish(nil)
	cfg := testBase("known.example.net")
	dwr, err := base.BuildDWR(dict.Default, cfg, 0)
	if err != nil {
		t.Fatal(err)
	}
	a.onWire(event{kind: wireEvent, s: s, msg: dwr})
	w := <-s.writes
	if w.msg.Header.CommandCode != diam.DeviceWatchdog || w.msg.Header.HopByHopID != dwr.Header.HopByHopID || code(t, w.msg) != diam.Success {
		t.Fatal("wrong DWA")
	}
	dpr, err := base.BuildDPR(dict.Default, cfg, 0)
	if err != nil {
		t.Fatal(err)
	}
	a.onWire(event{kind: wireEvent, s: s, msg: dpr})
	w = <-s.writes
	if a.state != Closing || w.msg.Header.CommandCode != diam.DisconnectPeer || code(t, w.msg) != diam.Success {
		t.Fatal("wrong DPA or state")
	}
	clock.fire()
	a.handle(<-a.events)
	if a.state != Closed {
		t.Fatalf("Closing timer left state %s", a.state)
	}
	select {
	case <-s.closed:
	default:
		t.Fatal("Closing timer left transport open")
	}
	closeManager(t, m, nil)
}

func TestMismatchedDPRIsReportedWithoutDPA(t *testing.T) {
	for _, state := range []PeerState{IOpen, ROpen, Closing} {
		t.Run(string(state), func(t *testing.T) {
			records := logtest.New()
			m, err := New(Config{Logger: records.Logger(), Settings: testSettings("local.example.net")})
			if err != nil {
				t.Fatal(err)
			}
			defer closeManager(t, m, nil)
			a := &actor{m: m, cfg: PeerConfig{Host: "known.example.net"}, state: state, events: make(chan event, 8), done: make(chan struct{})}
			s := &session{m: m, c: newFakeConn(), actor: a, gen: 1, writes: make(chan writeRequest, 8), closed: make(chan struct{})}
			defer s.close()
			if state == IOpen {
				a.i = s
			} else {
				a.r = s
			}
			a.active = s
			a.publish(nil)
			bad, err := base.BuildDPR(dict.Default, testBase("other.example.net"), 0)
			if err != nil {
				t.Fatal(err)
			}
			a.onWire(event{kind: wireEvent, s: s, msg: bad})
			if a.state != state {
				t.Fatalf("mismatched DPR moved state from %s to %s", state, a.state)
			}
			select {
			case <-s.writes:
				t.Fatal("mismatched DPR received DPA")
			default:
			}
			got := records.Records()
			if len(got) != 1 || !strings.Contains(logtest.Attr(got[0], "error").Any().(error).Error(), "DPR Origin-Host mismatch") {
				t.Fatalf("mismatch records=%v", got)
			}
			good, err := base.BuildDPR(dict.Default, testBase("KNOWN.example.net"), 0)
			if err != nil {
				t.Fatal(err)
			}
			a.onWire(event{kind: wireEvent, s: s, msg: good})
			if a.state != Closing {
				t.Fatalf("matching DPR left state %s", a.state)
			}
			select {
			case answer := <-s.writes:
				if answer.msg.Header.CommandCode != diam.DisconnectPeer || code(t, answer.msg) != diam.Success {
					t.Fatal("matching DPR did not receive successful DPA")
				}
			default:
				t.Fatal("matching DPR received no DPA")
			}
		})
	}
}

func TestFakeTransportDPAIdentifiersAndPeer(t *testing.T) {
	for _, state := range []PeerState{IOpen, ROpen} {
		t.Run(string(state), func(t *testing.T) {
			clock := &fakeClock{}
			m, err := New(Config{Settings: testSettings("local.example.net"), Clock: clock})
			if err != nil {
				t.Fatal(err)
			}
			defer closeManager(t, m, nil)
			a := &actor{m: m, cfg: PeerConfig{Host: "known.example.net"}, state: state, events: make(chan event, 8), done: make(chan struct{})}
			s := &session{m: m, c: newFakeConn(), actor: a, gen: 1, writes: make(chan writeRequest, 8), closed: make(chan struct{})}
			defer s.close()
			if state == IOpen {
				a.i = s
			} else {
				a.r = s
			}
			a.active = s
			a.publish(nil)
			a.stop(sm.DisconnectBusy)
			if a.state != Closing {
				t.Fatalf("state=%s", a.state)
			}
			dpr := (<-s.writes).msg
			if dpr.Header.CommandCode != diam.DisconnectPeer || dpr.Header.CommandFlags&diam.RequestFlag == 0 {
				t.Fatal("missing DPR")
			}
			answer := func() *diam.Message {
				m, err := base.BuildDPA(dpr, testBase("known.example.net"))
				if err != nil {
					t.Fatal(err)
				}
				return m
			}
			for _, mutate := range []func(*diam.Message){
				func(m *diam.Message) { m.Header.HopByHopID++ },
				func(m *diam.Message) { m.Header.EndToEndID++ },
				func(m *diam.Message) {
					a, _ := m.FindAVP(avp.ResultCode, 0)
					a.Data = datatype.Unsigned32(diam.UnableToComply)
				},
				func(m *diam.Message) {
					a, _ := m.FindAVP(avp.OriginHost, 0)
					a.Data = datatype.DiameterIdentity("other.example.net")
				},
			} {
				a.onWire(event{kind: wireEvent, s: s, msg: func() *diam.Message { m := answer(); mutate(m); return m }()})
				if a.state != Closing {
					t.Fatalf("invalid DPA moved state to %s", a.state)
				}
			}
			a.onWire(event{kind: wireEvent, s: s, msg: answer()})
			if a.state != Closed {
				t.Fatalf("valid DPA left state %s", a.state)
			}
		})
	}
}

func TestManagerSupportsApplication(t *testing.T) {
	m, e := New(Config{Settings: testSettings("local.example.net")})
	if e != nil {
		t.Fatal(e)
	}
	defer closeManager(t, m, nil)
	for appID, want := range map[uint32]bool{0: true, diam.CHARGING_CONTROL_APP_ID: true, 0x00abcdef: false} {
		if got := m.supportsApplication(appID); got != want {
			t.Errorf("supportsApplication(%d) = %t, want %t", appID, got, want)
		}
	}
	m.localApps[0xffffffff] = struct{}{} // RFC 6733 §2.4: a relay supports every application.
	if !m.supportsApplication(0x00abcdef) {
		t.Error("a relay must support every application")
	}
}

// TestManagedUnsupportedApplication checks RFC 6733 §7.1.3: a request for an
// application the manager does not advertise gets an E-bit 3007, not 3001.
func TestManagedUnsupportedApplication(t *testing.T) {
	m, e := New(Config{Settings: testSettings("local.example.net")})
	if e != nil {
		t.Fatal(e)
	}
	if e = m.AddPeer(PeerConfig{Host: "known.example.net"}); e != nil {
		t.Fatal(e)
	}
	l, srv := startReceiver(t, m)
	defer closeManager(t, m, srv)
	c, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = c.Close() }()
	cer, e := base.BuildCER(dict.Default, testBase("known.example.net"))
	if e != nil {
		t.Fatal(e)
	}
	write(t, c, cer)
	if cea := read(t, c); code(t, cea) != diam.Success {
		t.Fatalf("CEA %d", code(t, cea))
	}
	awaitState(t, m, ROpen)
	for _, tc := range []struct {
		appID uint32
		want  uint32
	}{
		{0x00abcdef, diam.ApplicationUnsupported},
		{diam.CHARGING_CONTROL_APP_ID, diam.CommandUnsupported},
	} {
		req := diam.NewMessage(999, diam.RequestFlag, tc.appID, 0x1234, 0x5678, dict.Default)
		write(t, c, req)
		ans := read(t, c)
		if ans.Header.CommandFlags&diam.ErrorFlag == 0 || code(t, ans) != tc.want {
			t.Fatalf("application %d: answer %+v, Result-Code %d, want E-bit %d", tc.appID, ans.Header, code(t, ans), tc.want)
		}
	}
}

func TestManagedControlAndUnsupported(t *testing.T) {
	records := logtest.New()
	m, e := New(Config{Logger: records.Logger(), Settings: testSettings("local.example.net")})
	if e != nil {
		t.Fatal(e)
	}
	if e = m.AddPeer(PeerConfig{Host: "known.example.net"}); e != nil {
		t.Fatal(e)
	}
	l, srv := startReceiver(t, m)
	defer closeManager(t, m, srv)
	c, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = c.Close() }()
	cfg := testBase("known.example.net")
	cer, e := base.BuildCER(dict.Default, cfg)
	if e != nil {
		t.Fatal(e)
	}
	write(t, c, cer)
	cea := read(t, c)
	if code(t, cea) != diam.Success {
		t.Fatalf("CEA %d", code(t, cea))
	}
	awaitState(t, m, ROpen)
	dwr, e := base.BuildDWR(dict.Default, cfg, 0)
	if e != nil {
		t.Fatal(e)
	}
	write(t, c, dwr)
	dwa := read(t, c)
	if dwa.Header.CommandCode != diam.DeviceWatchdog || code(t, dwa) != diam.Success {
		t.Fatalf("DWA %+v", dwa.Header)
	}
	req := diam.NewRequest(999, 0, dict.Default)
	write(t, c, req)
	ans := read(t, c)
	if ans.Header.CommandFlags&diam.ErrorFlag == 0 || code(t, ans) != diam.CommandUnsupported {
		t.Fatalf("unsupported answer %+v", ans.Header)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := records.Wait(ctx, 1)
	if err != nil || !logtest.Attr(got[0], "message.request").Bool() {
		t.Fatalf("request records=%v, err=%v", got, err)
	}
	write(t, c, req.Answer(diam.Success))
	got, err = records.Wait(ctx, 2)
	if err != nil || logtest.Attr(got[1], "message.request").Bool() {
		t.Fatalf("answer records=%v, err=%v", got, err)
	}
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	var extra [1]byte
	if _, err := c.Read(extra[:]); err == nil {
		t.Fatal("answered an answer")
	}
	dpr, e := base.BuildDPR(dict.Default, cfg, 0)
	if e != nil {
		t.Fatal(e)
	}
	write(t, c, dpr)
	dpa := read(t, c)
	if dpa.Header.CommandCode != diam.DisconnectPeer || code(t, dpa) != diam.Success {
		t.Fatalf("DPA %+v", dpa.Header)
	}
	_ = c.Close()
	awaitState(t, m, Closed)
}

func TestInboundSurvivesOutboundNackWithoutCERTimer(t *testing.T) {
	clock := &fakeClock{}
	release := make(chan struct{})
	m, err := New(Config{
		Settings: testSettings("local.example.net"), Clock: clock,
		Dial: func(context.Context, Endpoint) (net.Conn, error) {
			<-release
			return nil, errors.New("dial refused")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.AddPeer(PeerConfig{Host: "known.example.net", Endpoints: []Endpoint{{Network: "tcp", Address: "127.0.0.1:1"}}}); err != nil {
		t.Fatal(err)
	}
	l, srv := startReceiver(t, m)
	defer closeManager(t, m, srv)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	awaitState(t, m, WaitConnAck)
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	cfg := testBase("known.example.net")
	cer, err := base.BuildCER(dict.Default, cfg)
	if err != nil {
		t.Fatal(err)
	}
	write(t, c, cer)
	awaitState(t, m, WaitConnAckElect)
	close(release)
	if got := code(t, read(t, c)); got != diam.Success {
		t.Fatalf("CEA Result-Code=%d", got)
	}
	awaitState(t, m, ROpen)
	clock.fire()
	if got := m.Peers()[0].State; got != ROpen {
		t.Fatalf("stale CER timer closed peer: %s", got)
	}
	// Firing the fake clock also expires the valid watchdog timer. Answer its
	// DWR so the following read checks the DPR/DPA exchange alone.
	probe := read(t, c)
	if probe.Header.CommandCode != diam.DeviceWatchdog || probe.Header.CommandFlags&diam.RequestFlag == 0 {
		t.Fatalf("watchdog probe: %+v", probe.Header)
	}
	answer, err := base.BuildDWA(probe, cfg)
	if err != nil {
		t.Fatal(err)
	}
	write(t, c, answer)
	dpr, err := base.BuildDPR(dict.Default, cfg, 0)
	if err != nil {
		t.Fatal(err)
	}
	write(t, c, dpr)
	if got := code(t, read(t, c)); got != diam.Success {
		t.Fatalf("DPA Result-Code=%d", got)
	}
	_ = c.Close()
	awaitState(t, m, Closed)
}

func TestRejectedCEA(t *testing.T) {
	for _, name := range []string{"bad-result", "missing-origin-host", "no-common-application"} {
		t.Run(name, func(t *testing.T) {
			l, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer func() { _ = l.Close() }()
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				c, e := l.Accept()
				if e != nil {
					return
				}
				defer func() { _ = c.Close() }()
				cer, e := diam.ReadMessage(c, dict.Default)
				if e != nil {
					return
				}
				cfg := testBase("remote.example.net")
				result := uint32(diam.Success)
				if name == "bad-result" {
					result = diam.UnableToComply
				}
				if name == "no-common-application" {
					cfg.Applications = nil
					cfg.AuthApplicationID = []*diam.AVP{}
					cfg.AcctApplicationID = []*diam.AVP{}
					cfg.VendorSpecificApplicationID = []*diam.AVP{}
				}
				if name != "no-common-application" {
					cfg.Applications = []base.LocalApplication{{ID: uint32(cfg.AuthApplicationID[0].Data.(datatype.Unsigned32)), AppType: "auth"}}
				}
				cea, e := base.BuildCEA(cer, cfg, result)
				if e != nil {
					t.Errorf("build CEA: %v", e)
					return
				}
				if name == "missing-origin-host" {
					out := cea.AVP[:0]
					for _, a := range cea.AVP {
						if a.Code != avp.OriginHost {
							out = append(out, a)
						}
					}
					cea.AVP = out
					cea.Header.MessageLength = uint32(cea.Len())
				}
				_, _ = cea.WriteTo(c)
				var b [1]byte
				_, _ = c.Read(b[:])
			}()
			m, e := New(Config{Settings: testSettings("local.example.net")})
			if e != nil {
				t.Fatal(e)
			}
			if e = m.AddPeer(PeerConfig{Host: "remote.example.net", Endpoints: []Endpoint{{Network: "tcp", Address: l.Addr().String()}}}); e != nil {
				t.Fatal(e)
			}
			if e = m.Start(context.Background()); e != nil {
				t.Fatal(e)
			}
			end := time.Now().Add(time.Second)
			for time.Now().Before(end) {
				p := m.Peers()[0]
				if p.State == Closed && p.Generation > 0 {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if p := m.Peers()[0]; p.State != Closed || p.Generation == 0 {
				t.Fatalf("state after CEA: %+v", p)
			}
			closeManager(t, m, nil)
			select {
			case <-serverDone:
			case <-time.After(time.Second):
				t.Fatal("server leaked")
			}
		})
	}
}

func TestBindServerRejectsServingAndHandler(t *testing.T) {
	m, e := New(Config{Settings: testSettings("local.example.net")})
	if e != nil {
		t.Fatal(e)
	}
	defer closeManager(t, m, nil)
	srv := &diam.Server{Handler: diam.NewServeMux()}
	if e = m.BindServer(srv); e == nil {
		t.Fatal("accepted existing handler")
	}
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = l.Close() }()
	accepted := make(chan struct{}, 1)
	serving := &diam.Server{OnNewConnection: func(diam.Conn) { accepted <- struct{}{} }}
	go func() { _ = serving.Serve(l) }()
	c, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = c.Close() }()
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("server did not begin serving")
	}
	if e = m.BindServer(serving); e == nil {
		t.Fatal("accepted serving server")
	}
	_ = serving.Close()
}

func TestBindServerRequiresMatchingDictionary(t *testing.T) {
	first, err := dict.NewParser()
	if err != nil {
		t.Fatal(err)
	}
	second, err := dict.NewParser()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		manager    *dict.Parser
		server     *dict.Parser
		wantReject bool
	}{
		{name: "both default"},
		{name: "explicit default manager", manager: dict.Default},
		{name: "explicit default server", server: dict.Default},
		{name: "same custom parser", manager: first, server: first},
		{name: "manager custom server default", manager: first, wantReject: true},
		{name: "manager default server custom", server: first, wantReject: true},
		{name: "distinct custom parsers", manager: first, server: second, wantReject: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := testSettings("local.example.net")
			settings.Dict = tc.manager
			m, err := New(Config{Settings: settings})
			if err != nil {
				t.Fatal(err)
			}
			defer closeManager(t, m, nil)
			srv := &diam.Server{Dict: tc.server}
			err = m.BindServer(srv)
			if tc.wantReject {
				if err == nil || !strings.Contains(err.Error(), "dictionary") {
					t.Fatalf("BindServer mismatch error=%v", err)
				}
				if srv.Handler != nil {
					t.Fatal("rejected server was modified")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSessionAdmissionRejectsAfterClose(t *testing.T) {
	t.Run("inbound", func(t *testing.T) {
		m, err := New(Config{Settings: testSettings("local.example.net")})
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Close(context.Background(), sm.DisconnectRebooting); err != nil {
			t.Fatal(err)
		}
		c := newFakeConn()
		if s := m.newSession(c, nil, 0, true); s != nil {
			s.close()
			t.Fatal("inbound session admitted after Close returned")
		}
		select {
		case <-c.done:
		default:
			t.Fatal("rejected inbound transport remained open")
		}
	})
	t.Run("outbound dial", func(t *testing.T) {
		var remote net.Conn
		m, err := New(Config{Settings: testSettings("local.example.net"), Dial: func(context.Context, Endpoint) (net.Conn, error) {
			local, peer := net.Pipe()
			remote = peer
			return local, nil
		}})
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Close(context.Background(), sm.DisconnectRebooting); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		s, err := m.dialEndpoint(ctx, Endpoint{Network: "tcp", Address: "peer.example.net:3868"}, nil, 1)
		if remote != nil {
			defer func() { _ = remote.Close() }()
		}
		if s != nil {
			s.close()
			t.Fatal("outbound session admitted after Close returned")
		}
		if err == nil {
			t.Fatal("outbound dial did not report manager shutdown")
		}
	})
}

func TestCloseRacesInboundConnections(t *testing.T) {
	for run := 0; run < 40; run++ {
		m, err := New(Config{Settings: testSettings("local.example.net")})
		if err != nil {
			t.Fatal(err)
		}
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &diam.Server{}
		if err := m.BindServer(srv); err != nil {
			t.Fatal(err)
		}
		go func() { _ = srv.Serve(l) }()
		start := make(chan struct{})
		var clients sync.WaitGroup
		for attempt := 0; attempt < 4; attempt++ {
			clients.Add(1)
			go func() {
				defer clients.Done()
				<-start
				if c, err := net.DialTimeout("tcp", l.Addr().String(), time.Second); err == nil {
					_ = c.Close()
				}
			}()
		}
		closed := make(chan error, 1)
		go func() {
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			closed <- m.Close(ctx, sm.DisconnectRebooting)
		}()
		close(start)
		clients.Wait()
		if err := <-closed; err != nil {
			t.Fatalf("run %d Close: %v", run, err)
		}
		if err := srv.Close(); err != nil {
			t.Fatalf("run %d server Close: %v", run, err)
		}
		m.mu.RLock()
		remaining := len(m.sessions)
		m.mu.RUnlock()
		if remaining != 0 {
			t.Fatalf("run %d left %d sessions after Close", run, remaining)
		}
	}
}

func TestBindServerChainsHooks(t *testing.T) {
	m, err := New(Config{Settings: testSettings("local.example.net")})
	if err != nil {
		t.Fatal(err)
	}
	var newCalls, shutdownCalls int
	srv := &diam.Server{OnNewConnection: func(diam.Conn) { newCalls++ }, OnShutdownConnection: func(context.Context, diam.Conn) { shutdownCalls++ }}
	if err := m.BindServer(srv); err != nil {
		t.Fatal(err)
	}
	c := newFakeConn()
	srv.OnNewConnection(c)
	srv.OnShutdownConnection(context.Background(), c)
	if newCalls != 1 || shutdownCalls != 1 {
		t.Fatalf("hooks called new=%d shutdown=%d", newCalls, shutdownCalls)
	}
	c.Close()
	closeManager(t, m, nil)
}
