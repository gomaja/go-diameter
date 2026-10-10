package sm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

type watchdogPipeListener struct {
	accepted chan net.Conn
	closed   chan struct{}
	once     sync.Once
}

type acceptedWatchdogProbeConn struct {
	*handshakeConn
	done         chan struct{}
	badLocalAddr bool
}

type acceptedWatchdogInvalidAddr struct{}

func (acceptedWatchdogInvalidAddr) Network() string { return "test" }
func (acceptedWatchdogInvalidAddr) String() string  { return "not-a-local-IP" }

func newAcceptedWatchdogProbeConn() *acceptedWatchdogProbeConn {
	return &acceptedWatchdogProbeConn{handshakeConn: newHandshakeConn(), done: make(chan struct{})}
}

func (c *acceptedWatchdogProbeConn) DispatchDone() <-chan struct{} { return c.done }
func (c *acceptedWatchdogProbeConn) LocalAddr() net.Addr {
	if c.badLocalAddr {
		return acceptedWatchdogInvalidAddr{}
	}
	return c.handshakeConn.LocalAddr()
}

func (l *watchdogPipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.accepted:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *watchdogPipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (*watchdogPipeListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3868}
}

type acceptedWatchdogEvent struct {
	conn  diam.Conn
	event WatchdogEvent
	at    time.Time
}

func newAcceptedWatchdogSettings() Settings {
	cfg := *serverSettings
	cfg.HostIPAddresses = []datatype.Address{localhostAddress}
	cfg.EnableWatchdog = true
	cfg.WatchdogInterval = 100 * time.Millisecond
	cfg.watchdogTiming = &watchdogTiming{floor: time.Millisecond}
	return cfg
}

func acceptedWatchdogEvents(cfg *Settings) <-chan acceptedWatchdogEvent {
	events := make(chan acceptedWatchdogEvent, 32)
	cfg.OnWatchdogConnEvent = func(c diam.Conn, event WatchdogEvent) {
		events <- acceptedWatchdogEvent{c, event, time.Now()}
	}
	return events
}

func awaitAcceptedEvent(t *testing.T, events <-chan acceptedWatchdogEvent, want WatchdogEvent, conn diam.Conn) acceptedWatchdogEvent {
	return awaitAcceptedEventWithin(t, events, want, conn, 2*time.Second)
}

func awaitAcceptedEventWithin(t *testing.T, events <-chan acceptedWatchdogEvent, want WatchdogEvent, conn diam.Conn, within time.Duration) acceptedWatchdogEvent {
	t.Helper()
	select {
	case got := <-events:
		if got.event != want || conn != nil && got.conn != conn {
			t.Fatalf("watchdog event = (%p, %s), want (%p, %s)", got.conn, got.event, conn, want)
		}
		return got
	case <-time.After(within):
		t.Fatalf("missing watchdog event %s", want)
		return acceptedWatchdogEvent{}
	}
}

func acceptedWatchdogOnWire(t *testing.T, peer net.Conn) *diam.Message {
	t.Helper()
	if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	m, err := diam.ReadMessage(peer, dict.Default)
	if err != nil || m.Header.CommandCode != diam.DeviceWatchdog || m.Header.CommandFlags&diam.RequestFlag == 0 || m.Header.ApplicationID != 0 {
		t.Fatalf("DWR on wire = %v, %v", m, err)
	}
	return m
}

func acceptedDWA(t *testing.T, request *diam.Message, result uint32) *diam.Message {
	t.Helper()
	a := request.Answer(result)
	mustSMClientAVP(t, a, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
	mustSMClientAVP(t, a, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
	return a
}

func acceptedWatchdogState(t *testing.T, sm *StateMachine, c diam.Conn) *acceptedWatchdog {
	t.Helper()
	value, ok := sm.watchdogs.Load(c)
	if !ok {
		t.Fatal("watchdog supervisor missing for accepted connection")
	}
	return value.(*acceptedWatchdog)
}

func acceptedWatchdogStopped(t *testing.T, sm *StateMachine, c diam.Conn, state *acceptedWatchdog) {
	t.Helper()
	select {
	case <-state.exited:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog goroutine did not exit")
	}
	if _, ok := sm.watchdogs.Load(c); ok {
		t.Fatal("watchdog map retained closed connection")
	}
}

func newAcceptedWatchdogPipe(t *testing.T, cfg *Settings) (*StateMachine, net.Conn, func()) {
	t.Helper()
	sm := mustNewStateMachine(t, cfg)
	server := &diam.Server{Handler: sm, Dict: dict.Default}
	listener := &watchdogPipeListener{accepted: make(chan net.Conn, 1), closed: make(chan struct{})}
	serverSide, peer := net.Pipe()
	listener.accepted <- serverSide
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	return sm, peer, func() {
		_ = peer.Close()
		_ = server.Close()
		if err := <-serveDone; err != nil && !errors.Is(err, diam.ErrServerClosed) {
			t.Errorf("Serve: %v", err)
		}
	}
}

func acceptedPipeHandshake(t *testing.T, peer net.Conn) {
	t.Helper()
	if _, err := regressionCER(t, dict.Default, 1001).WriteTo(peer); err != nil {
		t.Fatal(err)
	}
	cea, err := diam.ReadMessage(peer, dict.Default)
	if err != nil || !testResultCode(cea, diam.Success) {
		t.Fatalf("CEA: %v, %v", cea, err)
	}
}

// RFC 6733 §5.5.3 and RFC 3539 §3.4.1: an accepted, idle connection must
// receive a DWR after Twinit. The default Twinit is 30 seconds with ±2s jitter.
func TestAcceptedWatchdogIssueReproducerDefaultTwinit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := *serverSettings
		cfg.HostIPAddresses = []datatype.Address{localhostAddress}
		cfg.EnableWatchdog = true
		var handshakeTime time.Time
		accepted := make(chan diam.Conn, 1)
		cfg.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) {
			handshakeTime = time.Now()
			accepted <- c
		}
		events := acceptedWatchdogEvents(&cfg)
		sm := mustNewStateMachine(t, &cfg)
		server := &diam.Server{Handler: sm, Dict: dict.Default}
		listener := &watchdogPipeListener{accepted: make(chan net.Conn, 1), closed: make(chan struct{})}
		serverSide, peer := net.Pipe()
		listener.accepted <- serverSide
		serveDone := make(chan error, 1)
		go func() { serveDone <- server.Serve(listener) }()
		defer func() {
			_ = peer.Close()
			_ = server.Close()
			if err := <-serveDone; err != nil && !errors.Is(err, diam.ErrServerClosed) {
				t.Errorf("Serve: %v", err)
			}
		}()
		if _, err := regressionCER(t, dict.Default, 1001).WriteTo(peer); err != nil {
			t.Fatal(err)
		}
		cea, err := diam.ReadMessage(peer, dict.Default)
		if err != nil || !testResultCode(cea, diam.Success) {
			t.Fatalf("CEA: %v, %v", cea, err)
		}
		c := <-accepted
		incoming := make(chan *diam.Message, 1)
		go func() {
			m, _ := diam.ReadMessage(peer, dict.Default)
			incoming <- m
		}()
		select {
		case m := <-incoming:
			if m == nil || m.Header.CommandCode != diam.DeviceWatchdog || m.Header.CommandFlags&diam.RequestFlag == 0 {
				t.Fatalf("first idle message = %v, want DWR", m)
			}
			if elapsed := time.Since(handshakeTime); elapsed < 28*time.Second || elapsed > 32*time.Second {
				t.Fatalf("first DWR after %v, want [28s,32s]", elapsed)
			}
		case <-time.After(33 * time.Second):
			t.Fatal("accepted idle connection received no DWR by default Twinit + jitter")
		}
		first := awaitAcceptedEvent(t, events, WatchdogRequestSent, c)
		state := acceptedWatchdogState(t, sm, c)
		second := awaitAcceptedEventWithin(t, events, WatchdogSuspect, c, 33*time.Second)
		third := awaitAcceptedEventWithin(t, events, WatchdogTimedOut, c, 33*time.Second)
		// RFC 3539 §3.4.1 [1], Appendix A SetWatchdog: each reset draws
		// Tw independently. Exact equality is possible, but has probability
		// below 1 in 4 billion for each draw with nanosecond jitter.
		intervals := [...]time.Duration{
			first.at.Sub(handshakeTime),
			second.at.Sub(first.at),
			third.at.Sub(second.at),
		}
		for i, tw := range intervals {
			if tw < 28*time.Second || tw > 32*time.Second || tw == 30*time.Second {
				t.Fatalf("Tw[%d] = %v, want jittered interval within [28s,32s] and unequal to Twinit", i, tw)
			}
			if i > 0 && tw == intervals[i-1] {
				t.Fatalf("Tw[%d] = Tw[%d] = %v; consecutive timers did not redraw jitter", i, i-1, tw)
			}
		}
		_, err = diam.ReadMessage(peer, dict.Default)
		if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
			t.Fatalf("after DOWN read error = %v, want EOF", err)
		}
		acceptedWatchdogStopped(t, sm, c, state)
	})
}

// RFC 3539 §3.4.1 [2],[4] and Appendix A: one DWR is outstanding, SUSPECT
// leaves the transport up, and DOWN closes it only on the third expiry.
func TestAcceptedWatchdogReproducerTCP(t *testing.T) {
	for _, mode := range []int{0, 4, -1} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			cfg := newAcceptedWatchdogSettings()
			accepted := make(chan diam.Conn, 1)
			cfg.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { accepted <- c }
			events := acceptedWatchdogEvents(&cfg)
			sm := mustNewStateMachine(t, &cfg)
			srv := diamtest.NewUnstartedServer(sm, dict.Default)
			srv.Config.MaxConcurrentHandlers = mode
			srv.Start()
			defer srv.Close()
			cea, peer := regressionExchange(t, srv, regressionCER(t, dict.Default, 1001), dict.Default)
			if !testResultCode(cea, diam.Success) {
				t.Fatalf("CEA = %v", cea)
			}
			c := <-accepted
			request := acceptedWatchdogOnWire(t, peer)
			if request.Header.CommandCode != diam.DeviceWatchdog {
				t.Fatal("missing DWR")
			}
			state := acceptedWatchdogState(t, sm, c)
			awaitAcceptedEvent(t, events, WatchdogRequestSent, c)
			awaitAcceptedEvent(t, events, WatchdogSuspect, c)
			if c.Closed() {
				t.Fatal("connection closed at SUSPECT")
			}
			awaitAcceptedEvent(t, events, WatchdogTimedOut, c)
			regressionClosed(t, peer)
			acceptedWatchdogStopped(t, sm, c, state)
		})
	}
}

// RFC 3539 §3.4.1 [3],[4] and Appendix A: a valid DWA clears Pending and
// rearms Tw; an invalid answer leaves the request outstanding.
func TestAcceptedWatchdogDWA(t *testing.T) {
	cfg := newAcceptedWatchdogSettings()
	accepted := make(chan diam.Conn, 1)
	cfg.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { accepted <- c }
	events := acceptedWatchdogEvents(&cfg)
	sm := mustNewStateMachine(t, &cfg)
	userDWA := make(chan struct{}, 1)
	sm.HandleFunc("DWA", func(diam.Conn, *diam.Message) { userDWA <- struct{}{} })
	logs := logtest.New()
	srv := diamtest.NewUnstartedServer(sm, dict.Default)
	srv.Config.Logger = logs.Logger()
	srv.Start()
	defer srv.Close()
	cea, peer := regressionExchange(t, srv, regressionCER(t, dict.Default, 1001), dict.Default)
	if !testResultCode(cea, diam.Success) {
		t.Fatalf("CEA = %v", cea)
	}
	c := <-accepted
	for cycle := 0; cycle < 3; cycle++ {
		request := acceptedWatchdogOnWire(t, peer)
		if _, err := acceptedDWA(t, request, diam.Success).WriteTo(peer); err != nil {
			t.Fatal(err)
		}
		awaitAcceptedEvent(t, events, WatchdogRequestSent, c)
		awaitAcceptedEvent(t, events, WatchdogAnswerReceived, c)
		select {
		case <-userDWA:
			t.Fatal("user DWA route received supervised answer")
		default:
		}
	}
	for _, record := range logs.Records() {
		if strings.Contains(record.Message, "unhandled answer") {
			t.Fatalf("supervised DWA logged as unhandled: %s", record.Message)
		}
	}
	request := acceptedWatchdogOnWire(t, peer)
	if _, err := acceptedDWA(t, request, diam.UnableToDeliver).WriteTo(peer); err != nil {
		t.Fatal(err)
	}
	awaitAcceptedEvent(t, events, WatchdogRequestSent, c)
	awaitAcceptedEvent(t, events, WatchdogInvalidAnswer, c)
	awaitAcceptedEvent(t, events, WatchdogSuspect, c)
	if c.Closed() {
		t.Fatal("invalid DWA caused close at SUSPECT")
	}
}

// RFC 3539 §3.4.1 [3]: an answer from one peer cannot clear another
// connection's Pending flag.
func TestAcceptedWatchdogRoutesAnswersPerConnection(t *testing.T) {
	cfg := newAcceptedWatchdogSettings()
	events := acceptedWatchdogEvents(&cfg)
	accepted := make(chan diam.Conn, 2)
	cfg.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { accepted <- c }
	sm := mustNewStateMachine(t, &cfg)
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	peers := make([]net.Conn, 2)
	conns := make([]diam.Conn, 2)
	for i := range peers {
		cea, peer := regressionExchange(t, srv, regressionCER(t, dict.Default, 1001), dict.Default)
		if !testResultCode(cea, diam.Success) {
			t.Fatalf("peer %d CEA = %v", i, cea)
		}
		peers[i], conns[i] = peer, <-accepted
	}
	// Both requests must be outstanding before the first answer arrives;
	// otherwise a broadcast DWA can reach the silent peer before Pending.
	requests := make([]*diam.Message, len(peers))
	for i, peer := range peers {
		requests[i] = acceptedWatchdogOnWire(t, peer)
	}
	if _, err := acceptedDWA(t, requests[0], diam.Success).WriteTo(peers[0]); err != nil {
		t.Fatal(err)
	}
	seen := map[diam.Conn][]WatchdogEvent{}
	deadline := time.After(2 * time.Second)
	for {
		select {
		case got := <-events:
			seen[got.conn] = append(seen[got.conn], got.event)
			if got.conn == conns[1] && got.event == WatchdogAnswerReceived {
				t.Fatal("silent peer credited DWA sent by another connection")
			}
			if got.conn == conns[0] && got.event == WatchdogTimedOut {
				t.Fatal("answering connection reached DOWN")
			}
			if got.conn == conns[1] && got.event == WatchdogTimedOut {
				if !slices.Contains(seen[conns[0]], WatchdogAnswerReceived) || !slices.Contains(seen[conns[1]], WatchdogSuspect) {
					t.Fatalf("per-connection events: %v", seen)
				}
				if conns[0].Closed() {
					t.Fatal("answering connection closed when other peer went DOWN")
				}
				return
			}
		case <-deadline:
			t.Fatalf("silent peer did not reach DOWN; events: %v", seen)
		}
	}
}

// RFC 6733 §5.6: DWA interception applies only while the accepted
// connection is under watchdog supervision.
func TestAcceptedWatchdogDisabledByDefault(t *testing.T) {
	cfg := *serverSettings
	accepted := make(chan diam.Conn, 1)
	cfg.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { accepted <- c }
	sm := mustNewStateMachine(t, &cfg)
	routed := make(chan struct{}, 1)
	sm.HandleFunc("DWA", func(diam.Conn, *diam.Message) { routed <- struct{}{} })
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	cea, peer := regressionExchange(t, srv, regressionCER(t, dict.Default, 1001), dict.Default)
	if !testResultCode(cea, diam.Success) {
		t.Fatalf("CEA = %v", cea)
	}
	c := <-accepted
	if _, ok := sm.watchdogs.Load(c); ok {
		t.Fatal("disabled watchdog started supervisor")
	}
	answer := acceptedDWA(t, regressionDWR(t), diam.Success)
	if _, err := answer.WriteTo(peer); err != nil {
		t.Fatal(err)
	}
	select {
	case <-routed:
	case <-time.After(time.Second):
		t.Fatal("unsupervised DWA did not reach user route")
	}
}

// RFC 3539 §3.4.1 [1], Appendix A: inbound traffic resets Tw, including
// messages other than DWA. A pending DWR still remains outstanding.
func TestAcceptedWatchdogRecoversOnTraffic(t *testing.T) {
	for _, mode := range []int{0, 4, -1} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			cfg := newAcceptedWatchdogSettings()
			accepted := make(chan diam.Conn, 1)
			cfg.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { accepted <- c }
			events := acceptedWatchdogEvents(&cfg)
			sm := mustNewStateMachine(t, &cfg)
			srv := diamtest.NewUnstartedServer(sm, dict.Default)
			srv.Config.MaxConcurrentHandlers = mode
			srv.Start()
			defer srv.Close()
			cea, peer := regressionExchange(t, srv, regressionCER(t, dict.Default, 1001), dict.Default)
			if !testResultCode(cea, diam.Success) {
				t.Fatalf("CEA = %v", cea)
			}
			c := <-accepted
			acceptedWatchdogOnWire(t, peer)
			awaitAcceptedEvent(t, events, WatchdogRequestSent, c)
			awaitAcceptedEvent(t, events, WatchdogSuspect, c)
			if _, err := regressionDWR(t).WriteTo(peer); err != nil {
				t.Fatal(err)
			}
			if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			a, err := diam.ReadMessage(peer, dict.Default)
			if err != nil || a.Header.CommandCode != diam.DeviceWatchdog || a.Header.CommandFlags&diam.RequestFlag != 0 || !testResultCode(a, diam.Success) {
				t.Fatalf("peer DWA = %v, %v", a, err)
			}
			awaitAcceptedEvent(t, events, WatchdogRecovered, c)
			awaitAcceptedEvent(t, events, WatchdogSuspect, c)
			if c.Closed() {
				t.Fatal("traffic recovery closed connection at SUSPECT")
			}
			awaitAcceptedEvent(t, events, WatchdogTimedOut, c)
			regressionClosed(t, peer)
		})
	}
}

// RFC 3539 §3.4.1 [1] and Appendix A SetWatchdog: traffic resets Tw at
// receipt, so a steady inbound peer sends no unnecessary DWR.
func TestAcceptedWatchdogTrafficSuppressesDWR(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := newAcceptedWatchdogSettings()
		cfg.HostIPAddresses = []datatype.Address{localhostAddress}
		accepted := make(chan diam.Conn, 1)
		cfg.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { accepted <- c }
		events := acceptedWatchdogEvents(&cfg)
		_, peer, cleanup := newAcceptedWatchdogPipe(t, &cfg)
		defer cleanup()
		acceptedPipeHandshake(t, peer)
		c := <-accepted
		for i := 0; i < 4; i++ {
			time.Sleep(60 * time.Millisecond)
			if _, err := regressionDWR(t).WriteTo(peer); err != nil {
				t.Fatal(err)
			}
			a, err := diam.ReadMessage(peer, dict.Default)
			if err != nil || a.Header.CommandCode != diam.DeviceWatchdog || a.Header.CommandFlags&diam.RequestFlag != 0 || !testResultCode(a, diam.Success) {
				t.Fatalf("peer DWA = %v, %v", a, err)
			}
			synctest.Wait()
			select {
			case event := <-events:
				t.Fatalf("watchdog emitted %s during inbound traffic", event.event)
			default:
			}
		}
		time.Sleep(99 * time.Millisecond)
		synctest.Wait()
		select {
		case event := <-events:
			t.Fatalf("watchdog emitted %s before idle Tw", event.event)
		default:
		}
		incoming := make(chan *diam.Message, 1)
		go func() { m, _ := diam.ReadMessage(peer, dict.Default); incoming <- m }()
		select {
		case m := <-incoming:
			if m == nil || m.Header.CommandCode != diam.DeviceWatchdog || m.Header.CommandFlags&diam.RequestFlag == 0 {
				t.Fatalf("idle message = %v, want DWR", m)
			}
		case <-time.After(2 * time.Millisecond):
			t.Fatal("idle Tw did not send DWR")
		}
		awaitAcceptedEvent(t, events, WatchdogRequestSent, c)
	})
}

// RFC 6733 §5.6.1 and RFC 3539 §3.4.1 [1]: Tw begins after the success
// CEA and the handshake callback, never on accept or during CER processing.
func TestAcceptedWatchdogNoDWRBeforeHandshake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := newAcceptedWatchdogSettings()
		cfg.HandshakeTimeout = time.Hour
		sm := mustNewStateMachine(t, &cfg)
		c := newAcceptedWatchdogProbeConn()
		defer close(c.done)
		cleanup := sm.HandleAccept(c)
		defer cleanup()
		time.Sleep(4 * cfg.WatchdogInterval)
		synctest.Wait()
		select {
		case <-c.writes:
			t.Fatal("watchdog wrote before CER/CEA")
		default:
		}
		if _, ok := sm.watchdogs.Load(c); ok {
			t.Fatal("watchdog started before handshake")
		}
		sm.ServeDIAM(c, regressionCER(t, dict.Default, 1001))
		if m, err := diam.ReadMessage(bytes.NewReader(<-c.writes), dict.Default); err != nil || !testResultCode(m, diam.Success) {
			t.Fatalf("CEA: %v, %v", m, err)
		}
		select {
		case <-c.writes:
			t.Fatal("DWR sent before Tw after handshake")
		default:
		}
		synctest.Wait()
		time.Sleep(cfg.WatchdogInterval)
		synctest.Wait()
		select {
		case wire := <-c.writes:
			m, err := diam.ReadMessage(bytes.NewReader(wire), dict.Default)
			if err != nil || m.Header.CommandCode != diam.DeviceWatchdog {
				t.Fatalf("post-handshake DWR: %v, %v", m, err)
			}
		default:
			t.Fatal("watchdog did not start after success CEA")
		}
	})
}

func TestAcceptedWatchdogWaitsForCEAWrite(t *testing.T) {
	for _, rejected := range []bool{false, true} {
		t.Run(fmt.Sprint(rejected), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := newAcceptedWatchdogSettings()
				cfg.HandshakeTimeout = time.Hour
				sm := mustNewStateMachine(t, &cfg)
				c := newAcceptedWatchdogProbeConn()
				defer close(c.done)
				cleanup := sm.HandleAccept(c)
				defer cleanup()
				entered, unblock := make(chan struct{}), make(chan struct{})
				var release sync.Once
				open := func() { release.Do(func() { close(unblock) }) }
				defer open()
				c.afterWrite = func(seq int32) {
					if seq == 1 {
						close(entered)
						<-unblock
					}
				}
				request := regressionCER(t, dict.Default, 1001)
				if rejected {
					request = regressionCER(t, dict.Default, 9999)
				}
				done := make(chan struct{})
				go func() { sm.ServeDIAM(c, request); close(done) }()
				<-entered
				wire := <-c.writes
				a, err := diam.ReadMessage(bytes.NewReader(wire), dict.Default)
				if err != nil || testResultCode(a, diam.Success) == rejected {
					t.Fatalf("CEA during blocked write = %v, %v", a, err)
				}
				time.Sleep(4 * cfg.WatchdogInterval)
				synctest.Wait()
				if _, ok := sm.watchdogs.Load(c); ok {
					t.Fatal("watchdog started before CEA write returned")
				}
				select {
				case <-c.writes:
					t.Fatal("DWR sent before CEA write returned")
				default:
				}
				open()
				<-done
				if rejected {
					if _, ok := sm.watchdogs.Load(c); ok {
						t.Fatal("rejected CER started watchdog")
					}
					return
				}
				synctest.Wait()
				time.Sleep(cfg.WatchdogInterval)
				synctest.Wait()
				select {
				case wire := <-c.writes:
					m, err := diam.ReadMessage(bytes.NewReader(wire), dict.Default)
					if err != nil || m.Header.CommandCode != diam.DeviceWatchdog {
						t.Fatalf("post-CEA DWR = %v, %v", m, err)
					}
				default:
					t.Fatal("watchdog did not start after CEA write")
				}
			})
		})
	}
}

// RFC 6733 §5.6.1: rejected or aborted CER exchanges never establish a
// connection on which the RFC 3539 watchdog can run.
func TestAcceptedWatchdogNotStartedAfterRejectedOrAbortedCER(t *testing.T) {
	for _, scenario := range []string{"no-common-application", "missing-origin-host", "timer-won", "CEA-build-fails", "CEA-write-fails", "OnCER-closes"} {
		t.Run(scenario, func(t *testing.T) {
			cfg := newAcceptedWatchdogSettings()
			cfg.HandshakeTimeout = time.Hour
			if scenario == "CEA-build-fails" {
				cfg.HostIPAddresses = nil // fake connection has no local address
			}
			if scenario == "OnCER-closes" {
				cfg.OnCER = func(c diam.Conn, _ *diam.Message) { c.Close() }
			}
			sm := mustNewStateMachine(t, &cfg)
			c := newAcceptedWatchdogProbeConn()
			if scenario == "CEA-build-fails" {
				c.badLocalAddr = true
			}
			defer close(c.done)
			cleanup := sm.HandleAccept(c)
			defer cleanup()
			request := regressionCER(t, dict.Default, 1001)
			switch scenario {
			case "no-common-application":
				request = regressionCER(t, dict.Default, 9999)
			case "missing-origin-host":
				for i, a := range request.AVP {
					if a.Code == avp.OriginHost {
						request.AVP = append(request.AVP[:i], request.AVP[i+1:]...)
						break
					}
				}
			case "timer-won":
				value, _ := sm.accepted.Load(c)
				state := value.(*acceptedHandshake)
				state.mu.Lock()
				state.timedOut = true
				state.mu.Unlock()
			case "CEA-write-fails":
				c.writeErr = errors.New("CEA write failed")
			}
			sm.ServeDIAM(c, request)
			if _, ok := sm.watchdogs.Load(c); ok {
				t.Fatal("watchdog started without successful CEA")
			}
			if !c.Closed() {
				t.Fatal("rejected or aborted CER left connection open")
			}
		})
	}
}

func TestAcceptedWatchdogStartsAfterOnHandshake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := newAcceptedWatchdogSettings()
		cfg.HandshakeTimeout = time.Hour
		entered, release := make(chan struct{}), make(chan struct{})
		cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) { close(entered); <-release }
		sm := mustNewStateMachine(t, &cfg)
		c := newAcceptedWatchdogProbeConn()
		defer close(c.done)
		cleanup := sm.HandleAccept(c)
		defer cleanup()
		dispatchDone := make(chan struct{})
		request := regressionCER(t, dict.Default, 1001)
		go func() { sm.ServeDIAM(c, request); close(dispatchDone) }()
		if m, err := diam.ReadMessage(bytes.NewReader(<-c.writes), dict.Default); err != nil || !testResultCode(m, diam.Success) {
			t.Fatalf("CEA: %v, %v", m, err)
		}
		<-entered
		time.Sleep(4 * cfg.WatchdogInterval)
		synctest.Wait()
		select {
		case <-c.writes:
			t.Fatal("DWR sent during OnHandshake")
		default:
		}
		close(release)
		<-dispatchDone
		if _, ok := sm.watchdogs.Load(c); !ok {
			t.Fatal("watchdog missing after OnHandshake returned")
		}
		synctest.Wait()
		time.Sleep(cfg.WatchdogInterval)
		synctest.Wait()
		select {
		case wire := <-c.writes:
			m, err := diam.ReadMessage(bytes.NewReader(wire), dict.Default)
			if err != nil || m.Header.CommandCode != diam.DeviceWatchdog {
				t.Fatalf("DWR after OnHandshake: %v, %v", m, err)
			}
		default:
			t.Fatal("watchdog did not arm after OnHandshake")
		}
	})
	t.Run("panic-in-concurrent-dispatch", func(t *testing.T) {
		cfg := newAcceptedWatchdogSettings()
		cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) { panic("handshake callback") }
		events := acceptedWatchdogEvents(&cfg)
		sm := mustNewStateMachine(t, &cfg)
		srv := diamtest.NewUnstartedServer(sm, dict.Default)
		srv.Config.MaxConcurrentHandlers = -1
		srv.Start()
		defer srv.Close()
		cea, peer := regressionExchange(t, srv, regressionCER(t, dict.Default, 1001), dict.Default)
		if !testResultCode(cea, diam.Success) {
			t.Fatalf("CEA = %v", cea)
		}
		acceptedWatchdogOnWire(t, peer)
		awaitAcceptedEvent(t, events, WatchdogRequestSent, nil)
	})
}

// RFC 3539 §3.4.1 [1]: a message with an invalid Diameter header is not
// valid peer traffic and cannot reset Tw.
func TestAcceptedWatchdogInvalidHeaderDoesNotResetActivity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := newAcceptedWatchdogSettings()
		sm := mustNewStateMachine(t, &cfg)
		c := newAcceptedWatchdogProbeConn()
		defer close(c.done)
		cleanup := sm.HandleAccept(c)
		defer cleanup()
		sm.ServeDIAM(c, regressionCER(t, dict.Default, 1001))
		<-c.writes // CEA
		synctest.Wait()
		time.Sleep(cfg.WatchdogInterval / 2)
		invalid := diam.NewMessage(diam.DeviceWatchdog, 0, 4, 1, 2, dict.Default)
		sm.ServeDIAM(c, invalid)
		time.Sleep(cfg.WatchdogInterval / 2)
		synctest.Wait()
		select {
		case wire := <-c.writes:
			m, err := diam.ReadMessage(bytes.NewReader(wire), dict.Default)
			if err != nil || m.Header.CommandCode != diam.DeviceWatchdog || m.Header.CommandFlags&diam.RequestFlag == 0 {
				t.Fatalf("first idle DWR = %v, %v", m, err)
			}
		default:
			t.Fatal("invalid header incorrectly reset Tw")
		}
	})
}

// RFC 3539 §3.4.1 [1] and Appendix A: a syntactically valid received
// message is traffic even when request validation rejects its AVPs.
func TestAcceptedWatchdogRejectedRequestsCountAsActivity(t *testing.T) {
	for _, reason := range []string{"unknown-mandatory", "invalid-grammar"} {
		t.Run(reason, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := newAcceptedWatchdogSettings()
				cfg.RejectUnknownMandatoryAVPs = reason == "unknown-mandatory"
				cfg.ValidateRequests = reason == "invalid-grammar"
				sm := mustNewStateMachine(t, &cfg)
				c := newAcceptedWatchdogProbeConn()
				defer close(c.done)
				cleanup := sm.HandleAccept(c)
				defer cleanup()
				sm.ServeDIAM(c, regressionCER(t, dict.Default, 1001))
				<-c.writes // CEA
				synctest.Wait()
				time.Sleep(60 * time.Millisecond)
				request := regressionDWR(t)
				if reason == "unknown-mandatory" {
					request.AddAVP(diam.NewAVP(0xfedc, avp.Mbit|avp.Vbit, 10415, datatype.OctetString("unknown")))
					var wire bytes.Buffer
					if _, err := request.WriteTo(&wire); err != nil {
						t.Fatal(err)
					}
					var err error
					request, err = diam.ReadMessage(&wire, dict.Default)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					for i, a := range request.AVP {
						if a.Code == avp.OriginHost {
							request.AVP = append(request.AVP[:i], request.AVP[i+1:]...)
							break
						}
					}
				}
				sm.ServeDIAM(c, request)
				select {
				case wire := <-c.writes:
					a, err := diam.ReadMessage(bytes.NewReader(wire), dict.Default)
					if err != nil || a.Header.CommandFlags&diam.RequestFlag != 0 || testResultCode(a, diam.Success) {
						t.Fatalf("rejection answer = %v, %v", a, err)
					}
				default:
					t.Fatal("invalid request did not receive error answer")
				}
				synctest.Wait()
				time.Sleep(60 * time.Millisecond)
				synctest.Wait()
				select {
				case <-c.writes:
					t.Fatal("watchdog ignored received rejected request")
				default:
				}
				time.Sleep(40 * time.Millisecond)
				synctest.Wait()
				select {
				case wire := <-c.writes:
					m, err := diam.ReadMessage(bytes.NewReader(wire), dict.Default)
					if err != nil || m.Header.CommandCode != diam.DeviceWatchdog || m.Header.CommandFlags&diam.RequestFlag == 0 {
						t.Fatalf("idle DWR = %v, %v", m, err)
					}
				default:
					t.Fatal("Tw did not expire after rejected request")
				}
			})
		})
	}
}

func TestAcceptedWatchdogMessageErrorDoesNotResetActivity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := newAcceptedWatchdogSettings()
		sm := mustNewStateMachine(t, &cfg)
		c := newAcceptedWatchdogProbeConn()
		defer close(c.done)
		cleanup := sm.HandleAccept(c)
		defer cleanup()
		sm.ServeDIAM(c, regressionCER(t, dict.Default, 1001))
		<-c.writes // CEA
		synctest.Wait()
		time.Sleep(cfg.WatchdogInterval / 2)
		if err := sm.HandleMessageError(c, regressionDWR(t), &diam.MessageError{ResultCode: diam.AVPUnsupported}); err != nil {
			t.Fatal(err)
		}
		<-c.writes // error answer
		time.Sleep(cfg.WatchdogInterval / 2)
		synctest.Wait()
		select {
		case wire := <-c.writes:
			m, err := diam.ReadMessage(bytes.NewReader(wire), dict.Default)
			if err != nil || m.Header.CommandCode != diam.DeviceWatchdog || m.Header.CommandFlags&diam.RequestFlag == 0 {
				t.Fatalf("idle DWR = %v, %v", m, err)
			}
		default:
			t.Fatal("HandleMessageError incorrectly reset Tw")
		}
	})
}

func acceptedDPR(t *testing.T) *diam.Message {
	t.Helper()
	m := diam.NewRequest(diam.DisconnectPeer, 0, dict.Default)
	mustSMClientAVP(t, m, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
	mustSMClientAVP(t, m, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
	mustSMClientAVP(t, m, avp.DisconnectCause, avp.Mbit, 0, datatype.Enumerated(0))
	return m
}

// RFC 6733 §5.6: receiving DPR moves the responder to Closing; no more
// DWRs are sent after a valid DPR.
func TestAcceptedWatchdogStopsOnDPR(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := newAcceptedWatchdogSettings()
		cfg.DPRCloseTimeout = time.Hour
		accepted := make(chan diam.Conn, 1)
		cfg.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { accepted <- c }
		events := acceptedWatchdogEvents(&cfg)
		sm, peer, cleanup := newAcceptedWatchdogPipe(t, &cfg)
		defer cleanup()
		acceptedPipeHandshake(t, peer)
		c := <-accepted
		synctest.Wait()
		state := acceptedWatchdogState(t, sm, c)
		request := acceptedDPR(t)
		if _, err := request.WriteTo(peer); err != nil {
			t.Fatal(err)
		}
		a, err := diam.ReadMessage(peer, dict.Default)
		if err != nil || a.Header.CommandCode != diam.DisconnectPeer || !testResultCode(a, diam.Success) {
			t.Fatalf("DPA: %v, %v", a, err)
		}
		acceptedWatchdogStopped(t, sm, c, state)
		unexpected := make(chan *diam.Message, 1)
		go func() { m, _ := diam.ReadMessage(peer, dict.Default); unexpected <- m }()
		select {
		case m := <-unexpected:
			t.Fatalf("watchdog wrote in Closing: %v", m)
		case <-time.After(3 * cfg.WatchdogInterval):
		}
		select {
		case got := <-events:
			t.Fatalf("watchdog event after DPR: %s", got.event)
		default:
		}
	})
}

// RFC 6733 §5.6: local Stop transitions to Closing before sending DPR.
func TestAcceptedWatchdogStopsOnDisconnect(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := newAcceptedWatchdogSettings()
		accepted := make(chan diam.Conn, 1)
		cfg.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { accepted <- c }
		events := acceptedWatchdogEvents(&cfg)
		sm, peer, cleanup := newAcceptedWatchdogPipe(t, &cfg)
		defer cleanup()
		acceptedPipeHandshake(t, peer)
		c := <-accepted
		synctest.Wait()
		state := acceptedWatchdogState(t, sm, c)
		result := make(chan error, 1)
		go func() { result <- sm.Disconnect(c, DisconnectRebooting, time.Hour) }()
		request, err := diam.ReadMessage(peer, dict.Default)
		if err != nil || request.Header.CommandCode != diam.DisconnectPeer || request.Header.CommandFlags&diam.RequestFlag == 0 {
			t.Fatalf("DPR: %v, %v", request, err)
		}
		acceptedWatchdogStopped(t, sm, c, state)
		unexpected := make(chan *diam.Message, 1)
		go func() { m, _ := diam.ReadMessage(peer, dict.Default); unexpected <- m }()
		select {
		case m := <-unexpected:
			t.Fatalf("watchdog wrote during local Closing: %v", m)
		case <-time.After(3 * cfg.WatchdogInterval):
		}
		if _, err := acceptedDWA(t, request, diam.Success).WriteTo(peer); err != nil {
			t.Fatal(err)
		}
		if err := <-result; err != nil {
			t.Fatalf("Disconnect: %v", err)
		}
		select {
		case got := <-events:
			t.Fatalf("watchdog event after Disconnect: %s", got.event)
		default:
		}
	})
}

// RFC 3539 §3.4.1 Appendix A DOWN and RFC 6733 §5.6: the supervisor
// releases its connection entry after every way the transport can end.
func TestAcceptedWatchdogNoLeak(t *testing.T) {
	for _, ending := range []string{"peer-FIN", "DOWN", "local-Close", "Server-Shutdown"} {
		t.Run(ending, func(t *testing.T) {
			cfg := newAcceptedWatchdogSettings()
			accepted := make(chan diam.Conn, 1)
			cfg.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { accepted <- c }
			events := acceptedWatchdogEvents(&cfg)
			sm := mustNewStateMachine(t, &cfg)
			srv := diamtest.NewServer(sm, dict.Default)
			defer srv.Close()
			cea, peer := regressionExchange(t, srv, regressionCER(t, dict.Default, 1001), dict.Default)
			if !testResultCode(cea, diam.Success) {
				t.Fatalf("CEA = %v", cea)
			}
			c := <-accepted
			acceptedWatchdogOnWire(t, peer)
			awaitAcceptedEvent(t, events, WatchdogRequestSent, c)
			state := acceptedWatchdogState(t, sm, c)
			switch ending {
			case "peer-FIN":
				if err := peer.Close(); err != nil {
					t.Fatal(err)
				}
			case "DOWN":
				awaitAcceptedEvent(t, events, WatchdogSuspect, c)
				awaitAcceptedEvent(t, events, WatchdogTimedOut, c)
			case "local-Close":
				c.Close()
			case "Server-Shutdown":
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				if err := srv.Config.Shutdown(ctx); err != nil && !errors.Is(err, diam.ErrServerClosed) {
					t.Fatalf("Shutdown: %v", err)
				}
			}
			acceptedWatchdogStopped(t, sm, c, state)
		})
	}
}

// RFC 6733 §2.1 and RFC 3539 §3.4.1 [5]: a shared StateMachine supervises
// accepted connections; a Client owns the watchdog for connections it dials.
func TestSharedStateMachineWatchdogsIndependent(t *testing.T) {
	cfg := newAcceptedWatchdogSettings()
	accepted := make(chan diam.Conn, 2)
	cfg.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { accepted <- c }
	sm := mustNewStateMachine(t, &cfg)
	local := diamtest.NewServer(sm, dict.Default)
	defer local.Close()
	cea, localPeer := regressionExchange(t, local, regressionCER(t, dict.Default, 1001), dict.Default)
	if !testResultCode(cea, diam.Success) {
		t.Fatalf("local CEA = %v", cea)
	}
	localConn := <-accepted
	acceptedWatchdogOnWire(t, localPeer)
	if _, ok := sm.watchdogs.Load(localConn); !ok {
		t.Fatal("shared StateMachine did not supervise accepted connection")
	}
	remoteCfg := *serverSettings
	remoteDWR := make(chan struct{}, 4)
	remoteCfg.OnDWR = func(diam.Conn, *diam.Message) { remoteDWR <- struct{}{} }
	remote := diamtest.NewServer(mustNewStateMachine(t, &remoteCfg), dict.Default)
	defer remote.Close()
	cli := newLivenessClient(t)
	cli.Handler = sm
	cli.WatchdogInterval = cfg.WatchdogInterval
	dialed, err := cli.Dial(remote.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer dialed.Close()
	if _, ok := sm.watchdogs.Load(dialed); ok {
		t.Fatal("accepted-connection watchdog also supervised dialed connection")
	}
	for i := 0; i < 2; i++ {
		select {
		case <-remoteDWR:
		case <-time.After(2 * time.Second):
			t.Fatalf("client watchdog did not send DWR %d", i+1)
		}
	}
	if _, ok := sm.watchdogs.Load(dialed); ok {
		t.Fatal("dialed connection acquired second supervisor")
	}
	_ = localPeer.Close()
}

// A user callback cannot crash the server or strand the accepted watchdog.
func TestAcceptedWatchdogEventPanicClosesConnection(t *testing.T) {
	cfg := newAcceptedWatchdogSettings()
	accepted := make(chan diam.Conn, 1)
	cfg.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { accepted <- c }
	stateAtPanic := make(chan *acceptedWatchdog, 1)
	var sm *StateMachine
	cfg.OnWatchdogConnEvent = func(c diam.Conn, _ WatchdogEvent) {
		if value, ok := sm.watchdogs.Load(c); ok {
			stateAtPanic <- value.(*acceptedWatchdog)
		}
		panic("watchdog event callback")
	}
	sm = mustNewStateMachine(t, &cfg)
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	cea, peer := regressionExchange(t, srv, regressionCER(t, dict.Default, 1001), dict.Default)
	if !testResultCode(cea, diam.Success) {
		t.Fatalf("CEA = %v", cea)
	}
	c := <-accepted
	acceptedWatchdogOnWire(t, peer)
	var state *acceptedWatchdog
	select {
	case state = <-stateAtPanic:
	case <-time.After(2 * time.Second):
		t.Fatal("callback did not see its supervisor")
	}
	regressionClosed(t, peer)
	acceptedWatchdogStopped(t, sm, c, state)
}
