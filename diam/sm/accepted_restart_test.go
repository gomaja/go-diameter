package sm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"

	"github.com/gomaja/go-diameter/diam/internal/logtest"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
)

func TestAcceptedRetiredMessagesDoNotDispatch(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	cfg := *testMessageErrorSettings(testDict)
	calls := 0
	cfg.OnDWR = func(diam.Conn, *diam.Message) { calls++ }
	sm := mustNewStateMachine(t, &cfg, testDict)
	c := &retiredHandshakeConn{handshakeConn: newHandshakeConn()}
	cleanup := sm.HandleAccept(c)
	defer cleanup()
	sm.ServeDIAM(c, regressionCER(t, testDict, 1001))
	<-c.writes
	c.closed.Store(true)
	c.reason = diam.SCTPAssociationRestart
	sm.ServeDIAM(c, regressionDWR(t))
	if calls != 0 {
		t.Fatalf("retired generation ran %d DWR hooks", calls)
	}
	select {
	case wire := <-c.writes:
		t.Fatalf("retired generation wrote %d bytes", len(wire))
	default:
	}
}

func TestAcceptedRetiredWatchdogSuppressesStaleWork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := newAcceptedWatchdogSettings()
		events := acceptedWatchdogEvents(&cfg)
		sm := mustNewStateMachine(t, &cfg)
		c := newAcceptedWatchdogProbeConn()
		defer close(c.done)
		sm.startWatchdog(c)
		w := acceptedWatchdogState(t, sm, c)
		defer w.stop()
		c.closed.Store(true)
		w.received()
		if w.signals.last.Load() != 0 {
			t.Error("retired activity reset Tw")
		}
		w.observe(c, WatchdogSuspect)
		if w.send() {
			t.Error("retired generation published DWR")
		}
		select {
		case event := <-events:
			t.Errorf("retired generation emitted %s", event.event)
		default:
		}
		select {
		case wire := <-c.writes:
			t.Errorf("retired generation wrote %d bytes", len(wire))
		default:
		}
	})
}

func TestAcceptedRetirementCancelsProtocolState(t *testing.T) {
	cfg := newAcceptedWatchdogSettings()
	sm := mustNewStateMachine(t, &cfg)
	c := newAcceptedWatchdogProbeConn()
	cleanup := sm.HandleAccept(c)
	defer cleanup()
	defer close(c.done)
	value, _ := sm.accepted.Load(c)
	state := value.(*acceptedHandshake)
	sm.startWatchdog(c)
	w := acceptedWatchdogState(t, sm, c)
	defer w.stop()
	c.closed.Store(true)
	retire, ok := any(sm).(diam.RetireHandler)
	if !ok {
		t.Fatal("StateMachine cannot retire an accepted generation")
	}
	if err := retire.HandleRetire(c, diam.SCTPAssociationRestart); err != nil {
		t.Fatal(err)
	}
	if _, ok := sm.accepted.Load(c); ok {
		t.Error("retired admission state remains")
	}
	if state.timer.Stop() {
		t.Error("retired admission timer remains active")
	}
	if _, ok := sm.watchdogs.Load(c); ok {
		t.Error("retired watchdog remains registered")
	}
	if !w.stopped.Load() {
		t.Error("retired watchdog is not stopped")
	}
	select {
	case <-w.stopc:
	default:
		t.Error("retired watchdog stop is not latched")
	}
}

func TestAcceptedRetirementAllowsBlockedWatchdogObserver(t *testing.T) {
	cfg := newAcceptedWatchdogSettings()
	cfg.WatchdogInterval = time.Hour
	entered, release := make(chan struct{}), make(chan struct{})
	cfg.OnWatchdogConnEvent = func(diam.Conn, WatchdogEvent) { close(entered); <-release }
	sm := mustNewStateMachine(t, &cfg)
	c := newAcceptedWatchdogProbeConn()
	cleanup := sm.HandleAccept(c)
	defer cleanup()
	defer close(c.done)
	sm.startWatchdog(c)
	w := acceptedWatchdogState(t, sm, c)
	observed := make(chan struct{})
	go func() { w.observe(c, WatchdogSuspect); close(observed) }()
	<-entered
	c.closed.Store(true)
	retired := make(chan error, 1)
	go func() { retired <- sm.HandleRetire(c, diam.SCTPAssociationRestart) }()
	select {
	case err := <-retired:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(200 * time.Millisecond):
		close(release)
		<-observed
		t.Fatal("retirement waited for old watchdog observer")
	}
	if !w.stopped.Load() {
		t.Error("observer hid stop latch")
	}
	if _, ok := sm.watchdogs.Load(c); ok {
		t.Error("observer kept old supervisor registered")
	}
	close(release)
	<-observed
	select {
	case <-w.exited:
	case <-time.After(time.Second):
		t.Fatal("watchdog worker did not exit after observer finished")
	}
}

func TestAcceptedRetirementDuringWatchdogRegistration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := newAcceptedWatchdogSettings()
		sm := mustNewStateMachine(t, &cfg)
		c := &watchdogRegistrationConn{disconnectCleanupConn: newDisconnectCleanupConn(), lookupEntered: make(chan struct{}), allowLookup: make(chan struct{})}
		defer close(c.done)
		close(c.allowClose)
		cleanup := sm.HandleAccept(c)
		defer cleanup()
		registered := make(chan struct{})
		go func() { sm.startWatchdog(c); close(registered) }()
		<-c.lookupEntered
		c.closed.Store(true)
		if err := sm.HandleRetire(c, diam.SCTPAssociationRestart); err != nil {
			t.Fatal(err)
		}
		close(c.allowLookup)
		<-registered
		if _, ok := sm.watchdogs.Load(c); ok {
			t.Fatal("watchdog resurrected after retirement")
		}
		sm.startWatchdog(c)
		if _, ok := sm.watchdogs.Load(c); ok {
			t.Fatal("deferred watchdog start resurrected after retirement")
		}
	})
}

func TestAcceptedCERRenewalEligibility(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	sm := mustNewStateMachine(t, testMessageErrorSettings(testDict), testDict)
	c := newHandshakeConn()
	if sm.CanRenewAcceptedCER(c) {
		t.Fatal("unaccepted connection eligible")
	}
	cleanup := sm.HandleAccept(c)
	defer cleanup()
	if sm.CanRenewAcceptedCER(c) {
		t.Fatal("pre-CER connection eligible")
	}
	sm.ServeDIAM(c, regressionCER(t, testDict, 1001))
	<-c.writes
	if !sm.CanRenewAcceptedCER(c) {
		t.Fatal("admitted accepted connection ineligible")
	}
	sm.markAcceptedClosing(c)
	if sm.CanRenewAcceptedCER(c) {
		t.Fatal("Closing connection eligible")
	}
	if err := sm.HandleRetire(c, diam.AcceptedCERRenewal); err != nil {
		t.Fatal(err)
	}
	if sm.CanRenewAcceptedCER(c) {
		t.Fatal("retired connection eligible")
	}
}

type acceptedRestartRead struct {
	data []byte
	err  error
}
type acceptedRestartTransport struct {
	net.Conn
	reads     chan acceptedRestartRead
	remaining []byte
	closed    chan struct{}
	once      sync.Once
}

func (c *acceptedRestartTransport) Read(b []byte) (int, error) {
	if len(c.remaining) == 0 {
		select {
		case read := <-c.reads:
			if read.err != nil {
				return 0, read.err
			}
			c.remaining = read.data
		case <-c.closed:
			return 0, net.ErrClosed
		}
	}
	n := copy(b, c.remaining)
	c.remaining = c.remaining[n:]
	return n, nil
}
func (c *acceptedRestartTransport) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}
func (c *acceptedRestartTransport) message(t *testing.T, m *diam.Message) {
	t.Helper()
	b, err := m.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	c.reads <- acceptedRestartRead{data: b}
}
func (c *acceptedRestartTransport) restart() {
	c.reads <- acceptedRestartRead{err: &diam.TransportRestartError{AssociationID: 81, InboundStreams: 16, OutboundStreams: 16}}
}

type acceptedRestartPair struct {
	old, next diam.Conn
	reason    diam.RetirementReason
}

func newAcceptedRestartServer(t *testing.T, cfg *Settings, mode int) (*StateMachine, *acceptedRestartTransport, net.Conn, <-chan diam.Conn, <-chan acceptedRestartPair) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	t.Helper()
	handshakes := make(chan diam.Conn, 4)
	cfg.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { handshakes <- c }
	sm := mustNewStateMachine(t, cfg, testDict)
	restarts := make(chan acceptedRestartPair, 4)
	server := &diam.Server{Handler: sm, Dict: testDict, MaxConcurrentHandlers: mode, OnConnectionRestart: func(old, next diam.Conn, reason diam.RetirementReason) {
		restarts <- acceptedRestartPair{old, next, reason}
	}}
	listener := &watchdogPipeListener{accepted: make(chan net.Conn, 1), closed: make(chan struct{})}
	local, peer := net.Pipe()
	transport := &acceptedRestartTransport{Conn: local, reads: make(chan acceptedRestartRead, 8), closed: make(chan struct{})}
	listener.accepted <- transport
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	t.Cleanup(func() {
		_ = transport.Close()
		_ = peer.Close()
		_ = server.Close()
		if err := <-serveDone; err != nil && !errors.Is(err, diam.ErrServerClosed) {
			t.Error(err)
		}
	})
	return sm, transport, peer, handshakes, restarts
}
func acceptedRestartCEA(t *testing.T, peer net.Conn, want uint32) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	t.Helper()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	m, err := diam.ReadMessage(peer, testDict)
	if err != nil || m.Header.CommandCode != diam.CapabilitiesExchange || !testResultCode(m, want) {
		t.Fatalf("CEA=%v,%v want%d", m, err, want)
	}
}
func acceptedRestartCER(t *testing.T, host string, app uint32, state uint32) *diam.Message {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	t.Helper()
	m := regressionCER(t, testDict, app)
	a, err := m.FindAVP(avp.OriginHost, 0)
	if err != nil {
		t.Fatal(err)
	}
	a.Data = datatype.DiameterIdentity(host)
	mustSMClientAVP(t, m, avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(state))
	return m
}

func TestAcceptedRestartFreshHandshake(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())
	serverSettings2 := cloneTestSettings(serverSettings2, testDict)

	for _, mode := range []int{0, 1, 2, -1} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			cfg := *serverSettings2
			sm, transport, peer, handshakes, restarts := newAcceptedRestartServer(t, &cfg, mode)
			transport.message(t, acceptedRestartCER(t, "first.example", 1001, 111))
			acceptedRestartCEA(t, peer, diam.Success)
			old := <-handshakes
			oldMeta, _ := smpeer.FromContext(old.Context())
			transport.restart()
			transport.message(t, acceptedRestartCER(t, "second.example", 1002, 222))
			acceptedRestartCEA(t, peer, diam.Success)
			next := <-handshakes
			pair := <-restarts
			nextMeta, _ := smpeer.FromContext(next.Context())
			if old == next || pair.old != old || pair.next != next || pair.reason != diam.SCTPAssociationRestart || !old.Closed() || next.Closed() {
				t.Fatal("invalid renewed connection lifecycle")
			}
			if oldMeta == nil || nextMeta == nil || oldMeta == nextMeta || oldMeta.OriginHost != "first.example" || nextMeta.OriginHost != "second.example" || !slices.Equal(oldMeta.Applications, []uint32{1001}) || !slices.Equal(nextMeta.Applications, []uint32{1002}) || oldMeta.CER.OriginStateID.Data != datatype.Unsigned32(111) || nextMeta.CER.OriginStateID.Data != datatype.Unsigned32(222) {
				t.Fatalf("metadata old=%+v next=%+v", oldMeta, nextMeta)
			}
			if _, ok := sm.accepted.Load(old); ok {
				t.Fatal("old admission retained")
			}
			if !sm.CanRenewAcceptedCER(next) {
				t.Fatal("replacement not admitted")
			}
			if lifecycle, ok := diam.ConnAs[diam.ConnLifecycle](next); !ok || lifecycle.Generation() != 2 {
				t.Fatal("replacement generation !=2")
			}
			old.Close()
			if next.Closed() {
				t.Fatal("old Close closed replacement")
			}
			transport.message(t, regressionDWR(t))
			m, err := diam.ReadMessage(peer, testDict)
			if err != nil || m.Header.CommandCode != diam.DeviceWatchdog || !testResultCode(m, diam.Success) {
				t.Fatalf("replacement DWA=%v,%v", m, err)
			}
		})
	}
}

func TestAcceptedRestartBeforeInitialCERStartsFreshTimer(t *testing.T) {
	testDict := newSMTestDictionary(
		dict.Base())
	serverSettings2 := cloneTestSettings(serverSettings2, testDict)

	synctest.Test(t, func(t *testing.T) {
		cfg := *serverSettings2
		cfg.HandshakeTimeout = 10 * time.Millisecond
		_, transport, peer, _, restarts := newAcceptedRestartServer(t, &cfg, 0)
		synctest.Wait()
		time.Sleep(5 * time.Millisecond)
		transport.restart()
		pair := <-restarts
		if !pair.old.Closed() || pair.next.Closed() {
			t.Fatal("pre-CER restart did not renew")
		}
		time.Sleep(6 * time.Millisecond)
		if pair.next.Closed() {
			t.Fatal("old timer closed replacement")
		}
		time.Sleep(5 * time.Millisecond)
		<-mustConnAs[diam.CloseNotifier](t, pair.next).CloseNotify()
		if !pair.next.Closed() {
			t.Fatal("fresh pre-CER timer did not close replacement")
		}
		_ = peer.Close()
	})
}

func TestAcceptedCERRenewalPolicyOnWire(t *testing.T) {
	testAcceptedCERRenewalPolicyOnWire(t, "tcp")
}

func testAcceptedCERRenewalPolicyOnWire(t *testing.T, network string) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())
	serverSettings2 := cloneTestSettings(serverSettings2, testDict)

	t.Helper()
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("%s/%v", network, enabled), func(t *testing.T) {
			cfg := *serverSettings2
			handshakes := make(chan diam.Conn, 4)
			cers := make(chan diam.Conn, 4)
			cfg.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { handshakes <- c }
			cfg.OnCER = func(c diam.Conn, _ *diam.Message) { cers <- c }
			sm := mustNewStateMachine(t, &cfg, testDict)
			server := diamtest.NewUnstartedServerNetwork(network, sm, testDict)
			server.Config.RenewAcceptedCER = enabled
			server.Config.MaxConcurrentHandlers = 2
			server.Start()
			defer server.Close()
			answers := make(chan *diam.Message, 4)
			mux := diam.NewServeMux()
			mux.HandleFunc("ALL", func(_ diam.Conn, m *diam.Message) { answers <- m })
			peer, err := diam.DialNetworkTimeout(network, server.Addr, mux, testDict, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			write := func(m *diam.Message) {
				t.Helper()
				if _, err := m.WriteTo(peer); err != nil {
					t.Fatal(err)
				}
			}
			answer := func(code, want uint32) {
				t.Helper()
				select {
				case m := <-answers:
					if m.Header.CommandCode != code || !testResultCode(m, want) {
						t.Fatalf("answer=%v want code%d result%d", m, code, want)
					}
				case <-time.After(time.Second):
					t.Fatal("answer missing")
				}
			}
			write(acceptedRestartCER(t, "first.example", 1001, 111))
			answer(diam.CapabilitiesExchange, diam.Success)
			old := <-handshakes
			if observed := <-cers; observed != old {
				t.Fatal("first OnCER Conn differs")
			}
			write(acceptedRestartCER(t, "second.example", 1002, 222))
			if enabled {
				answer(diam.CapabilitiesExchange, diam.Success)
				next := <-handshakes
				if observed := <-cers; observed != next || next == old {
					t.Fatal("renewed OnCER Conn differs")
				}
				metadata, _ := smpeer.FromContext(next.Context())
				if metadata.OriginHost != "second.example" || !slices.Equal(metadata.Applications, []uint32{1002}) || metadata.CER.OriginStateID.Data != datatype.Unsigned32(222) {
					t.Fatalf("renewed metadata=%+v", metadata)
				}
				write(acceptedRestartCER(t, "second.example", 1002, 222))
				answer(diam.CapabilitiesExchange, diam.Success)
				duplicate := <-handshakes
				if observed := <-cers; observed != duplicate || duplicate == next {
					t.Fatal("eligible duplicate CER did not renew")
				}
			} else {
				if observed := <-cers; observed != old {
					t.Fatal("default second OnCER changed Conn")
				}
				metadata, _ := smpeer.FromContext(old.Context())
				if metadata.OriginHost != "first.example" {
					t.Fatal("default duplicate CER replaced metadata")
				}
			}
			write(regressionDWR(t))
			answer(diam.DeviceWatchdog, diam.Success)
			select {
			case extra := <-handshakes:
				t.Fatalf("extra handshake on %p", extra)
			default:
			}
		})
	}
}

func TestAcceptedCERRenewalRejectsInvalidCapabilities(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())
	serverSettings2 := cloneTestSettings(serverSettings2, testDict)

	cfg := *serverSettings2
	handshakes := make(chan diam.Conn, 2)
	cfg.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { handshakes <- c }
	sm := mustNewStateMachine(t, &cfg, testDict)
	server := diamtest.NewUnstartedServer(sm, testDict)
	server.Config.RenewAcceptedCER = true
	server.Start()
	defer server.Close()
	peer, err := net.DialTimeout("tcp", server.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	_, err = acceptedRestartCER(t, "first.example", 1001, 111).WriteTo(peer)
	if err != nil {
		t.Fatal(err)
	}
	acceptedRestartCEA(t, peer, diam.Success)
	old := <-handshakes
	_, err = acceptedRestartCER(t, "second.example", 9999, 222).WriteTo(peer)
	if err != nil {
		t.Fatal(err)
	}
	acceptedRestartCEA(t, peer, diam.NoCommonApplication)
	if !old.Closed() {
		t.Fatal("invalid fresh CER did not retire old generation")
	}
	select {
	case <-handshakes:
		t.Fatal("invalid fresh CER admitted")
	default:
	}
	regressionClosed(t, peer)
}

func TestAcceptedIncomingDPRDisablesCERRenewal(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())
	clientSettings := cloneTestSettings(clientSettings, testDict)

	sm := mustNewStateMachine(t, testMessageErrorSettings(testDict), testDict)
	c := newHandshakeConn()
	cleanup := sm.HandleAccept(c)
	defer cleanup()
	sm.ServeDIAM(c, regressionCER(t, testDict, 1001))
	<-c.writes
	dpr := diam.NewRequest(diam.DisconnectPeer, 0, testDict)
	mustSMClientAVP(t, dpr, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
	mustSMClientAVP(t, dpr, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
	mustSMClientAVP(t, dpr, avp.DisconnectCause, avp.Mbit, 0, datatype.Enumerated(0))
	sm.ServeDIAM(c, dpr)
	<-c.writes
	if c.Closed() {
		t.Fatal("receiver closed before peer FIN")
	}
	if sm.CanRenewAcceptedCER(c) {
		t.Fatal("incoming DPR left renewal eligible in Closing")
	}
}

type retirementDisconnectConn struct {
	*blockingDisconnectConn
	entered chan struct{}
}

func (c *retirementDisconnectConn) Write(b []byte) (int, error) {
	close(c.entered)
	return c.blockingDisconnectConn.Write(b)
}
func (c *retirementDisconnectConn) WriteStream(b []byte, _ uint) (int, error) { return c.Write(b) }

func TestAcceptedRetirementDisconnectDuringWrite(t *testing.T) {
	testDict := newSMTestDictionary(
		dict.Base())
	serverSettings := cloneTestSettings(serverSettings, testDict)

	sm := mustNewStateMachine(t, serverSettings, testDict)
	c := &retirementDisconnectConn{blockingDisconnectConn: &blockingDisconnectConn{dictionary: testDict, closed: make(chan struct{})}, entered: make(chan struct{})}
	cleanup := sm.HandleAccept(c)
	defer cleanup()
	result := make(chan error, 1)
	go func() { result <- sm.Disconnect(c, DisconnectBusy, time.Hour) }()
	<-c.entered
	c.Close()
	if err := sm.HandleRetire(c, diam.SCTPAssociationRestart); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrDisconnectClosed) {
			t.Fatalf("retired DPR write returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Disconnect did not finish at retirement")
	}
	if err := sm.Disconnect(c, DisconnectBusy, time.Hour); !errors.Is(err, ErrDisconnectClosed) {
		t.Fatalf("late retired Disconnect=%v", err)
	}
}

func TestAcceptedRetirementSuppressesDWACredit(t *testing.T) {
	cfg := newAcceptedWatchdogSettings()
	events := acceptedWatchdogEvents(&cfg)
	sm := mustNewStateMachine(t, &cfg)
	c := newAcceptedWatchdogProbeConn()
	defer close(c.done)
	sm.startWatchdog(c)
	w := acceptedWatchdogState(t, sm, c)
	defer w.stop()
	c.closed.Store(true)
	w.dwa.ServeDIAM(c, acceptedDWA(t, regressionDWR(t), diam.Success))
	select {
	case <-w.signals.dwac:
		t.Fatal("retired generation credited DWA")
	default:
	}
	select {
	case event := <-events:
		t.Fatalf("retired generation emitted%s", event.event)
	default:
	}
	if w.signals.last.Load() != 0 {
		t.Fatal("retired received traffic reset Tw")
	}
}

func TestAcceptedRetiredHandshakeCannotPublish(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	sm := mustNewStateMachine(t, testMessageErrorSettings(testDict), testDict)
	c := newHandshakeConn()
	cleanup := sm.HandleAccept(c)
	defer cleanup()
	c.closed.Store(true)
	if sm.completeAcceptedHandshake(c) {
		t.Fatal("retired handshake published admission")
	}
	handleCER(sm).ServeDIAM(c, regressionCER(t, testDict, 1001))
	if _, ok := smpeer.FromContext(c.Context()); ok {
		t.Fatal("retired CER published metadata")
	}
	select {
	case <-c.writes:
		t.Fatal("retired CER wrote CEA")
	default:
	}
}

func TestAcceptedRetiredAcceptanceCannotRegister(t *testing.T) {
	sm := mustNewStateMachine(t, testMessageErrorSettings())
	c := newHandshakeConn()
	c.closed.Store(true)
	cleanup := sm.HandleAccept(c)
	defer cleanup()
	if _, ok := sm.accepted.Load(c); ok {
		t.Fatal("closed generation acquired admission state")
	}
}

func TestAcceptedRepeatedCERLogsIgnoredPolicy(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	records := logtest.New()
	cfg := *testMessageErrorSettings(testDict)
	sm := mustNewStateMachine(t, &cfg, testDict)
	c := loggerHandshakeConn{newHandshakeConn(), records.Logger()}
	cleanup := sm.HandleAccept(c)
	defer cleanup()
	sm.ServeDIAM(c, regressionCER(t, testDict, 1001))
	<-c.writes
	sm.ServeDIAM(c, regressionCER(t, testDict, 1001))
	found := false
	for _, r := range records.Records() {
		if r.Level == slog.LevelWarn && strings.Contains(r.Message, "ignoring CER on admitted connection") {
			found = true
		}
	}
	if !found {
		t.Fatal("default ignored CER has no policy warning")
	}
	select {
	case <-c.writes:
		t.Fatal("default ignored CER answered")
	default:
	}
}

func TestAcceptedRetirementReleasesDisconnectWithBlockedObserver(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	cfg := newAcceptedWatchdogSettings()
	cfg.WatchdogInterval = time.Hour
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	cfg.OnWatchdogConnEvent = func(diam.Conn, WatchdogEvent) { close(entered); <-release }
	sm, transport, peer, handshakes, _ := newAcceptedRestartServer(t, &cfg, 2)
	transport.message(t, acceptedRestartCER(t, "first.example", 1001, 111))
	acceptedRestartCEA(t, peer, diam.Success)
	old := <-handshakes
	// Finish the first CER's admission before the synthetic observer can
	// hold the watchdog mutex during its deferred startup.
	transport.message(t, regressionDWR(t))
	dwa, err := diam.ReadMessage(peer, testDict)
	if err != nil || dwa.Header.CommandCode != diam.DeviceWatchdog || !testResultCode(dwa, diam.Success) {
		t.Fatalf("initial admission DWA=%v,%v", dwa, err)
	}
	deadline := time.Now().Add(time.Second)
	for sm.supervised(old) == nil {
		if time.Now().After(deadline) {
			t.Fatal("watchdog not registered")
		}
		runtime.Gosched()
	}
	w := acceptedWatchdogState(t, sm, old)
	observed := make(chan struct{})
	go func() { w.observe(old, WatchdogSuspect); close(observed) }()
	<-entered
	result := make(chan error, 1)
	go func() { result <- sm.Disconnect(old, DisconnectBusy, time.Hour) }()
	for !sm.acceptedClosing(old) {
		if time.Now().After(deadline) {
			t.Fatal("Disconnect did not enter Closing")
		}
		runtime.Gosched()
	}
	transport.restart()
	transport.message(t, acceptedRestartCER(t, "second.example", 1002, 222))
	acceptedRestartCEA(t, peer, diam.Success)
	next := <-handshakes
	select {
	case err := <-result:
		if !errors.Is(err, ErrDisconnectClosed) {
			t.Fatalf("retired Disconnect=%v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("retired Disconnect waited for old observer")
	}
	if next.Closed() {
		t.Fatal("Disconnect cleanup closed replacement")
	}
	unblock()
	<-observed
}

type acceptedDPRGateConn struct {
	diam.Conn
	gate             atomic.Bool
	entered, release chan struct{}
	once             sync.Once
}

func (c *acceptedDPRGateConn) Context() context.Context {
	if c.gate.Load() {
		c.once.Do(func() { close(c.entered) })
		<-c.release
	}
	return c.Conn.Context()
}
func (c *acceptedDPRGateConn) Unwrap() diam.Conn { return c.Conn }

type acceptedDPRGateHandler struct {
	*StateMachine
	conns sync.Map
}

func (h *acceptedDPRGateHandler) wrap(c diam.Conn) *acceptedDPRGateConn {
	value, _ := h.conns.LoadOrStore(c, &acceptedDPRGateConn{Conn: c, entered: make(chan struct{}), release: make(chan struct{})})
	return value.(*acceptedDPRGateConn)
}
func (h *acceptedDPRGateHandler) HandleAccept(c diam.Conn) func() {
	return h.StateMachine.HandleAccept(h.wrap(c))
}
func (h *acceptedDPRGateHandler) HandleRetire(c diam.Conn, r diam.RetirementReason) error {
	return h.StateMachine.HandleRetire(h.wrap(c), r)
}
func (h *acceptedDPRGateHandler) CanRenewAcceptedCER(c diam.Conn) bool {
	return h.StateMachine.CanRenewAcceptedCER(h.wrap(c))
}
func (h *acceptedDPRGateHandler) ServeDIAM(c diam.Conn, m *diam.Message) {
	wrapped := h.wrap(c)
	if m.Header.CommandCode == diam.DisconnectPeer && m.Header.CommandFlags&diam.RequestFlag != 0 {
		wrapped.gate.Store(true)
	}
	h.StateMachine.ServeDIAM(wrapped, m)
}

func TestAcceptedDPRAdmissionPrecedesCERRenewal(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())
	serverSettings2 := cloneTestSettings(serverSettings2, testDict)
	clientSettings := cloneTestSettings(clientSettings, testDict)

	cfg := *serverSettings2
	cfg.HandshakeTimeout = -1
	handshakes := make(chan diam.Conn, 2)
	cfg.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { handshakes <- c }
	sm := mustNewStateMachine(t, &cfg, testDict)
	handler := &acceptedDPRGateHandler{StateMachine: sm}
	restarts := make(chan struct{}, 1)
	server := &diam.Server{Handler: handler, Dict: testDict, MaxConcurrentHandlers: 2, RenewAcceptedCER: true, OnConnectionRestart: func(diam.Conn, diam.Conn, diam.RetirementReason) { restarts <- struct{}{} }}
	listener := &watchdogPipeListener{accepted: make(chan net.Conn, 1), closed: make(chan struct{})}
	local, peer := net.Pipe()
	transport := &acceptedRestartTransport{Conn: local, reads: make(chan acceptedRestartRead, 8), closed: make(chan struct{})}
	listener.accepted <- transport
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	var unblock sync.Once
	var old *acceptedDPRGateConn
	defer func() {
		if old != nil {
			unblock.Do(func() { close(old.release) })
		}
		_ = transport.Close()
		_ = peer.Close()
		_ = server.Close()
		<-serveDone
	}()
	transport.message(t, acceptedRestartCER(t, "first.example", 1001, 111))
	acceptedRestartCEA(t, peer, diam.Success)
	old = (<-handshakes).(*acceptedDPRGateConn)
	dpr := diam.NewRequest(diam.DisconnectPeer, 0, testDict)
	mustSMClientAVP(t, dpr, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
	mustSMClientAVP(t, dpr, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
	mustSMClientAVP(t, dpr, avp.DisconnectCause, avp.Mbit, 0, datatype.Enumerated(0))
	transport.message(t, dpr)
	<-old.entered // DPR's handshake check is paused before Closing is published.
	transport.message(t, acceptedRestartCER(t, "second.example", 1002, 222))
	select {
	case <-restarts:
		t.Fatal("later CER renewed before preceding DPR entered Closing")
	case <-time.After(30 * time.Millisecond):
	}
	unblock.Do(func() { close(old.release) })
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	answer, err := diam.ReadMessage(peer, testDict)
	if err != nil || answer.Header.CommandCode != diam.DisconnectPeer || !testResultCode(answer, diam.Success) {
		t.Fatalf("DPA=%v,%v", answer, err)
	}
	transport.message(t, regressionDWR(t))
	answer, err = diam.ReadMessage(peer, testDict)
	if err != nil || answer.Header.CommandCode != diam.DeviceWatchdog {
		t.Fatalf("Closing CER produced unexpected answer %v,%v", answer, err)
	}
	select {
	case <-restarts:
		t.Fatal("CER renewed in Closing")
	default:
	}
	metadata, _ := smpeer.FromContext(old.Context())
	if metadata.OriginHost != "first.example" {
		t.Fatal("Closing CER replaced metadata")
	}
}

func TestAcceptedRetiredMessageErrorDoesNotAnswer(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	sm := mustNewStateMachine(t, testMessageErrorSettings(testDict), testDict)
	c := newHandshakeConn()
	cleanup := sm.HandleAccept(c)
	defer cleanup()
	sm.ServeDIAM(c, regressionCER(t, testDict, 1001))
	<-c.writes
	c.closed.Store(true)
	if err := sm.HandleMessageError(c, regressionDWR(t), &diam.MessageError{ResultCode: diam.InvalidAVPValue}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.writes:
		t.Fatal("retired message error wrote an answer")
	default:
	}
}

func TestAcceptedRestartWatchdogStates(t *testing.T) {
	for _, state := range []string{"OKAY", "PENDING", "SUSPECT"} {
		t.Run(state, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := newAcceptedWatchdogSettings()
				events := acceptedWatchdogEvents(&cfg)
				sm, transport, peer, handshakes, _ := newAcceptedRestartServer(t, &cfg, 2)
				transport.message(t, acceptedRestartCER(t, "first.example", 1001, 111))
				acceptedRestartCEA(t, peer, diam.Success)
				old := <-handshakes
				synctest.Wait()
				oldWatchdog := acceptedWatchdogState(t, sm, old)
				if state != "OKAY" {
					_ = acceptedWatchdogOnWire(t, peer)
					awaitAcceptedEvent(t, events, WatchdogRequestSent, old)
				}
				if state == "SUSPECT" {
					awaitAcceptedEvent(t, events, WatchdogSuspect, old)
				}
				transport.restart()
				transport.message(t, acceptedRestartCER(t, "second.example", 1002, 222))
				acceptedRestartCEA(t, peer, diam.Success)
				next := <-handshakes
				synctest.Wait()
				if _, ok := sm.watchdogs.Load(old); ok || !oldWatchdog.stopped.Load() {
					t.Fatal("old watchdog retained after restart")
				}
				select {
				case <-oldWatchdog.exited:
				default:
					t.Fatal("old watchdog still running")
				}
				if acceptedWatchdogState(t, sm, next) == oldWatchdog {
					t.Fatal("replacement reused old watchdog")
				}
				_ = acceptedWatchdogOnWire(t, peer)
				awaitAcceptedEvent(t, events, WatchdogRequestSent, next)
				// No old timeout/recovery event may follow the boundary.
				select {
				case event := <-events:
					t.Fatalf("extra watchdog event %s for%p", event.event, event.conn)
				default:
				}
			})
		})
	}
}

func TestAcceptedRestartOldDPAIsNotNewDisconnectAnswer(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())
	serverSettings2 := cloneTestSettings(serverSettings2, testDict)

	cfg := *serverSettings2
	sm, transport, peer, handshakes, _ := newAcceptedRestartServer(t, &cfg, 2)
	transport.message(t, acceptedRestartCER(t, "first.example", 1001, 111))
	acceptedRestartCEA(t, peer, diam.Success)
	old := <-handshakes
	oldResult := make(chan error, 1)
	go func() { oldResult <- sm.Disconnect(old, DisconnectBusy, time.Hour) }()
	oldDPR, err := diam.ReadMessage(peer, testDict)
	if err != nil || oldDPR.Header.CommandCode != diam.DisconnectPeer {
		t.Fatalf("old DPR=%v,%v", oldDPR, err)
	}
	transport.restart()
	transport.message(t, acceptedRestartCER(t, "second.example", 1002, 222))
	acceptedRestartCEA(t, peer, diam.Success)
	next := <-handshakes
	if err := <-oldResult; !errors.Is(err, ErrDisconnectClosed) {
		t.Fatalf("old Disconnect=%v", err)
	}
	if next.Closed() {
		t.Fatal("old Disconnect cleanup closed new generation")
	}
	nextResult := make(chan error, 1)
	go func() { nextResult <- sm.Disconnect(next, DisconnectBusy, time.Hour) }()
	nextDPR, err := diam.ReadMessage(peer, testDict)
	if err != nil || nextDPR.Header.CommandCode != diam.DisconnectPeer {
		t.Fatalf("new DPR=%v,%v", nextDPR, err)
	}
	if oldDPR.Header.HopByHopID == nextDPR.Header.HopByHopID {
		t.Fatal("test disconnect request IDs collided")
	}
	transport.message(t, acceptedDWA(t, oldDPR, diam.Success))
	transport.message(t, regressionDWR(t))
	answer, err := diam.ReadMessage(peer, testDict)
	if err != nil || answer.Header.CommandCode != diam.DeviceWatchdog {
		t.Fatalf("post-oldDPA answer=%v,%v", answer, err)
	}
	select {
	case err := <-nextResult:
		t.Fatalf("old DPA completed new Disconnect: %v", err)
	default:
	}
	transport.message(t, acceptedDWA(t, nextDPR, diam.Success))
	select {
	case err := <-nextResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("matching new DPA did not complete Disconnect")
	}
}

type retiredHandshakeConn struct {
	*handshakeConn
	reason diam.RetirementReason
}

func (c *retiredHandshakeConn) Generation() uint64                      { return 1 }
func (c *retiredHandshakeConn) RetirementReason() diam.RetirementReason { return c.reason }

func TestAcceptedRetiredBusinessAnswerDoesNotDispatch(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	sm := mustNewStateMachine(t, testMessageErrorSettings(testDict), testDict)
	c := &retiredHandshakeConn{handshakeConn: newHandshakeConn()}
	cleanup := sm.HandleAccept(c)
	defer cleanup()
	sm.ServeDIAM(c, regressionCER(t, testDict, 1001))
	<-c.writes
	calls := 0
	sm.Handle("ALL", diam.HandlerFunc(func(diam.Conn, *diam.Message) { calls++ }))
	c.closed.Store(true)
	c.reason = diam.SCTPAssociationRestart
	sm.ServeDIAM(c, diam.NewRequest(999, 1001, testDict).Answer(diam.Success))
	if calls != 0 {
		t.Fatalf("retired generation delivered %d business answers", calls)
	}
}

func TestDecodedBusinessAnswerDispatchByRetirement(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	for _, reason := range []diam.RetirementReason{0, diam.SCTPAssociationRestart, diam.AcceptedCERRenewal} {
		t.Run(fmt.Sprint(reason), func(t *testing.T) {
			sm := mustNewStateMachine(t, testMessageErrorSettings(testDict), testDict)
			c := &retiredHandshakeConn{handshakeConn: newHandshakeConn()}
			cleanup := sm.HandleAccept(c)
			defer cleanup()
			sm.ServeDIAM(c, regressionCER(t, testDict, 1001))
			<-c.writes
			calls := 0
			sm.Handle("ALL", diam.HandlerFunc(func(diam.Conn, *diam.Message) { calls++ }))
			// Ordinary closure may race an already decoded callback without retiring
			// its generation. Only renewal cancels its application delivery.
			c.closed.Store(true)
			c.reason = reason
			sm.ServeDIAM(c, diam.NewRequest(999, 1001, testDict).Answer(diam.Success))
			want := 0
			if reason == 0 {
				want = 1
			}
			if calls != want {
				t.Fatalf("Closed connection with retirement reason %v delivered %d business answers, want %d", reason, calls, want)
			}
		})
	}
}
