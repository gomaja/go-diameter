package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/sm"
)

// Input events are read boundaries; output is the actual serialized frame.
// Channel-backed I/O keeps every worker inside the synctest bubble.
type renewalScriptTransport struct {
	reads      chan restartEvent
	writes     chan []byte
	pending    []byte
	closed     chan struct{}
	once       sync.Once
	deadlineMu sync.Mutex
	deadlines  []time.Time
}

func (c *renewalScriptTransport) Read(b []byte) (int, error) {
	if len(c.pending) == 0 {
		select {
		case <-c.closed:
			return 0, net.ErrClosed
		case e := <-c.reads:
			if e.err != nil {
				return 0, e.err
			}
			c.pending = e.data
		}
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
func (c *renewalScriptTransport) Write(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	c.writes <- append([]byte(nil), b...)
	return len(b), nil
}
func (c *renewalScriptTransport) Close() error { c.once.Do(func() { close(c.closed) }); return nil }
func (*renewalScriptTransport) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3868}
}
func (*renewalScriptTransport) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 43868}
}
func (*renewalScriptTransport) SetDeadline(time.Time) error     { return nil }
func (*renewalScriptTransport) SetReadDeadline(time.Time) error { return nil }
func (c *renewalScriptTransport) SetWriteDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	c.deadlines = append(c.deadlines, deadline)
	c.deadlineMu.Unlock()
	return nil
}

type renewalScriptPair struct {
	old, next diam.Conn
	reason    diam.RetirementReason
}

type renewalScriptContextKey struct{}

type renewalScriptServerOption struct {
	beforeBind func(*diam.Server)
	afterBind  func(*diam.Server)
}
type renewalScriptWrapper struct{ inner diam.Handler }

func (h renewalScriptWrapper) Unwrap() diam.Handler                     { return h.inner }
func (h renewalScriptWrapper) ServeDIAM(c diam.Conn, msg *diam.Message) { h.inner.ServeDIAM(c, msg) }

type renewalScriptHarness struct {
	m         *Manager
	srv       *diam.Server
	transport *renewalScriptTransport
	initial   diam.Conn
	pairs     chan renewalScriptPair
	events    chan PeerEvent
	protocol  chan diam.ProtocolErrorEvent
	physical  chan diam.Conn
	clock     *fakeClock
	records   *logtest.Recorder
	output    []byte
}

func renewalScriptNew(t *testing.T, mode int, enabled, wrapped bool, change func(*Config), options ...renewalScriptServerOption) *renewalScriptHarness {
	t.Helper()
	h := &renewalScriptHarness{pairs: make(chan renewalScriptPair, 16), events: make(chan PeerEvent, 64), protocol: make(chan diam.ProtocolErrorEvent, 64), physical: make(chan diam.Conn, 4), clock: &fakeClock{}}
	settings := testSettings("local.example.net")
	settings.AuthApplicationID = []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)), diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(5))}
	settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { h.protocol <- e }
	records := logtest.New()
	h.records = records
	cfg := Config{Settings: settings, Clock: h.clock, Logger: records.Logger(), OnPeerEvent: func(e PeerEvent) { h.events <- e }}
	if change != nil {
		change(&cfg)
	}
	var err error
	h.m, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []datatype.DiameterIdentity{"known.example.net", "second.example.net"} {
		if err = h.m.AddPeer(PeerConfig{Host: host}); err != nil {
			t.Fatal(err)
		}
	}
	h.transport = &renewalScriptTransport{reads: make(chan restartEvent, 32), writes: make(chan []byte, 64), closed: make(chan struct{})}
	h.srv = &diam.Server{Logger: records.Logger(), MaxConcurrentHandlers: mode, RenewAcceptedCER: enabled, OnNewConnection: func(c diam.Conn) { h.physical <- c }, OnConnectionRestart: func(old, next diam.Conn, r diam.RetirementReason) { h.pairs <- renewalScriptPair{old, next, r} }}
	for _, option := range options {
		if option.beforeBind != nil {
			option.beforeBind(h.srv)
		}
	}
	if err = h.m.BindServer(h.srv); err != nil {
		t.Fatal(err)
	}
	if wrapped {
		h.srv.Handler = renewalScriptWrapper{renewalScriptWrapper{h.m}}
	}
	for _, option := range options {
		if option.afterBind != nil {
			option.afterBind(h.srv)
		}
	}
	listener := &restartScriptListener{conn: h.transport, closed: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- h.srv.Serve(listener) }()
	t.Cleanup(func() {
		_ = h.transport.Close()
		_ = h.srv.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := h.m.Close(ctx, sm.DisconnectRebooting); err != nil {
			t.Error(err)
		}
		if err := <-done; !errors.Is(err, diam.ErrServerClosed) {
			t.Error(err)
		}
	})
	h.initial = renewalScriptReceive(t, h.physical, "physical acceptance")
	return h
}

func renewalScriptReceive[T any](t *testing.T, ch <-chan T, label string) T {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case got := <-ch:
		return got
	case <-timer.C:
		t.Fatalf("missing %s", label)
		var zero T
		return zero
	}
}
func (h *renewalScriptHarness) feed(t *testing.T, msgs ...*diam.Message) {
	t.Helper()
	var data []byte
	for _, m := range msgs {
		b, err := m.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, b...)
	}
	h.transport.reads <- restartEvent{data: data}
}
func (h *renewalScriptHarness) restart() {
	h.transport.reads <- restartEvent{err: &diam.TransportRestartError{AssociationID: 81, InboundStreams: 16, OutboundStreams: 16}}
}
func (h *renewalScriptHarness) message(t *testing.T) *diam.Message {
	t.Helper()
	for len(h.output) < 20 || len(h.output) < int(uint32(h.output[1])<<16|uint32(h.output[2])<<8|uint32(h.output[3])) {
		h.output = append(h.output, renewalScriptReceive(t, h.transport.writes, "serialized response")...)
	}
	n := int(uint32(h.output[1])<<16 | uint32(h.output[2])<<8 | uint32(h.output[3]))
	m, err := diam.ReadMessage(bytes.NewReader(h.output[:n]), dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	h.output = h.output[n:]
	return m
}
func (h *renewalScriptHarness) answer(t *testing.T, cmd uint32, want uint32) *diam.Message {
	t.Helper()
	m := h.message(t)
	if m.Header.CommandCode != cmd || m.Header.CommandFlags&diam.RequestFlag != 0 || code(t, m) != want {
		t.Fatalf("answer header=%+v result=%d, want command=%d result=%d", m.Header, code(t, m), cmd, want)
	}
	return m
}
func renewalScriptCER(t *testing.T, host, realm string, app, state uint32) *diam.Message {
	t.Helper()
	cfg := testBase(host)
	cfg.OriginRealm = datatype.DiameterIdentity(realm)
	cfg.OriginStateID = datatype.Unsigned32(state)
	cfg.AuthApplicationID = []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(app))}
	m, err := base.BuildCER(dict.Default, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func (h *renewalScriptHarness) open(t *testing.T) {
	t.Helper()
	h.feed(t, renewalScriptCER(t, "known.example.net", "example.net", 4, 111))
	h.answer(t, diam.CapabilitiesExchange, diam.Success)
	synctest.Wait()
	p := h.m.Peers()[0]
	if p.State != ROpen || p.Watchdog != WatchdogOkay || !p.Eligible {
		t.Fatalf("initial admission=%+v", p)
	}
}
func renewalScriptLifecycle(t *testing.T, c diam.Conn) diam.ConnLifecycle {
	t.Helper()
	l, ok := diam.ConnAs[diam.ConnLifecycle](c)
	if !ok {
		t.Fatal("connection lifecycle missing")
	}
	return l
}

func TestManagerRenewalScriptInterfaces(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := renewalScriptNew(t, 0, false, false, nil)
		if _, ok := diam.HandlerAs[diam.AcceptHandler](h.m); !ok {
			t.Error("Manager lacks accepted-generation registration")
		}
		if _, ok := diam.HandlerAs[diam.RetireHandler](h.m); !ok {
			t.Error("Manager lacks accepted-generation retirement")
		}
		if _, ok := diam.HandlerAs[diam.AcceptedCERHandler](h.m); !ok {
			t.Error("Manager lacks accepted CER eligibility")
		}
	})
}

func TestManagerRenewalScriptRestart(t *testing.T) {
	for _, mode := range []int{0, 1, 2, -1} {
		for _, wrapped := range []bool{false, true} {
			for _, admitted := range []bool{false, true} {
				t.Run(fmt.Sprintf("dispatch=%d/wrapped=%t/admitted=%t", mode, wrapped, admitted), func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						h := renewalScriptNew(t, mode, false, wrapped, nil)
						if admitted {
							h.open(t)
						}
						oldContext := context.WithValue(h.initial.Context(), renewalScriptContextKey{}, "old application context")
						h.initial.SetContext(oldContext)
						h.restart()
						pair := renewalScriptReceive(t, h.pairs, "replacement on original physical connection")
						synctest.Wait()
						if pair.old != h.initial || pair.next == pair.old || pair.reason != diam.SCTPAssociationRestart || !pair.old.Closed() || pair.next.Closed() {
							t.Fatal("restart did not retire exactly the accepted generation")
						}
						if renewalScriptLifecycle(t, pair.old).RetirementReason() != diam.SCTPAssociationRestart || renewalScriptLifecycle(t, pair.next).Generation() != 2 {
							t.Fatal("incorrect physical generation lifecycle")
						}
						if _, err := pair.old.Write([]byte("stale")); !errors.Is(err, diam.ErrConnectionRetired) {
							t.Fatalf("old write=%v", err)
						}
						if _, err := pair.old.WriteStream([]byte("stale"), 0); !errors.Is(err, diam.ErrConnectionRetired) {
							t.Fatalf("old stream write=%v", err)
						}
						pair.old.Close()
						if pair.next.Closed() {
							t.Fatal("old Close affected replacement")
						}
						h.feed(t, renewalScriptCER(t, "known.example.net", "fresh.example.net", 5, 222))
						h.answer(t, diam.CapabilitiesExchange, diam.Success)
						synctest.Wait()
						p := h.m.Peers()[0]
						if p.State != ROpen || p.Realm != "fresh.example.net" || !reflect.DeepEqual(p.Applications, []uint32{5}) {
							t.Fatalf("replacement capabilities=%+v", p)
						}
						if pair.next.Context().Value(renewalScriptContextKey{}) != nil || pair.old.Context() != oldContext {
							t.Fatal("replacement reused old application context or changed old context")
						}
						if admitted {
							if p.Watchdog != WatchdogReopen || p.Eligible {
								t.Fatalf("replacement bypassed recovery=%+v", p)
							}
							retireEvents := 0
							for len(h.events) > 0 {
								if e := <-h.events; errors.Is(e.Reason, diam.ErrConnectionRetired) {
									retireEvents++
								}
							}
							if retireEvents != 1 {
								t.Fatalf("retirement events=%d want1", retireEvents)
							}
						} else if p.Watchdog != WatchdogOkay || !p.Eligible {
							t.Fatalf("first admission after restart=%+v", p)
						}
						if len(h.physical) != 0 {
							t.Fatal("restart repeated physical acceptance hook")
						}
						if len(h.protocol) != 0 {
							t.Fatal("successful restart reported protocol error")
						}
					})
				})
			}
		}
	}
}

func TestManagerRenewalScriptRepeatedRestartAndEOF(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := renewalScriptNew(t, 2, false, true, nil)
		previous := h.initial
		for generation := uint64(2); generation <= 4; generation++ {
			h.restart()
			pair := renewalScriptReceive(t, h.pairs, "sequential replacement")
			synctest.Wait()
			if pair.old != previous || !previous.Closed() || renewalScriptLifecycle(t, pair.next).Generation() != generation {
				t.Fatalf("restart generation=%d old=%v next=%v", generation, pair.old, pair.next)
			}
			previous = pair.next
		}
		h.transport.reads <- restartEvent{err: io.EOF}
		synctest.Wait()
		if !previous.Closed() {
			t.Fatal("EOF retained replacement generation")
		}
		select {
		case <-h.transport.closed:
		default:
			t.Fatal("EOF retained physical transport")
		}
		if len(h.pairs) != 0 || len(h.protocol) != 0 {
			t.Fatal("EOF fabricated renewal or protocol error")
		}
	})
}

func TestManagerRenewalScriptCERPolicy(t *testing.T) {
	for _, mode := range []int{0, 1, 2, -1} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("dispatch=%d/enabled=%t", mode, enabled), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					h := renewalScriptNew(t, mode, enabled, true, nil)
					h.open(t)
					before := h.m.Peers()[0]
					ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
					defer cancel()
					pending := sendAsync(h.m, ctx, outboundRequest("known.example.net", "example.net"))
					request := h.message(t)
					second := renewalScriptCER(t, "known.example.net", "fresh.example.net", 5, 222)
					h.feed(t, second)
					if enabled {
						pair := renewalScriptReceive(t, h.pairs, "opt-in CER replacement")
						h.answer(t, diam.CapabilitiesExchange, diam.Success)
						synctest.Wait()
						if pair.old != h.initial || pair.reason != diam.AcceptedCERRenewal || !pair.old.Closed() || pair.next.Closed() {
							t.Fatal("CER did not renew the admitted generation")
						}
						p := h.m.Peers()[0]
						if p.Generation == before.Generation || p.State != ROpen || p.Realm != "fresh.example.net" || !reflect.DeepEqual(p.Applications, []uint32{5}) {
							t.Fatalf("CER replacement=%+v", p)
						}
						got := renewalScriptReceive(t, pending, "retired pending request completion")
						if got.err == nil || got.answer != nil {
							t.Fatalf("retirement completed old request successfully: %+v", got)
						}
						if len(h.protocol) != 0 {
							t.Fatal("successful CER renewal reported protocol error")
						}
					} else {
						e := renewalScriptReceive(t, h.protocol, "ignored Open CER notification")
						synctest.Wait()
						protocolErrorCheck(t, e, h.initial, *second.Header, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0, 0)
						if h.initial.Closed() || !reflect.DeepEqual(h.m.Peers()[0], before) || len(h.pairs) != 0 || len(h.transport.writes) != 0 {
							t.Fatal("default CER changed generation, capabilities, or sent an answer")
						}
						select {
						case got := <-pending:
							t.Fatalf("ignored CER completed request=%+v", got)
						default:
						}
						h.feed(t, request.Answer(diam.Success))
						got := renewalScriptReceive(t, pending, "preserved request answer")
						if got.err != nil || got.answer == nil || got.answer.Header.HopByHopID != request.Header.HopByHopID {
							t.Fatalf("preserved request=%+v", got)
						}
					}
				})
			})
		}
	}
}

func TestManagerRenewalScriptFreshIdentityAndRejection(t *testing.T) {
	for _, tc := range []struct {
		name, host  string
		app, result uint32
	}{
		{"known identity", "second.example.net", 5, diam.Success},
		{"unknown identity", "unknown.example.net", 5, diam.UnknownPeer},
		{"no common application", "second.example.net", 999999, diam.NoCommonApplication},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := renewalScriptNew(t, 2, true, false, nil)
				h.open(t)
				h.feed(t, renewalScriptCER(t, tc.host, "fresh.example.net", tc.app, 222))
				pair := renewalScriptReceive(t, h.pairs, "fresh identity generation")
				answer := h.answer(t, diam.CapabilitiesExchange, tc.result)
				synctest.Wait()
				peers := h.m.Peers()
				if peers[0].State != Closed || peers[0].Eligible {
					t.Fatalf("old identity still admitted=%+v", peers[0])
				}
				if tc.result == diam.Success {
					if pair.next.Closed() || peers[1].State != ROpen || peers[1].Realm != "fresh.example.net" || !reflect.DeepEqual(peers[1].Applications, []uint32{5}) {
						t.Fatalf("known identity not re-admitted=%+v", peers[1])
					}
					if len(h.protocol) != 0 {
						t.Fatal("known identity renewal reported protocol error")
					}
				} else {
					if !pair.next.Closed() || peers[1].State != Closed || peers[1].Eligible {
						t.Fatalf("rejected generation admitted: closed=%t peer=%+v", pair.next.Closed(), peers[1])
					}
					if (answer.Header.CommandFlags&diam.ErrorFlag != 0) != (tc.result >= 3000 && tc.result < 4000) {
						t.Fatalf("rejection result=%d flags=%#x", tc.result, answer.Header.CommandFlags)
					}
					e := renewalScriptReceive(t, h.protocol, "replacement rejection notification")
					if e.Conn != pair.next || !e.Closing || e.ReplyCode != tc.result || e.Reply != diam.ProtocolReplyQueued {
						t.Fatalf("rejection notification=%+v", e)
					}
				}
			})
		})
	}
}

func TestManagerRenewalScriptDPRBeforeCER(t *testing.T) {
	for _, mode := range []int{0, 1, 2, -1} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := renewalScriptNew(t, mode, true, true, nil)
				h.open(t)
				dpr, err := base.BuildDPR(dict.Default, testBase("known.example.net"), uint32(sm.DisconnectDoNotWantToTalkToYou))
				if err != nil {
					t.Fatal(err)
				}
				// One transport read leaves both messages available before either
				// concurrent callback can run. Admission must commit DPR first.
				h.feed(t, dpr, renewalScriptCER(t, "known.example.net", "fresh.example.net", 5, 222))
				h.answer(t, diam.DisconnectPeer, diam.Success)
				synctest.Wait()
				if len(h.pairs) != 0 {
					t.Fatal("CER renewed after preceding DPR committed Closing")
				}
				p := h.m.Peers()[0]
				if p.State != Closing || p.Eligible || p.Realm != "example.net" || !reflect.DeepEqual(p.Applications, []uint32{4}) {
					t.Fatalf("DPR then CER changed admission=%+v", p)
				}
				if len(h.transport.writes) != 0 {
					t.Fatal("Closing CER sent an answer")
				}
			})
		})
	}
}

func TestManagerRenewalScriptBlockedObservers(t *testing.T) {
	for _, blocked := range []string{"protocol", "peer", "both"} {
		t.Run(blocked, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				protocolEntered, peerEntered := make(chan struct{}, 1), make(chan struct{}, 1)
				release := make(chan struct{})
				defer close(release)
				h := renewalScriptNew(t, -1, false, true, func(cfg *Config) {
					cfg.Limits.Events = 2
					if blocked == "protocol" || blocked == "both" {
						cfg.Settings.OnProtocolError = func(diam.ProtocolErrorEvent) {
							select {
							case protocolEntered <- struct{}{}:
							default:
							}
							<-release
						}
					}
					if blocked == "peer" || blocked == "both" {
						cfg.OnPeerEvent = func(PeerEvent) {
							select {
							case peerEntered <- struct{}{}:
							default:
							}
							<-release
						}
					}
				})
				h.open(t)
				if blocked == "peer" || blocked == "both" {
					renewalScriptReceive(t, peerEntered, "blocked peer observer")
				}
				if blocked == "protocol" || blocked == "both" {
					dwr, err := base.BuildDWR(dict.Default, testBase("other.example.net"), 0)
					if err != nil {
						t.Fatal(err)
					}
					h.feed(t, dwr)
					renewalScriptReceive(t, protocolEntered, "blocked protocol observer")
				}
				h.restart()
				pair := renewalScriptReceive(t, h.pairs, "retirement while observer blocked")
				if !pair.old.Closed() || pair.next.Closed() {
					t.Fatal("blocked observer prevented replacement")
				}
				h.feed(t, renewalScriptCER(t, "known.example.net", "fresh.example.net", 5, 222))
				h.answer(t, diam.CapabilitiesExchange, diam.Success)
				synctest.Wait()
				if p := h.m.Peers()[0]; p.State != ROpen || p.Realm != "fresh.example.net" {
					t.Fatalf("observer blocked protocol commit=%+v", p)
				}
				if blocked == "peer" || blocked == "both" {
					found := false
					for _, record := range h.records.Records() {
						if record.Message == "peer: event queue full; event dropped" {
							found = true
						}
					}
					if !found {
						t.Fatal("bounded observer queue was not saturated")
					}
				}
			})
		})
	}
}

type renewalScriptRetireBarrier struct {
	renewalScriptWrapper
	entered chan struct{}
	release chan struct{}
}

func (h *renewalScriptRetireBarrier) HandleRetire(c diam.Conn, reason diam.RetirementReason) error {
	close(h.entered)
	<-h.release
	inner, ok := diam.HandlerAs[diam.RetireHandler](h.inner)
	if !ok {
		return errors.New("inner handler lacks retirement")
	}
	return inner.HandleRetire(c, reason)
}

func TestManagerRenewalScriptCloseAtRetirement(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		for _, admitted := range []bool{false, true} {
			t.Run(fmt.Sprintf("shutdown=%t/admitted=%t", shutdown, admitted), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					barrier := &renewalScriptRetireBarrier{entered: make(chan struct{}), release: make(chan struct{})}
					h := renewalScriptNew(t, 2, true, false, nil, renewalScriptServerOption{afterBind: func(srv *diam.Server) {
						barrier.inner = srv.Handler
						srv.Handler = barrier
					}})
					if admitted {
						h.open(t)
					}
					h.restart()
					renewalScriptReceive(t, barrier.entered, "retirement barrier")
					done := make(chan error, 1)
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if shutdown {
						go func() { done <- h.srv.Shutdown(ctx) }()
					} else {
						go func() { done <- h.m.Close(ctx, sm.DisconnectRebooting) }()
					}
					synctest.Wait()
					close(barrier.release)
					if err := renewalScriptReceive(t, done, "close crossing retirement"); err != nil {
						t.Fatal(err)
					}
					synctest.Wait()
					select {
					case <-h.transport.closed:
					default:
						t.Fatal("close left physical transport open")
					}
					for _, p := range h.m.Peers() {
						if p.Eligible || p.State == ROpen {
							t.Fatalf("close resurrected peer=%+v", p)
						}
					}
					if shutdown && len(h.pairs) != 0 {
						t.Fatal("Server Shutdown published a replacement")
					}
					for len(h.transport.writes) > 0 {
						m := h.message(t)
						if m.Header.CommandCode == diam.DisconnectPeer && m.Header.CommandFlags&diam.RequestFlag != 0 {
							t.Fatal("close sent shutdown DPR to retired or replacement generation")
						}
					}
				})
			})
		}
	}
}

func TestManagerRenewalScriptRecoveryRequiresFreshDWAs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := renewalScriptNew(t, 2, true, false, nil)
		h.open(t)
		h.clock.fire()
		oldProbe := h.message(t)
		if oldProbe.Header.CommandCode != diam.DeviceWatchdog || oldProbe.Header.CommandFlags&diam.RequestFlag == 0 {
			t.Fatalf("old probe=%+v", oldProbe.Header)
		}
		h.restart()
		renewalScriptReceive(t, h.pairs, "recovering replacement")
		h.feed(t, renewalScriptCER(t, "known.example.net", "example.net", 4, 222))
		h.answer(t, diam.CapabilitiesExchange, diam.Success)
		probe := h.message(t)
		stale, err := base.BuildDWA(oldProbe, testBase("known.example.net"))
		if err != nil {
			t.Fatal(err)
		}
		h.feed(t, stale)
		synctest.Wait()
		if p := h.m.Peers()[0]; p.Watchdog != WatchdogReopen || p.Eligible {
			t.Fatalf("old DWA restored health=%+v", p)
		}
		for count := 1; count <= 3; count++ {
			if probe.Header.CommandCode != diam.DeviceWatchdog || probe.Header.HopByHopID == oldProbe.Header.HopByHopID || probe.Header.EndToEndID == oldProbe.Header.EndToEndID {
				t.Fatalf("replacement probe reused old identifiers=%+v", probe.Header)
			}
			answer, err := base.BuildDWA(probe, testBase("known.example.net"))
			if err != nil {
				t.Fatal(err)
			}
			h.feed(t, answer)
			synctest.Wait()
			p := h.m.Peers()[0]
			if count < 3 {
				if p.Watchdog != WatchdogReopen || p.Eligible {
					t.Fatalf("DWA %d restored health early=%+v", count, p)
				}
				h.clock.fire()
				probe = h.message(t)
			} else if p.Watchdog != WatchdogOkay || !p.Eligible {
				t.Fatalf("three fresh DWAs did not restore health=%+v", p)
			}
		}
	})
}

func TestManagerRenewalScriptOrdinaryEOFDrainsAnswer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := renewalScriptNew(t, 2, false, false, nil)
		h.open(t)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		pending := sendAsync(h.m, ctx, outboundRequest("known.example.net", "example.net"))
		request := h.message(t)
		h.feed(t, request.Answer(diam.Success))
		h.transport.reads <- restartEvent{err: io.EOF}
		got := renewalScriptReceive(t, pending, "answer admitted before ordinary EOF")
		if got.err != nil || got.answer == nil || got.answer.Header.HopByHopID != request.Header.HopByHopID {
			t.Fatalf("ordinary EOF discarded admitted answer=%+v", got)
		}
		synctest.Wait()
		if !h.initial.Closed() || h.m.Peers()[0].State != Closed {
			t.Fatal("EOF retained admitted session")
		}
		if len(h.pairs) != 0 {
			t.Fatal("ordinary EOF fabricated replacement")
		}
	})
}

func TestManagerRenewalScriptFirstCERAtRestart(t *testing.T) {
	for _, mode := range []int{0, 1, 2, -1} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := renewalScriptNew(t, mode, false, true, nil)
				h.feed(t, renewalScriptCER(t, "known.example.net", "old.example.net", 4, 111))
				h.restart()
				pair := renewalScriptReceive(t, h.pairs, "restart immediately after first CER read")
				synctest.Wait()
				if p := h.m.Peers()[0]; p.Eligible || p.State == ROpen {
					t.Fatalf("old CER restored retired admission=%+v", p)
				}
				// An old CEA could have reached the transport before retirement; discard
				// only those already emitted bytes before admitting the replacement.
				for len(h.transport.writes) > 0 {
					h.message(t)
				}
				h.feed(t, renewalScriptCER(t, "known.example.net", "fresh.example.net", 5, 222))
				h.answer(t, diam.CapabilitiesExchange, diam.Success)
				synctest.Wait()
				if p := h.m.Peers()[0]; p.State != ROpen || p.Realm != "fresh.example.net" || !reflect.DeepEqual(p.Applications, []uint32{5}) {
					t.Fatalf("first CER race lost replacement capabilities=%+v", p)
				}
				if !pair.old.Closed() || pair.next.Closed() {
					t.Fatal("first CER race retained old generation")
				}
			})
		})
	}
}

func TestManagerRenewalScriptCERThenMalformed(t *testing.T) {
	for _, mode := range []int{0, 1, 2, -1} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := renewalScriptNew(t, mode, true, true, nil)
				h.restart()
				pair := renewalScriptReceive(t, h.pairs, "pre-CER replacement")
				cer := renewalScriptCER(t, "known.example.net", "example.net", 4, 222)
				malformed, err := base.BuildDWR(dict.Default, testBase("known.example.net"), 0)
				if err != nil {
					t.Fatal(err)
				}
				malformed.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2}))
				h.feed(t, cer, malformed)
				cea := h.answer(t, diam.CapabilitiesExchange, diam.Success)
				errorAnswer := h.answer(t, diam.DeviceWatchdog, diam.InvalidAVPLength)
				if cea.Header.HopByHopID != cer.Header.HopByHopID || errorAnswer.Header.HopByHopID != malformed.Header.HopByHopID {
					t.Fatal("CER and malformed response order or correlation changed")
				}
				synctest.Wait()
				if pair.next.Closed() || h.m.Peers()[0].State != ROpen {
					t.Fatal("malformed following request discarded admitted replacement CER")
				}
				e := renewalScriptReceive(t, h.protocol, "malformed input notification")
				if e.Conn != pair.next || e.Closing || e.Reply != diam.ProtocolReplyQueued || e.ReplyCode != diam.InvalidAVPLength {
					t.Fatalf("malformed generation notification=%+v", e)
				}
			})
		})
	}
}

func TestManagerRenewalScriptWriteTimeoutOwnership(t *testing.T) {
	for _, configured := range []time.Duration{0, time.Second, 10 * time.Second} {
		t.Run(configured.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := renewalScriptNew(t, 2, false, false, func(cfg *Config) { cfg.Timers.Closing = 2 * time.Second }, renewalScriptServerOption{beforeBind: func(srv *diam.Server) { srv.WriteTimeout = configured }})
				want := 2 * time.Second
				if configured > 0 && configured < want {
					want = configured
				}
				if h.srv.WriteTimeout != want {
					t.Fatalf("server write timeout=%s want%s", h.srv.WriteTimeout, want)
				}
				h.open(t)
				h.transport.deadlineMu.Lock()
				deadlines := append([]time.Time(nil), h.transport.deadlines...)
				h.transport.deadlineMu.Unlock()
				if len(deadlines) == 0 {
					t.Fatal("CEA write did not apply Server write timeout")
				}
				for _, deadline := range deadlines {
					if got := time.Until(deadline); got != want {
						t.Fatalf("CEA write deadline=%s want%s; session must not replace or clear Server deadline", got, want)
					}
				}
			})
		})
	}
}

type renewalScriptCallbackBarrier struct {
	renewalScriptWrapper
	entered chan struct{}
	release chan struct{}
}

func (h *renewalScriptCallbackBarrier) ServeDIAM(c diam.Conn, msg *diam.Message) {
	h.inner.ServeDIAM(c, msg)
	if msg.Header.CommandCode == diam.DeviceWatchdog {
		close(h.entered)
		<-h.release
	}
}

func TestManagerRenewalScriptRepeatedRestartWithOutstandingCallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		barrier := &renewalScriptCallbackBarrier{entered: make(chan struct{}), release: make(chan struct{})}
		defer close(barrier.release)
		h := renewalScriptNew(t, 2, false, false, nil, renewalScriptServerOption{afterBind: func(srv *diam.Server) {
			barrier.inner = srv.Handler
			srv.Handler = barrier
		}})
		h.open(t)
		dwr, err := base.BuildDWR(dict.Default, testBase("known.example.net"), 0)
		if err != nil {
			t.Fatal(err)
		}
		h.feed(t, dwr)
		h.answer(t, diam.DeviceWatchdog, diam.Success)
		renewalScriptReceive(t, barrier.entered, "old Server callback held after protocol admission")
		h.restart()
		pair := renewalScriptReceive(t, h.pairs, "first replacement while old callback remains")
		synctest.Wait()
		done, ok := diam.ConnAs[interface{ DispatchDone() <-chan struct{} }](pair.old)
		if !ok {
			t.Fatal("old dispatch completion missing")
		}
		select {
		case <-done.DispatchDone():
			t.Fatal("old Server callback unexpectedly completed")
		default:
		}
		h.restart()
		renewalScriptReceive(t, h.transport.closed, "physical closure on second restart")
		synctest.Wait()
		if !pair.old.Closed() || !pair.next.Closed() || len(h.pairs) != 0 || len(h.physical) != 0 {
			t.Fatal("second restart published another generation while old callback remained")
		}
		for _, peer := range h.m.Peers() {
			if peer.Eligible || peer.State == ROpen {
				t.Fatalf("second restart retained old admission=%+v", peer)
			}
		}
		select {
		case <-done.DispatchDone():
			t.Fatal("physical closure returned blocked Server callback")
		default:
		}
	})
}

// The client endpoint crosses the same channel boundaries as the scripted
// plaintext transport, but a real TLS handshake and records cross them.
type renewalScriptTLSOther struct {
	*renewalScriptTransport
	pending []byte
}

func (c *renewalScriptTLSOther) Read(b []byte) (int, error) {
	if len(c.pending) == 0 {
		select {
		case <-c.closed:
			return 0, net.ErrClosed
		case c.pending = <-c.writes:
		}
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
func (c *renewalScriptTLSOther) Write(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	c.reads <- restartEvent{data: append([]byte(nil), b...)}
	return len(b), nil
}

func renewalScriptCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"scripted.example.net"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}
}

func TestManagerRenewalScriptTLSRestartClosesPhysical(t *testing.T) {
	certificate := renewalScriptCertificate(t)
	for _, admitted := range []bool{false, true} {
		t.Run(fmt.Sprintf("admitted=%t", admitted), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				m, err := New(Config{Settings: testSettings("local.example.net"), Clock: &fakeClock{}, Logger: logtest.New().Logger()})
				if err != nil {
					t.Fatal(err)
				}
				if err = m.AddPeer(PeerConfig{Host: "known.example.net"}); err != nil {
					t.Fatal(err)
				}
				raw := &renewalScriptTransport{reads: make(chan restartEvent, 32), writes: make(chan []byte, 64), closed: make(chan struct{})}
				serverTLS := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}})
				// This certificate and endpoint exist only in this isolated test.
				clientTLS := tls.Client(&renewalScriptTLSOther{renewalScriptTransport: raw}, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}) // #nosec G402 -- synthetic local certificate
				accepted := make(chan diam.Conn, 1)
				replacements := make(chan renewalScriptPair, 1)
				srv := &diam.Server{MaxConcurrentHandlers: 2, RenewAcceptedCER: true, Logger: logtest.New().Logger(), OnNewConnection: func(c diam.Conn) { accepted <- c }, OnConnectionRestart: func(old, next diam.Conn, reason diam.RetirementReason) {
					replacements <- renewalScriptPair{old, next, reason}
				}}
				if err = m.BindServer(srv); err != nil {
					t.Fatal(err)
				}
				listener := &restartScriptListener{conn: serverTLS, closed: make(chan struct{})}
				serveDone := make(chan error, 1)
				go func() { serveDone <- srv.Serve(listener) }()
				t.Cleanup(func() {
					_ = raw.Close()
					_ = srv.Close()
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					if err := m.Close(ctx, sm.DisconnectRebooting); err != nil {
						t.Error(err)
					}
					if err := <-serveDone; !errors.Is(err, diam.ErrServerClosed) {
						t.Error(err)
					}
				})
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := clientTLS.HandshakeContext(ctx); err != nil {
					t.Fatal(err)
				}
				old := renewalScriptReceive(t, accepted, "TLS physical acceptance")
				if old.TLS() == nil || old.TLS().Version != tls.VersionTLS13 {
					t.Fatal("accepted transport did not complete real TLS handshake")
				}
				if admitted {
					request := reviewCER(t)
					if _, err := request.WriteTo(clientTLS); err != nil {
						t.Fatal(err)
					}
					answer, err := diam.ReadMessage(clientTLS, dict.Default)
					if err != nil {
						t.Fatal(err)
					}
					if answer.Header.CommandCode != diam.CapabilitiesExchange || code(t, answer) != diam.Success {
						t.Fatalf("TLS admission response=%+v", answer.Header)
					}
					synctest.Wait()
					if p := m.Peers()[0]; p.State != ROpen || !p.Eligible {
						t.Fatalf("TLS admission=%+v", p)
					}
				}
				raw.reads <- restartEvent{err: &diam.TransportRestartError{AssociationID: 81, InboundStreams: 16, OutboundStreams: 16}}
				renewalScriptReceive(t, raw.closed, "TLS restart physical closure")
				synctest.Wait()
				if !old.Closed() || len(replacements) != 0 || len(accepted) != 0 || renewalScriptLifecycle(t, old).Generation() != 1 {
					t.Fatal("TLS restart retained physical connection or published a replacement")
				}
				if n, err := old.Write([]byte("stale TLS write")); n != 0 || !errors.Is(err, net.ErrClosed) {
					t.Fatalf("old TLS write escaped: n=%d error=%v", n, err)
				}
				if p := m.Peers()[0]; p.State != Closed || p.Eligible {
					t.Fatalf("TLS restart retained peer admission=%+v", p)
				}
			})
		})
	}
}

type renewalScriptWriterHold struct {
	diam.Conn
	entered, release chan struct{}
	once             sync.Once
	releaseOnce      sync.Once
	attempts         atomic.Int32
}

func (c *renewalScriptWriterHold) unblock() { c.releaseOnce.Do(func() { close(c.release) }) }

func (c *renewalScriptWriterHold) Unwrap() diam.Conn           { return c.Conn }
func (c *renewalScriptWriterHold) Write(b []byte) (int, error) { return c.WriteStream(b, 0) }
func (c *renewalScriptWriterHold) WriteStream(b []byte, stream uint) (int, error) {
	c.attempts.Add(1)
	n, err := c.Conn.WriteStream(b, stream)
	if err == nil {
		c.once.Do(func() { close(c.entered); <-c.release })
	}
	return n, err
}

func TestManagerRenewalScriptDiscardsQueuedOldWrites(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := renewalScriptNew(t, 2, false, false, nil)
		h.open(t)
		old := h.m.getSession(h.initial)
		hold := &renewalScriptWriterHold{Conn: old.c, entered: make(chan struct{}), release: make(chan struct{})}
		defer hold.unblock()
		old.c = hold
		first := outboundRequest("known.example.net", "example.net")
		first.Header.HopByHopID = 101
		if err := old.send(first, false); err != nil {
			t.Fatal(err)
		}
		if actual := h.message(t); actual.Header.HopByHopID != 101 {
			t.Fatal("first old write did not reach transport")
		}
		renewalScriptReceive(t, hold.entered, "old Manager writer held after first serialized write")
		for id := uint32(102); id <= 104; id++ {
			queued := outboundRequest("known.example.net", "example.net")
			queued.Header.HopByHopID = id
			if err := old.send(queued, false); err != nil {
				t.Fatal(err)
			}
		}
		if len(old.writes) != 3 {
			t.Fatal("old Manager writes were not explicitly queued")
		}
		h.restart()
		pair := renewalScriptReceive(t, h.pairs, "replacement while old writer remains held")
		h.feed(t, renewalScriptCER(t, "known.example.net", "fresh.example.net", 5, 222))
		h.answer(t, diam.CapabilitiesExchange, diam.Success)
		probe := h.message(t)
		if probe.Header.CommandCode != diam.DeviceWatchdog || probe.Header.CommandFlags&diam.RequestFlag == 0 {
			t.Fatal("replacement recovery probe missing")
		}
		hold.unblock()
		synctest.Wait()
		if hold.attempts.Load() != 1 || len(h.transport.writes) != 0 {
			t.Fatal("queued retired writes were submitted after retirement")
		}
		if !pair.old.Closed() || pair.next.Closed() {
			t.Fatal("discarding queued writes affected replacement")
		}
		fresh := h.m.getSession(pair.next)
		sentinel := outboundRequest("known.example.net", "fresh.example.net")
		sentinel.Header.HopByHopID = 201
		if err := fresh.send(sentinel, false); err != nil {
			t.Fatal(err)
		}
		if actual := h.message(t); actual.Header.HopByHopID != 201 {
			t.Fatalf("same physical socket did not retain replacement writer=%+v", actual.Header)
		}
	})
}

func TestManagerRenewalScriptCloseAfterPublication(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		t.Run(fmt.Sprintf("shutdown=%t", shutdown), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				entered, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				defer unblock()
				h := renewalScriptNew(t, 2, false, false, nil, renewalScriptServerOption{afterBind: func(srv *diam.Server) {
					previous := srv.OnConnectionRestart
					srv.OnConnectionRestart = func(old, next diam.Conn, reason diam.RetirementReason) {
						previous(old, next, reason)
						close(entered)
						<-release
					}
				}})
				h.open(t)
				h.restart()
				pair := renewalScriptReceive(t, h.pairs, "published replacement before first CER")
				renewalScriptReceive(t, entered, "replacement publication hook")
				h.feed(t, renewalScriptCER(t, "known.example.net", "fresh.example.net", 5, 222))
				done := make(chan error, 1)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if shutdown {
					go func() { done <- h.srv.Shutdown(ctx) }()
				} else {
					go func() { done <- h.m.Close(ctx, sm.DisconnectRebooting) }()
				}
				synctest.Wait()
				select {
				case <-h.transport.closed:
				default:
					t.Fatal("close did not seal published generation while its first CER waited")
				}
				unblock()
				if err := renewalScriptReceive(t, done, "close after replacement publication"); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				if !pair.next.Closed() || len(h.transport.writes) != 0 || h.m.Peers()[0].State != Closed || h.m.Peers()[0].Eligible {
					t.Fatal("first CER resurrected published replacement after close")
				}
			})
		})
	}
}

func TestManagerRenewalScriptShutdownAfterReplacementAdmission(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		t.Run(fmt.Sprintf("shutdown=%t", shutdown), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := renewalScriptNew(t, 2, false, false, nil)
				h.open(t)
				h.restart()
				pair := renewalScriptReceive(t, h.pairs, "replacement before local shutdown")
				h.feed(t, renewalScriptCER(t, "known.example.net", "fresh.example.net", 5, 222))
				h.answer(t, diam.CapabilitiesExchange, diam.Success)
				probe := h.message(t)
				if probe.Header.CommandCode != diam.DeviceWatchdog || probe.Header.CommandFlags&diam.RequestFlag == 0 {
					t.Fatal("replacement recovery probe missing")
				}
				done := make(chan error, 1)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if shutdown {
					go func() { done <- h.srv.Shutdown(ctx) }()
				} else {
					go func() { done <- h.m.Close(ctx, sm.DisconnectRebooting) }()
				}
				dpr := h.message(t)
				if dpr.Header.CommandCode != diam.DisconnectPeer || dpr.Header.CommandFlags&diam.RequestFlag == 0 || !pair.old.Closed() || pair.next.Closed() || renewalScriptLifecycle(t, pair.next).Generation() != 2 {
					t.Fatal("shutdown did not send DPR on the live replacement")
				}
				dpa, err := base.BuildDPA(dpr, testBase("known.example.net"))
				if err != nil {
					t.Fatal(err)
				}
				h.feed(t, dpa)
				if err := renewalScriptReceive(t, done, "replacement DPR/DPA shutdown"); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				if !pair.next.Closed() || h.m.Peers()[0].State != Closed || len(h.pairs) != 0 {
					t.Fatal("shutdown retained or replaced admitted generation")
				}
			})
		})
	}
}

type renewalScriptExceptionalOrder struct {
	renewalScriptWrapper
	manager                          *Manager
	messageError                     bool
	secondDispatched, secondAdmitted chan struct{}
}

func (h *renewalScriptExceptionalOrder) ServeDIAM(c diam.Conn, msg *diam.Message) {
	if msg.Header.HopByHopID == 101 {
		// Both messages must own Server dispatch positions before the first
		// exceptional path closes the physical connection.
		<-h.secondDispatched
		if h.messageError {
			// Invoke the actual message-error hook with a synthetic decoding
			// failure. Server's reader invokes decoder errors synchronously,
			// so this wrapper supplies two already-dispatched positions.
			_ = h.manager.HandleMessageError(c, msg, &diam.MessageError{ResultCode: diam.InvalidAVPLength})
		} else {
			h.manager.ServeDIAM(c, msg)
		}
		return
	}
	close(h.secondDispatched)
	release := msg.BeginDispatch()
	defer release()
	close(h.secondAdmitted)
}

func TestManagerRenewalScriptExceptionalObserverReleasesAdmission(t *testing.T) {
	for _, messageError := range []bool{false, true} {
		t.Run(map[bool]string{false: "unmanaged ServeDIAM", true: "sealed ingress HandleMessageError"}[messageError], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				observerEntered := make(chan diam.ProtocolErrorEvent, 1)
				observerRelease := make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(observerRelease) }) }
				defer unblock()
				ordered := &renewalScriptExceptionalOrder{messageError: messageError, secondDispatched: make(chan struct{}), secondAdmitted: make(chan struct{})}
				h := renewalScriptNew(t, 2, false, false, func(cfg *Config) {
					cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { observerEntered <- e; <-observerRelease }
				}, renewalScriptServerOption{afterBind: func(srv *diam.Server) {
					ordered.manager = srv.Handler.(*Manager)
					ordered.inner = srv.Handler
					srv.Handler = ordered
					previous := srv.OnNewConnection
					srv.OnNewConnection = func(c diam.Conn) {
						s := ordered.manager.getSession(c)
						if messageError {
							s.ingressMu.Lock()
							s.ingressClosed = true
							s.ingressMu.Unlock()
						} else {
							ordered.manager.unregister(s)
						}
						previous(c)
					}
				}})
				first, err := base.BuildDWR(dict.Default, testBase("known.example.net"), 0)
				if err != nil {
					t.Fatal(err)
				}
				first.Header.HopByHopID = 101
				second, err := base.BuildDWR(dict.Default, testBase("known.example.net"), 0)
				if err != nil {
					t.Fatal(err)
				}
				second.Header.HopByHopID = 202
				h.feed(t, first, second)
				e := renewalScriptReceive(t, observerEntered, "blocked exceptional protocol observer")
				synctest.Wait()
				if e.Conn != h.initial || !e.Closing || e.Reply != diam.ProtocolReplyNone {
					t.Fatalf("exceptional observer decision=%+v", e)
				}
				select {
				case <-ordered.secondAdmitted:
				default:
					t.Error("exceptional protocol observer retained admission and blocked later already-dispatched message")
				}
				unblock()
				renewalScriptReceive(t, ordered.secondAdmitted, "later admission after exceptional observer release")
			})
		})
	}
}
