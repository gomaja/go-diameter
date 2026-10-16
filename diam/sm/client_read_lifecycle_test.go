package sm

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/internal/transport"
)

type clientReadPair struct {
	client   *Client
	peer     diam.Conn
	conn     diam.Conn
	requests chan *diam.Message
	dialed   chan protocolClientDialResult
	logs     *logtest.Recorder
	events   chan diam.ProtocolErrorEvent
}

// The peer runs only a wire CER/CEA exchange and records subsequent requests.
// Both transports use the public Client dial methods and the native reader.
func newClientReadPair(t *testing.T, network string, answer bool, mode int, configure func(*Client)) *clientReadPair {
	t.Helper()
	p := &clientReadPair{client: newLivenessClient(t), requests: make(chan *diam.Message, 8), dialed: make(chan protocolClientDialResult, 1), logs: logtest.New(), events: make(chan diam.ProtocolErrorEvent, 8)}
	p.client.Logger = p.logs.Logger()
	p.client.Handler.cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) { p.events <- e }
	p.client.AcctApplicationID = nil
	p.client.AuthApplicationID = []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4))}
	p.client.WatchdogInterval = time.Hour
	p.client.RetransmitInterval = time.Hour
	if configure != nil {
		configure(p.client)
	}
	peers := make(chan diam.Conn, 1)
	srv := diamtest.NewUnstartedServer(diam.HandlerFunc(func(c diam.Conn, m *diam.Message) {
		if m.Header.CommandCode == diam.CapabilitiesExchange {
			peers <- c
			if answer {
				if _, err := protocolClientCEA(m, diam.Success).WriteTo(c); err != nil {
					t.Error(err)
				}
			}
			return
		}
		p.requests <- m
	}), p.client.Dict)
	if network == "tls" {
		srv.StartTLS()
		p.client.TLSConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- local test certificate
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)
	go func() {
		var c diam.Conn
		var err error
		if mode != 0 {
			c, err = p.client.dial(func(activity *watchdogActivity) (diam.Conn, error) {
				template := p.client.server("tcp", srv.Addr, nil, activity)
				template.MaxConcurrentHandlers = mode
				if network == "tls" {
					return template.DialTLS("", "", 0)
				}
				return template.Dial(0)
			})
		} else if network == "tls" {
			c, err = p.client.DialTLS(srv.Addr, "", "")
		} else {
			c, err = p.client.Dial(srv.Addr)
		}
		p.dialed <- protocolClientDialResult{conn: c, err: err}
	}()
	select {
	case p.peer = <-peers:
	case <-time.After(10 * time.Second):
		t.Fatal("peer did not receive CER")
	}
	return p
}

func (p *clientReadPair) admit(t *testing.T) *acceptedHandshake {
	t.Helper()
	select {
	case result := <-p.dialed:
		if result.err != nil || result.conn == nil {
			t.Fatalf("Dial = %+v", result)
		}
		p.conn = result.conn
	case <-time.After(10 * time.Second):
		t.Fatal("Dial did not complete")
	}
	t.Cleanup(p.conn.Close)
	state := p.client.Handler.acceptedCore(p.conn, nil, false)
	if state == nil {
		t.Fatal("admitted client has no core")
	}
	return state
}

func awaitReadCondition(t *testing.T, condition func() bool, description string) {
	t.Helper()
	until := time.Now().Add(10 * time.Second)
	for !condition() {
		if time.Now().After(until) {
			t.Fatal(description)
		}
		runtime.Gosched()
	}
}

func clientReadDone(t *testing.T, c diam.Conn) <-chan struct{} {
	t.Helper()
	done, ok := transport.ReadDone(c)
	if !ok {
		t.Fatal("native connection does not expose its private read signal")
	}
	return done
}

func TestClientPeerEOFWhileHandlerRuns(t *testing.T) {
	for _, network := range []string{"tcp", "tls"} {
		for _, mode := range []int{0, 2, -1} {
			t.Run(fmt.Sprintf("%s/handlers%d", network, mode), func(t *testing.T) {
				entered, release, delivered := make(chan struct{}), make(chan struct{}), make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				defer unblock()
				p := newClientReadPair(t, network, true, mode, func(c *Client) {
					c.Handler.Handle("ALL", diam.HandlerFunc(func(_ diam.Conn, m *diam.Message) {
						close(entered)
						<-release
						if m.Header.HopByHopID != 123 || m.Header.EndToEndID != 456 {
							t.Error("decoded message changed during EOF")
						}
						close(delivered)
					}))
				})
				state := p.admit(t)
				done := clientReadDone(t, p.conn)
				dispatchDone := mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, p.conn).DispatchDone()
				message := diam.NewMessage(999, 0, 1001, 123, 456, p.client.Dict)
				if _, err := message.WriteTo(p.peer); err != nil {
					t.Fatal(err)
				}
				protocolGenerationAwait(t, entered)
				closeDialTest(t, p.peer.Connection())
				if mode == 0 {
					// The reader cannot observe EOF until this callback returns.
					select {
					case <-done:
						t.Fatal("read signal overtook the sequential callback")
					default:
					}
				} else {
					protocolGenerationAwait(t, done)
					protocolGenerationAwait(t, state.watchdogState().exited)
				}
				if p.conn.Closed() {
					t.Error("EOF published Closed before callback completion")
				}
				select {
				case <-dispatchDone:
					t.Fatal("EOF completed dispatch before callback completion")
				default:
				}
				if _, retained := p.client.Handler.cores.Load(p.conn); !retained {
					t.Fatal("EOF discarded the draining core")
				}
				unblock()
				protocolGenerationAwait(t, delivered)
				protocolGenerationAwait(t, done)
				protocolGenerationAwait(t, dispatchDone)
				awaitReadCondition(t, func() bool { _, retained := p.client.Handler.cores.Load(p.conn); return !retained }, "drained core was retained")
			})
		}
	}
}

func TestClientReadSignalOnPeerEOF(t *testing.T) {
	for _, network := range []string{"tcp", "tls"} {
		t.Run(network, func(t *testing.T) {
			p := newClientReadPair(t, network, true, 0, nil)
			state := p.admit(t)
			done := clientReadDone(t, p.conn)
			closeDialTest(t, p.peer.Connection())
			protocolGenerationAwait(t, done)
			protocolGenerationAwait(t, state.watchdogState().exited)
			protocolGenerationAwait(t, mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, p.conn).DispatchDone())
		})
	}
}

func TestClientCloseNotifyWhileSequentialHandlerRuns(t *testing.T) {
	for _, network := range []string{"tcp", "tls"} {
		t.Run(network, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			defer unblock()
			p := newClientReadPair(t, network, true, 0, func(c *Client) {
				c.Handler.Handle("ALL", diam.HandlerFunc(func(diam.Conn, *diam.Message) { close(entered); <-release }))
			})
			state := p.admit(t)
			if _, err := diam.NewMessage(999, 0, 4, 123, 456, p.client.Dict).WriteTo(p.peer); err != nil {
				t.Fatal(err)
			}
			protocolGenerationAwait(t, entered)
			gone := mustConnAs[diam.CloseNotifier](t, p.conn).CloseNotify()
			closeDialTest(t, p.peer.Connection())
			protocolGenerationAwait(t, gone)
			protocolGenerationAwait(t, state.watchdogState().exited)
			if p.conn.Closed() {
				t.Fatal("public EOF notification published Closed before callback completion")
			}
			unblock()
			protocolGenerationAwait(t, mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, p.conn).DispatchDone())
		})
	}
}

func TestClientReadEOFWithSaturatedDispatch(t *testing.T) {
	for _, network := range []string{"tcp", "tls"} {
		t.Run(network, func(t *testing.T) {
			first, second := make(chan struct{}), make(chan struct{})
			unblockFirst, unblockSecond := sync.OnceFunc(func() { close(first) }), sync.OnceFunc(func() { close(second) })
			defer unblockFirst()
			defer unblockSecond()
			entered := make(chan uint32, 2)
			p := newClientReadPair(t, network, true, 1, func(c *Client) {
				c.Handler.Handle("ALL", diam.HandlerFunc(func(_ diam.Conn, m *diam.Message) {
					entered <- m.Header.HopByHopID
					if m.Header.HopByHopID == 123 {
						<-first
					} else {
						<-second
					}
				}))
			})
			state := p.admit(t)
			done := clientReadDone(t, p.conn)
			for _, hop := range []uint32{123, 124} {
				if _, err := diam.NewMessage(999, 0, 4, hop, 456, p.client.Dict).WriteTo(p.peer); err != nil {
					t.Fatal(err)
				}
				if hop == 123 {
					select {
					case got := <-entered:
						if got != hop {
							t.Fatal("second callback overtook first")
						}
					case <-time.After(10 * time.Second):
						t.Fatal("first callback did not start")
					}
				}
			}
			closeDialTest(t, p.peer.Connection())
			select {
			case <-done:
				t.Fatal("EOF overtook occupied dispatch capacity")
			default:
			}
			unblockFirst()
			select {
			case got := <-entered:
				if got != 124 {
					t.Fatalf("second callback = %d", got)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("second decoded callback was lost")
			}
			protocolGenerationAwait(t, done)
			protocolGenerationAwait(t, state.watchdogState().exited)
			if p.conn.Closed() {
				t.Fatal("EOF published Closed before final callback drained")
			}
			unblockSecond()
			protocolGenerationAwait(t, mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, p.conn).DispatchDone())
		})
	}
}

func TestClientDisconnectPeerEOF(t *testing.T) {
	for _, network := range []string{"tcp", "tls"} {
		t.Run(network, func(t *testing.T) {
			p := newClientReadPair(t, network, true, 0, nil)
			p.admit(t)
			result := make(chan error, 1)
			go func() { result <- p.client.Handler.Disconnect(p.conn, DisconnectBusy, time.Hour) }()
			select {
			case request := <-p.requests:
				if request.Header.CommandCode != diam.DisconnectPeer || request.Header.CommandFlags&diam.RequestFlag == 0 {
					t.Fatalf("expected DPR, got %+v", request.Header)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Disconnect did not send DPR")
			}
			closeDialTest(t, p.peer.Connection())
			select {
			case err := <-result:
				if !errors.Is(err, ErrDisconnectClosed) {
					t.Fatalf("Disconnect = %v, want ErrDisconnectClosed", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Disconnect did not observe peer EOF")
			}
		})
	}
}

func TestClientDisconnectWhileReaderIsOccupied(t *testing.T) {
	for _, network := range []string{"tcp", "tls"} {
		for _, expire := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/timeout%t", network, expire), func(t *testing.T) {
				entered, release := make(chan struct{}), make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				defer unblock()
				p := newClientReadPair(t, network, true, 0, func(c *Client) {
					c.Handler.Handle("ALL", diam.HandlerFunc(func(diam.Conn, *diam.Message) { close(entered); <-release }))
				})
				state := p.admit(t)
				if _, err := diam.NewMessage(999, 0, 4, 123, 456, p.client.Dict).WriteTo(p.peer); err != nil {
					t.Fatal(err)
				}
				protocolGenerationAwait(t, entered)
				result := make(chan error, 1)
				go func() { result <- p.client.Handler.Disconnect(p.conn, DisconnectBusy, time.Hour) }()
				select {
				case request := <-p.requests:
					if request.Header.CommandCode != diam.DisconnectPeer || request.Header.CommandFlags&diam.RequestFlag == 0 {
						t.Fatalf("expected DPR, got %+v", request.Header)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("Disconnect did not send DPR while callback ran")
				}
				closeDialTest(t, p.peer.Connection())
				select {
				case err := <-result:
					t.Fatalf("Disconnect completed before the reader could observe EOF: %v", err)
				default:
				}
				want := ErrDisconnectClosed
				if expire {
					timer := state.snapshot().Timer(protocol.ClosingTimer)
					if timer.Token == 0 {
						t.Fatal("Disconnect did not retain its deadline")
					}
					state.apply(protocol.Input{Kind: protocol.TimerExpired, Timer: protocol.ClosingTimer, Token: timer.Token, At: timer.Deadline})
					want = ErrDisconnectTimeout
				} else {
					unblock()
				}
				select {
				case err := <-result:
					if err != want {
						t.Fatalf("Disconnect = %v, want %v", err, want)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("Disconnect lost its terminal result")
				}
				unblock()
			})
		}
	}
}

type clientSignalConn struct {
	*watchdogProbeConn
	transport.Signal
	notifyCalls atomic.Int32
}

func (c *clientSignalConn) CloseNotify() <-chan struct{} {
	c.notifyCalls.Add(1)
	return c.closed
}
func (c *clientSignalConn) DispatchDone() <-chan struct{} { return c.closed }

func TestClientSupervisionUsesReadSignal(t *testing.T) {
	cli := newLivenessClient(t)
	cli.WatchdogInterval = time.Hour
	c := &clientSignalConn{watchdogProbeConn: newWatchdogProbeConn()}
	c.Signal = func() <-chan struct{} { return c.closed }
	primeClientTestCore(t, cli, c)
	result := make(chan error, 1)
	go func() { result <- cli.Handler.Disconnect(c, DisconnectBusy, time.Hour) }()
	select {
	case <-c.writes:
	case <-time.After(10 * time.Second):
		t.Fatal("Disconnect did not publish DPR")
	}
	awaitReadCondition(t, func() bool {
		state := cli.Handler.acceptedCore(c, nil, false)
		return state != nil && state.snapshot().Phase() == protocol.Closing
	}, "Disconnect did not enter Closing")
	c.Close()
	select {
	case err := <-result:
		if err != ErrDisconnectClosed {
			t.Fatalf("Disconnect = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Disconnect did not observe read signal")
	}
	if calls := c.notifyCalls.Load(); calls != 0 {
		t.Fatalf("library supervision called public CloseNotify %d times", calls)
	}
}

func TestClientHandshakePeerEOFResponseWindow(t *testing.T) {
	for _, network := range []string{"tcp", "tls"} {
		for _, retries := range []uint{0, 1} {
			t.Run(fmt.Sprintf("%s/retries%d", network, retries), func(t *testing.T) {
				p := newClientReadPair(t, network, false, 0, func(c *Client) { c.MaxRetransmits = retries })
				var state *acceptedHandshake
				p.client.Handler.cores.Range(func(_, value any) bool { state = value.(*acceptedHandshake); return false })
				if state == nil {
					t.Fatal("waiting handshake has no core")
				}
				t.Cleanup(state.conn.Close)
				timer := awaitClientRetryTimer(t, state, 0)
				closeDialTest(t, p.peer.Connection())
				if !clientStartupCheckpointForTest(state) {
					t.Fatal("lifecycle watcher did not consume EOF")
				}
				if state.snapshot().Phase() != protocol.WaitCEA || state.snapshot().Timer(protocol.RetryTimer) != timer {
					t.Fatal("EOF changed the successful CER response interval")
				}
				select {
				case result := <-p.dialed:
					t.Fatalf("EOF completed handshake before response expiry: %+v", result)
				default:
				}
				if len(p.logs.Records()) != 0 || len(p.events) != 0 {
					t.Fatal("EOF emitted a premature handshake observation")
				}
				expireClientResponseWindow(t, state, timer)
				select {
				case result := <-p.dialed:
					if retries == 0 && result.err != ErrHandshakeTimeout || retries != 0 && !errors.Is(result.err, net.ErrClosed) {
						t.Fatalf("handshake after EOF = %v", result.err)
					}
					if retries == 0 {
						event := protocolEvent(t, p.events)
						assertProtocolEvent(t, event, state.conn, nil, diam.ProtocolHandshakeTimeout, 0, true, diam.ProtocolReplyNone, 0)
						records := p.logs.Records()
						if len(records) != 1 || records[0].Level != slog.LevelWarn || records[0].Message != "sm: CEA timeout; closing connection" || !errors.Is(logError(records[0]), ErrHandshakeTimeout) {
							t.Fatalf("timeout logs = %v", records)
						}
					} else if len(p.events) != 0 || len(p.logs.Records()) != 0 {
						t.Fatal("failed retry emitted a timeout observation")
					}

				case <-time.After(10 * time.Second):
					t.Fatal("handshake did not complete at response expiry")
				}
			})
		}
	}
}
