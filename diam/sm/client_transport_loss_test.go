package sm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

func TestClientEOFWhileFirstCERWriterCompletes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		retries uint
		failure error
	}{{"success-timeout", 0, nil}, {"success-retry", 1, nil}, {"failed-write", 0, &net.OpError{Op: "write", Net: "tcp", Err: errors.New("synthetic held CER failure")}}} {
		t.Run(tc.name, func(t *testing.T) {
			const interval = time.Hour
			release := make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			defer unblock()
			p := newClientCoreTCPDial(t, func(cli *Client) {
				cli.RetransmitInterval, cli.MaxRetransmits = interval, tc.retries
			}, func(cli *Client, addr string) (diam.Conn, error) {
				rw, err := net.Dial("tcp", addr)
				if err != nil {
					return nil, err
				}
				return cli.NewConn(&clientPublishedCERFailureConn{Conn: rw, release: release, failure: tc.failure}, addr)
			})
			var state *acceptedHandshake
			p.client.Handler.cores.Range(func(_, value any) bool { state = value.(*acceptedHandshake); return false })
			if state == nil {
				t.Fatal("missing selected CER core")
			}
			closeDialTest(t, p.peer)
			deadline := time.Now().Add(10 * time.Second)
			for {
				if _, retained := p.client.Handler.cores.Load(state.conn); !retained {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("real lifecycle watcher did not consume EOF")
				}
				runtime.Gosched()
			}
			select {
			case result := <-p.dialed:
				t.Fatalf("EOF returned before first writer completed: %+v", result)
			default:
			}
			if timer := state.snapshot().Timer(protocol.RetryTimer); timer.Token != 0 {
				t.Fatal("response timer armed before the first CER writer completed")
			}
			unblock()
			if tc.failure == nil {
				timer := awaitClientRetryTimer(t, state, 0)
				expireClientResponseWindow(t, state, timer)
			}
			result := p.dialResult(t)
			if tc.failure != nil {
				if !errors.Is(result.err, tc.failure) {
					t.Fatalf("first writer error = %v; want writer error %v", result.err, tc.failure)
				}
			} else {
				if tc.retries == 0 && result.err != ErrHandshakeTimeout || tc.retries != 0 && !errors.Is(result.err, net.ErrClosed) {
					t.Fatalf("EOF after successful held writer = %v", result.err)
				}
			}
		})
	}
}

// EOF preserves the current CER response window. Its deadline either reports
// handshake timeout or selects the next write when retransmissions remain.
func TestClientPeerEOFResponseWindow(t *testing.T)     { testClientPeerEOFResponseWindow(t, "tcp") }
func TestClientPeerEOFResponseWindowSCTP(t *testing.T) { testClientPeerEOFResponseWindow(t, "sctp") }

func testClientPeerEOFResponseWindow(t *testing.T, network string) {
	t.Helper()
	for _, tc := range []struct{ retries, successful uint }{{0, 1}, {1, 1}, {3, 1}, {1, 2}, {3, 4}} {
		t.Run(fmt.Sprintf("budget%d/written%d", tc.retries, tc.successful), func(t *testing.T) {
			const interval = time.Hour
			cli := newLivenessClient(t)
			cli.EnableWatchdog = false
			cli.RetransmitInterval, cli.MaxRetransmits = interval, tc.retries
			logs := logtest.New()
			cli.Logger = logs.Logger()
			events := make(chan diam.ProtocolErrorEvent, 8)
			cli.Handler.cfg.OnProtocolError = func(event diam.ProtocolErrorEvent) { events <- event }
			listener, err := diam.MultistreamListen(network, "127.0.0.1:0")
			if err != nil {
				if network == "sctp" {
					t.Skipf("SCTP not available: %v", err)
				}
				t.Fatal(err)
			}
			defer closeDialTest(t, listener)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				var conn diam.Conn
				var err error
				conn, err = cli.DialContext(ctx, network, listener.Addr().String(), nil)
				if conn != nil {
					conn.Close()
				}
				done <- err
			}()
			type accepted struct {
				conn net.Conn
				err  error
			}
			accept := make(chan accepted)
			stopAccept := make(chan struct{})
			defer close(stopAccept)
			go func() {
				conn, err := listener.Accept()
				select {
				case accept <- accepted{conn, err}:
				case <-stopAccept:
					if conn != nil {
						_ = conn.Close()
					}
				}
			}()
			var peer net.Conn
			select {
			case result := <-accept:
				if result.err != nil {
					t.Fatal(result.err)
				}
				peer = result.conn
			case result := <-done:
				t.Fatalf("Dial returned before transport acceptance: %v", result)
			case <-time.After(10 * time.Second):
				t.Fatal("Dial did not open its transport")
			}
			defer closeDialTest(t, peer)
			if err := peer.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			cer, err := diam.ReadMessage(peer, cli.Dict)
			if err != nil {
				t.Fatal(err)
			}

			var state *acceptedHandshake
			cli.Handler.cores.Range(func(_, value any) bool { state = value.(*acceptedHandshake); return false })
			if state == nil {
				t.Fatal("CER did not select a connection core")
			}
			timer := awaitClientRetryTimer(t, state, 0)
			for attempt := uint(1); attempt < tc.successful; attempt++ {
				state.apply(protocol.Input{Kind: protocol.TimerExpired, Timer: protocol.RetryTimer, Token: timer.Token, At: timer.Deadline})
				retry, err := diam.ReadMessage(peer, cli.Dict)
				if err != nil || retry.Header.HopByHopID != cer.Header.HopByHopID || retry.Header.EndToEndID != cer.Header.EndToEndID {
					t.Fatalf("CER retry = %v, %v", retry, err)
				}
				timer = awaitClientRetryTimer(t, state, timer.Token)
			}
			closeDialTest(t, peer)
			if !clientStartupCheckpointForTest(state) {
				t.Fatal("lifecycle watcher did not consume EOF")
			}
			if state.snapshot().Phase() != protocol.WaitCEA || state.snapshot().Timer(protocol.RetryTimer) != timer {
				t.Fatal("EOF changed the published CER response window")
			}
			select {
			case result := <-done:
				t.Fatalf("EOF completed handshake before its response deadline: %v", result)
			default:
			}
			expireClientResponseWindow(t, state, timer)
			var result error
			select {
			case result = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("EOF lost handshake completion")
			}

			if tc.successful == tc.retries+1 {
				if result != ErrHandshakeTimeout {
					t.Errorf("EOF handshake error = %v; want ErrHandshakeTimeout", result)
				}
				e := protocolEvent(t, events)
				assertProtocolEvent(t, e, e.Conn, nil, diam.ProtocolHandshakeTimeout, 0, true, diam.ProtocolReplyNone, 0)
				records := logs.Records()
				if len(records) != 1 || records[0].Level != slog.LevelWarn || records[0].Message != "sm: CEA timeout; closing connection" || !errors.Is(logError(records[0]), ErrHandshakeTimeout) {
					t.Errorf("EOF timeout records = %v", records)
				}
			} else {
				if !errors.Is(result, net.ErrClosed) {
					t.Errorf("EOF retry error = %v; want native write error", result)
				}
				select {
				case event := <-events:
					t.Errorf("EOF retry notified %+v", event)
				default:
				}
				if records := logs.Records(); len(records) != 0 {
					t.Errorf("EOF retry records = %v; want none", records)
				}
			}
		})
	}
}

// RetryTimer publication is the successful CER writer's completion boundary.
func awaitClientRetryTimer(t *testing.T, state *acceptedHandshake, previous uint64) protocol.TimerSnapshot {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		timer := state.snapshot().Timer(protocol.RetryTimer)
		if timer.Token != 0 && timer.Token != previous {
			return timer
		}
		if time.Now().After(deadline) {
			t.Fatal("CER writer did not publish its response timer")
		}
		runtime.Gosched()
	}
}

func expireClientResponseWindow(t *testing.T, state *acceptedHandshake, timer protocol.TimerSnapshot) {
	t.Helper()
	state.apply(protocol.Input{Kind: protocol.TimerExpired, Timer: protocol.RetryTimer, Token: timer.Token, At: timer.Deadline.Add(-time.Nanosecond)})
	if state.snapshot().Phase() != protocol.WaitCEA || state.snapshot().Timer(protocol.RetryTimer) != timer {
		t.Fatal("response window completed before its published deadline")
	}
	state.apply(protocol.Input{Kind: protocol.TimerExpired, Timer: protocol.RetryTimer, Token: timer.Token, At: timer.Deadline})
}
