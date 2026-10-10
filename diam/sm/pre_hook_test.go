package sm

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

func TestPreHookCloseTCPInEveryWiring(t *testing.T) {
	testPreHookCloseInEveryWiring(t, "tcp", func(addr string) (net.Conn, error) {
		return net.DialTimeout("tcp", addr, 5*time.Second)
	})
}

// RFC 6733 §§5.3, 5.5 and 5.6.1: local rejection cannot advance the
// handshake or produce a watchdog answer on the closed transport.
func testPreHookCloseInEveryWiring(t *testing.T, network string, dial func(string) (net.Conn, error)) {
	for _, wiring := range []string{"direct", "unwrap", "nested", "opaque", "mux"} {
		for _, mode := range []int{0, 1, -1} {
			for _, hook := range []string{"CER", "DWR"} {
				t.Run(fmt.Sprintf("%s/%d/%s", wiring, mode, hook), func(t *testing.T) {
					logs := logtest.New()
					cfg := testMessageErrorSettings()
					var cea, dwa, handshake atomic.Int32
					cfg.OnCEA = func(diam.Conn, *diam.Message) { cea.Add(1) }
					cfg.OnDWA = func(diam.Conn, *diam.Message) { dwa.Add(1) }
					cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) { handshake.Add(1) }
					closed := make(chan diam.Conn, 1)
					closeHook := func(c diam.Conn, _ *diam.Message) { c.Close(); closed <- c }
					if hook == "CER" {
						cfg.OnCER = closeHook
					} else {
						cfg.OnDWR = closeHook
					}
					sm := mustNewStateMachine(t, cfg)
					h := admissionWiring(wiring, sm)
					if wiring == "unwrap" {
						h = plainHandlerWrapper{sm}
					}
					if wiring == "nested" {
						h = plainHandlerWrapper{plainHandlerWrapper{sm}}
					}
					srv := diamtest.NewUnstartedServerNetwork(network, h, dict.Default)
					srv.Config.Logger = logs.Logger()
					srv.Config.MaxConcurrentHandlers = mode
					srv.Start()
					defer srv.Close()
					c, err := dial(srv.Addr)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = c.Close() }()
					if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
						t.Fatal(err)
					}
					if _, err := regressionCER(t, dict.Default, 1001).WriteTo(c); err != nil {
						t.Fatal(err)
					}
					if hook == "DWR" {
						answer, err := diam.ReadMessage(c, dict.Default)
						if err != nil || !testResultCode(answer, diam.Success) {
							t.Fatalf("CEA=%v err=%v", answer, err)
						}
						if _, err := regressionDWR(t).WriteTo(c); err != nil {
							t.Fatal(err)
						}
					}
					var b [1]byte
					if n, err := c.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
						t.Fatalf("reply=%x err=%v, want EOF without answer", b[:n], err)
					}
					var peer diam.Conn
					select {
					case peer = <-closed:
					case <-time.After(5 * time.Second):
						t.Fatal("pre-hook did not close")
					}
					select {
					case <-mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, peer).DispatchDone():
					case <-time.After(5 * time.Second):
						t.Fatal("dispatch did not finish")
					}
					want := int32(0)
					if hook == "DWR" {
						want = 1
					}
					if cea.Load() != want || handshake.Load() != want || dwa.Load() != 0 {
						t.Errorf("OnCEA=%d OnHandshake=%d OnDWA=%d, want %d/%d/0", cea.Load(), handshake.Load(), dwa.Load(), want, want)
					}
					if hook == "CER" && admittedPeer(peer) {
						t.Error("closed OnCER published peer metadata")
					}
					for _, r := range logs.Records() {
						if r.Level > slog.LevelDebug {
							t.Errorf("close hook logged %s: %s", r.Level, r.Message)
						}
					}
				})
			}
		}
	}
}

func TestPreHookCloseDoesNotAdmit(t *testing.T) {
	cfg := testMessageErrorSettings()
	cfg.OnCER = func(c diam.Conn, _ *diam.Message) { c.Close() }
	sm := mustNewStateMachine(t, cfg)
	c := newHandshakeConn()
	cleanup := sm.HandleAccept(c)
	defer cleanup()
	sm.ServeDIAM(c, regressionCER(t, dict.Default, 1001))
	value, _ := sm.accepted.Load(c)
	state := value.(*acceptedHandshake)
	state.mu.Lock()
	complete := state.complete
	state.mu.Unlock()
	if complete {
		t.Error("closed OnCER completed accepted handshake")
	}
	if admittedPeer(c) {
		t.Error("closed OnCER published peer metadata")
	}
	if n := c.writeSeq.Load(); n != 0 {
		t.Errorf("closed OnCER wrote %d answers", n)
	}
}

func TestChainPreHook(t *testing.T) {
	for _, wrap := range []string{"direct", "unwrap", "opaque"} {
		for _, hook := range []string{"nil", "open", "close", "already closed"} {
			t.Run(wrap+"/"+hook, func(t *testing.T) {
				raw := newHandshakeConn()
				var c diam.Conn = raw
				if wrap == "unwrap" {
					c = unwrapTestConn{unwrapTestConn{c}}
				}
				if wrap == "opaque" {
					c = struct{ diam.Conn }{c}
				}
				var pre diam.HandlerFunc
				calls := 0
				if hook == "already closed" {
					c.Close()
				}
				if hook != "nil" && hook != "already closed" {
					pre = func(c diam.Conn, _ *diam.Message) {
						calls++
						if hook == "close" {
							c.Close()
						}
					}
				}
				next := 0
				chainPreHook(pre, func(diam.Conn, *diam.Message) { next++ })(c, nil)
				wantPre, wantNext := 1, 1
				if hook == "nil" || hook == "already closed" {
					wantPre = 0
				}
				if hook == "close" || hook == "already closed" {
					wantNext = 0
				}
				if calls != wantPre || next != wantNext {
					t.Fatalf("pre=%d next=%d, want %d/%d", calls, next, wantPre, wantNext)
				}
			})
		}
	}
}

func TestPreHookHandshakeTimeoutInEveryWiring(t *testing.T) {
	for _, wiring := range stateMachineWrappers {
		for _, mode := range []int{0, 1, -1} {
			t.Run(fmt.Sprintf("%s/%d", wiring.name, mode), func(t *testing.T) {
				logs := logtest.New()
				cfg := testMessageErrorSettings()
				cfg.HandshakeTimeout = time.Hour
				entered := make(chan diam.Conn, 1)
				release := make(chan struct{})
				var sm *StateMachine
				cfg.OnCER = func(c diam.Conn, _ *diam.Message) {
					entered <- c
					// Expire the real handshake timer only after the hook starts.
					value, ok := sm.accepted.Load(c)
					if !ok {
						t.Error("missing accepted handshake")
						c.Close()
						return
					}
					value.(*acceptedHandshake).timer.Reset(0)
					<-release
				}
				var cea, handshake atomic.Int32
				cfg.OnCEA = func(diam.Conn, *diam.Message) { cea.Add(1) }
				cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) { handshake.Add(1) }
				sm = mustNewStateMachine(t, cfg)
				srv := diamtest.NewUnstartedServer(wiring.wrap(sm), dict.Default)
				srv.Config.Logger = logs.Logger()
				srv.Config.MaxConcurrentHandlers = mode
				srv.Start()
				defer srv.Close()
				// Release the handler before closing the server on any failed assertion.
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				defer unblock()
				c, err := net.DialTimeout("tcp", srv.Addr, 5*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = c.Close() }()
				if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				if _, err := regressionCER(t, dict.Default, 1001).WriteTo(c); err != nil {
					t.Fatal(err)
				}
				var peer diam.Conn
				select {
				case peer = <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("OnCER not entered")
				}
				// The actual timer closes the socket while OnCER is still running.
				var b [1]byte
				if n, err := c.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
					t.Fatalf("timeout reply=%x err=%v", b[:n], err)
				}
				unblock()
				select {
				case <-mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, peer).DispatchDone():
				case <-time.After(5 * time.Second):
					t.Fatal("timeout did not finish dispatch")
				}
				if cea.Load() != 0 || handshake.Load() != 0 || admittedPeer(peer) {
					t.Fatalf("expired hook: OnCEA=%d OnHandshake=%d admitted=%t", cea.Load(), handshake.Load(), admittedPeer(peer))
				}
				// The timer owns the only warning. Continuing into handleCER would
				// build a CEA and emit a second warning after trying to admit the peer.
				warnings := 0
				for _, r := range logs.Records() {
					if r.Level == slog.LevelWarn && r.Message == "sm: handshake timeout; closing connection" {
						warnings++
					} else if r.Level > slog.LevelDebug {
						t.Errorf("expired pre-hook continued processing: %s: %s", r.Level, r.Message)
					}
				}
				if warnings != 1 {
					t.Errorf("handshake timer warnings=%d, want 1", warnings)
				}
			})
		}
	}
}
