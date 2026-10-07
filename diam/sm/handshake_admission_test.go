package sm

import (
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"strings"
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

func TestOnHandshakeCalledForEveryPeer(t *testing.T) {
	const peers = 1100
	var serverCalls, clientCalls atomic.Int32
	serverDone := make(chan struct{})
	cfg := *serverSettings
	cfg.OnHandshake = func(c diam.Conn, p *smpeer.Metadata) {
		if p == nil || p.CER == nil {
			t.Error("server callback missing CER metadata")
		}
		if serverCalls.Add(1) == peers {
			close(serverDone)
		}
	}
	srv := diamtest.NewServer(mustNewStateMachine(t, &cfg), dict.Default)
	defer srv.Close()
	clientCfg := *clientSettings
	clientCfg.OnHandshake = func(c diam.Conn, p *smpeer.Metadata) {
		if got, ok := smpeer.FromContext(c.Context()); !ok || got != p || p.CEA == nil {
			t.Error("client callback missing CEA context metadata")
		}
		clientCalls.Add(1)
	}
	cli := newLivenessClient(t)
	cli.EnableWatchdog = false
	cli.RetransmitInterval = 2 * time.Second
	cli.Handler = mustNewStateMachine(t, &clientCfg)
	for i := 0; i < peers; i++ {
		c, err := cli.Dial(srv.Addr)
		if err != nil {
			t.Fatalf("handshake %d: %v", i, err)
		}
		if got := clientCalls.Load(); got != int32(i+1) {
			t.Fatalf("Dial returned before OnHandshake: %d", got)
		}
		c.Close()
		<-c.(interface{ DispatchDone() <-chan struct{} }).DispatchDone()
	}
	// Reading CEA and closing the listener do not wait for the server callback.
	// Wait for the callbacks themselves before asserting their exact count.
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatalf("server callbacks did not complete: %d, want %d", serverCalls.Load(), peers)
	}
	if got := serverCalls.Load(); got != peers {
		t.Fatalf("server calls %d, want %d", got, peers)
	}
	if got := clientCalls.Load(); got != peers {
		t.Fatalf("client calls %d, want %d", got, peers)
	}
}

// C1 and RFC 6733 §5.6: the CEA can be read while OnHandshake is blocked,
// but no subsequent message may be admitted before the callback returns.
func TestOnHandshakeHoldsServerAdmission(t *testing.T) {
	for _, mode := range []int{0, -1} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			entered, release, dwr := make(chan struct{}), make(chan struct{}), make(chan struct{}, 1)
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			cfg := *serverSettings
			cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) { close(entered); <-release }
			cfg.OnDWR = func(diam.Conn, *diam.Message) { dwr <- struct{}{} }
			srv := diamtest.NewUnstartedServer(mustNewStateMachine(t, &cfg), dict.Default)
			srv.Config.MaxConcurrentHandlers = mode
			srv.Start()
			defer srv.Close()
			defer unblock()
			c, err := net.Dial("tcp", srv.Addr)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			if err = c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err = regressionCER(t, dict.Default, 1001).WriteTo(c); err != nil {
				t.Fatal(err)
			}
			if a, err := diam.ReadMessage(c, dict.Default); err != nil || !testResultCode(a, diam.Success) {
				t.Fatalf("CEA: %v %v", a, err)
			}
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("OnHandshake not called")
			}
			if _, err = regressionDWR(t).WriteTo(c); err != nil {
				t.Fatal(err)
			}
			select {
			case <-dwr:
				t.Fatal("DWR admitted during OnHandshake")
			case <-time.After(30 * time.Millisecond):
			}
			unblock()
			if a, err := diam.ReadMessage(c, dict.Default); err != nil || a.Header.CommandCode != diam.DeviceWatchdog || !testResultCode(a, diam.Success) {
				t.Fatalf("DWA: %v %v", a, err)
			}
		})
	}
}
func TestOnHandshakeHoldsClientAdmissionAndDial(t *testing.T) {
	for _, mode := range []int{0, -1} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			entered, release, dwr := make(chan struct{}), make(chan struct{}), make(chan struct{}, 1)
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			serverCfg := *serverSettings
			serverCfg.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) {
				if _, err := regressionDWR(t).WriteTo(c); err != nil {
					t.Errorf("peer DWR: %v", err)
				}
			}
			serverSM := mustNewStateMachine(t, &serverCfg)
			serverSM.HandleFunc("DWA", func(diam.Conn, *diam.Message) {})
			srv := diamtest.NewServer(serverSM, dict.Default)
			defer srv.Close()
			defer unblock()
			cfg := *clientSettings
			cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) { close(entered); <-release }
			cfg.OnDWR = func(diam.Conn, *diam.Message) { dwr <- struct{}{} }
			cli := newLivenessClient(t)
			cli.EnableWatchdog = false
			cli.Handler = mustNewStateMachine(t, &cfg)
			cli.RetransmitInterval = 2 * time.Second
			type result struct {
				c   diam.Conn
				err error
			}
			done := make(chan result, 1)
			go func() {
				c, err := cli.dial(func(activity *watchdogActivity) (diam.Conn, error) {
					s := cli.server("tcp", srv.Addr, nil, activity)
					s.MaxConcurrentHandlers = mode
					return s.Dial(time.Second)
				})
				done <- result{c, err}
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("client OnHandshake not called")
			}
			select {
			case got := <-done:
				if got.c != nil {
					got.c.Close()
				}
				t.Fatalf("Dial returned during callback: %v", got.err)
			case <-time.After(30 * time.Millisecond):
			}
			select {
			case <-dwr:
				t.Fatal("DWR admitted during client OnHandshake")
			default:
			}
			unblock()
			select {
			case got := <-done:
				if got.err != nil {
					t.Fatal(got.err)
				}
				defer got.c.Close()
			case <-time.After(time.Second):
				t.Fatal("Dial blocked after callback")
			}
			select {
			case <-dwr:
			case <-time.After(time.Second):
				t.Fatal("DWR blocked after callback")
			}
		})
	}
}

func TestOnHandshakeOutlastsClientRetryBudget(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	cfg := *clientSettings
	cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) { close(entered); <-release }
	srv := diamtest.NewServer(mustNewStateMachine(t, serverSettings), dict.Default)
	defer srv.Close()
	defer unblock()
	cli := newLivenessClient(t)
	cli.EnableWatchdog = false
	cli.Handler = mustNewStateMachine(t, &cfg)
	cli.RetransmitInterval = 500 * time.Millisecond
	cli.MaxRetransmits = 1
	type result struct {
		c   diam.Conn
		err error
	}
	done := make(chan result, 1)
	go func() { c, err := cli.Dial(srv.Addr); done <- result{c, err} }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("CEA was not validated")
	}
	// More than twice the complete CER retry budget, while the CEA is valid.
	select {
	case got := <-done:
		if got.c != nil {
			got.c.Close()
		}
		t.Fatalf("Dial returned during slow OnHandshake: %v", got.err)
	case <-time.After(2200 * time.Millisecond):
	}
	unblock()
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatal(got.err)
		}
		got.c.Close()
	case <-time.After(time.Second):
		t.Fatal("Dial did not complete after OnHandshake")
	}
}

func TestOnHandshakePanicCompletesDial(t *testing.T) {
	for _, mode := range []int{0, -1} {
		for _, termination := range []string{"panic", "Goexit"} {
			t.Run(fmt.Sprintf("%d/%s", mode, termination), func(t *testing.T) {
				records := logtest.New()
				accepted := make(chan diam.Conn, 1)
				serverCfg := *serverSettings
				serverCfg.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { accepted <- c }
				srv := diamtest.NewServer(mustNewStateMachine(t, &serverCfg), dict.Default)
				defer srv.Close()
				cfg := *clientSettings
				cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) {
					if termination == "Goexit" {
						runtime.Goexit()
					}
					panic("callback failed")
				}
				cli := newLivenessClient(t)
				cli.EnableWatchdog = false
				cli.Handler = mustNewStateMachine(t, &cfg)
				cli.Logger = records.Logger()
				cli.RetransmitInterval = time.Second
				done := make(chan error, 1)
				go func() {
					c, err := cli.dial(func(activity *watchdogActivity) (diam.Conn, error) {
						s := cli.server("tcp", srv.Addr, nil, activity)
						s.MaxConcurrentHandlers = mode
						return s.Dial(time.Second)
					})
					if c != nil {
						c.Close()
					}
					done <- err
				}()
				select {
				case err := <-done:
					if err == nil || !strings.Contains(err.Error(), "OnHandshake terminated") {
						t.Fatalf("panic handshake error=%v", err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("Dial hung after OnHandshake panic")
				}
				var peer diam.Conn
				select {
				case peer = <-accepted:
				case <-time.After(time.Second):
					t.Fatal("missing peer handshake")
				}
				select {
				case <-peer.(diam.CloseNotifier).CloseNotify():
				case <-time.After(time.Second):
					t.Fatal("callback panic did not close peer")
				}
				// C3: the callback owns this close even with concurrent panic recovery.
				found := false
				for _, r := range records.Records() {
					if r.Message == "sm: OnHandshake terminated; closing connection" && r.Level == slog.LevelError {
						found = true
					}
				}
				if !found {
					t.Fatalf("peer closed before callback termination record: %v", records.Records())
				}
			})
		}
	}
}
