package sm

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

type sourceListener struct {
	net.Listener
	source chan net.Addr
}

func (l sourceListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.source <- c.RemoteAddr()
	}
	return c, err
}

func TestClientTLSLocalAddress(t *testing.T) {
	for _, method := range []string{"DialNetworkTLS", "DialTLSExt"} {
		t.Run(method, func(t *testing.T) {
			srv := diamtest.NewUnstartedServer(mustNewStateMachine(t, serverSettings), dict.Default)
			source := make(chan net.Addr, 1)
			srv.Listener = sourceListener{srv.Listener, source}
			srv.StartTLS()
			defer srv.Close()
			reserve, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			local := reserve.Addr()
			if err := reserve.Close(); err != nil {
				t.Fatal(err)
			}
			cli := newLivenessClient(t)
			cli.EnableWatchdog = false
			cli.TLSConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- local test certificate
			var c diam.Conn
			if method == "DialNetworkTLS" {
				c, err = cli.DialNetworkTLS("tcp", srv.Addr, "", "", local)
			} else {
				c, err = cli.DialTLSExt("tcp", srv.Addr, "", "", 0, local)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if got := <-source; got.String() != local.String() {
				t.Fatalf("accepted source = %s, want bound address %s", got, local)
			}
		})
	}
}

func TestClientDialContextCancelCER(t *testing.T) { testClientDialContextCancelCER(t, "tcp") }

func testClientDialContextCancelCER(t *testing.T, network string) {
	before := runtime.NumGoroutine()
	ln, err := diam.MultistreamListen(network, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer closeDialTest(t, ln)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cli := newLivenessClient(t)
	cli.MaxRetransmits = 5
	cli.RetransmitInterval = 2 * time.Second
	var events atomic.Int32
	cli.OnWatchdogEvent = func(WatchdogEvent) { events.Add(1) }
	result := make(chan error, 1)
	go func() {
		c, err := cli.DialContext(ctx, network, ln.Addr().String(), nil)
		if c != nil {
			c.Close()
		}
		result <- err
	}()
	peer, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer closeDialTest(t, peer)
	if err := peer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	m, err := diam.ReadMessage(peer, dict.Default)
	if err != nil || m.Header.CommandCode != diam.CapabilitiesExchange {
		t.Fatalf("CER = %v, %v", m, err)
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("dial error = %v, want context.Canceled", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("dial did not stop within 500ms of cancellation (retransmit interval 2s)")
	}
	b := make([]byte, 4096)
	wantClose := error(io.EOF)
	if strings.HasPrefix(network, "sctp") {
		wantClose = syscall.ECONNRESET
	}
	if n, err := peer.Read(b); n != 0 || !errors.Is(err, wantClose) {
		t.Fatalf("peer read after cancellation = %d, %v, want %v", n, err, wantClose)
	}
	if events.Load() != 0 {
		t.Fatal("watchdog started for cancelled dial")
	}
	settleDialGoroutines(t, before)
}

func TestClientDialContextAlreadyCancelled(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "tcp", true: "tls"}[secure], func(t *testing.T) {
			ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer closeDialTest(t, ln)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			cli := newLivenessClient(t)
			var c diam.Conn
			if secure {
				c, err = cli.DialTLSContext(ctx, "tcp", ln.Addr().String(), "", "", nil)
			} else {
				c, err = cli.DialContext(ctx, "tcp", ln.Addr().String(), nil)
			}
			if c != nil {
				c.Close()
				t.Fatal("cancelled dial returned a connection")
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("dial = %v, want context.Canceled", err)
			}
			if err := ln.SetDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			peer, err := ln.Accept()
			if err == nil {
				closeDialTest(t, peer)
				t.Fatal("already-cancelled dial opened a connection")
			}
			var ne net.Error
			if !errors.As(err, &ne) || !ne.Timeout() {
				t.Fatalf("accept = %v", err)
			}
		})
	}
}

func TestClientDialTLSContextCancelHandshake(t *testing.T) {
	before := runtime.NumGoroutine()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer closeDialTest(t, ln)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cli := newLivenessClient(t)
	cli.TLSConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- silent local TLS peer
	result := make(chan error, 1)
	go func() {
		c, err := cli.DialTLSContext(ctx, "tcp", ln.Addr().String(), "", "", nil)
		if c != nil {
			c.Close()
		}
		result <- err
	}()
	peer, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer closeDialTest(t, peer)
	if err := peer.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := io.ReadFull(peer, b[:]); err != nil {
		t.Fatal(err)
	}
	if b[0] != 22 {
		t.Fatalf("TLS record type = %d, want handshake (22)", b[0])
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("dial = %v, want context.Canceled", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("TLS handshake ignored cancellation")
	}
	if _, err := io.Copy(io.Discard, peer); err != nil {
		t.Fatalf("peer did not observe close: %v", err)
	}
	settleDialGoroutines(t, before)
}

func settleDialGoroutines(t *testing.T, before int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > before {
		t.Fatalf("goroutines after settling = %d, before = %d", got, before)
	}
}

func TestClientDialContextSurvivesCancellation(t *testing.T) {
	testClientDialContextSurvivesCancellation(t, "tcp")
}

func testClientDialContextSurvivesCancellation(t *testing.T, network string) {
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "tcp", true: "tls"}[secure], func(t *testing.T) {
			received := make(chan struct{}, 1)
			serverSM := mustNewStateMachine(t, serverSettings)
			serverSM.HandleFunc("DWA", func(diam.Conn, *diam.Message) { received <- struct{}{} })
			srv := diamtest.NewUnstartedServerNetwork(network, serverSM, dict.Default)
			if secure {
				srv.StartTLS()
			} else {
				srv.Start()
			}
			defer srv.Close()
			cli := newLivenessClient(t)
			cli.EnableWatchdog = false
			cli.TLSConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- local test certificate
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var c diam.Conn
			var err error
			if secure {
				c, err = cli.DialTLSContext(ctx, network, srv.Addr, "", "", nil)
			} else {
				c, err = cli.DialContext(ctx, network, srv.Addr, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			cancel()
			select {
			case <-c.(diam.CloseNotifier).CloseNotify():
				t.Fatal("successful connection closed after cancelling dial context")
			case <-time.After(20 * time.Millisecond):
			}
			// A valid post-handshake message must reach the peer after cancellation.
			m := diam.NewRequest(diam.DeviceWatchdog, 0, dict.Default).Answer(diam.Success)
			mustSMClientAVP(t, m, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
			mustSMClientAVP(t, m, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
			if _, err := m.WriteTo(c); err != nil {
				t.Fatal(err)
			}
			select {
			case <-received:
			case <-time.After(time.Second):
				t.Fatal("connection stopped working after successful dial context was cancelled")
			}
		})
	}
}

func TestClientDialTLSContextCancelCER(t *testing.T) {
	received := make(chan diam.Conn, 1)
	mux := diam.NewServeMux()
	mux.HandleFunc("CER", func(c diam.Conn, _ *diam.Message) { received <- c })
	srv := diamtest.NewUnstartedServer(mux, dict.Default)
	srv.StartTLS()
	defer srv.Close()
	cli := newLivenessClient(t)
	cli.RetransmitInterval = 2 * time.Second
	cli.TLSConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- local test certificate
	var events atomic.Int32
	cli.OnWatchdogEvent = func(WatchdogEvent) { events.Add(1) }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		c, err := cli.DialTLSContext(ctx, "tcp", srv.Addr, "", "", nil)
		if c != nil {
			c.Close()
		}
		result <- err
	}()
	var peer diam.Conn
	select {
	case peer = <-received:
	case <-time.After(time.Second):
		t.Fatal("no CER")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("dial = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("TLS CER wait ignored cancellation")
	}
	select {
	case <-peer.(diam.CloseNotifier).CloseNotify():
	case <-time.After(time.Second):
		t.Fatal("TLS peer did not observe close")
	}
	if events.Load() != 0 {
		t.Fatal("watchdog started on cancelled TLS dial")
	}
}

func TestClientDialTimeoutOnlyBoundsConnect(t *testing.T) {
	for _, method := range []string{"DialTimeout", "DialExt", "DialTLSTimeout", "DialTLSExt"} {
		t.Run(method, func(t *testing.T) {
			received, release := make(chan struct{}), make(chan struct{})
			serverSM := mustNewStateMachine(t, serverSettings)
			mux := diam.NewServeMux()
			mux.HandleFunc("CER", func(c diam.Conn, m *diam.Message) { close(received); <-release; handleCER(serverSM)(c, m) })
			srv := diamtest.NewUnstartedServer(mux, dict.Default)
			if method == "DialTLSTimeout" || method == "DialTLSExt" {
				srv.StartTLS()
			} else {
				srv.Start()
			}
			defer srv.Close()
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			cli := newLivenessClient(t)
			cli.EnableWatchdog = false
			cli.RetransmitInterval = 2 * time.Second
			cli.TLSConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- local test certificate
			result := make(chan error, 1)
			go func() {
				var c diam.Conn
				var err error
				switch method {
				case "DialTimeout":
					c, err = cli.DialTimeout(srv.Addr, 20*time.Millisecond)
				case "DialExt":
					c, err = cli.DialExt("tcp", srv.Addr, 20*time.Millisecond, nil)
				case "DialTLSTimeout":
					c, err = cli.DialTLSTimeout(srv.Addr, "", "", 20*time.Millisecond)
				case "DialTLSExt":
					c, err = cli.DialTLSExt("tcp", srv.Addr, "", "", 20*time.Millisecond, nil)
				}
				if c != nil {
					c.Close()
				}
				result <- err
			}()
			select {
			case <-received:
			case <-time.After(time.Second):
				t.Fatal("no CER")
			}
			select {
			case err := <-result:
				t.Fatalf("connect timeout ended CER wait: %v", err)
			case <-time.After(60 * time.Millisecond):
			}
			unblock()
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("dial did not finish")
			}
		})
	}
}

func TestClientDialContextCancelRetransmission(t *testing.T) {
	received := make(chan struct{}, 8)
	mux := diam.NewServeMux()
	mux.HandleFunc("CER", func(diam.Conn, *diam.Message) { received <- struct{}{} })
	srv := diamtest.NewServer(mux, dict.Default)
	defer srv.Close()
	cli := newLivenessClient(t)
	cli.RetransmitInterval = 20 * time.Millisecond
	cli.MaxRetransmits = 100
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		c, err := cli.DialContext(ctx, "tcp", srv.Addr, nil)
		if c != nil {
			c.Close()
		}
		result <- err
	}()
	for range 2 {
		select {
		case <-received:
		case <-time.After(time.Second):
			t.Fatal("CER was not retransmitted")
		}
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("retransmission ignored cancellation")
	}
}

type blockedCERConn struct {
	net.Conn
	writing chan struct{}
}

func (c blockedCERConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3868}
}
func (c blockedCERConn) Write(b []byte) (int, error) { close(c.writing); return c.Conn.Write(b) }

func TestClientDialContextCancelsBlockedCERWrite(t *testing.T) {
	before := runtime.NumGoroutine()
	rw, peer := net.Pipe()
	defer closeDialTest(t, peer)
	writing := make(chan struct{})
	cli := newLivenessClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		c, err := cli.dialContext(ctx, func(activity *watchdogActivity) (diam.Conn, error) {
			return cli.server("tcp", "", nil, activity).NewConn(blockedCERConn{rw, writing})
		})
		if c != nil {
			c.Close()
		}
		result <- err
	}()
	select {
	case <-writing:
	case <-time.After(time.Second):
		t.Fatal("CER write did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("dial = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("blocked CER write ignored cancellation")
	}
	settleDialGoroutines(t, before)
}

func closeDialTest(t *testing.T, c io.Closer) {
	t.Helper()
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("close: %v", err)
	}
}

func TestClientDialContextCancelsDuringHandshakeCallback(t *testing.T) {
	entered := make(chan diam.Conn, 1)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	cfg := *clientSettings
	cfg.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { entered <- c; <-release }
	cli := newLivenessClient(t)
	cli.Handler = mustNewStateMachine(t, &cfg)
	cli.RetransmitInterval = 2 * time.Second
	srv := diamtest.NewServer(mustNewStateMachine(t, serverSettings), dict.Default)
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		c, err := cli.DialContext(ctx, "tcp", srv.Addr, nil)
		if c != nil {
			c.Close()
		}
		result <- err
	}()
	var conn diam.Conn
	select {
	case conn = <-entered:
	case <-time.After(time.Second):
		t.Fatal("handshake callback did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("dial = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("validated CEA wait ignored cancellation")
	}
	// Cancellation cannot forcibly terminate application code. Once it returns,
	// the existing handler goroutine must also finish.
	unblock()
	select {
	case <-conn.(interface{ DispatchDone() <-chan struct{} }).DispatchDone():
	case <-time.After(time.Second):
		t.Fatal("handler did not finish after callback returned")
	}
}
