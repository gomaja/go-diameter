//go:build linux && !386

package sm

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"golang.org/x/sys/unix"
)

func TestClientDialContextCancelCERSCTP(t *testing.T) {
	testClientDialContextCancelCER(t, "sctp")
}

func TestClientDialContextTransportDeadline(t *testing.T) {
	// A backlog of zero admits one connection on Linux. Keep it queued without
	// accepting it; subsequent SYNs are dropped locally. This avoids dependence
	// on routing or firewalls for TEST-NET addresses, which may reject immediately.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if fd < 0 {
			return
		}
		if err := unix.Close(fd); err != nil {
			t.Errorf("close socket: %v", err)
		}
	}()
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(fd, 0); err != nil {
		t.Fatal(err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	addr := (&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sa.(*unix.SockaddrInet4).Port}).String()
	filler, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDialTest(t, filler)
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "tcp", true: "tls"}[secure], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			cli := newLivenessClient(t)
			start := time.Now()
			result := make(chan error, 1)
			go func() {
				var c diam.Conn
				var err error
				if secure {
					c, err = cli.DialTLSContext(ctx, "tcp", addr, "", "", nil)
				} else {
					c, err = cli.DialContext(ctx, "tcp", addr, nil)
				}
				if c != nil {
					c.Close()
				}
				result <- err
			}()
			var err error
			select {
			case err = <-result:
			case <-time.After(time.Second):
				t.Error("transport connect ignored context for 1s")
				if err := unix.Close(fd); err != nil {
					t.Error(err)
				}
				fd = -1
				<-result
				return
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("dial = %v, want context.DeadlineExceeded", err)
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("deadline took %s", elapsed)
			}
		})
	}
}

func TestSCTPHostnameContextCancellation(t *testing.T) {
	// These subtests replace net.DefaultResolver and must remain serial.
	for _, caller := range []string{"client", "server"} {
		for _, hosts := range []string{"blocked.invalid", "127.0.0.1/blocked.invalid"} {
			for _, mode := range []string{"cancel", "deadline"} {
				t.Run(caller+"/"+hosts+"/"+mode, func(t *testing.T) {
					before := runtime.NumGoroutine()
					cli := newLivenessClient(t)
					ln, err := diam.MultistreamListen("sctp4", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					_, port, err := net.SplitHostPort(ln.Addr().String())
					if err != nil {
						closeDialTest(t, ln)
						t.Fatal(err)
					}
					t.Logf("DNS cancellation listener: %s", ln.Addr())
					ctx, cancel := context.WithCancel(context.Background())
					if mode == "deadline" {
						cancel()
						ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
					}
					entered := make(chan struct{}, 1)
					release := make(chan struct{})
					var lookupMu sync.Mutex
					var lookups []<-chan struct{}
					oldResolver := net.DefaultResolver
					net.DefaultResolver = &net.Resolver{
						PreferGo: true,
						Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
							done := make(chan struct{})
							lookupMu.Lock()
							lookups = append(lookups, done)
							lookupMu.Unlock()
							defer close(done)
							select {
							case entered <- struct{}{}:
							default:
							}
							select {
							case <-ctx.Done():
								return nil, ctx.Err()
							case <-release:
								return nil, errors.New("test resolver released")
							}
						},
					}
					accepted := make(chan struct{}, 1)
					acceptDone := make(chan struct{})
					go func() {
						defer close(acceptDone)
						c, err := ln.Accept()
						if err == nil {
							closeDialTest(t, c)
							accepted <- struct{}{}
						}
					}()
					result := make(chan error, 1)
					dialDone := make(chan struct{})
					go func() {
						defer close(dialDone)
						addr := hosts + ":" + port
						var c diam.Conn
						var err error
						if caller == "client" {
							c, err = cli.DialContext(ctx, "sctp4", addr, nil)
						} else {
							srv := &diam.Server{Network: "sctp4", Addr: addr}
							c, err = srv.DialContext(ctx)
						}
						if c != nil {
							c.Close()
						}
						result <- err
					}()
					stopListening := sync.OnceFunc(func() {
						closeDialTest(t, ln)
						<-acceptDone
					})
					t.Cleanup(func() {
						cancel()
						close(release)
						stopListening()
						<-dialDone
						// Resolver cancellation can return before its DNS workers finish.
						// Let those workers settle before restoring the shared resolver.
						defer func() { net.DefaultResolver = oldResolver }()
						settleDialGoroutines(t, before)
						lookupMu.Lock()
						completed := append([]<-chan struct{}(nil), lookups...)
						lookupMu.Unlock()
						for _, done := range completed {
							<-done
						}
						select {
						case <-accepted:
							t.Error("connection attempted during cancelled hostname resolution")
						default:
						}
					})
					select {
					case <-entered:
					case err := <-result:
						t.Fatalf("dial returned before resolver blocked: %v", err)
					case <-time.After(2 * time.Second):
						t.Fatal("resolver did not start")
					}
					want := error(context.Canceled)
					if mode == "cancel" {
						cancel()
					} else {
						<-ctx.Done()
						want = context.DeadlineExceeded
					}
					select {
					case err := <-result:
						if !errors.Is(err, want) {
							t.Fatalf("dial error = %v, want %v", err, want)
						}
					case <-time.After(500 * time.Millisecond):
						t.Fatal("SCTP hostname resolution did not stop within 500ms of context completion")
					}
					stopListening()
					<-dialDone
					// Check cancellation itself releases DNS workers, before the cleanup
					// fallback releases a broken resolver implementation.
					settleDialGoroutines(t, before)
				})
			}
		}
	}
}

func TestSCTPLegacyTimeoutDoesNotBoundDNS(t *testing.T) {
	for _, caller := range []string{"client", "server"} {
		t.Run(caller, func(t *testing.T) {
			before := runtime.NumGoroutine()
			cli := newLivenessClient(t)
			entered := make(chan struct{}, 1)
			release := make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			oldResolver := net.DefaultResolver
			net.DefaultResolver = &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
					select {
					case entered <- struct{}{}:
					default:
					}
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-release:
						return nil, errors.New("test resolver released")
					}
				},
			}
			result := make(chan error, 1)
			done := make(chan struct{})
			go func() {
				defer close(done)
				var c diam.Conn
				var err error
				if caller == "client" {
					c, err = cli.DialExt("sctp4", "blocked.invalid:3868", 20*time.Millisecond, nil)
				} else {
					srv := &diam.Server{Network: "sctp4", Addr: "blocked.invalid:3868"}
					c, err = srv.Dial(20 * time.Millisecond)
				}
				if c != nil {
					c.Close()
				}
				result <- err
			}()
			t.Cleanup(func() {
				unblock()
				<-done
				defer func() { net.DefaultResolver = oldResolver }()
				settleDialGoroutines(t, before)
			})
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("resolver did not start")
			}
			select {
			case err := <-result:
				t.Fatalf("SCTP connect timeout ended DNS resolution: %v", err)
			case <-time.After(60 * time.Millisecond):
			}
			unblock()
			select {
			case err := <-result:
				var timeout net.Error
				if err == nil || (errors.As(err, &timeout) && timeout.Timeout()) {
					t.Fatalf("released resolver returned %v, want a DNS error without timeout", err)
				}
			case <-time.After(time.Second):
				t.Fatal("dial did not return after resolver was released")
			}
		})
	}
}

func TestClientDialContextSurvivesCancellationSCTP(t *testing.T) {
	testClientDialContextSurvivesCancellation(t, "sctp4")
}
