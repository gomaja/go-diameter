//go:build linux

package diam_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"golang.org/x/sys/unix"
)

func TestServerDialContextConnectCancellation(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, mode := range []string{"cancel", "deadline"} {
			name := "tcp/" + mode
			if secure {
				name = "tls/" + mode
			}
			t.Run(name, func(t *testing.T) {
				// Linux admits one queued connection at backlog zero. Once filled, SYNs
				// stall locally, independent of routing or external firewall behavior.
				fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
				if err != nil {
					t.Fatal(err)
				}
				closeListener := sync.OnceFunc(func() {
					if err := unix.Close(fd); err != nil {
						t.Error(err)
					}
				})
				defer closeListener()
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
				defer func() { _ = filler.Close() }()
				ctx, cancel := context.WithCancel(context.Background())
				var timer *time.Timer
				want := error(context.Canceled)
				if mode == "deadline" {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
					want = context.DeadlineExceeded
				} else {
					timer = time.AfterFunc(100*time.Millisecond, cancel)
					defer timer.Stop()
				}
				defer cancel()
				done := make(chan error, 1)
				go func() {
					srv := &diam.Server{Network: "tcp", Addr: addr}
					var c diam.Conn
					var err error
					if secure {
						c, err = srv.DialTLSContext(ctx, "", "")
					} else {
						c, err = srv.DialContext(ctx)
					}
					if c != nil {
						c.Close()
					}
					done <- err
				}()
				select {
				case err := <-done:
					if !errors.Is(err, want) {
						t.Errorf("connect = %v, want %v", err, want)
					}
				case <-time.After(time.Second):
					t.Error("transport connect ignored context for 1s")
					closeListener()
					<-done
				}
			})
		}
	}
}
