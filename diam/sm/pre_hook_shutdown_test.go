package sm

import (
	"context"
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

func TestPreHookShutdownDeadline(t *testing.T) {
	for _, mode := range []int{0, 1, -1} {
		for _, hook := range []string{"CER", "DWR"} {
			t.Run(fmt.Sprintf("%d/%s", mode, hook), func(t *testing.T) {
				logs := logtest.New()
				cfg := testMessageErrorSettings()
				entered := make(chan diam.Conn, 1)
				release := make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				pre := func(c diam.Conn, _ *diam.Message) { entered <- c; <-release }
				if hook == "CER" {
					cfg.OnCER = pre
				} else {
					cfg.OnDWR = pre
				}
				var cea, dwa, handshake atomic.Int32
				cfg.OnCEA = func(diam.Conn, *diam.Message) { cea.Add(1) }
				cfg.OnDWA = func(diam.Conn, *diam.Message) { dwa.Add(1) }
				cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) { handshake.Add(1) }
				sm := mustNewStateMachine(t, cfg)
				srv := diamtest.NewUnstartedServer(sm, dict.Default)
				srv.Config.Logger = logs.Logger()
				srv.Config.MaxConcurrentHandlers = mode
				srv.Start()
				defer srv.Close()
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
				if hook == "DWR" {
					a, err := diam.ReadMessage(c, dict.Default)
					if err != nil || !testResultCode(a, diam.Success) {
						t.Fatalf("CEA=%v err=%v", a, err)
					}
					if _, err := regressionDWR(t).WriteTo(c); err != nil {
						t.Fatal(err)
					}
				}
				var peer diam.Conn
				select {
				case peer = <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("pre-hook not entered")
				}
				ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				defer cancel()
				if err := srv.Config.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("Shutdown=%v", err)
				}
				if !peer.Closed() {
					t.Error("Shutdown closed transport without publishing Closed")
				}
				unblock()
				select {
				case <-mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, peer).DispatchDone():
				case <-time.After(5 * time.Second):
					t.Fatal("shutdown did not finish dispatch")
				}
				var b [1]byte
				if n, err := c.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
					t.Fatalf("reply=%x err=%v, want EOF without answer", b[:n], err)
				}
				want := int32(0)
				if hook == "DWR" {
					want = 1
				}
				if cea.Load() != want || dwa.Load() != 0 || handshake.Load() != want {
					t.Errorf("OnCEA=%d OnDWA=%d OnHandshake=%d, want %d/0/%d", cea.Load(), dwa.Load(), handshake.Load(), want, want)
				}
				if hook == "CER" && admittedPeer(peer) {
					t.Error("shutdown hook published peer metadata")
				}
				for _, r := range logs.Records() {
					if r.Level >= slog.LevelError {
						t.Errorf("shutdown hook logged %s: %s", r.Level, r.Message)
					}
				}
			})
		}
	}
}
