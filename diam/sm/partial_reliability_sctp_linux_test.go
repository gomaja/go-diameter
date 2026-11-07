//go:build linux && !386

package sm

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/testutil"
	"github.com/gomaja/go-sctp"
)

func TestClientSCTPPartialReliability(t *testing.T) {
	value, err := os.ReadFile("/proc/sys/net/sctp/prsctp_enable")
	if err != nil {
		t.Fatalf("read SCTP PR-SCTP sysctl: %v", err)
	}
	if strings.TrimSpace(string(value)) != "1" {
		t.Fatalf("net.sctp.prsctp_enable = %q; need 1 so default-off checks cannot pass vacuously", strings.TrimSpace(string(value)))
	}
	for _, offer := range []bool{false, true} {
		for _, peerOffer := range []bool{false, true} {
			t.Run(fmt.Sprintf("offer=%t/peer=%t", offer, peerOffer), func(t *testing.T) {
				address, err := sctp.ResolveAddr("sctp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				listener, err := (&sctp.Config{PartialReliability: &peerOffer}).Listen("sctp", address)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = listener.Close() }()
				if err := listener.SetDeadline(time.Now().Add(testutil.SCTPTimeout)); err != nil {
					t.Fatal(err)
				}
				client := newLivenessClient(t)
				client.EnableWatchdog = false
				client.SCTPPartialReliability = offer
				ctx, cancel := context.WithTimeout(context.Background(), testutil.SCTPTimeout)
				defer cancel()
				type dialResult struct {
					conn diam.Conn
					err  error
				}
				result := make(chan dialResult, 1)
				go func() {
					conn, err := client.DialContext(ctx, "sctp", listener.Addr().String(), nil)
					result <- dialResult{conn: conn, err: err}
				}()
				received := false
				defer func() {
					cancel()
					if !received {
						dialed := <-result
						if dialed.conn != nil {
							dialed.conn.Close()
						}
					}
				}()
				raw, err := listener.AcceptSCTP()
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = raw.Close() }()
				if err := raw.SetDeadline(time.Now().Add(testutil.SCTPTimeout)); err != nil {
					t.Fatal(err)
				}
				cer, err := diam.ReadMessage(raw, client.Dict)
				if err != nil {
					t.Fatal(err)
				}
				cfg := cloneTestSettings(serverSettings2, client.Dict)
				cfg.AcctApplicationID = client.AcctApplicationID
				cea, err := base.BuildCEA(cer, baseSettings(cfg), diam.Success)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := cea.WriteTo(raw); err != nil {
					t.Fatal(err)
				}
				var dialed dialResult
				select {
				case dialed = <-result:
					received = true
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				if dialed.err != nil {
					t.Fatal(dialed.err)
				}
				defer dialed.conn.Close()
				transport, ok := dialed.conn.Connection().(*diam.SCTPConn)
				if !ok {
					t.Fatalf("client transport = %T, want *diam.SCTPConn", dialed.conn.Connection())
				}
				want := offer && peerOffer
				for _, side := range []struct {
					name string
					conn *sctp.Conn
				}{{"client", transport.Conn}, {"raw peer", raw}} {
					got, err := side.conn.PRSupported()
					if side.name == "client" {
						t.Logf("PR-SCTP association local=%s remote=%s go_offer=%t peer_offer=%t supported=%t", side.conn.LocalAddr(), side.conn.RemoteAddr(), offer, peerOffer, got)
					}
					if err != nil || got != want {
						t.Errorf("%s PRSupported() = %t, %v; want %t", side.name, got, err, want)
					}
				}
			})
		}
	}
}
