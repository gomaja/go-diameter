//go:build linux && !386

package peer

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/testutil"
	"github.com/gomaja/go-sctp"
)

func TestManagerSCTPPartialReliability(t *testing.T) {
	value, err := os.ReadFile("/proc/sys/net/sctp/prsctp_enable")
	if err != nil {
		t.Fatalf("read SCTP PR-SCTP sysctl: %v", err)
	}
	if strings.TrimSpace(string(value)) != "1" {
		t.Fatalf("net.sctp.prsctp_enable = %q; need 1 so default-off checks cannot pass vacuously", strings.TrimSpace(string(value)))
	}
	for _, customDial := range []bool{false, true} {
		for _, offer := range []bool{false, true} {
			for _, peerOffer := range []bool{false, true} {
				t.Run(fmt.Sprintf("custom-dial=%t/offer=%t/peer=%t", customDial, offer, peerOffer), func(t *testing.T) {
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
					actualOffer := offer
					config := Config{Settings: testSettings("local.example.net")}
					if customDial {
						actualOffer = !offer
						config.Dial = func(ctx context.Context, endpoint Endpoint) (net.Conn, error) {
							address, err := sctp.ResolveAddr(endpoint.Network, endpoint.Address)
							if err != nil {
								return nil, err
							}
							raw, err := (&sctp.Config{PartialReliability: &actualOffer}).Dial(ctx, endpoint.Network, nil, address)
							if err != nil {
								return nil, err
							}
							wrapped, err := diam.NewSCTPConn(raw)
							if err != nil {
								_ = raw.Close()
							}
							return wrapped, err
						}
					}
					manager, err := New(config)
					if err != nil {
						t.Fatal(err)
					}
					defer closeManager(t, manager, nil)
					if err := manager.AddPeer(PeerConfig{Host: "known.example.net", NoAutoReconnect: true, Endpoints: []Endpoint{{Network: "sctp", Address: listener.Addr().String(), SCTPPartialReliability: offer}}}); err != nil {
						t.Fatal(err)
					}
					if err := manager.Start(context.Background()); err != nil {
						t.Fatal(err)
					}
					raw, err := listener.AcceptSCTP()
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = raw.Close() }()
					if err := raw.SetDeadline(time.Now().Add(testutil.SCTPTimeout)); err != nil {
						t.Fatal(err)
					}
					cer, err := diam.ReadMessage(raw, manager.dictionary())
					if err != nil {
						t.Fatal(err)
					}
					cea := correlationCEA(t, cer, "known.example.net")
					if _, err := cea.WriteTo(raw); err != nil {
						t.Fatal(err)
					}
					awaitState(t, manager, IOpen)
					manager.mu.RLock()
					var dialed diam.Conn
					for conn := range manager.sessions {
						dialed = conn
					}
					count := len(manager.sessions)
					manager.mu.RUnlock()
					if count != 1 {
						t.Fatalf("manager sessions = %d, want 1", count)
					}
					transport, ok := dialed.Connection().(*diam.SCTPConn)
					if !ok {
						t.Fatalf("manager transport = %T, want *diam.SCTPConn", dialed.Connection())
					}
					want := actualOffer && peerOffer
					for _, side := range []struct {
						name string
						conn *sctp.Conn
					}{{"manager", transport.Conn}, {"raw peer", raw}} {
						got, err := side.conn.PRSupported()
						if side.name == "manager" {
							t.Logf("PR-SCTP association local=%s remote=%s go_offer=%t peer_offer=%t supported=%t", side.conn.LocalAddr(), side.conn.RemoteAddr(), actualOffer, peerOffer, got)
						}
						if err != nil || got != want {
							t.Errorf("%s PRSupported() = %t, %v; want %t", side.name, got, err, want)
						}
					}
					if err := raw.Close(); err != nil {
						t.Fatal(err)
					}
					awaitState(t, manager, Closed)
				})
			}
		}
	}
}
