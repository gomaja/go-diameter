//go:build linux && !386

package diam

import (
	"context"
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/internal/testutil"
	"github.com/gomaja/go-sctp"
)

func TestSCTPPartialReliabilityTLSListener(t *testing.T) {
	requirePRSCTPDefault(t)
	cert := generationCertificate(t)
	for _, offer := range []bool{false, true} {
		for _, peerOffer := range []bool{false, true} {
			t.Run(fmt.Sprintf("offer=%t/peer=%t", offer, peerOffer), func(t *testing.T) {
				srv := &Server{Network: "sctp4", Addr: "127.0.0.1:0", SCTPPartialReliability: offer,
					TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13,
						GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }}}
				addr, accepted := startPRSCTPServer(t, srv, func() error { return srv.ListenAndServeTLS("", "") })
				ra, err := sctp.ResolveAddr("sctp4", addr.String())
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), testutil.SCTPTimeout)
				defer cancel()
				peer, err := (&sctp.Config{PartialReliability: &peerOffer}).Dial(ctx, "sctp4", nil, ra)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = peer.Close() }()
				client := tls.Client(peer, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) // #nosec G402 -- synthetic local certificate
				if err := client.HandshakeContext(ctx); err != nil {
					t.Fatal(err)
				}
				select {
				case c := <-accepted:
					defer c.Close()
					wantPRSCTP(t, rawPRSCTPConn(c.Connection()), peer, offer, peerOffer)
				case <-ctx.Done():
					t.Fatal("TLS association was not accepted")
				}
			})
		}
	}
}

func TestSCTPPartialReliabilityTLSDialers(t *testing.T) {
	requirePRSCTPDefault(t)
	cert := generationCertificate(t)
	for _, kind := range []string{"DialTLSContext", "legacy"} {
		for _, offer := range []bool{false, true} {
			for _, peerOffer := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/offer=%t/peer=%t", kind, offer, peerOffer), func(t *testing.T) {
					ra, err := sctp.ResolveAddr("sctp4", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					listener, err := (&sctp.Config{PartialReliability: &peerOffer}).Listen("sctp4", ra)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = listener.Close() }()
					if err := listener.SetDeadline(time.Now().Add(testutil.SCTPTimeout)); err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithTimeout(context.Background(), testutil.SCTPTimeout)
					defer cancel()
					type result struct {
						peer *sctp.Conn
						err  error
					}
					ready := make(chan result, 1)
					go func() {
						peer, err := listener.AcceptSCTP()
						if err == nil {
							server := tls.Server(peer, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
							err = server.HandshakeContext(ctx)
						}
						ready <- result{peer, err}
					}()
					defer func() {
						cancel()
						r := <-ready
						if r.peer != nil {
							_ = r.peer.Close()
						}
					}()
					srv := &Server{Network: "sctp4", Addr: listener.Addr().String(), SCTPPartialReliability: offer,
						TLSConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}} // #nosec G402 -- synthetic local certificate
					var c Conn
					if kind == "legacy" {
						c, err = dialTLS(srv, "", "", testutil.SCTPTimeout)
						if err == nil {
							err = c.Connection().(*tls.Conn).HandshakeContext(ctx)
						}
					} else {
						c, err = srv.DialTLSContext(ctx, "", "")
					}
					if c != nil {
						defer c.Close()
					}
					if err != nil {
						t.Fatal(err)
					}
					r := <-ready
					ready <- r
					if r.err != nil {
						t.Fatal(r.err)
					}
					wantPRSCTP(t, rawPRSCTPConn(c.Connection()), r.peer, offer, peerOffer)
				})
			}
		}
	}
}

// A supplied association's policy wins over Server's setting and is unchanged
// by NewSCTPConn, which cannot renegotiate an established association.
func TestSCTPPartialReliabilitySuppliedListener(t *testing.T) {
	requirePRSCTPDefault(t)
	for _, offer := range []bool{false, true} {
		for _, peerOffer := range []bool{false, true} {
			t.Run(fmt.Sprintf("listener=%t/peer=%t", offer, peerOffer), func(t *testing.T) {
				ra, err := sctp.ResolveAddr("sctp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				listener, err := (&sctp.Config{PartialReliability: &offer}).Listen("sctp4", ra)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
				srv := &Server{SCTPPartialReliability: !offer}
				_, accepted := startPRSCTPServer(t, srv, func() error { return srv.Serve(listener) })
				ctx, cancel := context.WithTimeout(context.Background(), testutil.SCTPTimeout)
				defer cancel()
				peer, err := (&sctp.Config{PartialReliability: &peerOffer}).Dial(ctx, "sctp4", nil, listener.Addr().(*sctp.Addr))
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = peer.Close() }()
				select {
				case c := <-accepted:
					defer c.Close()
					local := rawPRSCTPConn(c.Connection())
					wantPRSCTP(t, local, peer, offer, peerOffer)
					if _, err := NewSCTPConn(local); err != nil {
						t.Fatal(err)
					}
					wantPRSCTP(t, local, peer, offer, peerOffer)
				case <-ctx.Done():
					t.Fatal("association was not accepted")
				}
			})
		}
	}
}
