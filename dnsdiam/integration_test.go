package dnsdiam

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	dns "codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
	"github.com/gomaja/go-diameter/diam/peer"
	"github.com/gomaja/go-diameter/diam/sm"
)

func TestAuthoritativeDNSAndTLSManager(t *testing.T) {
	serverTLS, clientTLS := fixtureTLS(t, []string{"example.net", "_diameters._tcp.example.net", "peer.example.net"})
	// Optional local synthetic key log permits packet-level CER/CEA evidence.
	if path := os.Getenv("I100_TLS_KEYLOG"); path != "" {
		log, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := log.Close(); err != nil {
				t.Error(err)
			}
		})
		clientTLS.KeyLogWriter = log
		serverTLS.KeyLogWriter = log
	}
	credential := clientTLS.Certificates[0]
	clientTLS.Certificates = nil
	clientTLS.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &credential, nil }
	addr := fixturePeer(t, fixtureSettings("peer.example.net", "example.net"), serverTLS, nil)
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	var tcpQueries atomic.Int32
	var withdrawn atomic.Bool
	dnsAddr := authoritative(t, func(q *dns.Msg, network string) *dns.Msg {
		r := reply(q)
		if network == "udp" && q.Question[0].Header().Name == "example.net." {
			r.Truncated = true
			return r
		}
		if network == "tcp" {
			tcpQueries.Add(1)
		}
		h := dns.Header{Name: q.Question[0].Header().Name, Class: dns.ClassINET, TTL: 7200}
		switch q.Question[0].(type) {
		case *dns.NAPTR:
			r.Answer = []dns.RR{&dns.NAPTR{Hdr: h, NAPTR: rdata.NAPTR{Flags: "S", Service: "aaa+ap4:diameter.tls.tcp", Replacement: "_diameters._tcp.example.net."}}}
		case *dns.SRV:
			target := "peer.example.net."
			if withdrawn.Load() {
				target = "."
			}
			r.Answer = []dns.RR{&dns.SRV{Hdr: h, SRV: rdata.SRV{Port: uint16(p), Weight: 1, Target: target}}}
		case *dns.A:
			r.Answer = []dns.RR{&dns.A{Hdr: h, A: rdata.A{Addr: netip.MustParseAddr("127.0.0.1")}}}
		}
		return r
	})
	t.Logf("synthetic DNS %s TLS Diameter %s", dnsAddr, addr)
	resolver, err := NewResolver(DNSConfig{Servers: []string{dnsAddr}, Attempts: 1, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	d, err := New(Config{Resolver: resolver, RandIntn: func(int) int { return 0 }})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := peer.New(peer.Config{Settings: fixtureSettings("client.example.net", "local.net"), Timers: peer.Timers{Closing: 50 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := manager.Close(ctx, sm.DisconnectRebooting); err != nil {
			t.Error(err)
		}
	})
	controller, err := NewController(d, manager, Policy{TLSConfig: clientTLS, Authorize: authorizeFixture})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := controller.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if err = controller.Ensure(ctx, "example.net", 4); err != nil {
		t.Fatal(err)
	}
	peers := manager.Peers()
	if tcpQueries.Load() == 0 || len(peers) != 1 || !peers[0].Eligible || !peers[0].Dynamic || !peers[0].ExpiresAt.Equal(credential.Leaf.NotAfter) {
		t.Fatalf("DNS/TLS admission or certificate cap missing: %+v tcp=%d", peers, tcpQueries.Load())
	}
	// Force refresh through the same controller path used by Watch. A dynamic
	// client credential cap must survive TLS-config reuse on the live connection.
	key := bindingKey{"example.net", 4}
	if err = controller.lock(ctx); err != nil {
		t.Fatal(err)
	}
	err = controller.ensureLocked(ctx, Request{Realm: "example.net", ApplicationID: 4}, key, true)
	controller.unlock()
	if err != nil {
		t.Fatal(err)
	}
	refreshed := manager.Peers()
	if len(refreshed) != 1 || refreshed[0].Generation != peers[0].Generation || !refreshed[0].ExpiresAt.Equal(peers[0].ExpiresAt) {
		t.Fatalf("refresh changed verified identity/certificate cap: %+v", refreshed)
	}
	withdrawn.Store(true)
	if err = controller.lock(ctx); err != nil {
		t.Fatal(err)
	}
	err = controller.ensureLocked(ctx, Request{Realm: "example.net", ApplicationID: 4}, key, true)
	controller.unlock()
	if err == nil || manager.HasRoute("example.net", 4) {
		t.Fatalf("withdrawn authority retained route: %v", err)
	}
}
