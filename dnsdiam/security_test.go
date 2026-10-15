package dnsdiam

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/peer"
	"github.com/gomaja/go-diameter/diam/sm"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// Keep the pending dictionary API migration confined to this fixture.
func fixtureDictionary() *dict.Parser { return dict.Default }

func fixtureSettings(host, realm string) sm.Settings {
	return sm.Settings{OriginHost: datatype.DiameterIdentity(host), OriginRealm: datatype.DiameterIdentity(realm), VendorID: 1, ProductName: "discovery-test", Dict: fixtureDictionary(), AuthApplicationID: []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4))}, AcctApplicationID: []*diam.AVP{}, VendorSpecificApplicationID: []*diam.AVP{}}
}

func makeCertificate(t *testing.T, template, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (tls.Certificate, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{raw}, PrivateKey: key, Leaf: parsed}, parsed, key
}

func fixtureTLS(t *testing.T, names []string) (*tls.Config, *tls.Config) {
	t.Helper()
	now := time.Now()
	_, ca, key := makeCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil, nil)
	server, _, _ := makeCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: names, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, ca, key)
	client, _, _ := makeCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(3), DNSNames: []string{"client.example.net"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, ca, key)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &tls.Config{Certificates: []tls.Certificate{server}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12}, &tls.Config{Certificates: []tls.Certificate{client}, RootCAs: pool, MinVersion: tls.VersionTLS12}
}

func fixturePeer(t *testing.T, settings sm.Settings, config *tls.Config, handler func(*sm.StateMachine)) string {
	t.Helper()
	machine, err := sm.New(&settings)
	if err != nil {
		t.Fatal(err)
	}
	if handler != nil {
		handler(machine)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if config != nil {
		listener = tls.NewListener(listener, config)
	}
	server := &diam.Server{Handler: machine, Dict: fixtureDictionary(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("server did not stop")
		}
	})
	return listener.Addr().String()
}

func liveDiscovery(t *testing.T, addr string, transport Transport) *Discoverer {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeResolver{answers: basicAnswers(), errors: make(map[lookupKey]error)}
	for key, a := range r.answers {
		a.ReceivedAt = time.Now()
		r.answers[key] = a
	}
	a := r.answers[lookupKey{"example.net.", TypeNAPTR}]
	a.Records[0].NAPTR.Service = "aaa+ap4:" + string(transport)
	r.answers[lookupKey{"example.net.", TypeNAPTR}] = a
	a = r.answers[lookupKey{"_diameters._tcp.example.net.", TypeSRV}]
	a.Records[0].SRV.Port = uint16(p)
	r.answers[lookupKey{"_diameters._tcp.example.net.", TypeSRV}] = a
	r.answers[lookupKey{"peer.example.net.", TypeA}] = Answer{ReceivedAt: time.Now(), Records: []Record{address("peer.example.net.", "127.0.0.1", 600)}}
	delete(r.answers, lookupKey{"peer.example.net.", TypeAAAA})
	d, err := New(Config{Resolver: r})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func authorizeFixture(Candidate, diam.Conn, *smpeer.Metadata) error { return nil }

func TestDialMutualTLSDiscoveryAdmission(t *testing.T) {
	names := []string{"example.net", "_diameters._tcp.example.net", "peer.example.net"}
	for _, tc := range []struct {
		name        string
		names       []string
		realm, host string
		rejectRole  bool
		want        bool
	}{
		{"authorized", names, "example.net", "peer.example.net", false, true},
		{"target-only certificate", names[2:], "example.net", "peer.example.net", false, false},
		{"wrong realm", names, "other.net", "peer.example.net", false, false},
		{"wrong host", names, "example.net", "other.example.net", false, false},
		{"unauthorized role", names, "example.net", "peer.example.net", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverTLS, clientTLS := fixtureTLS(t, tc.names)
			var serverAuthenticated atomic.Bool
			serverTLS.VerifyConnection = func(state tls.ConnectionState) error {
				serverAuthenticated.Store(len(state.VerifiedChains) > 0 && len(state.PeerCertificates) > 0)
				return nil
			}
			addr := fixturePeer(t, fixtureSettings(tc.host, tc.realm), serverTLS, nil)
			d := liveDiscovery(t, addr, TLS)
			var admitted atomic.Bool
			settings := fixtureSettings("client.example.net", "example.net")
			settings.OnHandshake = func(diam.Conn, *smpeer.Metadata) { admitted.Store(true) }
			policy := Policy{TLSConfig: clientTLS, Authorize: authorizeFixture}
			if tc.rejectRole {
				policy.Authorize = func(Candidate, diam.Conn, *smpeer.Metadata) error { return errors.New("role denied") }
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := d.DialContext(ctx, Request{Realm: "example.net", ApplicationID: 4}, DialConfig{Settings: settings, Policy: policy})
			if tc.want {
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				if !serverAuthenticated.Load() || !admitted.Load() {
					t.Fatal("mutual authentication or admission missing")
				}
			} else if err == nil || admitted.Load() {
				if conn != nil {
					conn.Close()
				}
				t.Fatalf("unauthorized connection admitted: %v", err)
			}
		})
	}
}

func TestPolicyRejectsUnsafeConfiguration(t *testing.T) {
	candidate := Candidate{Realm: "example.net", ApplicationID: 4, Transport: TLS, Host: "peer.example.net", Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, ExpiresAt: time.Now().Add(time.Minute)}
	_, client := fixtureTLS(t, []string{"peer.example.net"})
	for _, policy := range []Policy{{}, {Authorize: authorizeFixture}, {TLSConfig: client}, {TLSConfig: &tls.Config{InsecureSkipVerify: true}, Authorize: authorizeFixture}} {
		if _, err := policy.prepare(candidate, time.Now); err == nil {
			t.Fatal("unsafe policy accepted")
		}
	}
	candidate.Transport = TCP
	if _, err := (Policy{Authorize: authorizeFixture}).prepare(candidate, time.Now); !errors.Is(err, ErrUnauthorized) {
		t.Fatal(err)
	}
	candidate.Transport = DTLS
	if _, err := (Policy{Authorize: authorizeFixture}).prepare(candidate, time.Now); !errors.Is(err, ErrUnsupportedTransport) {
		t.Fatal(err)
	}
}

func TestManagerTLSLeaseAndDelegatedRealm(t *testing.T) {
	serverTLS, clientTLS := fixtureTLS(t, []string{"example.net", "_diameters._tcp.example.net", "peer.example.net"})
	addr := fixturePeer(t, fixtureSettings("peer.example.net", "delegated.net"), serverTLS, nil)
	d := liveDiscovery(t, addr, TLS)
	manager, err := peer.New(peer.Config{Settings: fixtureSettings("client.example.net", "example.net")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if err := manager.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := manager.Close(context.Background(), sm.DisconnectDoNotWantToTalkToYou); err != nil {
			t.Error(err)
		}
	}()
	controller, err := NewController(d, manager, Policy{TLSConfig: clientTLS, Authorize: authorizeFixture, AllowRealm: func(expected, actual string) bool { return expected == "example.net" && actual == "delegated.net" }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := controller.Close(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	if err := controller.Ensure(ctx, "example.net", 4); err != nil {
		t.Fatal(err)
	}
	if !manager.HasRoute("example.net", 4) {
		t.Fatal("validated delegated realm route missing")
	}
}
