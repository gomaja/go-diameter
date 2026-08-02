// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diamtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/dict"
)

// A Server is a Diameter server listening on a system-chosen port on the
// local loopback interface, for use in end-to-end tests.
type Server struct {
	Network  string
	Addr     string
	Listener net.Listener
	TLS      *tls.Config
	Config   *diam.Server
}

// NewServer starts and returns a new Server.
// The caller should call Close when finished, to shut it down.
func NewServer(handler diam.Handler, dp *dict.Parser) *Server {
	return NewServerNetwork("tcp", handler, dp)
}

// NewUnstartedServer returns a new Server but doesn't start it.
//
// After changing its configuration, the caller should call Start or
// StartTLS.
//
// The caller should call Close when finished, to shut it down.
func NewUnstartedServer(handler diam.Handler, dp *dict.Parser) *Server {
	return NewUnstartedServerNetwork("tcp", handler, dp)
}

// NewServerNetwork starts and returns a new Server listening on specified network.
// The caller should call Close when finished, to shut it down.
func NewServerNetwork(network string, handler diam.Handler, dp *dict.Parser) *Server {
	ts := NewUnstartedServerNetwork(network, handler, dp)
	ts.Start()
	return ts
}

// NewUnstartedServerNetwork returns a new Server on the network but doesn't start it.
//
// After changing its configuration, the caller should call Start or
// StartTLS.
//
// The caller should call Close when finished, to shut it down.
func NewUnstartedServerNetwork(network string, handler diam.Handler, dp *dict.Parser) *Server {
	return &Server{
		Listener: newLocalListener(network),
		Config: &diam.Server{
			Network: network,
			Handler: handler,
			Dict:    dp,
		},
	}
}

func newLocalListener(network string) net.Listener {
	if len(network) == 0 {
		network = "tcp"
	}
	l, err := diam.MultistreamListen(network, "127.0.0.1:0")
	if err != nil {
		fmt.Printf("diamtest: failed initial listen on network %s: %v", network, err)
		switch network {
		case "sctp":
			network = "sctp6"
		case "tcp":
			network = "tcp6"
		default:
			panic(fmt.Sprintf("diamtest: failed to listen on network %s: %v", network, err))
		}
		if l, err = diam.MultistreamListen(network, "[::1]:0"); err != nil {
			panic(fmt.Sprintf("diamtest: failed to listen on a port: %v", err))
		}
	}
	return l
}

// Start starts a server from NewUnstartedServer.
func (s *Server) Start() {
	if s.Addr != "" {
		panic("Server already started")
	}
	s.Addr = s.Listener.Addr().String()
	go func() {
		if err := s.Config.Serve(s.Listener); err != nil && !errors.Is(err, diam.ErrServerClosed) {
			panic(err)
		}
	}()
}

// StartTLS starts TLS on a server from NewUnstartedServer.
func (s *Server) StartTLS() {
	if s.Addr != "" {
		panic("Server already started")
	}
	cert, err := newLocalhostCertificate()
	if err != nil {
		panic(fmt.Sprintf("diamtest: NewTLSServer: %v", err))
	}
	if s.TLS != nil {
		s.TLS = diam.TLSConfigClone(s.TLS)
	} else {
		s.TLS = new(tls.Config)
	}
	/*
		if s.TLS.NextProtos == nil {
			s.TLS.NextProtos = []string{"diameter"}
		}
	*/
	if len(s.TLS.Certificates) == 0 {
		s.TLS.Certificates = []tls.Certificate{cert}
	}
	tlsListener := tls.NewListener(s.Listener, s.TLS)
	s.Listener = tlsListener
	s.Addr = s.Listener.Addr().String()
	go func() {
		if err := s.Config.Serve(s.Listener); err != nil && !errors.Is(err, diam.ErrServerClosed) {
			panic(err)
		}
	}()
}

// Close shuts down the server.
func (s *Server) Close() {
	if err := s.Config.Close(); err != nil && !errors.Is(err, diam.ErrServerClosed) {
		panic(err)
	}
}

func newLocalhostCertificate() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"go-diameter"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		DNSNames:              []string{"example.com", "localhost"},
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("::1"),
		},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}
