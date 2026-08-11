//go:build linux && !386

// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diam_test

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/diamtest"
)

func requireSCTP(t *testing.T) {
	t.Helper()
	ln, err := diam.MultistreamListen("sctp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("close SCTP listener: %v", err)
	}
}

func TestCapabilitiesExchangeSCTP(t *testing.T) {
	requireSCTP(t)
	errc := make(chan error, 1)

	smux := diam.NewServeMux()
	smux.Handle("CER", handleCER(errc, false))

	srv := diamtest.NewServerNetwork("sctp", smux, nil)
	defer srv.Close()

	wait := make(chan struct{})
	cmux := diam.NewServeMux()
	cmux.Handle("CEA", handleCEA(errc, wait))

	cli, err := diam.DialNetwork("sctp", srv.Addr, cmux, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sendCER(cli); err != nil {
		t.Fatal(err)
	}

	select {
	case <-wait:
	case err := <-errc:
		t.Fatal(err)
	case err := <-smux.ErrorReports():
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("Timed out: no CER or CEA received")
	}
}

func TestCapabilitiesExchangeSCTP_TLS(t *testing.T) {
	requireSCTP(t)
	errc := make(chan error, 1)
	certFile, keyFile, cert := newTestCertificateFiles(t)

	smux := diam.NewServeMux()
	smux.Handle("CER", handleCER(errc, true))

	srv := diamtest.NewUnstartedServerNetwork("sctp", smux, nil)
	tm := 100 * time.Millisecond
	srv.Config.ReadTimeout = tm
	srv.Config.WriteTimeout = tm
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	srv.StartTLS()
	time.Sleep(time.Millisecond * 10) // let srv start
	defer srv.Close()

	wait := make(chan struct{})
	cmux := diam.NewServeMux()
	cmux.Handle("CEA", handleCEA(errc, wait))

	client := &diam.Server{
		Network:   "sctp",
		Addr:      srv.Addr,
		Handler:   cmux,
		TLSConfig: testClientTLSConfig(t, certFile),
	}
	cli, err := client.DialTLS(certFile, keyFile, 0)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sendCER(cli); err != nil {
		t.Fatal(err)
	}

	select {
	case <-wait:
	case err := <-errc:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("Timed out: no CER or CEA received")
	}
}
