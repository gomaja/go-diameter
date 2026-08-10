// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diam_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
)

func TestCapabilitiesExchange(t *testing.T) {
	errc := make(chan error, 1)

	smux := diam.NewServeMux()
	smux.Handle("CER", handleCER(errc, false))

	srv := diamtest.NewServer(smux, nil)
	defer srv.Close()

	wait := make(chan struct{})
	cmux := diam.NewServeMux()
	cmux.HandleIdx(diam.CommandIndex{AppID: 0, Code: diam.CapabilitiesExchange, Request: false}, handleCEA(errc, wait))

	cli, err := diam.Dial(srv.Addr, cmux, nil)
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

func TestCapabilitiesExchangeTLS(t *testing.T) {
	errc := make(chan error, 1)
	certFile, keyFile, cert := newTestCertificateFiles(t)

	smux := diam.NewServeMux()
	smux.Handle("CER", handleCER(errc, true))

	srv := diamtest.NewUnstartedServer(smux, nil)
	tm := time.Second
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

	cli, err := diam.DialTLSConfig(srv.Addr, certFile, keyFile, cmux, nil, testClientTLSConfig(t, certFile))
	if err != nil {
		t.Fatalf("diam.DialTLS Error: %v", err)
	}

	n, err := sendCER(cli)
	if err != nil {
		t.Fatalf("sendCER Error: %v", err)
	}
	if n <= 0 {
		t.Fatalf("sendCER: %d bytes sent", n)
	}

	select {
	case <-wait:
	case err := <-errc:
		t.Fatal(err)
	case <-time.After(time.Second * 3):
		t.Fatal("Timed out: no CER or CEA received")
	}
}

func TestDialTLSRejectsUntrustedCertificateByDefault(t *testing.T) {
	certFile, keyFile, cert := newTestCertificateFiles(t)

	srv := diamtest.NewUnstartedServer(diam.NewServeMux(), nil)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	srv.StartTLS()
	time.Sleep(time.Millisecond * 10) // let srv start
	defer srv.Close()

	cli, err := diam.DialTLS(srv.Addr, certFile, keyFile, diam.NewServeMux(), nil)
	if err != nil {
		t.Fatalf("DialTLS returned connection setup error before TLS verification: %v", err)
	}
	defer cli.Close()

	if _, err := sendCER(cli); err == nil {
		t.Fatal("DialTLS with default TLS config accepted an untrusted server certificate")
	}
}

func testClientTLSConfig(t *testing.T, certFile string) *tls.Config {
	t.Helper()

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to add test root certificate")
	}
	return &tls.Config{
		RootCAs:    roots,
		MinVersion: tls.VersionTLS13,
	}
}

func sendCER(w io.Writer) (n int64, err error) {
	m := diam.NewRequest(diam.CapabilitiesExchange, 0, nil)
	if _, err := m.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.OctetString("cli")); err != nil {
		return 0, err
	}
	if _, err := m.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.OctetString("localhost")); err != nil {
		return 0, err
	}
	if _, err := m.NewAVP(avp.HostIPAddress, avp.Mbit, 0, datatype.Address(net.ParseIP("127.0.0.1"))); err != nil {
		return 0, err
	}
	if _, err := m.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(99)); err != nil {
		return 0, err
	}
	if _, err := m.NewAVP(avp.ProductName, avp.Mbit, 0, datatype.UTF8String("go-diameter")); err != nil {
		return 0, err
	}
	if _, err := m.NewAVP(avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(1234)); err != nil {
		return 0, err
	}
	if _, err := m.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1)); err != nil {
		return 0, err
	}
	return m.WriteTo(w)
}

func handleCER(errc chan error, useTLS bool) diam.HandlerFunc {
	type CER struct {
		OriginHost        string    `avp:"Origin-Host"`
		OriginRealm       string    `avp:"Origin-Realm"`
		VendorID          int       `avp:"Vendor-Id"`
		ProductName       string    `avp:"Product-Name"`
		OriginStateID     *diam.AVP `avp:"Origin-State-Id"`
		AcctApplicationID *diam.AVP `avp:"Acct-Application-Id"`
	}
	return func(c diam.Conn, m *diam.Message) {

		if c.LocalAddr() == nil {
			errc <- fmt.Errorf("localAddr is nil")
		}
		if c.RemoteAddr() == nil {
			errc <- fmt.Errorf("localAddr is nil")
		}
		if useTLS && c.TLS() == nil {
			errc <- fmt.Errorf("tls is nil")
		}
		if !useTLS && c.TLS() != nil {
			errc <- fmt.Errorf("tls is supposed to be nil")
		}
		var req CER
		err := m.Unmarshal(&req)
		if err != nil {
			errc <- err
			return
		}
		if req.OriginHost != "cli" {
			errc <- fmt.Errorf("unexpected OriginHost. want cli, have %q", req.OriginHost)
			return
		}
		if req.OriginRealm != "localhost" {
			errc <- fmt.Errorf("unexpected OriginRealm. want localhost, have %q", req.OriginRealm)
			return
		}
		if req.VendorID != 99 {
			errc <- fmt.Errorf("unexpected VendorID. want 99, have %d", req.VendorID)
			return
		}
		if req.ProductName != "go-diameter" {
			errc <- fmt.Errorf("unexpected ProductName. want go-diameter, have %q", req.ProductName)
			return
		}
		a := m.Answer(diam.Success)
		_, err = sendCEA(c, a, req.OriginStateID, req.AcctApplicationID)
		if err != nil {
			errc <- err
		}
		c.(diam.CloseNotifier).CloseNotify()
		go func() {
			<-c.(diam.CloseNotifier).CloseNotify()
		}()
		//log.Println("Client", c.RemoteAddr(), "disconnected")
	}
}

func sendCEA(w io.Writer, m *diam.Message, OriginStateID, AcctApplicationID *diam.AVP) (n int64, err error) {
	if _, err := m.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.OctetString("srv")); err != nil {
		return 0, err
	}
	if _, err := m.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.OctetString("localhost")); err != nil {
		return 0, err
	}
	if _, err := m.NewAVP(avp.HostIPAddress, avp.Mbit, 0, datatype.Address(net.ParseIP("127.0.0.1"))); err != nil {
		return 0, err
	}
	if _, err := m.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(99)); err != nil {
		return 0, err
	}
	if _, err := m.NewAVP(avp.ProductName, avp.Mbit, 0, datatype.UTF8String("go-diameter")); err != nil {
		return 0, err
	}
	m.AddAVP(OriginStateID)
	m.AddAVP(AcctApplicationID)
	return m.WriteTo(w)
}

func handleCEA(errc chan error, wait chan struct{}) diam.HandlerFunc {
	type CEA struct {
		OriginHost        string `avp:"Origin-Host"`
		OriginRealm       string `avp:"Origin-Realm"`
		VendorID          int    `avp:"Vendor-Id"`
		ProductName       string `avp:"Product-Name"`
		OriginStateID     int    `avp:"Origin-State-Id"`
		AcctApplicationID int    `avp:"Acct-Application-Id"`
	}
	return func(c diam.Conn, m *diam.Message) {

		var resp CEA
		err := m.Unmarshal(&resp)
		if err != nil {
			errc <- err
			return
		}
		if resp.OriginHost != "srv" {
			errc <- fmt.Errorf("unexpected OriginHost. want srv, have %q", resp.OriginHost)
			return
		}
		if resp.OriginRealm != "localhost" {
			errc <- fmt.Errorf("unexpected OriginRealm. want localhost, have %q", resp.OriginRealm)
			return
		}
		if resp.VendorID != 99 {
			errc <- fmt.Errorf("unexpected VendorID. want 99, have %d", resp.VendorID)
			return
		}
		if resp.ProductName != "go-diameter" {
			errc <- fmt.Errorf("unexpected ProductName. want go-diameter, have %q", resp.ProductName)
			return
		}
		if resp.OriginStateID != 1234 {
			errc <- fmt.Errorf("unexpected OriginStateID. want 1234, have %d", resp.OriginStateID)
			return
		}
		if resp.AcctApplicationID != 1 {
			errc <- fmt.Errorf("unexpected AcctApplicationID. want 1, have %d", resp.AcctApplicationID)
			return
		}
		// Initialize & start close notifier
		closeNotifyChan := c.(diam.CloseNotifier).CloseNotify()
		// Wait on close notify chan outside of main serve loop, closeNotifier routine is started by
		// liveSwitchReader.Read to avoid io.Pipe deadlock issue
		go func() {
			<-closeNotifyChan // wait on c.Close to complete
			select {          // close only if not already closed
			case <-wait:
			default:
				close(wait)
			}
		}()
		c.Close()
	}
}
