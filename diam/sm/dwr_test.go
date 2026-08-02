// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
)

// These tests use dictionary, settings and functions from sm_test.go.

func TestHandleDWR(t *testing.T) {
	sm := New(serverSettings)
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	mc := make(chan *diam.Message, 1)
	mux := diam.NewServeMux()
	mux.HandleFunc("CEA", func(c diam.Conn, m *diam.Message) {
		mc <- m
	})
	mux.HandleFunc("DWA", func(c diam.Conn, m *diam.Message) {
		mc <- m
	})
	cli, err := diam.Dial(srv.Addr, mux, dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	// Send CER first.
	m := diam.NewRequest(diam.CapabilitiesExchange, 1001, dict.Default)
	mustSMClientAVP(t, m, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
	mustSMClientAVP(t, m, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
	mustSMClientAVP(t, m, avp.HostIPAddress, avp.Mbit, 0, localhostAddress)
	mustSMClientAVP(t, m, avp.VendorID, avp.Mbit, 0, clientSettings.VendorID)
	mustSMClientAVP(t, m, avp.ProductName, 0, 0, clientSettings.ProductName)
	mustSMClientAVP(t, m, avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(1))
	mustSMClientAVP(t, m, avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001))
	mustSMClientAVP(t, m, avp.FirmwareRevision, 0, 0, clientSettings.FirmwareRevision)
	_, err = m.WriteTo(cli)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case resp := <-mc:
		if !testResultCode(resp, diam.Success) {
			t.Fatalf("Unexpected result code for CEA.\n%s", resp)
		}
	case err := <-mux.ErrorReports():
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("No CEA received")
	}
	// Send DWR.
	m = diam.NewRequest(diam.DeviceWatchdog, 0, dict.Default)
	mustSMClientAVP(t, m, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
	mustSMClientAVP(t, m, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
	mustSMClientAVP(t, m, avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(1))
	_, err = m.WriteTo(cli)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case resp := <-mc:
		if !testResultCode(resp, diam.Success) {
			t.Fatalf("Unexpected result code for DWA.\n%s", resp)
		}
	case err := <-mux.ErrorReports():
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("No DWA received")
	}
}

func TestHandleDWR_Fail(t *testing.T) {
	sm := New(serverSettings)
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	mc := make(chan *diam.Message, 1)
	mux := diam.NewServeMux()
	mux.HandleFunc("CEA", func(c diam.Conn, m *diam.Message) {
		mc <- m
	})
	mux.HandleFunc("DWA", func(c diam.Conn, m *diam.Message) {
		mc <- m
	})
	cli, err := diam.Dial(srv.Addr, mux, dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	// Send CER first.
	m := diam.NewRequest(diam.CapabilitiesExchange, 1001, dict.Default)
	mustSMClientAVP(t, m, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
	mustSMClientAVP(t, m, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
	mustSMClientAVP(t, m, avp.HostIPAddress, avp.Mbit, 0, localhostAddress)
	mustSMClientAVP(t, m, avp.VendorID, avp.Mbit, 0, clientSettings.VendorID)
	mustSMClientAVP(t, m, avp.ProductName, 0, 0, clientSettings.ProductName)
	mustSMClientAVP(t, m, avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(1))
	mustSMClientAVP(t, m, avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001))
	mustSMClientAVP(t, m, avp.FirmwareRevision, 0, 0, clientSettings.FirmwareRevision)
	_, err = m.WriteTo(cli)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case resp := <-mc:
		if !testResultCode(resp, diam.Success) {
			t.Fatalf("Unexpected result code for CEA.\n%s", resp)
		}
	case err := <-mux.ErrorReports():
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("No CEA received")
	}
	// Send broken DWR (missing Origin-Host, etc).
	m = diam.NewRequest(diam.DeviceWatchdog, 0, dict.Default)
	_, err = m.WriteTo(cli)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-sm.ErrorReports():
		if err.Error != smparser.ErrMissingOriginHost {
			t.Fatalf("Unexpected error. Want ErrMissingOriginHost, have %#v", err.Error)
		}
	case err := <-mux.ErrorReports():
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("No DWA received")
	}
}
