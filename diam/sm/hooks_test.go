// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
)

// TestOnCERHook verifies that Settings.OnCER fires on a received CER before
// the state machine's default handler, and that the default handshake still
// completes. Regression test for #150.
func TestOnCERHook(t *testing.T) {
	var onCERCalls int32
	settings := *serverSettings
	settings.OnCER = func(c diam.Conn, m *diam.Message) {
		if m.Header.CommandCode != diam.CapabilitiesExchange {
			t.Errorf("OnCER invoked for non-CER command %d", m.Header.CommandCode)
		}
		atomic.AddInt32(&onCERCalls, 1)
	}

	sm := New(&settings)
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()

	cli, err := diam.Dial(srv.Addr, nil, dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	m := diam.NewRequest(diam.CapabilitiesExchange, 1001, dict.Default)
	mustSMClientAVP(t, m, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
	mustSMClientAVP(t, m, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
	mustSMClientAVP(t, m, avp.HostIPAddress, avp.Mbit, 0, localhostAddress)
	mustSMClientAVP(t, m, avp.VendorID, avp.Mbit, 0, clientSettings.VendorID)
	mustSMClientAVP(t, m, avp.ProductName, 0, 0, clientSettings.ProductName)
	mustSMClientAVP(t, m, avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(1))
	mustSMClientAVP(t, m, avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001))
	mustSMClientAVP(t, m, avp.FirmwareRevision, 0, 0, clientSettings.FirmwareRevision)
	if _, err := m.WriteTo(cli); err != nil {
		t.Fatal(err)
	}

	select {
	case <-sm.HandshakeNotify():
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not complete after OnCER hook")
	}

	if got := atomic.LoadInt32(&onCERCalls); got != 1 {
		t.Fatalf("OnCER calls = %d, want 1", got)
	}
}

// TestOnDWRHook verifies that Settings.OnDWR fires on a received DWR after
// the handshake and before the default DWR handler responds with DWA.
func TestOnDWRHook(t *testing.T) {
	onDWR := make(chan struct{}, 1)
	settings := *serverSettings
	settings.OnDWR = func(c diam.Conn, m *diam.Message) {
		if m.Header.CommandCode != diam.DeviceWatchdog {
			t.Errorf("OnDWR invoked for non-DWR command %d", m.Header.CommandCode)
		}
		onDWR <- struct{}{}
	}

	sm := New(&settings)
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()

	cli, err := diam.Dial(srv.Addr, nil, dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	cer := diam.NewRequest(diam.CapabilitiesExchange, 1001, dict.Default)
	mustSMClientAVP(t, cer, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
	mustSMClientAVP(t, cer, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
	mustSMClientAVP(t, cer, avp.HostIPAddress, avp.Mbit, 0, localhostAddress)
	mustSMClientAVP(t, cer, avp.VendorID, avp.Mbit, 0, clientSettings.VendorID)
	mustSMClientAVP(t, cer, avp.ProductName, 0, 0, clientSettings.ProductName)
	mustSMClientAVP(t, cer, avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(1))
	mustSMClientAVP(t, cer, avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001))
	mustSMClientAVP(t, cer, avp.FirmwareRevision, 0, 0, clientSettings.FirmwareRevision)
	if _, err := cer.WriteTo(cli); err != nil {
		t.Fatal(err)
	}

	select {
	case <-sm.HandshakeNotify():
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not complete")
	}

	dwr := diam.NewRequest(diam.DeviceWatchdog, 0, dict.Default)
	mustSMClientAVP(t, dwr, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
	mustSMClientAVP(t, dwr, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
	if _, err := dwr.WriteTo(cli); err != nil {
		t.Fatal(err)
	}

	select {
	case <-onDWR:
	case <-time.After(2 * time.Second):
		t.Fatal("OnDWR hook did not fire")
	}
}

// TestOnCEAHook verifies that Settings.OnCEA fires on the server immediately
// before a (success) CEA is sent, with the fully-constructed answer message,
// and that the default handshake still completes. Outbound counterpart of
// TestOnCERHook.
func TestOnCEAHook(t *testing.T) {
	var onCEACalls int32
	settings := *serverSettings
	settings.OnCEA = func(c diam.Conn, m *diam.Message) {
		if m.Header.CommandCode != diam.CapabilitiesExchange {
			t.Errorf("OnCEA invoked for non-CEA command %d", m.Header.CommandCode)
		}
		if m.Header.CommandFlags&diam.RequestFlag != 0 {
			t.Errorf("OnCEA invoked with a request message, want an answer")
		}
		atomic.AddInt32(&onCEACalls, 1)
	}

	sm := New(&settings)
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()

	cli, err := diam.Dial(srv.Addr, nil, dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	m := diam.NewRequest(diam.CapabilitiesExchange, 1001, dict.Default)
	mustSMClientAVP(t, m, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
	mustSMClientAVP(t, m, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
	mustSMClientAVP(t, m, avp.HostIPAddress, avp.Mbit, 0, localhostAddress)
	mustSMClientAVP(t, m, avp.VendorID, avp.Mbit, 0, clientSettings.VendorID)
	mustSMClientAVP(t, m, avp.ProductName, 0, 0, clientSettings.ProductName)
	mustSMClientAVP(t, m, avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(1))
	mustSMClientAVP(t, m, avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001))
	mustSMClientAVP(t, m, avp.FirmwareRevision, 0, 0, clientSettings.FirmwareRevision)
	if _, err := m.WriteTo(cli); err != nil {
		t.Fatal(err)
	}

	select {
	case <-sm.HandshakeNotify():
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not complete after OnCEA hook")
	}

	if got := atomic.LoadInt32(&onCEACalls); got != 1 {
		t.Fatalf("OnCEA calls = %d, want 1", got)
	}
}

// TestOnCEAHookErrorCEA verifies that Settings.OnCEA also fires when the
// server answers a CER with an error CEA (here: no common application),
// covering the errorCEA call site as well as successCEA.
func TestOnCEAHookErrorCEA(t *testing.T) {
	var onCEACalls int32
	onCEA := make(chan *diam.Message, 1)
	settings := *serverSettings
	settings.OnCEA = func(c diam.Conn, m *diam.Message) {
		if m.Header.CommandCode != diam.CapabilitiesExchange {
			t.Errorf("OnCEA invoked for non-CEA command %d", m.Header.CommandCode)
		}
		if m.Header.CommandFlags&diam.RequestFlag != 0 {
			t.Errorf("OnCEA invoked with a request message, want an answer")
		}
		if m.Header.CommandFlags&diam.ErrorFlag == 0 {
			t.Errorf("OnCEA error-CEA message does not have the Error flag set")
		}
		atomic.AddInt32(&onCEACalls, 1)
		select {
		case onCEA <- m:
		default:
		}
	}

	sm := New(&settings)
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()

	cli, err := diam.Dial(srv.Addr, nil, dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	// Request an application the server does not support, forcing errorCEA
	// (DIAMETER_NO_COMMON_APPLICATION).
	m := diam.NewRequest(diam.CapabilitiesExchange, 1001, dict.Default)
	mustSMClientAVP(t, m, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
	mustSMClientAVP(t, m, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
	mustSMClientAVP(t, m, avp.HostIPAddress, avp.Mbit, 0, localhostAddress)
	mustSMClientAVP(t, m, avp.VendorID, avp.Mbit, 0, clientSettings.VendorID)
	mustSMClientAVP(t, m, avp.ProductName, 0, 0, clientSettings.ProductName)
	mustSMClientAVP(t, m, avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(1))
	mustSMClientAVP(t, m, avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(99999))
	mustSMClientAVP(t, m, avp.FirmwareRevision, 0, 0, clientSettings.FirmwareRevision)
	if _, err := m.WriteTo(cli); err != nil {
		t.Fatal(err)
	}

	select {
	case a := <-onCEA:
		avpRC, err := a.FindAVP(avp.ResultCode, 0)
		if err != nil {
			t.Fatalf("OnCEA error answer has no Result-Code AVP: %v", err)
		}
		rc, ok := avpRC.Data.(datatype.Unsigned32)
		if !ok {
			t.Fatalf("OnCEA error answer Result-Code is not Unsigned32: %T", avpRC.Data)
		}
		if rc == diam.Success {
			t.Fatalf("OnCEA error answer Result-Code = %d, want a non-success code", rc)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnCEA hook did not fire on errorCEA")
	}

	if got := atomic.LoadInt32(&onCEACalls); got != 1 {
		t.Fatalf("OnCEA calls = %d, want 1", got)
	}
}

// TestOnDWAHook verifies that Settings.OnDWA fires on the server immediately
// before a DWA is sent in response to a peer DWR. Outbound counterpart of
// TestOnDWRHook.
func TestOnDWAHook(t *testing.T) {
	onDWA := make(chan *diam.Message, 1)
	settings := *serverSettings
	settings.OnDWA = func(c diam.Conn, m *diam.Message) {
		if m.Header.CommandCode != diam.DeviceWatchdog {
			t.Errorf("OnDWA invoked for non-DWA command %d", m.Header.CommandCode)
		}
		if m.Header.CommandFlags&diam.RequestFlag != 0 {
			t.Errorf("OnDWA invoked with a request message, want an answer")
		}
		select {
		case onDWA <- m:
		default:
		}
	}

	sm := New(&settings)
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()

	cli, err := diam.Dial(srv.Addr, nil, dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	cer := diam.NewRequest(diam.CapabilitiesExchange, 1001, dict.Default)
	mustSMClientAVP(t, cer, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
	mustSMClientAVP(t, cer, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
	mustSMClientAVP(t, cer, avp.HostIPAddress, avp.Mbit, 0, localhostAddress)
	mustSMClientAVP(t, cer, avp.VendorID, avp.Mbit, 0, clientSettings.VendorID)
	mustSMClientAVP(t, cer, avp.ProductName, 0, 0, clientSettings.ProductName)
	mustSMClientAVP(t, cer, avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(1))
	mustSMClientAVP(t, cer, avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001))
	mustSMClientAVP(t, cer, avp.FirmwareRevision, 0, 0, clientSettings.FirmwareRevision)
	if _, err := cer.WriteTo(cli); err != nil {
		t.Fatal(err)
	}

	select {
	case <-sm.HandshakeNotify():
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not complete")
	}

	dwr := diam.NewRequest(diam.DeviceWatchdog, 0, dict.Default)
	mustSMClientAVP(t, dwr, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
	mustSMClientAVP(t, dwr, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
	if _, err := dwr.WriteTo(cli); err != nil {
		t.Fatal(err)
	}

	select {
	case <-onDWA:
	case <-time.After(2 * time.Second):
		t.Fatal("OnDWA hook did not fire")
	}
}
