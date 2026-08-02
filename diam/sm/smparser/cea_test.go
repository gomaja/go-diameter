// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package smparser

import (
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

func mustCEAAVP(t *testing.T, m *diam.Message, code interface{}, flags uint8, vendor uint32, data datatype.Type) {
	t.Helper()
	if _, err := m.NewAVP(code, flags, vendor, data); err != nil {
		t.Fatal(err)
	}
}

func TestCEA_MissingResultCode(t *testing.T) {
	m := diam.NewMessage(diam.CapabilitiesExchange, 0, 0, 0, 0, nil)
	cea := new(CEA)
	err := cea.Parse(m, Client)
	if err == nil {
		t.Fatal("Broken CEA was parsed with no errors")
	}
	if err != ErrMissingResultCode {
		t.Fatal("Unexpected error:", err)
	}
}

func TestCEA_MissingOriginHost(t *testing.T) {
	m := diam.NewMessage(diam.CapabilitiesExchange, 0, 0, 0, 0, nil)
	mustCEAAVP(t, m, avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.Success))
	cea := new(CEA)
	err := cea.Parse(m, Client)
	if err == nil {
		t.Fatal("Broken CEA was parsed with no errors")
	}
	if err != ErrMissingOriginHost {
		t.Fatal("Unexpected error:", err)
	}
}

func TestCEA_MissingOriginRealm(t *testing.T) {
	m := diam.NewMessage(diam.CapabilitiesExchange, 0, 0, 0, 0, nil)
	mustCEAAVP(t, m, avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.Success))
	mustCEAAVP(t, m, avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("foobar"))
	cea := new(CEA)
	err := cea.Parse(m, Client)
	if err == nil {
		t.Fatal("Broken CEA was parsed with no errors")
	}
	if err != ErrMissingOriginRealm {
		t.Fatal("Unexpected error:", err)
	}
}

func TestCEA_MissingApplication(t *testing.T) {
	m := diam.NewMessage(diam.CapabilitiesExchange, 0, 0, 0, 0, dict.Default)
	mustCEAAVP(t, m, avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.Success))
	mustCEAAVP(t, m, avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("foobar"))
	mustCEAAVP(t, m, avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("test"))
	mustCEAAVP(t, m, avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(1))
	cea := new(CEA)
	err := cea.Parse(m, Client)
	if err == nil {
		t.Fatal("Broken CEA was parsed with no errors")
	}
	if err != ErrMissingApplication {
		t.Fatal("Unexpected error:", err)
	}
}

func TestCEA_MissingApplicationWithError(t *testing.T) {
	m := diam.NewMessage(diam.CapabilitiesExchange, 0, 0, 0, 0, dict.Default)
	mustCEAAVP(t, m, avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.ResourcesExceeded))
	mustCEAAVP(t, m, avp.FailedAVP, avp.Mbit, 0, &diam.GroupedAVP{
		AVP: []*diam.AVP{
			diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1000)),
		},
	})

	mustCEAAVP(t, m, avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("foobar"))
	mustCEAAVP(t, m, avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("test"))
	mustCEAAVP(t, m, avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(1))
	cea := new(CEA)
	err := cea.Parse(m, Client)
	if err == nil {
		t.Fatal("Broken CEA was parsed with no errors")
	}
	e, ok := err.(*ErrFailedResultCode)
	if !ok {
		t.Fatalf("Unexpected error type. Want *ErrFailedResultCode, have %T", err)
	}
	if e.ResultCode != diam.ResourcesExceeded {
		t.Fatalf("Unexpected ResultCode. Want %d, have %d", diam.ResourcesExceeded, e.ResultCode)
	}
	g, ok := e.FailedAVP[0].Data.(*diam.GroupedAVP)
	if !ok {
		t.Fatalf("Unexpected type. Want *diam.GroupedAVP, have %T", e.FailedAVP[0].Data)
	}
	d, ok := g.AVP[0].Data.(datatype.Unsigned32)
	if !ok {
		t.Fatalf("Unexpected type. Want *datatype.Unsigned32, have %T", e.FailedAVP[0].Data)
	}
	if d != 1000 {
		t.Fatalf("Wrong value for FailedAVP. Want 1000, have %d", d)
	}
}

func TestCEA_NoCommonApplication(t *testing.T) {
	m := diam.NewMessage(diam.CapabilitiesExchange, 0, 0, 0, 0, dict.Default)
	mustCEAAVP(t, m, avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.Success))
	mustCEAAVP(t, m, avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("foobar"))
	mustCEAAVP(t, m, avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("test"))
	mustCEAAVP(t, m, avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(1))
	mustCEAAVP(t, m, avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(2))
	cea := new(CEA)
	err := cea.Parse(m, Server)
	if err == nil {
		t.Fatal("Broken CEA was parsed with no errors")
	}
	if err != ErrNoCommonApplication {
		t.Fatal("Unexpected error:", err)
	}
}

func TestCEA_FailedAcctAppID(t *testing.T) {
	m := diam.NewMessage(diam.CapabilitiesExchange, 0, 0, 0, 0, nil)
	mustCEAAVP(t, m, avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.Success))
	mustCEAAVP(t, m, avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("foobar"))
	mustCEAAVP(t, m, avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("test"))
	mustCEAAVP(t, m, avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(1))
	mustCEAAVP(t, m, avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1000))
	cea := new(CEA)
	err := cea.Parse(m, Server)
	if err == nil {
		t.Fatal("Broken CEA was parsed with no errors")
	}
	if err != ErrNoCommonApplication {
		t.Fatal("Unexpected error:", err)
	}
}

func TestCEA(t *testing.T) {
	m := diam.NewMessage(diam.CapabilitiesExchange, 0, 0, 0, 0, nil)
	mustCEAAVP(t, m, avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.Success))
	mustCEAAVP(t, m, avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("foobar"))
	mustCEAAVP(t, m, avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("test"))
	mustCEAAVP(t, m, avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(1))
	mustCEAAVP(t, m, avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4))
	cea := new(CEA)
	if err := cea.Parse(m, Server); err != nil {
		t.Fatal(err)
	}
	if cea.ResultCode != diam.Success {
		t.Fatalf("Unexpected Result-Code. Want %d, have %d",
			diam.Success, cea.ResultCode)
	}
	if cea.OriginStateID != 1 {
		t.Fatalf("Unexpected Origin-State-ID. Want 1, have %d", cea.OriginStateID)
	}
	if app := cea.Applications(); len(app) != 1 {
		if app[0] != 4 {
			t.Fatalf("Unexpected app ID. Want 4, have %d", app[0])
		}
	}
}

// TestCommonAppIdCEA tests that at least one CEA AppID exist in the default dictionary
func TestCommonAppIdCEA(t *testing.T) {
	m := diam.NewMessage(diam.CapabilitiesExchange, 0, 0, 0, 0, nil)
	mustCEAAVP(t, m, avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.Success))
	mustCEAAVP(t, m, avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("foobar"))
	mustCEAAVP(t, m, avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("test"))
	mustCEAAVP(t, m, avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(1))
	mustCEAAVP(t, m, avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(20))
	mustCEAAVP(t, m, avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(21))
	mustCEAAVP(t, m, avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(22))
	mustCEAAVP(t, m, avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4))
	mustCEAAVP(t, m, avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(16302))
	mustCEAAVP(t, m, avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(16777223))
	mustCEAAVP(t, m, avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(16777236))
	mustCEAAVP(t, m, avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(16777238))
	mustCEAAVP(t, m, avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(16777266))
	mustCEAAVP(t, m, avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(16777272))
	mustCEAAVP(t, m, avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(2773))
	mustCEAAVP(t, m, avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(30))
	mustCEAAVP(t, m, avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(31))
	mustCEAAVP(t, m, avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(32))
	mustCEAAVP(t, m, avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(33))
	mustCEAAVP(t, m, avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(2))
	mustCEAAVP(t, m, avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(4))

	mustCEAAVP(t, m, avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{
		AVP: []*diam.AVP{
			diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(20)),
			diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(33)),
		},
	})
	mustCEAAVP(t, m, avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{
		AVP: []*diam.AVP{
			diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(22)),
			diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(30)),
		},
	})
	mustCEAAVP(t, m, avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{
		AVP: []*diam.AVP{
			diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(20)),
		},
	})
	mustCEAAVP(t, m, avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{
		AVP: []*diam.AVP{
			diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)),
		},
	})
	mustCEAAVP(t, m, avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{
		AVP: []*diam.AVP{
			diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(16777223)),
		},
	})
	mustCEAAVP(t, m, avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{
		AVP: []*diam.AVP{
			diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(16777236)),
		},
	})
	mustCEAAVP(t, m, avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{
		AVP: []*diam.AVP{
			diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(16777238)),
		},
	})
	mustCEAAVP(t, m, avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{
		AVP: []*diam.AVP{
			diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(16777266)),
		},
	})
	mustCEAAVP(t, m, avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{
		AVP: []*diam.AVP{
			diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(16777272)),
		},
	})
	mustCEAAVP(t, m, avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{
		AVP: []*diam.AVP{
			diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(16302)),
			diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(16302)),
		},
	})
	cea := new(CEA)
	if err := cea.Parse(m, Client); err != nil {
		t.Fatal(err)
	}
	if cea.ResultCode != diam.Success {
		t.Fatalf("Unexpected Result-Code. Want %d, have %d",
			diam.Success, cea.ResultCode)
	}
	if cea.OriginStateID != 1 {
		t.Fatalf("Unexpected Origin-State-ID. Want 1, have %d", cea.OriginStateID)
	}
	if app := cea.Applications(); len(app) != 1 {
		if app[0] != 4 {
			t.Fatalf("Unexpected app ID. Want 4, have %d", app[0])
		}
	}
}

// TestCEACapabilityAVPs verifies that the capability AVPs from RFC 6733 §5.3.2
// (Vendor-Id, Product-Name, Supported-Vendor-Id) are parsed into the CEA struct.
func TestCEACapabilityAVPs(t *testing.T) {
	m := diam.NewMessage(diam.CapabilitiesExchange, 0, 0, 0, 0, nil)
	mustCEAAVP(t, m, avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.Success))
	mustCEAAVP(t, m, avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("foobar"))
	mustCEAAVP(t, m, avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("test"))
	mustCEAAVP(t, m, avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(1))
	mustCEAAVP(t, m, avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(10415))
	mustCEAAVP(t, m, avp.ProductName, 0, 0, datatype.UTF8String("go-diameter"))
	mustCEAAVP(t, m, avp.SupportedVendorID, avp.Mbit, 0, datatype.Unsigned32(10415))
	mustCEAAVP(t, m, avp.SupportedVendorID, avp.Mbit, 0, datatype.Unsigned32(13019))
	mustCEAAVP(t, m, avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4))

	cea := new(CEA)
	if err := cea.Parse(m, Client); err != nil {
		t.Fatal(err)
	}
	if cea.VendorID != 10415 {
		t.Fatalf("Unexpected Vendor-Id. Want 10415, have %d", cea.VendorID)
	}
	if cea.ProductName != "go-diameter" {
		t.Fatalf("Unexpected Product-Name. Want %q, have %q", "go-diameter", cea.ProductName)
	}
	if len(cea.SupportedVendorID) != 2 {
		t.Fatalf("Unexpected Supported-Vendor-Id count. Want 2, have %d", len(cea.SupportedVendorID))
	}
	want := []datatype.Unsigned32{10415, 13019}
	for i, a := range cea.SupportedVendorID {
		v, ok := a.Data.(datatype.Unsigned32)
		if !ok {
			t.Fatalf("Unexpected Supported-Vendor-Id type at %d. Want datatype.Unsigned32, have %T", i, a.Data)
		}
		if v != want[i] {
			t.Fatalf("Unexpected Supported-Vendor-Id at %d. Want %d, have %d", i, want[i], v)
		}
	}
}

// TestCommonAppIdCEA tests that at least one CEA AppID exist in the default dictionary
func TestCEAAutAndAcct(t *testing.T) {
	m := diam.NewMessage(diam.CapabilitiesExchange, 0, 0, 0, 0, nil)
	mustCEAAVP(t, m, avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.Success))
	mustCEAAVP(t, m, avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("foobar"))
	mustCEAAVP(t, m, avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("test"))
	mustCEAAVP(t, m, avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(1))
	mustCEAAVP(t, m, avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4))
	mustCEAAVP(t, m, avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(4))

	cea := new(CEA)
	if err := cea.Parse(m, Client); err != nil {
		t.Fatal(err)
	}
	if cea.ResultCode != diam.Success {
		t.Fatalf("Unexpected Result-Code. Want %d, have %d",
			diam.Success, cea.ResultCode)
	}
	if cea.OriginStateID != 1 {
		t.Fatalf("Unexpected Origin-State-ID. Want 1, have %d", cea.OriginStateID)
	}
	if app := cea.Applications(); len(app) != 1 {
		if app[0] != 4 {
			t.Fatalf("Unexpected app ID. Want 4, have %d", app[0])
		}
	}
}
