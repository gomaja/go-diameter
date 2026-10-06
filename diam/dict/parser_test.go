// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package dict

import (
	"os"
	"strings"
	"testing"
)

var testDicts = []string{
	"./bundled/base.xml",
	"./bundled/credit_control.xml",
	"./bundled/network_access_server.xml",
	"./bundled/tgpp_ro_rf.xml",
	"./bundled/tgpp_s6a.xml",
	"./bundled/tgpp_swx.xml"}

func TestNewParser(t *testing.T) {
	for _, dict := range testDicts {
		p, err := NewParser(dict)
		if err != nil {
			t.Fatalf("Error Creating Parser from %s: %s", dict, err)
		}
		t.Log(p)
	}
}

// TS 29.214 §5.3.0 and §5.4.0: Rx AVPs with V set carry a vendor ID.
func TestDefaultDictVendorID(t *testing.T) {
	for _, app := range Default.Apps() {
		for _, avp := range app.AVP {
			if strings.Contains(avp.Must, "V") && avp.VendorID == 0 {
				t.Errorf("app %d: AVP %s (%d) has V in must but no vendor-id", app.ID, avp.Name, avp.Code)
			}
		}
	}
}

func TestRxVendorIDs(t *testing.T) {
	// TS 29.214 §5.3.0 (defined AVPs) and §5.4.0 (reused AVPs).
	const rxAppID, vendorID = 16777236, 10415
	for _, tc := range []struct {
		name string
		code uint32
	}{
		{"IMS-Content-Identifier", 563}, {"IMS-Content-Type", 564},
		{"AN-Trusted", 1503}, {"User-Location-Info-Time", 2812},
		{"RAN-NAS-Release-Cause", 2819}, {"TWAN-Identifier", 29},
		{"TCP-Source-Port", 2843}, {"UDP-Source-Port", 2806},
		{"UE-Local-IP-Address", 2805},
	} {
		for _, source := range []struct {
			name string
			load func() (*Parser, error)
		}{
			{"embedded", func() (*Parser, error) { return Default, nil }},
			{"selected", func() (*Parser, error) { return New(Rx), nil }},
		} {
			p, err := source.load()
			if err != nil {
				t.Fatal(err)
			}
			avp, err := p.FindAVPWithVendor(rxAppID, tc.code, vendorID)
			if err != nil || avp.Name != tc.name || avp.VendorID != vendorID {
				t.Errorf("%s: %s (%d) vendor lookup = %v, %v", source.name, tc.name, tc.code, avp, err)
			}
		}
	}
}

func TestS6aReusedIETFAVPsHaveNoVendor(t *testing.T) {
	// TS 29.272 Table 7.3.1/2 and §§7.3.36, 7.3.42, 7.3.45.
	const s6aAppID = 16777251
	for _, source := range []struct {
		name string
		load func() (*Parser, error)
	}{
		{"embedded", func() (*Parser, error) { return Default, nil }},
		{"selected", func() (*Parser, error) { return New(S6a), nil }},
	} {
		p, err := source.load()
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name string
			code uint32
		}{
			{"MIP-Home-Agent-Address", 334},
			{"MIP6-Agent-Info", 486},
			{"Service-Selection", 493},
		} {
			avp, err := p.FindAVPWithVendor(s6aAppID, tc.code, 0)
			if err != nil || avp.Name != tc.name || avp.VendorID != 0 {
				t.Errorf("%s: %s (%d) vendor-zero lookup = %v, %v", source.name, tc.name, tc.code, avp, err)
			}
		}
	}
}

func TestLoadFile(t *testing.T) {
	for _, dict := range testDicts {
		p, err := NewParser()
		if err != nil {
			t.Fatal(err)
		}
		if err := p.LoadFile(dict); err != nil {
			t.Fatalf("Error Loading %s: %s", dict, err)
		}
	}
}

func TestLoad(t *testing.T) {
	for _, dict := range testDicts {
		f, err := os.Open(dict)
		if err != nil {
			t.Fatalf("Error Opening %s: %s", dict, err)
		}
		p, _ := NewParser()
		if err = p.Load(f); err != nil {
			t.Fatalf("Error Loading Parsing %s: %s", dict, err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("Error Closing %s: %s", dict, err)
		}
	}
}
