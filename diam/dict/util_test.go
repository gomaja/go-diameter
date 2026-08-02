// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package dict

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-diameter/diam/datatype"
)

func TestApps(t *testing.T) {
	apps := Default.Apps()
	if len(apps) != 11 {
		t.Fatalf("Unexpected # of apps. Want 11, have %d", len(apps))
	}
	// Base protocol.
	if apps[0].ID != 0 {
		t.Fatalf("Unexpected app.ID. Want 0, have %d", apps[0].ID)
	}
	// Base accounting
	if apps[1].ID != 3 {
		t.Fatalf("Unexpected app.ID. Want 3, have %d", apps[1].ID)
	}
	// Credit-Control applications.
	if apps[2].ID != 4 {
		t.Fatalf("Unexpected app.ID. Want 4, have %d", apps[2].ID)
	}
	// Diameter Sy application.
	if apps[3].ID != 16777302 {
		t.Fatalf("Unexpected app.ID. Want 16777302, have %d", apps[3].ID)
	}
	// 3GPP Gx Charging Control applications
	if apps[4].ID != 16777238 {
		t.Fatalf("Unexpected app.ID. Want 16777238, have %d", apps[4].ID)
	}
	// NASREQ applications
	if apps[5].ID != 1 {
		t.Fatalf("Unexpected app.ID. Want 1, have %d", apps[5].ID)
	}
	// 3GPP Rx applications
	if apps[7].ID != 16777236 {
		t.Fatalf("Unexpected app.ID. Want 16777236, have %d", apps[7].ID)
	}
	// 3GPP S6a applications
	if apps[8].ID != 16777251 {
		t.Fatalf("Unexpected app.ID. Want 16777251, have %d", apps[8].ID)
	}
	// 3GPP S13 application
	if apps[9].ID != 16777252 {
		t.Fatalf("Unexpected app.ID. Want 16777252, have %d", apps[9].ID)
	}
	if apps[10].ID != 16777265 {
		t.Fatalf("Unexpected app.ID. Want 16777265, have %d", apps[10].ID)
	}
}

func TestApp(t *testing.T) {
	// Base protocol.
	if _, err := Default.App(0); err != nil {
		t.Fatal(err)
	}
	// Credit-Control applications.
	if _, err := Default.App(4); err != nil {
		t.Fatal(err)
	}
	// Diameter Sy application.
	if _, err := Default.App(16777302); err != nil {
		t.Fatal(err)
	}
}

func findAVPCodeTest(t *testing.T, app uint32, codeStr string, vendor, expectedCode uint32) {
	if avp, err := Default.FindAVPWithVendor(app, codeStr, vendor); err != nil {
		t.Fatalf("FindAVP error: %v for app %d & %s AVP", err, app, codeStr)
	} else if avp.Code != expectedCode {
		t.Fatalf(
			"Unexpected code %d for %s AVP and %d vendor. Expected: %d",
			avp.Code, codeStr, vendor, expectedCode)
	}
}

func TestFindAVPWithVendor(t *testing.T) {
	var nokiaXML = `<?xml version="1.0" encoding="UTF-8"?>
<diameter>
  <application id="43">
    <vendor id="94" name="Nokia" />
    <avp name="Session-Start-Indicator" code="5105" must="V" may="P,M" must-not="-" may-encrypt="N" vendor-id="94">
      <data type="UTF8String" />
    </avp>
  </application>
</diameter>`
	if err := Default.Load(bytes.NewReader([]byte(nokiaXML))); err != nil {
		t.Fatal(err)
	}
	if _, err := Default.FindAVPWithVendor(4, 999, UndefinedVendorID); err == nil {
		t.Error("Should get not found")
	}
	findAVPCodeTest(t, 4, "Session-Id", UndefinedVendorID, 263)
	findAVPCodeTest(t, 43, "Session-Start-Indicator", 94, 5105)
	findAVPCodeTest(t, 43, "Session-Start-Indicator", UndefinedVendorID, 5105)

	if _, err := Default.FindAVPWithVendor(4, "Session-Start-Indicator", 0); err == nil {
		t.Error("Should get not found")
	}
	findAVPCodeTest(t, 16777251, "Supported-Features", UndefinedVendorID, 628)

	// Test 'parent' AVP find - S6a app ID, tgpp_ro_rf dictionary
	findAVPCodeTest(t, 16777251, "GMLC-Address", UndefinedVendorID, 2405)

	if _, err := Default.FindAVPWithVendor(43, "User-Password", UndefinedVendorID); err == nil {
		t.Error("User-Password Should not be found for app 43")
	}
	findAVPCodeTest(t, 1, "User-Password", UndefinedVendorID, 2)
	findAVPCodeTest(t, 4, "User-Password", UndefinedVendorID, 2)
	findAVPCodeTest(t, 16777251, "User-Password", UndefinedVendorID, 2)
}

func TestFindAVP(t *testing.T) {
	if _, err := Default.FindAVP(999, 263); err != nil {
		t.Fatal(err)
	}
}

func TestScanAVP(t *testing.T) {
	if avp, err := Default.ScanAVP("Session-Id"); err != nil {
		t.Error(err)
	} else if avp.Code != 263 {
		t.Fatalf("Unexpected code %d for Session-Id AVP", avp.Code)
	}
}

func TestFindCommand(t *testing.T) {
	if cmd, err := Default.FindCommand(999, 257); err != nil {
		t.Error(err)
	} else if cmd.Short != "CE" {
		t.Fatalf("Unexpected command: %#v", cmd)
	}

	if cmd, err := Default.FindCommand(16777251, 316); err != nil {
		t.Error(err)
	} else if cmd.Short != "UL" {
		t.Fatalf("Unexpected command: %#v", cmd)
	}

	if cmd, err := Default.FindCommand(16777251, 318); err != nil {
		t.Error(err)
	} else if cmd.Short != "AI" {
		t.Fatalf("Unexpected command: %#v", cmd)
	}
}

func TestEnum(t *testing.T) {
	if item, err := Default.Enum(0, 274, 1); err != nil {
		t.Fatal(err)
	} else if item.Name != "AUTHENTICATE_ONLY" {
		t.Errorf(
			"Unexpected value %s, expected AUTHENTICATE_ONLY",
			item.Name,
		)
	}
}

func TestRule(t *testing.T) {
	if rule, err := Default.Rule(0, 284, "Proxy-Host"); err != nil {
		t.Fatal(err)
	} else if !rule.Required {
		t.Errorf("Unexpected rule %#v", rule)
	}
}

func TestFindAVPWithVendorNoInfiniteRecursion(t *testing.T) {
	// Looking up a non-existent AVP with a specific vendor ID should return
	// an Unknown AVP instead of causing infinite recursion between
	// FindAVPWithVendor and FindAVP.
	avp, _ := Default.FindAVPWithVendor(4, uint32(99999), 12345)
	if avp == nil {
		t.Fatal("Expected Unknown AVP, got nil")
	}
	if avp.Name != "Unknown-99999-12345" {
		t.Fatalf("Expected Unknown-99999-12345 AVP, got %s", avp.Name)
	}

	// A vendor-specific code must not cross-resolve to a base AVP with the
	// same numeric code (RFC 6733 §4.1/§11.1.1).
	avp, err := Default.FindAVPWithVendor(4, uint32(5), 10415)
	if err == nil {
		t.Fatal("Expected error for unknown vendor AVP code 5 / vendor 10415")
	}
	if avp == nil {
		t.Fatal("Expected Unknown AVP, got nil")
	}
	if avp.Name != "Unknown-5-10415" {
		t.Fatalf("Expected Unknown-5-10415 AVP, got %s", avp.Name)
	}
	if avp.Data.Type != datatype.UnknownType {
		t.Fatalf("Expected Unknown data type, got %v", avp.Data.Type)
	}
}

func TestFindAVPByCode(t *testing.T) {
	// Exact (appid, code, vendorID) match.
	if avp, err := Default.FindAVPByCode(4, 461, UndefinedVendorID); err != nil {
		t.Fatalf("FindAVPByCode error for Service-Context-Id: %v", err)
	} else if avp.Name != "Service-Context-Id" {
		t.Fatalf("Unexpected AVP %q, expected Service-Context-Id", avp.Name)
	}

	// Inherited base AVP (app 4 → base) resolves via the pre-merged index.
	if avp, err := Default.FindAVPByCode(4, 263, 0); err != nil {
		t.Fatalf("FindAVPByCode error for inherited Session-Id: %v", err)
	} else if avp.Name != "Session-Id" {
		t.Fatalf("Unexpected AVP %q, expected Session-Id", avp.Name)
	}

	// Base AVPs decode even when the application dictionary is not loaded
	// because RFC 6733 §2 applies base AVP rules to all Diameter messages.
	if avp, err := Default.FindAVPByCode(16777216, 263, 0); err != nil {
		t.Fatalf("FindAVPByCode error for unregistered-app Session-Id: %v", err)
	} else if avp.Name != "Session-Id" {
		t.Fatalf("Unexpected AVP %q, expected Session-Id", avp.Name)
	}

	// Inheritance through the full parent chain: Gx (16777238) → 4 → base.
	if avp, err := Default.FindAVPByCode(16777238, 264, 0); err != nil {
		t.Fatalf("FindAVPByCode error for inherited Origin-Host: %v", err)
	} else if avp.Name != "Origin-Host" {
		t.Fatalf("Unexpected AVP %q, expected Origin-Host", avp.Name)
	}

	// Unknown vendor AVP resolves to Unknown, not cross-vendor to base NAS-Port (code 5, vendor 0).
	avp, err := Default.FindAVPByCode(4, 5, 10415)
	if err == nil {
		t.Fatal("Expected error for unknown vendor AVP code 5 / vendor 10415")
	}
	if avp == nil {
		t.Fatal("Expected Unknown AVP, got nil")
	}
	if avp.Name != "Unknown-5-10415" {
		t.Fatalf("Expected Unknown-5-10415, got %q (cross-vendor mismatch)", avp.Name)
	}
	if avp.Data.Type != datatype.UnknownType {
		t.Fatalf("Expected Unknown data type, got %v", avp.Data.Type)
	}
}

func TestCreditControlRFC8506AVPs(t *testing.T) {
	tests := []struct {
		name     string
		code     uint32
		typeName string
	}{
		{"User-Equipment-Info-Extension", 653, "Grouped"},
		{"User-Equipment-Info-IMEISV", 654, "OctetString"},
		{"User-Equipment-Info-MAC", 655, "OctetString"},
		{"User-Equipment-Info-EUI64", 656, "OctetString"},
		{"User-Equipment-Info-ModifiedEUI64", 657, "OctetString"},
		{"User-Equipment-Info-IMEI", 658, "OctetString"},
		{"Subscription-Id-Extension", 659, "Grouped"},
		{"Subscription-Id-E164", 660, "UTF8String"},
		{"Subscription-Id-IMSI", 661, "UTF8String"},
		{"Subscription-Id-SIP-URI", 662, "UTF8String"},
		{"Subscription-Id-NAI", 663, "UTF8String"},
		{"Subscription-Id-Private", 664, "UTF8String"},
		{"Redirect-Server-Extension", 665, "Grouped"},
		{"Redirect-Address-IPAddress", 666, "Address"},
		{"Redirect-Address-URL", 667, "UTF8String"},
		{"Redirect-Address-SIP-URI", 668, "UTF8String"},
		{"QoS-Final-Unit-Indication", 669, "Grouped"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			avp, err := Default.FindAVPByCode(4, tt.code, UndefinedVendorID)
			if err != nil {
				t.Fatalf("FindAVPByCode(%d): %v", tt.code, err)
			}
			if avp.Name != tt.name {
				t.Fatalf("Name = %q, want %q", avp.Name, tt.name)
			}
			if avp.Data.TypeName != tt.typeName {
				t.Fatalf("TypeName = %q, want %q", avp.Data.TypeName, tt.typeName)
			}
		})
	}
}

func TestCreditControlRFC8506Occurrences(t *testing.T) {
	cmd, err := Default.FindCommand(4, 272)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		rule []*Rule
		avp  string
		max  int
	}{
		{"CCR subscription id", cmd.Request.Rule, "Subscription-Id", 0},
		{"CCR subscription extension", cmd.Request.Rule, "Subscription-Id-Extension", 0},
		{"CCR used units", cmd.Request.Rule, "Used-Service-Unit", 0},
		{"CCR multiple services", cmd.Request.Rule, "Multiple-Services-Credit-Control", 0},
		{"CCR service parameters", cmd.Request.Rule, "Service-Parameter-Info", 0},
		{"CCA multiple services", cmd.Answer.Rule, "Multiple-Services-Credit-Control", 0},
		{"CCA QoS final unit", cmd.Answer.Rule, "QoS-Final-Unit-Indication", 1},
		{"CCA failed avp", cmd.Answer.Rule, "Failed-AVP", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got *Rule
			for _, rule := range tt.rule {
				if rule.AVP == tt.avp {
					got = rule
					break
				}
			}
			if got == nil {
				t.Fatalf("missing rule for %s", tt.avp)
			}
			if got.Max != tt.max {
				t.Fatalf("Max = %d, want %d", got.Max, tt.max)
			}
		})
	}
}

func TestCreditControlRFC8506QoSReferences(t *testing.T) {
	avp, err := Default.FindAVPByCode(4, 509, UndefinedVendorID)
	if err != nil {
		t.Fatal(err)
	}
	if avp.Name != "Filter-Rule" {
		t.Fatalf("Name = %q, want Filter-Rule", avp.Name)
	}
	if avp.Data.TypeName != "Grouped" {
		t.Fatalf("TypeName = %q, want Grouped", avp.Data.TypeName)
	}
}

func BenchmarkFindAVPName(b *testing.B) {
	for n := 0; n < b.N; n++ {
		if _, err := Default.FindAVP(0, "Session-Id"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFindAVPCode(b *testing.B) {
	for n := 0; n < b.N; n++ {
		if _, err := Default.FindAVP(0, 263); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkScanAVPName(b *testing.B) {
	for n := 0; n < b.N; n++ {
		if _, err := Default.ScanAVP("Session-Id"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkScanAVPCode(b *testing.B) {
	for n := 0; n < b.N; n++ {
		if _, err := Default.ScanAVP(263); err != nil {
			b.Fatal(err)
		}
	}
}
