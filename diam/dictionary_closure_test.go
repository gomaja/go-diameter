package diam

import (
	"bytes"
	"net"
	"testing"

	"github.com/gomaja/go-diameter/diam/dict"
)

// 3GPP TS 32.299 V19.0.0 §§7.2, 7.3, 7.4 and the defining documents
// cited beside the XML definitions.
func TestChargingDictionaryClosureWire(t *testing.T) {
	for _, tc := range []struct {
		name     string
		code     uint32
		vendor   uint32
		typeName string
	}{
		{"Application-Port-Identifier", 3010, 10415, "Unsigned32"},
		{"Conditional-APN-Aggregate-Max-Bitrate", 2818, 10415, "Grouped"},
		{"DCD-Information", 2115, 10415, "Grouped"},
		{"Flow-Number", 509, 10415, "Unsigned32"},
		{"IM-Information", 2110, 10415, "Grouped"},
		{"Logical-Access-ID", 302, 13019, "OctetString"},
		{"Media-Component-Number", 518, 10415, "Unsigned32"},
		{"Physical-Access-ID", 313, 13019, "UTF8String"},
		{"Presence-Reporting-Area-Elements-List", 2820, 10415, "OctetString"},
		{"Service-Generic-Information", 1256, 10415, "Grouped"},
		{"3GPP2-BSID", 9010, 5535, "UTF8String"},
		{"3GPP2-MEID", 1471, 10415, "OctetString"},
		{"MSC-Number", 2403, 10415, "OctetString"},
		{"SGSN-Name", 2409, 10415, "DiameterIdentity"},
		{"SGSN-Realm", 2410, 10415, "DiameterIdentity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := dict.Default.FindAVP(4, tc.name)
			if err != nil || d.Code != tc.code || d.VendorID != tc.vendor || d.Data.TypeName != tc.typeName {
				t.Fatalf("definition: %v, %v", d, err)
			}
			msg := NewRequest(CreditControl, 4, dict.Default)
			msg.AddAVP(smsAVP(t, 4, tc.name))
			wire, err := msg.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			got, err := ReadMessage(bytes.NewReader(wire), dict.Default)
			if err != nil || got.DecodeErr != nil {
				t.Fatalf("decode: %v, %v", err, got.DecodeErr)
			}
			if got.AVP[0].Data.Type() != msg.AVP[0].Data.Type() {
				t.Fatalf("type changed: %T -> %T", msg.AVP[0].Data, got.AVP[0].Data)
			}
			left, right := net.Pipe()
			done := make(chan error, 1)
			go func() { _, e := msg.WriteTo(left); done <- e }()
			fromConn, err := ReadMessage(right, dict.Default)
			_ = left.Close()
			_ = right.Close()
			if writeErr := <-done; writeErr != nil {
				t.Fatal(writeErr)
			}
			if err != nil {
				t.Fatal(err)
			}
			if fromConn.DecodeErr != nil || len(fromConn.AVP) != 1 || fromConn.AVP[0].Data.Type() != msg.AVP[0].Data.Type() {
				t.Fatalf("connection decode: %v", fromConn.DecodeErr)
			}
		})
	}
}

// 3GPP TS 29.272 V19.5.0 §§7.3.47, 7.3.83, 7.3.106-116, 7.3.156,
// 7.3.184, 7.3.196, 7.3.199, with reused AVPs from TS 29.273 and 29.336.
func TestS6aDictionaryClosureWire(t *testing.T) {
	const appID = 16777251
	for _, tc := range []struct {
		name     string
		code     uint32
		typeName string
	}{
		{"Alert-Reason", 1434, "Enumerated"},
		{"EPS-Location-Information", 1496, "Grouped"},
		{"EPS-User-State", 1495, "Grouped"},
		{"Emergency-Services", 1538, "Unsigned32"},
		{"IDA-Flags", 1441, "Unsigned32"},
		{"IMS-Voice-Over-PS-Sessions-Supported", 1492, "Enumerated"},
		{"Last-UE-Activity-Time", 1494, "Time"},
		{"Local-Time-Zone", 1649, "Grouped"},
		{"Maximum-UE-Availability-Time", 3329, "Time"},
		{"Monitoring-Event-Config-Status", 3142, "Grouped"},
		{"Monitoring-Event-Report", 3123, "Grouped"},
		{"Reset-ID", 1670, "OctetString"},
		{"Supported-Services", 3143, "Grouped"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := dict.Default.FindAVP(appID, tc.name)
			if err != nil || d.Code != tc.code || d.VendorID != 10415 || d.Data.TypeName != tc.typeName {
				t.Fatalf("definition: %v, %v", d, err)
			}
			msg := NewRequest(319, appID, dict.Default)
			msg.AddAVP(smsAVP(t, appID, tc.name))
			wire, err := msg.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			got, err := ReadMessage(bytes.NewReader(wire), dict.Default)
			if err != nil {
				t.Fatal(err)
			}
			if got.DecodeErr != nil || len(got.AVP) != 1 || got.AVP[0].Data.Type() != msg.AVP[0].Data.Type() {
				t.Fatalf("decode: %v", got.DecodeErr)
			}
			left, right := net.Pipe()
			done := make(chan error, 1)
			go func() { _, e := msg.WriteTo(left); done <- e }()
			fromConn, err := ReadMessage(right, dict.Default)
			_ = left.Close()
			_ = right.Close()
			if writeErr := <-done; writeErr != nil {
				t.Fatal(writeErr)
			}
			if err != nil {
				t.Fatal(err)
			}
			if fromConn.DecodeErr != nil || len(fromConn.AVP) != 1 || fromConn.AVP[0].Data.Type() != msg.AVP[0].Data.Type() {
				t.Fatalf("connection decode: %v", fromConn.DecodeErr)
			}
		})
	}
}
