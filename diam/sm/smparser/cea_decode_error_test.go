package smparser_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
)

func TestCEANonStrictMalformedHostIPAddress(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
		result  uint32
	}{
		{"missing family", []byte{1}, diam.InvalidAVPLength},
		{"short IPv4", []byte{0, 1, 1, 2, 3}, diam.InvalidAVPValue},
		{"reserved family", []byte{255, 255, 1}, diam.InvalidAVPValue},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := dict.New(dict.Base)
			p.SetStrict(false)
			answer := diam.NewMessage(diam.CapabilitiesExchange, 0, 0, 1, 2, p)
			answer.AddAVP(diam.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.Success)))
			answer.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
			answer.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
			bad := diam.NewAVP(avp.HostIPAddress, avp.Mbit, 0, datatype.Unknown(tc.payload))
			answer.AddAVP(bad)
			answer.AddAVP(diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(0xffffffff)))
			wire, err := answer.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := diam.ReadMessage(bytes.NewReader(wire), p)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.DecodeErr == nil {
				t.Fatal("decoder did not retain malformed Host-IP-Address")
			}
			var cea smparser.CEA
			err = cea.Parse(parsed, smparser.ParseOptions{Role: smparser.Client})
			var messageErr *diam.MessageError
			if !errors.As(err, &messageErr) || messageErr.ResultCode != tc.result || !strings.Contains(err.Error(), "CEA") {
				t.Fatalf("Parse error = %T(%v), want CEA MessageError %d", err, err, tc.result)
			}
			failed := messageErr.FailedAVP
			if failed == nil || failed.Code != avp.HostIPAddress || failed.Flags != avp.Mbit || failed.VendorID != 0 || !bytes.Equal(failed.Data.Serialize(), tc.payload) {
				t.Fatalf("failed AVP = %v, want original Host-IP-Address payload %x", failed, tc.payload)
			}
		})
	}
}
