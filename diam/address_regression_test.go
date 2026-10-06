// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diam

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

func TestAddressE164DecodeValidate(t *testing.T) {
	for _, digits := range []string{"12", "12345678901234"} {
		t.Run(digits, func(t *testing.T) {
			payload := append([]byte{0, 8}, []byte(digits)...)
			// Originator-SCCP-Address is an Address AVP; validate its payload independently of
			// application grammar (RFC 6733 §4.3.1).
			wire, err := NewAVP(avp.OriginatorSCCPAddress, avp.Vbit|avp.Mbit, 10415, datatype.Unknown(payload)).Serialize()
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeAVP(wire, 4, dict.Default)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decoded.Data.Serialize(), payload) {
				t.Fatalf("payload changed: %x", decoded.Data.Serialize())
			}
			if err := validateAVPs([]*AVP{decoded}, []*dict.Rule{{AVP: "AVP"}}, 4, dict.Default.Snapshot()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMissingAddressMinimum(t *testing.T) {
	definition, err := dict.Default.FindAVPByCode(0, avp.HostIPAddress, 0)
	if err != nil {
		t.Fatal(err)
	}
	example := missingAVPExample(definition, 0, dict.Default.Snapshot(), make(map[validationKey]bool))
	if got := example.Data.Serialize(); !bytes.Equal(got, []byte{0, 0}) {
		t.Fatalf("missing Address payload = %x, want minimum zero family", got)
	}
}
