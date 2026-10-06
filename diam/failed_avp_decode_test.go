// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diam

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

func TestReadMessageAcceptsFailedAVPPayloads(t *testing.T) {
	for _, nested := range []bool{false, true} {
		for _, leaf := range [][]byte{rawAVP(avp.InbandSecurityID, []byte{1, 2}), rawAVP(avp.HostIPAddress, []byte{255, 255, 1})} {
			payload := leaf
			if nested {
				payload = rawAVP(avp.VendorSpecificApplicationID, leaf)
			}
			body := append(rawAVP(avp.FailedAVP, payload), rawAVP(avp.OriginHost, []byte("after.example"))...)
			m, err := ReadMessage(bytes.NewReader(testFramedMessage(t, 0, body)), dict.Default)
			if err != nil || m.DecodeErr != nil {
				t.Fatalf("Failed-AVP payload rejected: %v, DecodeErr=%v", err, m.DecodeErr)
			}
			g, ok := m.AVP[0].Data.(*GroupedAVP)
			if !ok || len(g.AVP) != 1 {
				t.Fatalf("Failed-AVP = %v", m.AVP[0])
			}
			if !bytes.Equal(g.Serialize(), payload) {
				t.Fatalf("Failed-AVP bytes = %x, want %x", g.Serialize(), payload)
			}
			child := g.AVP[0]
			if nested {
				inner, ok := child.Data.(*GroupedAVP)
				if !ok || len(inner.AVP) != 1 {
					t.Fatalf("nested hierarchy = %v", child)
				}
				child = inner.AVP[0]
			}
			if _, ok := child.Data.(datatype.Unknown); !ok {
				t.Fatalf("failed member data = %T, want Unknown", child.Data)
			}
			if len(m.AVP) != 2 || m.AVP[1].Code != avp.OriginHost {
				t.Fatalf("following AVP lost: %v", m.AVP)
			}
		}
	}
}

func TestReadMessageMalformedAnswerReturnsDecodeErr(t *testing.T) {
	for _, body := range [][]byte{rawAVP(avp.InbandSecurityID, []byte{1, 2}), rawAVP(avp.HostIPAddress, []byte{255, 255, 1})} {
		// Failed-AVP payload leniency must not extend to its siblings.
		body = append(rawAVP(avp.FailedAVP, rawAVP(avp.HostIPAddress, []byte{255, 255, 1})), body...)
		m, err := ReadMessage(bytes.NewReader(testFramedMessage(t, 0, body)), dict.Default)
		var me *MessageError
		if err == nil || errors.As(err, &me) || err != m.DecodeErr {
			t.Fatalf("malformed answer error = %T(%v), want plain DecodeErr", err, err)
		}
		if strings.Contains(m.DecodeErr.Error(), "Failed-AVP") {
			t.Fatalf("Failed-AVP polluted DecodeErr: %v", m.DecodeErr)
		}
	}
}

func TestFailedAVPLeniencyIsVendorScoped(t *testing.T) {
	d, err := dict.NewParser("dict/testdata/base.xml")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Load(strings.NewReader(`<diameter><application id="0"><avp name="Vendor-Group" code="279" vendor-id="10415"><data type="Grouped"/></avp></application></diameter>`)); err != nil {
		t.Fatal(err)
	}
	body, err := NewAVP(avp.FailedAVP, avp.Mbit, 10415, datatype.Unknown(rawAVP(avp.InbandSecurityID, []byte{1, 2}))).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	m, err := ReadMessage(bytes.NewReader(testFramedMessage(t, RequestFlag, body)), d)
	_ = requirePayloadMessageError(t, m, err, InvalidAVPLength)
}

func TestFailedAVPStillEnforcesFramingAndDepth(t *testing.T) {
	d, err := dict.NewParser("dict/testdata/base.xml")
	if err != nil {
		t.Fatal(err)
	}
	d.MaxGroupedDepth = 2
	for _, tc := range []struct {
		name    string
		payload []byte
		depth   bool
	}{
		{"overlong member", []byte{0, 0, 1, 2, avp.Mbit, 255, 255, 255}, false},
		{"truncated header", []byte{0, 0, 1, 2}, false},
		{"missing padding", rawAVP(avp.InbandSecurityID, []byte{1, 2})[:10], false},
		{"nested framing", rawAVP(avp.VendorSpecificApplicationID, []byte{0, 0, 1, 2}), false},
		{"nesting limit", rawAVP(avp.VendorSpecificApplicationID, rawAVP(avp.VendorSpecificApplicationID, nil)), true},
		{"payload then nesting limit", append(rawAVP(avp.HostIPAddress, []byte{255, 255, 1}), rawAVP(avp.VendorSpecificApplicationID, rawAVP(avp.VendorSpecificApplicationID, nil))...), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := ReadMessage(bytes.NewReader(testFramedMessage(t, 0, rawAVP(avp.FailedAVP, tc.payload))), d)
			if err == nil {
				t.Fatal("Failed-AVP bypassed framing or nesting limit")
			}
			if tc.depth {
				if !errors.Is(err, errGroupedTooDeep) || err != m.DecodeErr {
					t.Fatalf("nesting error = %v, want plain nesting DecodeErr", err)
				}
				return
			}
			var me *MessageError
			if !errors.As(err, &me) || me.ResultCode != InvalidAVPLength {
				t.Fatalf("framing error = %v", err)
			}
		})
	}
}
