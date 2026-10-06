// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diam

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

func TestReadMessageClassifiesPayloadLengths(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
	}{
		{"Integer32", 4}, {"Integer64", 8}, {"Unsigned32", 4}, {"Unsigned64", 8},
		{"Float32", 4}, {"Float64", 8}, {"Enumerated", 4}, {"Time", 4}, {"IPv4", 4}, {"IPv6", 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := dict.New(dict.Base)
			xml := fmt.Sprintf(`<diameter><application id="0"><avp name="Payload-Test" code="900001" vendor-id="10415"><data type="%s"/></avp></application></diameter>`, tc.name)
			if err := d.Load(strings.NewReader(xml)); err != nil {
				t.Fatal(err)
			}
			for _, size := range []int{0, tc.size - 1, tc.size, tc.size + 1, 4096} {
				t.Run(fmt.Sprint(size), func(t *testing.T) {
					a := NewAVP(900001, avp.Mbit|avp.Vbit, 10415, datatype.Unknown(bytes.Repeat([]byte{0x11}, size)))
					body, err := a.Serialize()
					if err != nil {
						t.Fatal(err)
					}
					body = append(body, rawAVP(avp.OriginHost, []byte("after.example"))...)
					m, err := ReadMessage(bytes.NewReader(testFramedMessage(t, RequestFlag, body)), d)
					if size == tc.size {
						if err != nil {
							t.Fatal(err)
						}
						return
					}
					me := requirePayloadMessageError(t, m, err, InvalidAVPLength)
					failed := me.FailedAVP
					if failed.Code != a.Code || failed.Flags != a.Flags || failed.VendorID != a.VendorID {
						t.Fatalf("Failed-AVP header = %+v, want %+v", failed, a)
					}
					if !bytes.Equal(failed.Data.Serialize(), a.Data.Serialize()) || failed.Length != a.Length || failed.Len() != a.Len() {
						t.Fatalf("Failed-AVP = %v, want original header length and payload", failed)
					}
					if len(m.AVP) != 2 || m.AVP[1].Code != avp.OriginHost {
						t.Fatalf("decoder did not continue: %v", m.AVP)
					}
					if u, ok := m.AVP[0].Data.(datatype.Unknown); !ok || !bytes.Equal(u, a.Data.Serialize()) {
						t.Fatalf("fallback = %v", m.AVP[0])
					}
				})
			}
		})
	}
}

func TestReadMessageClassifiesAddressFailures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
		result  uint32
	}{
		{"empty", nil, InvalidAVPLength}, {"one byte", []byte{1}, InvalidAVPLength},
		{"family only", []byte{0, 1}, InvalidAVPValue}, {"invalid family", []byte{255, 255, 1}, InvalidAVPValue},
		{"IPv4 short", []byte{0, 1, 127, 0, 0}, InvalidAVPValue}, {"IPv4 long", []byte{0, 1, 127, 0, 0, 1, 0}, InvalidAVPValue},
		{"IPv6 short", []byte{0, 2, 1}, InvalidAVPValue}, {"IPv6 long", append([]byte{0, 2}, make([]byte, 17)...), InvalidAVPValue},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, strict := range []bool{false, true} {
				d := dict.New(dict.Base)
				d.SetStrict(strict)
				m, err := ReadMessage(bytes.NewReader(testFramedMessage(t, RequestFlag, rawAVP(avp.HostIPAddress, tc.payload))), d)
				if !strict {
					if err != nil || m.DecodeErr == nil {
						t.Fatalf("non-strict: message=%v err=%v", m, err)
					}
					continue
				}
				me := requirePayloadMessageError(t, m, err, tc.result)
				want := tc.payload
				if me.FailedAVP.Code != avp.HostIPAddress || !bytes.Equal(me.FailedAVP.Data.Serialize(), want) {
					t.Fatalf("Failed-AVP = %v, want %x", me.FailedAVP, want)
				}
			}
		})
	}
}

func TestReadMessagePayloadFailureHierarchyAndPrecedence(t *testing.T) {
	length := rawAVP(avp.InbandSecurityID, []byte{1, 2})
	value := rawAVP(avp.HostIPAddress, []byte{255, 255, 1})
	framing := []byte{0, 0, 1, 2, avp.Mbit, 255, 255, 255}
	for _, tc := range []struct {
		name    string
		body    []byte
		result  uint32
		leaf    uint32
		nested  bool
		framing bool
	}{
		{"length first", append(append([]byte{}, length...), value...), InvalidAVPLength, avp.InbandSecurityID, false, false},
		{"value first", append(append([]byte{}, value...), length...), InvalidAVPValue, avp.HostIPAddress, false, false},
		{"nested length", append(append([]byte{}, length...), value...), InvalidAVPLength, avp.InbandSecurityID, true, false},
		{"nested value", append(append([]byte{}, value...), length...), InvalidAVPValue, avp.HostIPAddress, true, false},
		{"framing wins", append(append([]byte{}, value...), framing...), InvalidAVPLength, avp.AuthApplicationID, false, true},
		{"nested framing wins", append(append([]byte{}, value...), framing...), InvalidAVPLength, avp.AuthApplicationID, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body
			if tc.nested {
				body = rawAVP(avp.VendorSpecificApplicationID, rawAVP(avp.VendorSpecificApplicationID, body))
			}
			m, err := ReadMessage(bytes.NewReader(testFramedMessage(t, RequestFlag, body)), dict.Default)
			var me *MessageError
			if !errors.As(err, &me) || me.ResultCode != tc.result || me.Fatal {
				t.Fatalf("error=%v, want non-fatal %d", err, tc.result)
			}
			if !tc.framing {
				_ = requirePayloadMessageError(t, m, err, tc.result)
			}
			failed := me.FailedAVP
			if tc.nested {
				for range 2 {
					g, ok := failed.Data.(*GroupedAVP)
					if failed.Code != avp.VendorSpecificApplicationID || !ok || len(g.AVP) != 1 {
						t.Fatalf("hierarchy=%v", failed)
					}
					failed = g.AVP[0]
				}
			}
			if failed.Code != tc.leaf {
				t.Fatalf("leaf=%v, want %d", failed, tc.leaf)
			}
			if me.FailedAVP.Len() > 28 {
				t.Fatalf("Failed-AVP includes siblings: %v", me.FailedAVP)
			}
		})
	}
}

func TestReadMessageGroupedDepthFailure(t *testing.T) {
	d := dict.New(dict.Base)
	d.SetMaxGroupedDepth(2)
	body := rawAVP(avp.VendorSpecificApplicationID, rawAVP(avp.VendorSpecificApplicationID, rawAVP(avp.VendorSpecificApplicationID, rawAVP(avp.OriginHost, bytes.Repeat([]byte{'x'}, 4096)))))
	m, err := ReadMessage(bytes.NewReader(testFramedMessage(t, RequestFlag, body)), d)
	me := requirePayloadMessageError(t, m, err, InvalidAVPValue)
	if !errors.Is(err, errGroupedTooDeep) {
		t.Fatalf("nesting cause lost: %v", err)
	}
	failed := me.FailedAVP
	for range 2 {
		g, ok := failed.Data.(*GroupedAVP)
		if !ok || len(g.AVP) != 1 {
			t.Fatalf("hierarchy=%v", failed)
		}
		failed = g.AVP[0]
	}
	if failed.Code != avp.VendorSpecificApplicationID || failed.Data.Len() != 0 || me.FailedAVP.Len() != 24 {
		t.Fatalf("over-deep payload echoed: %v", me.FailedAVP)
	}
}

func TestReadMessagePayloadErrorText(t *testing.T) {
	body := append(rawAVP(avp.InbandSecurityID, []byte{1, 2}), rawAVP(avp.HostIPAddress, []byte{255, 255, 1})...)
	body = rawAVP(avp.VendorSpecificApplicationID, body)
	m, err := ReadMessage(bytes.NewReader(testFramedMessage(t, RequestFlag, body)), dict.Default)
	_ = requirePayloadMessageError(t, m, err, InvalidAVPLength)
	want := "failed to decode one or more AVPs: {Vendor-Specific-Application-Id(260): Grouped{Inband-Security-Id(299): size mismatch: Unsigned32 expects 4 bytes, wire has 2; Host-IP-Address(257): invalid address type received}}"
	if m.DecodeErr.Error() != want {
		t.Fatalf("DecodeErr = %q, want %q", m.DecodeErr, want)
	}
}

func requirePayloadMessageError(t *testing.T, m *Message, err error, result uint32) *MessageError {
	t.Helper()
	var me *MessageError
	if !errors.As(err, &me) {
		t.Fatalf("ReadMessage error = %T(%v), want *MessageError", err, err)
	}
	if me.ResultCode != result || me.Fatal || me.FailedAVP == nil {
		t.Fatalf("MessageError = %+v, want non-fatal %d with Failed-AVP", me, result)
	}
	if m == nil || m.DecodeErr == nil || !errors.Is(err, m.DecodeErr) {
		t.Fatalf("decode error not preserved: message=%v err=%v", m, err)
	}
	return me
}

func TestReadMessagePayloadDecoderCause(t *testing.T) {
	cause := &payloadDecoderError{}
	for _, typeID := range []datatype.TypeID{datatype.Unsigned32Type, datatype.OctetStringType} {
		t.Run(fmt.Sprint(typeID), func(t *testing.T) {
			original := datatype.Decoder[typeID]
			if err := datatype.RegisterDecoder(typeID, func([]byte) (datatype.Type, error) { return nil, cause }); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := datatype.RegisterDecoder(typeID, original); err != nil {
					t.Error(err)
				}
			})
			code := uint32(avp.InbandSecurityID)
			if typeID == datatype.OctetStringType {
				code = avp.ProxyState
			}
			body := rawAVP(avp.VendorSpecificApplicationID, rawAVP(code, []byte{1, 2, 3, 4}))
			m, err := ReadMessage(bytes.NewReader(testFramedMessage(t, RequestFlag, body)), dict.Default)
			_ = requirePayloadMessageError(t, m, err, InvalidAVPValue)
			var got *payloadDecoderError
			if !errors.Is(err, cause) || !errors.As(err, &got) || got != cause {
				t.Fatalf("decoder cause lost: %v", err)
			}
		})
	}
}

type payloadDecoderError struct{}

func (*payloadDecoderError) Error() string { return "test payload failure" }

func TestReadMessagePayloadFailureSizeBound(t *testing.T) {
	payload := append([]byte{255, 255}, bytes.Repeat([]byte{0x11}, 4096)...)
	leaf := rawAVP(avp.HostIPAddress, payload)
	siblings := rawAVP(avp.OriginHost, bytes.Repeat([]byte{'x'}, 8192))
	body := rawAVP(avp.VendorSpecificApplicationID, append(append(siblings, leaf...), siblings...))
	body = append(body, siblings...)
	m, err := ReadMessage(bytes.NewReader(testFramedMessage(t, RequestFlag, body)), dict.Default)
	me := requirePayloadMessageError(t, m, err, InvalidAVPValue)
	if me.FailedAVP.Len() != 8+len(leaf) {
		t.Fatalf("Failed-AVP length = %d, want parent header + leaf (%d)", me.FailedAVP.Len(), 8+len(leaf))
	}
	g, ok := me.FailedAVP.Data.(*GroupedAVP)
	if !ok || len(g.AVP) != 1 || !bytes.Equal(g.AVP[0].Data.Serialize(), payload) {
		t.Fatalf("Failed-AVP = %v", me.FailedAVP)
	}
}
