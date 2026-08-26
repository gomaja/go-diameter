// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diam

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

func TestDecodeHeaderClassifiesMessageErrors(t *testing.T) {
	tests := []struct {
		name       string
		version    uint8
		length     uint32
		resultCode uint32
	}{
		{name: "unsupported version", version: 2, length: HeaderLength, resultCode: UnsupportedVersion},
		{name: "length below header", version: 1, length: 0, resultCode: InvalidMessageLength},
		{name: "unaligned length", version: 1, length: HeaderLength + 1, resultCode: InvalidMessageLength},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := testMessageHeader(tt.version, tt.length, RequestFlag)
			_, err := DecodeHeader(wire)
			var messageErr *MessageError
			if !errors.As(err, &messageErr) {
				t.Fatalf("DecodeHeader error = %T(%v), want *MessageError", err, err)
			}
			if messageErr.ResultCode != tt.resultCode {
				t.Fatalf("ResultCode = %d, want %d", messageErr.ResultCode, tt.resultCode)
			}
			if !messageErr.Fatal {
				t.Fatal("header MessageError is not fatal")
			}
			if messageErr.FailedAVP != nil {
				t.Fatalf("FailedAVP = %v, want nil", messageErr.FailedAVP)
			}
		})
	}
}

func TestReadMessagePreservesDecodedHeaderOnMessageError(t *testing.T) {
	wire := testMessageHeader(2, HeaderLength, RequestFlag|ProxiableFlag)
	m, err := ReadMessage(bytes.NewReader(wire), dict.Default)
	var messageErr *MessageError
	if !errors.As(err, &messageErr) {
		t.Fatalf("ReadMessage error = %T(%v), want *MessageError", err, err)
	}
	if m == nil || m.Header == nil {
		t.Fatal("ReadMessage did not return the decoded header")
	}
	if m.Header.Version != 2 || m.Header.CommandCode != CapabilitiesExchange {
		t.Fatalf("decoded header = %+v", m.Header)
	}
	if m.Header.HopByHopID != 0x01020304 || m.Header.EndToEndID != 0x05060708 {
		t.Fatalf("decoded identifiers = %#x/%#x", m.Header.HopByHopID, m.Header.EndToEndID)
	}
}

func TestReadMessagePreservesStreamOnHeaderMessageError(t *testing.T) {
	reader := &messageErrorMultistreamReader{
		Reader: bytes.NewReader(testMessageHeader(2, HeaderLength, RequestFlag)),
		stream: 7,
	}
	m, err := ReadMessage(reader, dict.Default)
	var messageErr *MessageError
	if !errors.As(err, &messageErr) {
		t.Fatalf("ReadMessage error = %T(%v), want *MessageError", err, err)
	}
	if m == nil {
		t.Fatal("ReadMessage returned a nil message")
	}
	if got := m.MessageStream(); got != reader.stream {
		t.Fatalf("MessageStream = %d, want %d", got, reader.stream)
	}
}

func TestReadMessageClassifiesInvalidAVPLength(t *testing.T) {
	tests := []struct {
		name            string
		body            []byte
		failedCode      uint32
		failedFlags     uint8
		failedDataBytes int
		maxFailedLen    int
	}{
		{
			name: "declared payload exceeds message",
			body: []byte{
				0x00, 0x00, 0x01, 0x02,
				avp.Mbit, 0xff, 0xff, 0xff,
			},
			failedCode:      avp.AuthApplicationID,
			failedFlags:     avp.Mbit,
			failedDataBytes: 4,
			maxFailedLen:    12,
		},
		{
			name: "incomplete base header",
			body: []byte{
				0x00, 0x00, 0x01, 0x08,
			},
			failedCode:   avp.OriginHost,
			maxFailedLen: 8,
		},
		{
			name: "incomplete vendor header",
			body: []byte{
				0x00, 0x00, 0x01, 0x02,
				avp.Vbit | avp.Mbit, 0x00, 0x00, 0x0c,
			},
			failedCode:      avp.AuthApplicationID,
			failedFlags:     avp.Vbit | avp.Mbit,
			failedDataBytes: 4,
			maxFailedLen:    16,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := testFramedMessage(t, RequestFlag, tt.body)
			m, err := ReadMessage(bytes.NewReader(wire), dict.Default)
			var messageErr *MessageError
			if !errors.As(err, &messageErr) {
				t.Fatalf("ReadMessage error = %T(%v), want *MessageError", err, err)
			}
			if m == nil || m.Header == nil {
				t.Fatal("ReadMessage did not preserve the message header")
			}
			if messageErr.ResultCode != InvalidAVPLength {
				t.Fatalf("ResultCode = %d, want %d", messageErr.ResultCode, InvalidAVPLength)
			}
			if messageErr.Fatal {
				t.Fatal("AVP-local MessageError is fatal after the complete body was read")
			}
			failed := messageErr.FailedAVP
			if failed == nil {
				t.Fatal("FailedAVP is nil")
			}
			if failed.Code != tt.failedCode || failed.Flags != tt.failedFlags {
				t.Fatalf("FailedAVP code/flags = %d/%#x, want %d/%#x", failed.Code, failed.Flags, tt.failedCode, tt.failedFlags)
			}
			raw, ok := failed.Data.(datatype.Unknown)
			if !ok {
				t.Fatalf("FailedAVP data = %T, want datatype.Unknown", failed.Data)
			}
			if len(raw) != tt.failedDataBytes {
				t.Fatalf("FailedAVP payload length = %d, want %d", len(raw), tt.failedDataBytes)
			}
			if !bytes.Equal(raw, make([]byte, len(raw))) {
				t.Fatalf("FailedAVP payload = %x, want zero-filled", []byte(raw))
			}
			if failed.Len() > tt.maxFailedLen {
				t.Fatalf("FailedAVP length = %d, want <= %d", failed.Len(), tt.maxFailedLen)
			}
		})
	}
}

func TestReadMessageRejectsMissingGroupedAVPPadding(t *testing.T) {
	leaf := []byte{
		0x00, 0x00, 0x01, 0x08,
		avp.Mbit, 0x00, 0x00, 0x09,
		'x',
	}
	parent := append([]byte{
		0x00, 0x00, 0x01, 0x04,
		avp.Mbit, 0x00, 0x00, 0x11,
	}, leaf...)
	parent = append(parent, 0, 0, 0)

	m, err := ReadMessage(bytes.NewReader(testFramedMessage(t, RequestFlag, parent)), dict.Default)
	var messageErr *MessageError
	if !errors.As(err, &messageErr) {
		t.Fatalf("ReadMessage error = %T(%v), want *MessageError", err, err)
	}
	if m == nil {
		t.Fatal("ReadMessage returned a nil message")
	}
	assertFailedAVPPath(t, messageErr, avp.VendorSpecificApplicationID, avp.OriginHost)
}

func TestReadMessagePreservesNestedGroupedFailedAVPPath(t *testing.T) {
	leaf := []byte{
		0x00, 0x00, 0x01, 0x08,
		avp.Mbit, 0x00, 0x00, 0x09,
		'x',
	}
	inner := append([]byte{
		0x00, 0x00, 0x01, 0x04,
		avp.Mbit, 0x00, 0x00, 0x11,
	}, leaf...)
	inner = append(inner, 0, 0, 0)
	outer := append([]byte{
		0x00, 0x00, 0x01, 0x04,
		avp.Mbit, 0x00, 0x00, 0x1c,
	}, inner...)

	_, err := ReadMessage(bytes.NewReader(testFramedMessage(t, RequestFlag, outer)), dict.Default)
	var messageErr *MessageError
	if !errors.As(err, &messageErr) {
		t.Fatalf("ReadMessage error = %T(%v), want *MessageError", err, err)
	}
	assertFailedAVPPath(t, messageErr,
		avp.VendorSpecificApplicationID,
		avp.VendorSpecificApplicationID,
		avp.OriginHost,
	)
}

func TestDecodeGroupedFromBytesRejectsMissingPadding(t *testing.T) {
	b := []byte{
		0x00, 0x00, 0x01, 0x08,
		avp.Mbit, 0x00, 0x00, 0x09,
		'x',
	}
	g, err := DecodeGroupedFromBytes(b, 0, dict.Default)
	if err == nil {
		t.Fatal("DecodeGroupedFromBytes accepted an AVP whose padding exceeds the Grouped payload")
	}
	if len(g.AVP) != 0 {
		t.Fatalf("decoded AVPs = %d, want 0", len(g.AVP))
	}
}

func TestMinimumAVPPayloadLength(t *testing.T) {
	tests := []struct {
		name   string
		typeID datatype.TypeID
		want   int
	}{
		{name: "variable", typeID: datatype.OctetStringType, want: 0},
		{name: "grouped", typeID: datatype.GroupedType, want: 0},
		{name: "address family", typeID: datatype.AddressType, want: 2},
		{name: "32-bit", typeID: datatype.Unsigned32Type, want: 4},
		{name: "64-bit", typeID: datatype.Unsigned64Type, want: 8},
		{name: "IPv4", typeID: datatype.IPv4Type, want: 4},
		{name: "IPv6", typeID: datatype.IPv6Type, want: 16},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := minimumAVPPayloadLength(tt.typeID); got != tt.want {
				t.Fatalf("minimumAVPPayloadLength(%v) = %d, want %d", tt.typeID, got, tt.want)
			}
		})
	}
}

func assertFailedAVPPath(t *testing.T, messageErr *MessageError, want ...uint32) {
	t.Helper()
	if messageErr.ResultCode != InvalidAVPLength {
		t.Fatalf("ResultCode = %d, want %d", messageErr.ResultCode, InvalidAVPLength)
	}
	if messageErr.Fatal {
		t.Fatal("Grouped AVP MessageError is fatal")
	}
	failed := messageErr.FailedAVP
	for i, code := range want {
		if failed == nil {
			t.Fatalf("FailedAVP path ended at index %d, want code %d", i, code)
		}
		if failed.Code != code {
			t.Fatalf("FailedAVP path[%d] = %d, want %d", i, failed.Code, code)
		}
		if i == len(want)-1 {
			return
		}
		grouped, ok := failed.Data.(*GroupedAVP)
		if !ok {
			t.Fatalf("FailedAVP path[%d] data = %T, want *GroupedAVP", i, failed.Data)
		}
		if len(grouped.AVP) != 1 {
			t.Fatalf("FailedAVP path[%d] has %d children, want one", i, len(grouped.AVP))
		}
		failed = grouped.AVP[0]
	}
}

func testMessageHeader(version uint8, length uint32, flags uint8) []byte {
	return (&Header{
		Version:       version,
		MessageLength: length,
		CommandFlags:  flags,
		CommandCode:   CapabilitiesExchange,
		ApplicationID: 0,
		HopByHopID:    0x01020304,
		EndToEndID:    0x05060708,
	}).Serialize()
}

func testFramedMessage(t *testing.T, flags uint8, body []byte) []byte {
	t.Helper()
	length := HeaderLength + len(body)
	if length%4 != 0 {
		t.Fatalf("test message length %d is not aligned", length)
	}
	wire := testMessageHeader(1, uint32(length), flags)
	return append(wire, body...)
}

type messageErrorMultistreamReader struct {
	*bytes.Reader
	stream  uint
	current uint
}

func (r *messageErrorMultistreamReader) ReadAny(b []byte) (int, uint, error) {
	n, err := r.Read(b)
	return n, r.stream, err
}

func (r *messageErrorMultistreamReader) ReadStream(b []byte, _ uint) (int, error) {
	return r.Read(b)
}

func (r *messageErrorMultistreamReader) ReadAtLeast(b []byte, min int, stream uint) (int, uint, error) {
	if stream == InvalidStreamID {
		stream = r.stream
	}
	n, err := io.ReadAtLeast(r, b, min)
	return n, stream, err
}

func (r *messageErrorMultistreamReader) CurrentStream() uint {
	return r.current
}

func (r *messageErrorMultistreamReader) ResetCurrentStream() {
	r.current = InvalidStreamID
}

func (r *messageErrorMultistreamReader) SetCurrentStream(stream uint) uint {
	previous := r.current
	r.current = stream
	return previous
}
