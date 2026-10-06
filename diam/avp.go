// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diam

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// Used to signal that parsing should not stop.
type DecodeError error

// Pre-allocated sentinel errors for the hot decode path.
// Using errors.New avoids fmt.Errorf formatting overhead on error paths.
var (
	errAVPHeaderTooShort   = errors.New("not enough data to decode AVP header")
	errAVPDataTooShort     = errors.New("not enough data to decode AVP")
	errAVPVendorTooShort   = errors.New("not enough data to decode AVP with Vendor-ID")
	errAVPSerializeNilData = errors.New("failed to serialize AVP: Data is nil")
	errGroupedTooDeep      = errors.New("grouped AVP nesting exceeds limit")
)

// decodingSnapshot returns the dictionary state a decode uses throughout:
// d's current Snapshot, or dict.Default's when d is nil, as for
// Message.Dictionary. Resolving every AVP of a message against one Snapshot
// means a dictionary change made meanwhile applies to the whole message or
// to none of it.
func decodingSnapshot(d *dict.Parser) *dict.Snapshot {
	if d == nil {
		d = dict.Default
	}
	return d.Snapshot()
}

// AVP is a Diameter attribute-value-pair.
type AVP struct {
	Code     uint32        // Code of this AVP
	Flags    uint8         // Flags of this AVP
	Length   int           // Length of this AVP's payload
	VendorID uint32        // VendorId of this AVP
	Data     datatype.Type // Data of this AVP (payload)
}

// NewAVP creates and initializes a new AVP.
func NewAVP(code uint32, flags uint8, vendor uint32, data datatype.Type) *AVP {
	a := &AVP{
		Code:     code,
		Flags:    flags,
		VendorID: vendor,
		Data:     data,
	}
	a.Length = a.headerLen() + a.Data.Len() // no padding length
	if vendor > 0 && flags&avp.Vbit != avp.Vbit {
		a.Flags |= avp.Vbit
	}
	return a
}

// DecodeAVP decodes the bytes of a Diameter AVP.
// It uses the given application id and dictionary for decoding the bytes.
//
// Grouped AVPs are decoded at most dictionary.MaxGroupedDepth() levels deep
// (dict.DefaultMaxGroupedDepth unless set), counting the outermost Grouped
// AVP as level 1. A Grouped AVP nested deeper keeps its payload undecoded as
// datatype.Unknown and a DecodeError is returned, as for any Grouped AVP
// whose members fail to decode. The AVP and its members are resolved against
// one dict.Snapshot of dictionary; a nil dictionary means dict.Default.
func DecodeAVP(data []byte, application uint32, dictionary *dict.Parser) (*AVP, error) {
	return decodeAVP(data, application, decodingSnapshot(dictionary), 0, false)
}

// decodeAVP is DecodeAVP for an AVP enclosed by depth Grouped AVPs.
func decodeAVP(data []byte, application uint32, dictionary *dict.Snapshot, depth int, failedAVP bool) (*AVP, error) {
	a := &AVP{}
	if err := a.decodeFromBytes(data, application, dictionary, depth, failedAVP); err != nil {
		var lengthErr *avpLengthError
		if errors.As(err, &lengthErr) {
			return a, lengthErr
		}
		if errors.Is(err, errAVPHeaderTooShort) ||
			errors.Is(err, errAVPDataTooShort) ||
			errors.Is(err, errAVPVendorTooShort) {
			return a, newAVPLengthError(data, application, dictionary, err)
		}
		return a, err
	}
	return a, nil
}

// DecodeFromBytes decodes the bytes of a Diameter AVP.
// It uses the given application id and dictionary for decoding the bytes.
// Grouped AVP nesting is limited, and dictionary used, as described for
// DecodeAVP.
func (a *AVP) DecodeFromBytes(data []byte, application uint32, dictionary *dict.Parser) error {
	return a.decodeFromBytes(data, application, decodingSnapshot(dictionary), 0, false)
}

// decodeFromBytes is DecodeFromBytes for an AVP enclosed by depth Grouped
// AVPs. A Grouped AVP at depth dictionary.MaxGroupedDepth() is not descended
// into: its payload is kept as datatype.Unknown and a DecodeError is returned.
func (a *AVP) decodeFromBytes(data []byte, application uint32, dictionary *dict.Snapshot, depth int, failedAVP bool) error {
	if len(data) < 8 {
		return fmt.Errorf("%w: have %d need %d", errAVPHeaderTooShort, len(data), 8)
	}
	a.Code = binary.BigEndian.Uint32(data[0:4])
	a.Flags = data[4]
	a.Length = int(uint24to32(data[5:8]))
	if len(data) < a.Length {
		return fmt.Errorf("%w: have %d need %d", errAVPDataTooShort, len(data), a.Length)
	}
	data = data[:a.Length] // this cuts padded bytes off
	if len(data) < 8 {
		return fmt.Errorf("%w: have %d need %d", errAVPHeaderTooShort, len(data), 8)
	}

	var hdrLength int
	var payload []byte
	// Read VendorId when required.
	if a.Flags&avp.Vbit == avp.Vbit {
		if a.Length < 12 {
			return fmt.Errorf("%w: have %d need %d", errAVPVendorTooShort, a.Length, 12)
		}
		a.VendorID = binary.BigEndian.Uint32(data[8:12])
		payload = data[12:]
		hdrLength = 12
	} else {
		payload = data[8:]
		hdrLength = 8
	}
	// Find this code in the dictionary.
	dictAVP, err := dictionary.FindAVPByCode(application, a.Code, a.VendorID)
	if err != nil && dictAVP == nil {
		return err
	}
	bodyLen := a.Length - hdrLength
	if n := len(payload); n < bodyLen {
		return fmt.Errorf("%w: have %d need %d", errAVPDataTooShort, n, bodyLen)
	}
	// Handle grouped AVPs directly to avoid an intermediate copy.
	if dictAVP.Data.Type == datatype.GroupedType {
		// Command rules are not enforced while decoding, so a peer can nest a
		// Grouped AVP inside itself; each level costs a walk of everything
		// beneath it. The limit bounds that work for untrusted input.
		if depth >= dictionary.MaxGroupedDepth() {
			a.Data = fallbackData(payload[:bodyLen], depth)
			return newAVPDecodeError(a, dictAVP.Data.Type, fmt.Errorf("%s(%d): %w", dictAVP.Name, dictAVP.Code, errGroupedTooDeep))
		}
		// RFC 6733 §7.5: Failed-AVP carries erroneous values as evidence.
		// Its members and their Grouped descendants may retain undecodable
		// payloads; framing and nesting limits still apply.
		failedAVP = failedAVP || (a.Code == avp.FailedAVP && a.VendorID == 0)
		g, groupErr := decodeGroupedFromBytes(payload[:bodyLen], application, dictionary, depth+1, failedAVP)
		if groupErr != nil {
			var lengthErr *avpLengthError
			if errors.As(groupErr, &lengthErr) {
				// Preserve the complete outer AVP bytes for callers that need its
				// wire length, while the error separately carries a bounded
				// Failed-AVP hierarchy for RFC 6733 Sections 7.1.5 and 7.5.
				a.Data = fallbackData(payload[:bodyLen], depth)
				return lengthErr.withGroupedParent(a)
			}
			// Preserve raw bytes to prevent offset misalignment in the parent parse loop.
			a.Data = fallbackData(payload[:bodyLen], depth)
			err := fmt.Errorf("%s(%d): Grouped{%w}", dictAVP.Name, dictAVP.Code, groupErr)
			var decodeErr *avpDecodeError
			if errors.As(groupErr, &decodeErr) {
				return decodeErr.withGroupedParent(a, err)
			}
			return DecodeError(err)
		}
		a.Data = g
	} else {
		decoded, decodeErr := datatype.Decode(dictAVP.Data.Type, payload[:bodyLen])
		if decodeErr != nil || decoded.Len() != bodyLen {
			// Preserve raw bytes to prevent offset misalignment in the parent parse loop.
			if decodeErr == nil {
				decodeErr = fmt.Errorf("size mismatch: %s expects %d bytes, wire has %d", dictAVP.Data.TypeName, decoded.Len(), bodyLen)
			}
			a.Data = fallbackData(payload[:bodyLen], depth)
			return newAVPDecodeError(a, dictAVP.Data.Type, fmt.Errorf("%s(%d): %w", dictAVP.Name, dictAVP.Code, decodeErr))
		}
		a.Data = decoded
	}
	return nil
}

// Serialize returns the byte sequence that represents this AVP.
// It requires at least the Code, Flags and Data fields set.
func (a *AVP) Serialize() ([]byte, error) {
	if a.Data == nil {
		return nil, errAVPSerializeNilData
	}
	b := make([]byte, a.Len())
	err := a.SerializeTo(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// SerializeTo writes the byte sequence that represents this AVP to a byte array.
func (a *AVP) SerializeTo(b []byte) error {
	if a.Data == nil {
		return errAVPSerializeNilData
	}
	binary.BigEndian.PutUint32(b[0:4], a.Code)
	b[4] = a.Flags
	hl := a.headerLen()
	putUint24(b[5:8], uint32(hl+a.Data.Len()))
	if a.Flags&avp.Vbit == avp.Vbit {
		binary.BigEndian.PutUint32(b[8:12], a.VendorID)
	}
	payload := a.Data.Serialize()
	copy(b[hl:], payload)
	// reset padding bytes
	b = b[hl+len(payload):]
	for i := 0; i < a.Data.Padding(); i++ {
		b[i] = 0
	}
	return nil
}

// Len returns the length of this AVP in bytes with padding.
func (a *AVP) Len() int {
	if a.Data == nil {
		length := a.Length
		if headerLen := a.headerLen(); length < headerLen {
			length = headerLen
		}
		return paddedAVPLength(length)
	}
	return a.headerLen() + a.Data.Len() + a.Data.Padding()
}

// paddedAVPLength returns the bytes consumed by an AVP, including padding.
// RFC 6733 section 4.1 excludes padding from AVP Length while requiring the
// next AVP to start on a 32-bit boundary.
func paddedAVPLength(length int) int {
	return (length + 3) &^ 3
}

func (a *AVP) headerLen() int {
	if a.Flags&avp.Vbit == avp.Vbit {
		return 12
	}
	return 8
}

func (a *AVP) String() string {
	return fmt.Sprintf("{Code:%d,Flags:0x%x,Length:%d,VendorId:%d,Value:%s}",
		a.Code,
		a.Flags,
		a.Len(),
		a.VendorID,
		a.Data,
	)
}

// fallbackData keeps the payload of an AVP that failed to decode, enclosed by
// depth Grouped AVPs. Callers keep only the outermost AVP, so it owns a copy
// that stays valid after ReadMessage returns its pooled buffer. A failed
// member makes its enclosing Grouped AVP fall back too and discard its
// members, so a member's payload may alias the input: copying at every level
// multiplied the work by the nesting depth, 33 times the message size for an
// over-deep 16 MB message. Members that leave the decoder through a Failed-AVP
// or DecodeGroupedFromBytes are copied there by ownAVPData.
func fallbackData(payload []byte, depth int) datatype.Unknown {
	if depth > 0 {
		return datatype.Unknown(payload)
	}
	return unknownCopy(payload)
}

// ownAVPData gives a decoded Grouped member that leaves the decoder its own
// copy of fallback bytes. An AVP that decoded without error holds no input
// bytes: the datatype decoders copy theirs, and a Grouped AVP owns any
// failed members it retains inside Failed-AVP.
func ownAVPData(a *AVP) {
	if u, ok := a.Data.(datatype.Unknown); ok {
		a.Data = unknownCopy(u)
	}
}

// unknownCopy returns b as a datatype.Unknown with its own backing array.
func unknownCopy(b []byte) datatype.Unknown {
	return datatype.Unknown(append([]byte(nil), b...))
}
