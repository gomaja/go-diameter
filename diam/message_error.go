// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diam

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// MessageError describes a Diameter message that cannot be decoded safely.
// ResultCode is the RFC 6733 permanent-failure code to return for a request.
// Fatal reports whether the next message boundary on the connection is lost.
type MessageError struct {
	ResultCode uint32
	FailedAVP  *AVP
	Fatal      bool
	Err        error
}

// Error implements the error interface.
func (e *MessageError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("diameter message error %d: %v", e.ResultCode, e.Err)
}

// Unwrap returns the decoder error that caused this message error.
func (e *MessageError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type avpLengthError struct {
	failedAVP *AVP
	err       error
}

func (e *avpLengthError) Error() string {
	return e.err.Error()
}

func (e *avpLengthError) Unwrap() error {
	return e.err
}

func (e *avpLengthError) withGroupedParent(parent *AVP) *avpLengthError {
	failedParent := newAVPWithFlags(parent.Code, parent.Flags, parent.VendorID, &GroupedAVP{
		AVP: []*AVP{e.failedAVP},
	})
	return &avpLengthError{
		failedAVP: failedParent,
		err:       e,
	}
}

func newAVPLengthError(data []byte, application uint32, dictionary *dict.Snapshot, err error) *avpLengthError {
	return &avpLengthError{
		failedAVP: failedAVPFromWire(data, application, dictionary),
		err:       err,
	}
}

func newDecodedAVPLengthError(a *AVP, err error) *avpLengthError {
	return &avpLengthError{failedAVP: a, err: err}
}

func failedAVPFromWire(data []byte, application uint32, dictionary *dict.Snapshot) *AVP {
	var header [12]byte
	copy(header[:], data)

	code := binary.BigEndian.Uint32(header[0:4])
	flags := header[4]
	var vendorID uint32
	if flags&avp.Vbit != 0 {
		vendorID = binary.BigEndian.Uint32(header[8:12])
	}

	payloadLength := 0
	if dictionary != nil {
		if definition, err := dictionary.FindAVP(application, code, vendorID); err == nil {
			payloadLength = minimumAVPPayloadLength(definition.Data.Type)
		}
	}
	return newAVPWithFlags(code, flags, vendorID, datatype.Unknown(make([]byte, payloadLength)))
}

// minimumAVPPayloadLength returns the fixed minimum from RFC 6733 Sections
// 4.2 and 4.3. Variable-length and Grouped AVPs may have an empty payload.
func minimumAVPPayloadLength(typeID datatype.TypeID) int {
	switch typeID {
	case datatype.AddressType:
		// RFC 6733 §4.3.1: only the family prefix has a fixed minimum.
		return 2
	case datatype.EnumeratedType,
		datatype.Float32Type,
		datatype.IPv4Type,
		datatype.Integer32Type,
		datatype.TimeType,
		datatype.Unsigned32Type:
		return 4
	case datatype.Float64Type,
		datatype.Integer64Type,
		datatype.Unsigned64Type:
		return 8
	case datatype.IPv6Type:
		return 16
	default:
		return 0
	}
}

// avpDecodeError records a recoverable payload failure. Framing failures use
// avpLengthError instead and take precedence even in a non-strict dictionary.
type avpDecodeError struct {
	resultCode uint32
	failedAVP  *AVP
	err        error
}

func (e *avpDecodeError) Error() string { return e.err.Error() }
func (e *avpDecodeError) Unwrap() error { return e.err }

func (e *avpDecodeError) withGroupedParent(parent *AVP, err error) *avpDecodeError {
	// RFC 6733 §7.5 permits retaining the hierarchy leading to the offending AVP.
	return &avpDecodeError{
		resultCode: e.resultCode,
		failedAVP:  newAVPWithFlags(parent.Code, parent.Flags, parent.VendorID, &GroupedAVP{AVP: []*AVP{e.failedAVP}}),
		err:        err,
	}
}

func newAVPDecodeError(a *AVP, typeID datatype.TypeID, err error) *avpDecodeError {
	resultCode := uint32(InvalidAVPValue)
	minimum := minimumAVPPayloadLength(typeID)
	data := a.Data
	switch {
	case minimum > 0 && (a.Data.Len() < minimum || (typeID != datatype.AddressType && a.Data.Len() != minimum)):
		// RFC 6733 §§4.2, 4.3.1 and 7.1.5: fixed-size payloads must have
		// exactly their declared type's size; Address needs its family prefix.
		resultCode = InvalidAVPLength
	case typeID == datatype.GroupedType:
		// RFC 6733 §7.1.5: the Grouped header identifies the rejected AVP.
		// Never echo the payload that exceeded the decoder's nesting limit.
		data = datatype.Unknown(nil)
	}
	// RFC 6733 §7.5: an in-bounds payload failure retains the entire AVP,
	// including its original length and bytes. Only framing errors use a
	// minimum zero-filled payload. This leaf holds at most its own bytes;
	// an over-deep Grouped leaf is empty. Each ancestor adds only its
	// 8/12-byte header, never siblings or another payload copy.
	failed := newAVPWithFlags(a.Code, a.Flags, a.VendorID, data)
	if typeID != datatype.GroupedType {
		ownAVPData(failed) // A nested fallback may still alias the input.
	}
	return &avpDecodeError{resultCode: resultCode, failedAVP: failed, err: err}
}

// decodeErrors keeps the historical joined text and the first failure's
// cause. RFC 6733 §7.5 normally reports the first AVP processing error.
type decodeErrors struct {
	messages []string
	first    error
}

func (e *decodeErrors) add(err error) *decodeErrors {
	if e == nil {
		e = &decodeErrors{first: err}
	}
	e.messages = append(e.messages, err.Error())
	return e
}

func (e *decodeErrors) Error() string { return strings.Join(e.messages, "; ") }
func (e *decodeErrors) Unwrap() error { return e.first }
