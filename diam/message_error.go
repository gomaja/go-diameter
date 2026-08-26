// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diam

import (
	"encoding/binary"
	"fmt"

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
	failedParent := NewAVP(parent.Code, parent.Flags, parent.VendorID, &GroupedAVP{
		AVP: []*AVP{e.failedAVP},
	})
	return &avpLengthError{
		failedAVP: failedParent,
		err:       e,
	}
}

func newAVPLengthError(data []byte, application uint32, dictionary *dict.Parser, err error) *avpLengthError {
	return &avpLengthError{
		failedAVP: failedAVPFromWire(data, application, dictionary),
		err:       err,
	}
}

func newDecodedAVPLengthError(a *AVP, err error) *avpLengthError {
	return &avpLengthError{failedAVP: a, err: err}
}

func failedAVPFromWire(data []byte, application uint32, dictionary *dict.Parser) *AVP {
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
		if definition, err := dictionary.FindAVPByCode(application, code, vendorID); err == nil {
			payloadLength = minimumAVPPayloadLength(definition.Data.Type)
		}
	}
	return NewAVP(code, flags, vendorID, datatype.Unknown(make([]byte, payloadLength)))
}

// minimumAVPPayloadLength returns the fixed minimum from RFC 6733 Sections
// 4.2 and 4.3. Variable-length and Grouped AVPs may have an empty payload.
func minimumAVPPayloadLength(typeID datatype.TypeID) int {
	switch typeID {
	case datatype.AddressType:
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
