// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diam

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// GroupedAVPType is the identifier of the GroupedAVP data type.
// It must not conflict with other values from the datatype package.
const GroupedAVPType = 50

// GroupedAVP that is different from the dummy datatype.Grouped.
type GroupedAVP struct {
	AVP []*AVP
}

// DecodeGrouped decodes a Grouped AVP from a datatype.Grouped (byte array).
func DecodeGrouped(data datatype.Grouped, application uint32, dictionary *dict.Parser) (*GroupedAVP, error) {
	return DecodeGroupedFromBytes([]byte(data), application, dictionary)
}

// DecodeGroupedFromBytes decodes a Grouped AVP directly from a raw byte slice,
// avoiding the intermediate datatype.Grouped copy. b is the payload of a
// Grouped AVP at level 1; nesting is limited, and dictionary used, as
// described for DecodeAVP.
func DecodeGroupedFromBytes(b []byte, application uint32, dictionary *dict.Parser) (*GroupedAVP, error) {
	g, err := decodeGroupedFromBytes(b, application, decodingSnapshot(dictionary), 1, false)
	if err != nil {
		// The members are returned to the caller, so the fallback bytes of
		// the ones that failed must not alias b.
		for _, a := range g.AVP {
			ownAVPData(a)
		}
	}
	return g, err
}

// decodeGroupedFromBytes decodes the payload of a Grouped AVP whose members
// are enclosed by depth Grouped AVPs.
func decodeGroupedFromBytes(b []byte, application uint32, dictionary *dict.Snapshot, depth int, failedAVP bool) (*GroupedAVP, error) {
	g := &GroupedAVP{}
	var errs *decodeErrors
	for n := 0; n < len(b); {
		a, err := decodeAVP(b[n:], application, dictionary, depth, failedAVP)
		if err != nil {
			var lengthErr *avpLengthError
			if errors.As(err, &lengthErr) {
				return g, lengthErr
			}
			var decodeErr *avpDecodeError
			if failedAVP && errors.As(err, &decodeErr) && !errors.Is(err, errGroupedTooDeep) {
				// RFC 6733 §7.5: this member is evidence of a failed AVP,
				// not a failure of the containing message. It now escapes
				// the decoder, so its fallback must own the payload.
				ownAVPData(a)
			} else {
				errs = errs.add(err)
			}
			if a.Data == nil {
				// Fatal decode error (e.g., truncated sub-AVP header): remaining
				// bytes cannot form a valid sub-AVP. Break so the caller detects
				// g.Len() != bodyLen and falls back to Unknown for the parent AVP.
				break
			}
		}
		advance := a.Len()
		// RFC 6733 Sections 4.1 and 4.4 require each Grouped child, including
		// its padding, to fit within the Grouped AVP payload.
		if advance <= 0 || advance > len(b)-n {
			ownAVPData(a) // The Failed-AVP outlives the input.
			return g, newDecodedAVPLengthError(a, fmt.Errorf(
				"%w: grouped AVP at offset %d consumes %d padded bytes, have %d",
				errAVPDataTooShort, n, advance, len(b)-n))
		}
		g.AVP = append(g.AVP, a)
		n += advance
	}
	if errs != nil {
		return g, errs
	}
	return g, nil
}

// Serialize implements the datatype.Type interface without validating values.
// Message serialization validates Address members before writing to the wire.
func (g *GroupedAVP) Serialize() []byte {
	b := make([]byte, g.Len())
	var n int
	for _, a := range g.AVP {
		var payload []byte
		switch data := a.Data.(type) {
		case nil:
		case *datatype.Address:
			if data != nil {
				payload = data.Serialize()
			}
		default:
			payload = data.Serialize()
		}
		hl := a.serializeHeaderTo(b[n:], len(payload))
		copy(b[n+hl:], payload)
		n += a.Len()
	}
	return b
}

// Len implements the datatype.Type interface.
func (g *GroupedAVP) Len() int {
	var l int
	for _, a := range g.AVP {
		l += a.Len()
	}
	return l
}

// Padding implements the datatype.Type interface.
func (g *GroupedAVP) Padding() int {
	return 0
}

// Type implements the datatype.Type interface.
func (g *GroupedAVP) Type() datatype.TypeID {
	return GroupedAVPType
}

// String implements the datatype.Type interface.
func (g *GroupedAVP) String() string {
	var b bytes.Buffer
	for n, a := range g.AVP {
		if n > 0 {
			fmt.Fprint(&b, ",")
		}
		fmt.Fprint(&b, a)
	}
	return b.String()
}

// AddAVP adds the AVP to the GroupedAVP. It is not safe for concurrent calls.
func (g *GroupedAVP) AddAVP(a *AVP) {
	g.AVP = append(g.AVP, a)
}
