// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diam

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

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
// avoiding the intermediate datatype.Grouped copy.
func DecodeGroupedFromBytes(b []byte, application uint32, dictionary *dict.Parser) (*GroupedAVP, error) {
	g := &GroupedAVP{}
	var errs []string
	for n := 0; n < len(b); {
		a, err := DecodeAVP(b[n:], application, dictionary)
		if err != nil {
			var lengthErr *avpLengthError
			if errors.As(err, &lengthErr) {
				return g, lengthErr
			}
			errs = append(errs, err.Error())
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
			return g, newDecodedAVPLengthError(a, fmt.Errorf(
				"%w: grouped AVP at offset %d consumes %d padded bytes, have %d",
				errAVPDataTooShort, n, advance, len(b)-n))
		}
		g.AVP = append(g.AVP, a)
		n += advance
	}
	if len(errs) > 0 {
		return g, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return g, nil
}

// Serialize implements the datatype.Type interface.
func (g *GroupedAVP) Serialize() []byte {
	b := make([]byte, g.Len())
	var n int
	for _, a := range g.AVP {
		if err := a.SerializeTo(b[n:]); err != nil {
			panic(err)
		}
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
