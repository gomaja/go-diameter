// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package datatype

import (
	"bytes"
	"testing"
)

// RFC 6733 §4.3.1: the family, not the payload length, selects the format.
func TestAddressFamilyRoundTrip(t *testing.T) {
	for _, digits := range []string{"12", "12345678901234"} {
		t.Run(digits, func(t *testing.T) {
			wire := append([]byte{0, 8}, []byte(digits)...)
			got, err := DecodeAddress(wire)
			if err != nil {
				t.Fatal(err)
			}
			if got.Len() != len(wire) {
				t.Errorf("Address length = %d, wire has %d", got.Len(), len(wire))
			}
			if !bytes.Equal(got.Serialize(), wire) {
				t.Errorf("Address wire = %x, want %x", got.Serialize(), wire)
			}
		})
	}
}
