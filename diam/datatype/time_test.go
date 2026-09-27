// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package datatype

import (
	"bytes"
	"testing"
	"time"
)

func TestTime(t *testing.T) {
	n := Time(time.Unix(1377093974, 0))
	b := []byte{0xd5, 0xbf, 0x47, 0xd6}
	if v := n.Serialize(); !bytes.Equal(v, b) {
		t.Fatalf("Unexpected value. Want 0x%x, have 0x%x", b, v)
	}
	if n.Len() != 4 {
		t.Fatalf("Unexpected len. Want 4, have %d", n.Len())
	}
	if n.Padding() != 0 {
		t.Fatalf("Unexpected padding. Want 0, have %d", n.Padding())
	}
	if n.Type() != TimeType {
		t.Fatalf("Unexpected type. Want %d, have %d",
			TimeType, n.Type())
	}
	if len(n.String()) == 0 {
		t.Fatalf("Unexpected empty string")
	}
}

func TestDecodeTime(t *testing.T) {
	b := []byte{0xd5, 0xbf, 0x47, 0xd6}
	v, err := DecodeTime(b)
	if err != nil {
		t.Fatal(err)
	}
	if n := time.Time(v.(Time)).Unix(); n != 1377093974 {
		t.Fatalf("Unexpected value. Want 1377093974, have %d", n)
	}
}

func TestTimeRoundTripAcross2036(t *testing.T) {
	// RFC 6733 §4.3.1 requires the Time extension through 2104.
	// The bit-0 interpretation is described in obsolete RFC 4330 §3.
	for _, value := range []string{
		"1968-01-20T03:14:08Z", // first timestamp with bit 0 set
		"1968-02-01T00:00:00Z",
		"2000-01-01T00:00:00Z",
		"2036-02-07T06:28:15Z",
		"2036-02-07T06:28:16Z",
		"2036-02-07T06:28:17Z",
		"2104-02-07T06:28:15Z",
	} {
		want, err := time.Parse(time.RFC3339, value)
		if err != nil {
			t.Fatal(err)
		}
		wire := Time(want).Serialize()
		got, err := DecodeTime(wire)
		if err != nil {
			t.Fatal(err)
		}
		if !time.Time(got.(Time)).Equal(want) {
			t.Errorf("%s round-tripped as %s via %x", want, time.Time(got.(Time)), wire)
		}
	}
}

func BenchmarkTime(b *testing.B) {
	v := Time(time.Unix(1377093974, 0))
	for n := 0; n < b.N; n++ {
		v.Serialize()
	}
}

func BenchmarkDecodeTime(b *testing.B) {
	v := []byte{0x52, 0x14, 0xc9, 0x56}
	for n := 0; n < b.N; n++ {
		if _, err := DecodeTime(v); err != nil {
			b.Fatal(err)
		}
	}
}
