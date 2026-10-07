// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package datatype

import (
	"encoding/binary"
	"fmt"
	"time"
)

// Time data type.
type Time time.Time

const rfc868offset = 2208988800 // Diff. between 1970 and 1900 in seconds.
// RFC 6733 §4.3.1 requires the Time extension to 2104 and attributes it to
// RFC 5905, which uses NTP era numbers instead (RFC 5905 §6). The bit-0 rule
// it requires is the one in obsolete RFC 4330 §3.
// The post-rollover Unix offset is 2^32 - 2208988800 seconds.
const postRolloverUnixOffset = 2085978496

// DecodeTime decodes a Time data type from byte array.
func DecodeTime(b []byte) (Type, error) {
	if len(b) != 4 {
		return Time{}, fmt.Errorf("invalid Time data length: %d", len(b))
	}
	if (b[0] >> 7) == 0 {
		return Time(time.Unix(int64(binary.BigEndian.Uint32(b))+postRolloverUnixOffset, 0)), nil
	} else {
		return Time(time.Unix(int64(binary.BigEndian.Uint32(b))-rfc868offset, 0)), nil
	}

}

// Serialize implements the Type interface.
func (t Time) Serialize() []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(time.Time(t).Unix())+rfc868offset)
	return b
}

// Len implements the Type interface.
func (t Time) Len() int {
	return 4
}

// Padding implements the Type interface.
func (t Time) Padding() int {
	return 0
}

// Type implements the Type interface.
func (t Time) Type() TypeID {
	return TimeType
}

// String implements the Type interface.
func (t Time) String() string {
	return fmt.Sprintf("Time{%s}", time.Time(t))
}

// MarshalJSON implements the json.Marshaler interface.
func (t Time) MarshalJSON() ([]byte, error) {
	return time.Time(t).MarshalJSON()
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (t *Time) UnmarshalJSON(data []byte) error {
	var tt time.Time
	if err := tt.UnmarshalJSON(data); err != nil {
		return err
	}
	*t = Time(tt)
	return nil
}
