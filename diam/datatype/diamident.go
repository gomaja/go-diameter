// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package datatype

import "fmt"

// DiameterIdentity data type.
type DiameterIdentity OctetString

// DecodeDiameterIdentity decodes a DiameterIdentity from byte array.
func DecodeDiameterIdentity(b []byte) (Type, error) {
	d := make([]byte, len(b))
	copy(d, b)
	return DiameterIdentity(d), nil
}

// Serialize implements the Type interface.
func (s DiameterIdentity) Serialize() []byte {
	return []byte(s)
}

// Len implements the Type interface.
func (s DiameterIdentity) Len() int {
	return len(s)
}

// Padding implements the Type interface.
func (s DiameterIdentity) Padding() int {
	l := len(s)
	return pad4(l) - l
}

// Type implements the Type interface.
func (s DiameterIdentity) Type() TypeID {
	return DiameterIdentityType
}

// String implements the Type interface.
func (s DiameterIdentity) String() string {
	return fmt.Sprintf("DiameterIdentity{%s},Padding:%d", string(s), s.Padding())
}

// Valid reports whether s has the ASCII label syntax of a DiameterIdentity
// (RFC 6733 §4.3.1 and Appendix D): one or more labels of ASCII letters,
// digits and interior hyphens (RFC 1035 §2.3.1, as relaxed by RFC 1123
// §2.1), separated by dots, with an optional final root dot. Each label is
// 1–63 octets and the name without the final dot at most 253 octets
// (RFC 1035 §§2.3.4, 3.1). Valid checks neither that s names a host or realm
// nor IDNA validity: a label that looks like an A-label is checked as plain
// ASCII (RFC 5891 §5.3).
func (s DiameterIdentity) Valid() bool {
	name := string(s)
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	label := 0
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '.' {
			if label == 0 || name[i-1] == '-' {
				return false
			}
			label = 0
			continue
		}
		letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		digit := c >= '0' && c <= '9'
		if !letter && !digit && (c != '-' || label == 0) {
			return false
		}
		label++
		if label > 63 {
			return false
		}
	}
	return label > 0 && name[len(name)-1] != '-'
}
