// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package datatype

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// AddressFamily identifies the format of an Address value (RFC 6733 §4.3.1).
type AddressFamily uint16

// IANA Address Family Numbers:
// https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
const (
	AddressFamilyIPv4 AddressFamily = 1
	AddressFamilyIPv6 AddressFamily = 2
	AddressFamilyE164 AddressFamily = 8
)

// Address is the discriminated union in RFC 6733 §4.3.1.
// Value excludes the two-octet family prefix. Non-IP values retain their
// application-defined encoding. The zero value has a reserved family.
type Address struct {
	Family AddressFamily
	Value  []byte
}

// AddressFromIP returns an owned Address. IPv4-mapped IPv6 is unmapped to
// family IPv4. Copying an Address through netip.Addr or net.IP fields and
// marshaling it again therefore does not preserve family IPv6 for mapped IPs.
// Zones have no wire representation and are discarded. An invalid IP returns
// the zero Address.
func AddressFromIP(ip netip.Addr) Address {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return Address{}
	}
	family := AddressFamilyIPv6
	if ip.Is4() {
		family = AddressFamilyIPv4
	}
	return Address{Family: family, Value: ip.AsSlice()}
}

// IP returns the IP only when both the family and length match.
// A decoded IPv6 value remains IPv6, including IPv4-mapped IPv6. Converting
// it back with AddressFromIP (also used by reflection for netip.Addr and net.IP)
// unmaps it to family IPv4. Keep Address values to preserve the wire family.
func (addr Address) IP() (netip.Addr, bool) {
	if (addr.Family == AddressFamilyIPv4 && len(addr.Value) == 4) ||
		(addr.Family == AddressFamilyIPv6 && len(addr.Value) == 16) {
		return netip.AddrFromSlice(addr.Value)
	}
	return netip.Addr{}, false
}

// E164Address encodes decimal digits as UTF-8 for 3GPP TS 32.299 V19.0.0
// §§7.2.128 and 7.2.170 (Originator/Recipient-SCCP-Address).
// It checks digit syntax and the 15-digit limit (ITU-T E.164 (02/2026)
// §6.1 and Annex A.3.1.1), not numbering-plan assignments. Other application
// encodings can be supplied directly in Address.Value.
func E164Address(digits string) (Address, error) {
	if !e164Digits(digits) {
		return Address{}, errors.New("E.164 requires 1 to 15 decimal digits")
	}
	return Address{Family: AddressFamilyE164, Value: []byte(digits)}, nil
}

// E164 returns digits only for a family-8 value in the UTF-8 encoding used by
// 3GPP TS 32.299 V19.0.0 §§7.2.128 and 7.2.170. Raw values remain available in Value.
func (addr Address) E164() (string, bool) {
	if addr.Family != AddressFamilyE164 {
		return "", false
	}
	digits := string(addr.Value)
	if !e164Digits(digits) {
		return "", false
	}
	return digits, true
}

func e164Digits(digits string) bool {
	if len(digits) == 0 || len(digits) > 15 {
		return false
	}
	for i := range len(digits) {
		if digits[i] < '0' || digits[i] > '9' {
			return false
		}
	}
	return true
}

// Clone returns an Address with independent value storage.
func (addr Address) Clone() Address {
	addr.Value = bytes.Clone(addr.Value)
	return addr
}

// DecodeAddress decodes an owned Address (RFC 6733 §4.3.1).
func DecodeAddress(b []byte) (Type, error) {
	if len(b) < 2 {
		return Address{}, fmt.Errorf("not enough data to make an Address from byte[%d]", len(b))
	}
	addr := Address{Family: AddressFamily(binary.BigEndian.Uint16(b[:2])), Value: b[2:]}
	if err := addr.Valid(); err != nil {
		return Address{}, err
	}
	return addr.Clone(), nil
}

// Valid checks RFC 6733 §4.3.1 IP lengths and the reserved IANA families.
// Other families retain their application-defined value, including empty values.
func (addr Address) Valid() error {
	switch addr.Family {
	case 0, 65535:
		return errors.New("invalid address family received")
	case AddressFamilyIPv4:
		if len(addr.Value) != 4 {
			return errors.New("invalid length for IPv4")
		}
	case AddressFamilyIPv6:
		if len(addr.Value) != 16 {
			return errors.New("invalid length for IPv6")
		}
	}
	return nil
}

// Serialize implements the Type interface.
func (addr Address) Serialize() []byte {
	b := make([]byte, addr.Len())
	binary.BigEndian.PutUint16(b, uint16(addr.Family))
	copy(b[2:], addr.Value)
	return b
}

// Len implements the Type interface.
func (addr Address) Len() int { return 2 + len(addr.Value) }

// Padding implements the Type interface.
func (addr Address) Padding() int { return pad4(addr.Len()) - addr.Len() }

// Type implements the Type interface.
func (addr Address) Type() TypeID { return AddressType }

// String implements the Type interface.
func (addr Address) String() string {
	if ip, ok := addr.IP(); ok {
		return fmt.Sprintf("Address{%s},Padding:%d", ip, addr.Padding())
	}
	if digits, ok := addr.E164(); ok {
		return fmt.Sprintf("Address{%s},Family:E.164,Padding:%d", digits, addr.Padding())
	}
	return fmt.Sprintf("Address{%x},Family:%d,Padding:%d", addr.Value, addr.Family, addr.Padding())
}
