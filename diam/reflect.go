// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diam

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// parseAvpTag returns the AVP name in an avp struct tag and whether its
// omitempty option is set. Options follow the name as a comma-separated list
// and match exactly, as in encoding/json.
func parseAvpTag(tag reflect.StructTag) (string, bool) {
	avpName, opts, _ := strings.Cut(tag.Get("avp"), ",")
	for opts != "" {
		var opt string
		opt, opts, _ = strings.Cut(opts, ",")
		if opt == "omitempty" {
			return avpName, true
		}
	}
	return avpName, false
}

func isEmptyValue(v reflect.Value) bool {
	if v.CanInterface() {
		switch {
		case v.Type().ConvertibleTo(reflect.TypeFor[datatype.Address]()):
			address := v.Convert(reflect.TypeFor[datatype.Address]()).Interface().(datatype.Address)
			return address.Family == 0 && len(address.Value) == 0
		case v.Type().ConvertibleTo(reflect.TypeFor[netip.Addr]()):
			return !v.Convert(reflect.TypeFor[netip.Addr]()).Interface().(netip.Addr).IsValid()
		}
	}
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Pointer:
		return v.IsNil()
	}
	return false
}

// Marshal encodes struct into AVPs. Address fields support datatype.Address,
// net.IP, netip.Addr, and named types with the same underlying types.
func (m *Message) Marshal(src interface{}) error {
	v := reflect.ValueOf(src)
	if v.Kind() != reflect.Pointer {
		return errors.New("src is not a pointer to struct")
	}
	avps, err := marshalStruct(m, v)
	if err != nil {
		return err
	}
	m.AVP = avps
	m.Header.MessageLength = uint32(m.Len())
	return nil
}

func marshalStruct(m *Message, field reflect.Value) ([]*AVP, error) {
	var err error
	var dictAVP *dict.AVP
	var avps []*AVP

	base := reflect.Indirect(field)
	if base.Kind() != reflect.Struct {
		return nil, errors.New("src is not a pointer to struct")
	}

	for n := 0; n < base.NumField(); n++ {
		f := base.Field(n)
		bt := base.Type().Field(n)

		if bt.Anonymous && bt.Type.Kind() == reflect.Struct && len(bt.Tag) == 0 {
			embeddedAvps, err := marshalStruct(m, f)
			if err != nil {
				return nil, err
			}
			avps = append(avps, embeddedAvps...)
			continue
		}

		avpName, omitEmpty := parseAvpTag(bt.Tag)
		if len(avpName) == 0 || (omitEmpty && isEmptyValue(f)) {
			// TODO: check the required attribute in AVP rule?
			continue
		}

		// Lookup the AVP name (tag) in the dictionary, the dictionary AVP has the code.
		dictAVP, err = m.Dictionary().FindAVP(m.Header.ApplicationID, avpName)
		if err != nil {
			return nil, err
		}

		avp, err := marshal(m, f, dictAVP)
		if err != nil {
			return nil, err
		}
		avps = append(avps, avp...)
	}

	return avps, nil
}

// marshal returns a AVP type of the field
func marshal(m *Message, field reflect.Value, fieldAVP *dict.AVP) ([]*AVP, error) {
	var data datatype.Type
	var avps []*AVP
	fieldType := field.Type()

	var t reflect.Type
	switch field.Kind() {
	case reflect.Slice:
		// 1. []byte
		//  (1) dicttype.Grouped
		//  (2) other basic types represented by byte slices, including net.IP
		// if fieldType == reflect.TypeOf(([]byte)(nil))
		if fieldType.Elem().Kind() == reflect.Uint8 {
			goto BASIC_TYPE
		}

		// 2.  []*diam.AVP
		if fieldType == reflect.TypeOf(([]*AVP)(nil)) {
			avp := field.Interface().([]*AVP)
			avps = append(avps, avp...)
			return avps, nil
		}

		// 3. real array of diameter AVPs
		for n := 0; n < field.Len(); n++ {
			avp, err := marshal(m, field.Index(n), fieldAVP)
			if err != nil {
				return nil, err
			}
			avps = append(avps, avp...)
		}
		return avps, nil

	case reflect.Interface, reflect.Pointer:
		if field.IsNil() {
			return avps, nil // skip optional AVP
		}
		return marshal(m, field.Elem(), fieldAVP)
	}

BASIC_TYPE:
	switch fieldAVP.Data.Type {
	case datatype.AddressType:
		address, err := marshalAddress(field)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", fieldAVP.Name, err)
		}
		data = address
	case datatype.DiameterIdentityType:
		t = reflect.TypeOf((*datatype.DiameterIdentity)(nil)).Elem()
	case datatype.DiameterURIType:
		t = reflect.TypeOf((*datatype.DiameterURI)(nil)).Elem()
	case datatype.EnumeratedType:
		t = reflect.TypeOf((*datatype.Enumerated)(nil)).Elem()
	case datatype.Float32Type:
		t = reflect.TypeOf((*datatype.Float32)(nil)).Elem()
	case datatype.Float64Type:
		t = reflect.TypeOf((*datatype.Float64)(nil)).Elem()
	case datatype.IPFilterRuleType:
		t = reflect.TypeOf((*datatype.IPFilterRule)(nil)).Elem()
	case datatype.IPv4Type:
		t = reflect.TypeOf((*datatype.IPv4)(nil)).Elem()
	case datatype.Integer32Type:
		t = reflect.TypeOf((*datatype.Integer32)(nil)).Elem()
	case datatype.Integer64Type:
		t = reflect.TypeOf((*datatype.Integer64)(nil)).Elem()
	case datatype.OctetStringType:
		t = reflect.TypeOf((*datatype.OctetString)(nil)).Elem()
	case datatype.TimeType:
		t = reflect.TypeOf((*datatype.Time)(nil)).Elem()
	case datatype.UTF8StringType:
		t = reflect.TypeOf((*datatype.UTF8String)(nil)).Elem()
	case datatype.Unsigned32Type:
		t = reflect.TypeOf((*datatype.Unsigned32)(nil)).Elem()
	case datatype.Unsigned64Type:
		t = reflect.TypeOf((*datatype.Unsigned64)(nil)).Elem()
	case datatype.GroupedType:
		if field.Kind() == reflect.Struct {
			// 1.  diam.AVP
			// if fieldType.String() == "diam.AVP"
			if fieldType == reflect.TypeOf(AVP{}) {
				p := reflect.New(fieldType)
				v := reflect.ValueOf(p).Elem()
				v.Set(field)
				avp := p.Interface().(*AVP)
				return append(avps, avp), nil
			}

			// 2. GroupedAVP
			gAVP := &GroupedAVP{}
			for n := 0; n < field.NumField(); n++ {
				f := field.Field(n)
				bt := field.Type().Field(n)
				avpname, omitEmpty := parseAvpTag(bt.Tag)
				if len(avpname) == 0 || (omitEmpty && isEmptyValue(f)) {
					// TODO: check the required attribute in AVP rule?
					continue
				}
				// Lookup the AVP name (tag) in the dictionary, the dictionary AVP has the code.
				// Relies on the fact that in the same app will not be AVPs with same code but different vendorId
				d, err := m.Dictionary().FindAVP(m.Header.ApplicationID, avpname)
				if err != nil {
					return nil, err
				}
				avp, err := marshal(m, f, d)
				if err != nil {
					return nil, err
				}
				gAVP.AVP = append(gAVP.AVP, avp...) // gAVP.AddAVP()
			}
			data = gAVP
		} else if field.Kind() == reflect.Slice {
			// when code run here, we are certain that it is datatype.Grouped AVP
			// like "Failed-AVP", all we need to do is assigning the []byte slibe
			//  to a datatype.Grouped
			t = reflect.TypeOf((*datatype.Grouped)(nil)).Elem()
			break
		} else {
			return nil, errors.New(fieldAVP.Name + " AVP's Data type is unknown")
		}
	default:
		return nil, errors.New(fieldAVP.Name + " AVP's Data type is unknown")
	}

	if data == nil { // basic non-grouped AVP
		p := reflect.New(t)
		v := reflect.Indirect(p)

		if fieldType.AssignableTo(t) {
			// log.Println("assign: ", fieldAVP.Name, " ", fieldType.String(), " => ", t.String())
			v.Set(field)
		} else if fieldType.ConvertibleTo(t) {
			// log.Println("convert: ", fieldAVP.Name, " ", fieldType.String(), " => ", t.String())
			v.Set(field.Convert(t))
		} else {
			return nil, errors.New(fieldAVP.Name + " AVP type mismatched: " + fieldType.String() + " => " + t.String())
		}
		var ok bool
		data, ok = v.Interface().(datatype.Type)
		if !ok {
			return nil, errors.New(fieldAVP.Name + ", failed to convert AVP data to datatype.Type")
		}
	}

	var avpFlags uint8
	if strings.Contains(fieldAVP.Must, "M") {
		avpFlags = avp.Mbit
	}
	if fieldAVP.VendorID > 0 {
		avpFlags |= avp.Vbit
	}

	avp := &AVP{
		Code:     fieldAVP.Code,
		Flags:    avpFlags,
		VendorID: fieldAVP.VendorID,
		Data:     data,
	}

	return append(avps, avp), nil
}

// Unmarshal stores the result of a diameter message in the struct
// pointed to by dst.
//
// Unmarshal can not only decode AVPs into the struct, but also their
// Go equivalent data types, directly.
//
// For example:
//
//	type CER struct {
//		OriginHost  AVP    `avp:"Origin-Host"`
//		.. or
//		OriginHost  *AVP   `avp:"Origin-Host"`
//		.. or
//		OriginHost  string `avp:"Origin-Host"`
//	}
//	var d CER
//	err := diam.Unmarshal(&d)
//
// This decodes the Origin-Host AVP as three different types. The first, AVP,
// makes a copy of the AVP in the message and stores in the struct. The
// second, *AVP, stores a pointer to the original AVP in the message. If you
// change the values of it, you're actually changing the message.
// The third decodes the inner contents of AVP.Data, which in this case is
// a format.DiameterIdentity, and stores the value of it in the struct.
//
// Unmarshal supports all the basic Go types, including slices, for multiple
// AVPs of the same type) and structs, for grouped AVPs.
//
// Slices:
//
//	type CER struct {
//		Vendors  []*AVP `avp:"Supported-Vendor-Id"`
//	}
//	var d CER
//	err := diam.Unmarshal(&d)
//
// Slices have the same principles of other types. If they're of type
// []*AVP it'll store references in the struct, while []AVP makes
// shallow copies and []int (or []string, etc) decodes the AVP data for you.
// Raw AVP fields accept any Data, including undecoded datatype.Unknown values.
// Pointer fields refer to the original AVPs for every data type; value fields
// copy the AVP struct but share its Data storage.
//
// Grouped AVPs:
//
//	type VSA struct {
//		AuthAppID int `avp:"Auth-Application-Id"`
//		VendorID  int `avp:"Vendor-Id"`
//	}
//	type CER struct {
//		VSA VSA  `avp:"Vendor-Specific-Application-Id"`
//		.. or
//		VSA *VSA `avp:"Vendor-Specific-Application-Id"`
//		.. or
//		VSA struct {
//			AuthAppID int `avp:"Auth-Application-Id"`
//			VendorID  int `avp:"Vendor-Id"`
//		} `avp:"Vendor-Specific-Application-Id"`
//	}
//	var d CER
//	err := m.Unmarshal(&d)
//
// Address AVPs require valid datatype.Address data. Address fields support
// datatype.Address, net.IP, netip.Addr, and named types with the same underlying
// types. Named byte slices are interpreted as IP addresses; unnamed []byte and
// other unsupported field types return an error.
//
// Other types are supported as well, such as net.IP, netip.Addr and time.Time where
// applicable. See the format sub-package for details. Usually, you want
// to decode values to their native Go type when the AVPs don't have to be
// re-used in an answer, such as Origin-Host and friends. The ones that are
// usually added to responses, such as Origin-State-Id are better decoded to
// just AVP or *AVP, making it easier to re-use them in the answer.
//
// Note that decoding values to *AVP is much faster and more efficient than
// decoding to AVP or the native Go types.
func (m *Message) Unmarshal(dst interface{}) error {
	v := reflect.ValueOf(dst)
	if v.Kind() != reflect.Pointer {
		return errors.New("dst is not a pointer to struct")
	}
	return scanStruct(m, v, m.AVP)
}

// avpKey identifies an AVP by the Code and Vendor-ID pair (RFC 6733 §4.1).
type avpKey struct {
	Code     uint32
	VendorID uint32
}

// newIndex returns a map of AVPs indexed by Code and Vendor-ID.
// TODO: make this part of the Message.
func newIndex(avps []*AVP) map[avpKey][]*AVP {
	idx := make(map[avpKey][]*AVP, len(avps))
	for _, a := range avps {
		key := avpKey{a.Code, a.VendorID}
		idx[key] = append(idx[key], a)
	}
	return idx
}

func scanStruct(m *Message, field reflect.Value, avps []*AVP) error {
	base := reflect.Indirect(field)
	if base.Kind() != reflect.Struct {
		return errors.New("dst is not a pointer to struct")
	}
	idx := newIndex(avps)
	for n := 0; n < base.NumField(); n++ {
		f := base.Field(n)
		bt := base.Type().Field(n)

		if bt.Anonymous && bt.Type.Kind() == reflect.Struct && len(bt.Tag) == 0 {
			if err := scanStruct(m, f, avps); err != nil {
				return err
			}
			continue
		}

		avpname, _ := parseAvpTag(bt.Tag)
		if len(avpname) == 0 {
			continue
		}
		// Lookup the AVP name (tag) in the dictionary.
		// The dictionary AVP has the code.
		d, err := m.Dictionary().FindAVP(m.Header.ApplicationID, avpname)
		if err != nil {
			return err
		}
		// See if this AVP exist in the message.
		avps, exists := idx[avpKey{d.Code, d.VendorID}]
		if !exists {
			continue
		}
		//log.Println("Handling", f, bt)
		if err := unmarshal(m, f, avps, d.Data.Type); err != nil {
			return err
		}
	}
	return nil
}

func unmarshal(m *Message, f reflect.Value, avps []*AVP, expected datatype.TypeID) error {
	fieldType := f.Type()
	if !f.CanSet() {
		return fmt.Errorf("cannot set AVP field %s", fieldType)
	}
	if unmarshalRawAVP(f, avps) {
		return nil
	}
	_, addressData := avps[0].Data.(datatype.Address)
	if expected == datatype.AddressType || addressData || fieldType.ConvertibleTo(reflect.TypeFor[datatype.Address]()) {
		return unmarshalAddress(f, avps)
	}
	switch f.Kind() {
	case reflect.Slice:
		// Copy byte arrays.
		dv := reflect.ValueOf(avps[0].Data)
		if dv.Type().ConvertibleTo(fieldType) {
			f.Set(dv.Convert(fieldType))
			break
		}

		// Allocate new slice and copy all items.
		f.Set(reflect.MakeSlice(fieldType, len(avps), len(avps)))
		// TODO: optimize?
		for n := 0; n < len(avps); n++ {
			if err := unmarshal(m, f.Index(n), avps[n:], expected); err != nil {
				return err
			}
		}

	case reflect.Interface, reflect.Pointer:
		if f.IsNil() {
			f.Set(reflect.New(fieldType.Elem()))
		}
		return unmarshal(m, f.Elem(), avps, expected)

	case reflect.Struct:
		// Used for unmarshalling time datatype
		if fieldType.AssignableTo(reflect.TypeOf(avps[0].Data)) {
			f.Set(reflect.ValueOf(avps[0].Data))
			break
		}

		// Used for unmarshalling time type
		if fieldType.ConvertibleTo(reflect.TypeOf(avps[0].Data)) {
			timeStamp := reflect.ValueOf(avps[0].Data).Convert(fieldType)
			f.Set(timeStamp)
			break
		}

		// Handle grouped AVPs.
		if group, ok := avps[0].Data.(*GroupedAVP); ok {
			return scanStruct(m, f, group.AVP)
		}

	default:
		// Test for AVP.Data (e.g. format.UTF8String, string)
		dv := reflect.ValueOf(avps[0].Data)
		if dv.Type().ConvertibleTo(fieldType) {
			f.Set(dv.Convert(fieldType))
		}
	}
	return nil
}

// Raw AVP fields preserve undecoded data, including Failed-AVP evidence.
func unmarshalRawAVP(f reflect.Value, avps []*AVP) bool {
	switch f.Type() {
	case reflect.TypeFor[AVP]():
		f.Set(reflect.ValueOf(*avps[0]))
	case reflect.TypeFor[*AVP]():
		f.Set(reflect.ValueOf(avps[0]))
	case reflect.TypeFor[[]AVP](), reflect.TypeFor[[]*AVP]():
		values := reflect.MakeSlice(f.Type(), len(avps), len(avps))
		for i := range avps {
			unmarshalRawAVP(values.Index(i), avps[i:i+1])
		}
		f.Set(values)
	default:
		return false
	}
	return true
}

// Named byte slices (including net.IP) represent IP addresses. An unnamed
// []byte is deliberately not an Address field: it would lose the family.
func isAddressIPType(t reflect.Type) bool {
	return t.Name() != "" && t.Kind() == reflect.Slice && t.ConvertibleTo(reflect.TypeFor[net.IP]())
}

func marshalAddress(field reflect.Value) (datatype.Address, error) {
	t := field.Type()
	if t.ConvertibleTo(reflect.TypeFor[datatype.Address]()) {
		address := field.Convert(reflect.TypeFor[datatype.Address]()).Interface().(datatype.Address)
		if err := address.Valid(); err != nil {
			return datatype.Address{}, err
		}
		return address.Clone(), nil
	}
	var ip netip.Addr
	switch {
	case t.ConvertibleTo(reflect.TypeFor[netip.Addr]()):
		ip = field.Convert(reflect.TypeFor[netip.Addr]()).Interface().(netip.Addr)
	case isAddressIPType(t):
		ip, _ = netip.AddrFromSlice(field.Convert(reflect.TypeFor[net.IP]()).Interface().(net.IP))
	default:
		return datatype.Address{}, fmt.Errorf("cannot marshal %s as Address", t)
	}
	if !ip.IsValid() {
		return datatype.Address{}, errors.New("invalid IP address")
	}
	return datatype.AddressFromIP(ip), nil
}

func unmarshalAddress(f reflect.Value, avps []*AVP) error {
	t := f.Type()
	if !f.CanSet() {
		return fmt.Errorf("cannot set Address field %s", t)
	}
	if unmarshalRawAVP(f, avps) {
		return nil
	}
	seen := make(map[reflect.Type]bool)
	for leaf := t; leaf.Kind() == reflect.Pointer || (leaf.Kind() == reflect.Slice && leaf.Elem().Kind() != reflect.Uint8); leaf = leaf.Elem() {
		if seen[leaf] {
			return fmt.Errorf("cannot unmarshal Address into recursive type %s", t)
		}
		seen[leaf] = true
	}
	if t.Kind() == reflect.Slice && t.Elem().Kind() != reflect.Uint8 {
		values := reflect.MakeSlice(t, len(avps), len(avps))
		for i := range avps {
			if err := unmarshalAddress(values.Index(i), avps[i:i+1]); err != nil {
				return err
			}
		}
		f.Set(values)
		return nil
	}
	address, ok := avps[0].Data.(datatype.Address)
	if !ok {
		return fmt.Errorf("cannot unmarshal %T as Address into %s", avps[0].Data, t)
	}
	if err := address.Valid(); err != nil {
		return err
	}
	if t.Kind() == reflect.Pointer {
		value := reflect.New(t.Elem())
		if err := unmarshalAddress(value.Elem(), avps); err != nil {
			return err
		}
		f.Set(value)
		return nil
	}
	switch {
	case t.ConvertibleTo(reflect.TypeFor[datatype.Address]()):
		f.Set(reflect.ValueOf(address.Clone()).Convert(t))
	case isAddressIPType(t), t.ConvertibleTo(reflect.TypeFor[netip.Addr]()):
		ip, valid := address.IP()
		if !valid {
			return fmt.Errorf("cannot unmarshal Address family %d into %s", address.Family, t)
		}
		if isAddressIPType(t) {
			f.Set(reflect.ValueOf(net.IP(ip.AsSlice())).Convert(t))
		} else {
			f.Set(reflect.ValueOf(ip).Convert(t))
		}
	default:
		return fmt.Errorf("cannot unmarshal Address into %s", t)
	}
	return nil
}
