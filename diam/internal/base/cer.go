// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package base

import (
	"fmt"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// CER is a Capabilities-Exchange-Request message.
// See RFC 6733 section 5.3.1 for details.
type CER struct {
	OriginHost                  datatype.DiameterIdentity `avp:"Origin-Host"`
	OriginRealm                 datatype.DiameterIdentity `avp:"Origin-Realm"`
	OriginStateID               *diam.AVP                 `avp:"Origin-State-Id"`
	InbandSecurityID            *diam.AVP                 `avp:"Inband-Security-Id"`
	AcctApplicationID           []*diam.AVP               `avp:"Acct-Application-Id"`
	AuthApplicationID           []*diam.AVP               `avp:"Auth-Application-Id"`
	VendorSpecificApplicationID []*diam.AVP               `avp:"Vendor-Specific-Application-Id"`
	appID                       []uint32                  // List of supported application IDs.
}

// Parse parses and validates the given message, and returns nil when
// all AVPs are ok, and all accounting or authentication applications
// in the CER match the applications in our dictionary. If one or more
// mandatory AVPs are missing, it returns a nil failedAVP and a proper
// error. If all mandatory AVPs are present but no common application
// is found, then it returns the failedAVP (with the application that
// we don't support in our dictionary) and an error. Another cause
// for error is the presence of Inband Security, we don't support that.
func (cer *CER) Parse(m *diam.Message, localRole Role) (failedAVP *diam.AVP, err error) {
	return cer.ParseWithSecurity(m, localRole, false)
}

// ParseWithSecurity is like Parse but accepts a tlsActive flag. When
// tlsActive is true, Inband-Security-Id=1 (TLS) is accepted because
// the transport is already secured — per RFC 6733 §5.3.1 the peer is
// simply declaring its TLS capability which is already satisfied.
func (cer *CER) ParseWithSecurity(m *diam.Message, localRole Role, tlsActive bool) (failedAVP *diam.AVP, err error) {
	return cer.ParseWithSecurityAndDictionary(m, localRole, tlsActive, m.Dictionary())
}

// ParseWithSecurityAndDictionary validates capabilities against the dictionary
// used to advertise local applications (RFC 6733 §5.3). A nil dictionary uses
// the message dictionary.
func (cer *CER) ParseWithSecurityAndDictionary(m *diam.Message, localRole Role, tlsActive bool, dictionary *dict.Parser) (failedAVP *diam.AVP, err error) {
	if err = m.Unmarshal(cer); err != nil {
		return nil, err
	}
	if err = cer.sanityCheck(); err != nil {
		return nil, err
	}
	// RFC 6733 §§5.3.1 and 6.10: the AVP may repeat, and omission
	// means NO_INBAND_SECURITY. Every present AVP must have four bytes.
	var offered, common bool
	for _, a := range m.AVP {
		if a.Code != avp.InbandSecurityID || a.VendorID != 0 {
			continue
		}
		offered = true
		v, ok := a.Data.(datatype.Unsigned32)
		if !ok {
			return a, &diam.MessageError{ResultCode: diam.InvalidAVPLength, FailedAVP: a, Err: fmt.Errorf("Inband-Security-Id must be Unsigned32")}
		}
		common = common || v == 0 || tlsActive
	}
	if offered && !common {
		return nil, ErrNoCommonSecurity
	}
	app := &Application{
		AcctApplicationID:           cer.AcctApplicationID,
		AuthApplicationID:           cer.AuthApplicationID,
		VendorSpecificApplicationID: cer.VendorSpecificApplicationID,
	}
	if dictionary == nil {
		dictionary = m.Dictionary()
	}
	if failedAVP, err = app.Parse(dictionary, localRole); err != nil {
		return failedAVP, err
	}
	cer.appID = app.ID()
	return nil, nil
}

// sanityCheck ensures mandatory AVPs are present.
func (cer *CER) sanityCheck() error {
	if len(cer.OriginHost) == 0 {
		return ErrMissingOriginHost
	}
	if len(cer.OriginRealm) == 0 {
		return ErrMissingOriginRealm
	}
	return nil
}

// Applications return a list of supported Application IDs.
func (cer *CER) Applications() []uint32 {
	return cer.appID
}
