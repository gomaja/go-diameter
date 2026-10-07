// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package base

import (
	"fmt"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
)

// CEA is a Capabilities-Exchange-Answer message.
// See RFC 6733 section 5.3.2 for details.
type CEA struct {
	HostIPAddresses             []datatype.Address        `avp:"Host-IP-Address"`
	ResultCode                  uint32                    `avp:"Result-Code"`
	OriginHost                  datatype.DiameterIdentity `avp:"Origin-Host"`
	OriginRealm                 datatype.DiameterIdentity `avp:"Origin-Realm"`
	OriginStateID               uint32                    `avp:"Origin-State-Id"`
	VendorID                    uint32                    `avp:"Vendor-Id"`           // Peer's Vendor-Id (RFC 6733 §5.3.2, mandatory).
	ProductName                 string                    `avp:"Product-Name"`        // Peer's Product-Name (RFC 6733 §5.3.2, mandatory).
	SupportedVendorID           []*diam.AVP               `avp:"Supported-Vendor-Id"` // Vendor-Ids the peer supports (RFC 6733 §5.3.2).
	AcctApplicationID           []*diam.AVP               `avp:"Acct-Application-Id"`
	AuthApplicationID           []*diam.AVP               `avp:"Auth-Application-Id"`
	VendorSpecificApplicationID []*diam.AVP               `avp:"Vendor-Specific-Application-Id"`
	FailedAVP                   []*diam.AVP               `avp:"Failed-AVP"`
	ErrorMessage                string                    `avp:"Error-Message"`
	appID                       []uint32                  // List of supported application IDs.
}

// ErrFailedResultCode is returned by Dial or DialTLS when the handshake
// answer (CEA) contains a Result-Code AVP that is not success (2001).
type ErrFailedResultCode struct {
	*CEA
}

// Error implements the error interface.
func (e ErrFailedResultCode) Error() string {
	return fmt.Sprintf("failed Result-Code AVP: %d", e.ResultCode)
}

// Parse decodes and validates a CEA against the local capabilities offered on
// this connection (RFC 6733 §5.3.2). Answers never generate an error answer.
func (cea *CEA) Parse(m *diam.Message, options ParseOptions) (err error) {
	if err := ValidateHeader(m); err != nil {
		return err
	}
	// RFC 6733 §§5.3.2 and 7.1.5: a non-strict decoder preserves an
	// invalid Address as Unknown. Identify its original AVP before reflection
	// loses that context. The CEA is an answer, so this error is returned to
	// the initiating client; it must not generate another answer.
	for _, a := range m.AVP {
		if a.Code != avp.HostIPAddress || a.VendorID != 0 {
			continue
		}
		if _, raw := a.Data.(datatype.Unknown); raw {
			result := uint32(diam.InvalidAVPValue)
			if a.Data.Len() < 2 {
				result = diam.InvalidAVPLength
			}
			return &diam.MessageError{ResultCode: result, FailedAVP: a, Err: fmt.Errorf("invalid CEA Host-IP-Address: not a valid Address")}
		}
	}
	if err = m.Unmarshal(cea); err != nil {
		return err
	}
	if err = cea.sanityCheck(); err != nil {
		return err
	}
	if cea.ResultCode != diam.Success {
		return &ErrFailedResultCode{CEA: cea}
	}
	app := &Application{
		AcctApplicationID:           cea.AcctApplicationID,
		AuthApplicationID:           cea.AuthApplicationID,
		VendorSpecificApplicationID: cea.VendorSpecificApplicationID,
	}
	dictionary := options.Dictionary
	if dictionary == nil {
		dictionary = m.Dictionary()
	}
	if _, err := app.ParseWithApplicationIDs(dictionary, options.Role, options.LocalApplications); err != nil {
		return err
	}
	cea.appID = app.ID()
	return nil
}

// sanityCheck ensures mandatory AVPs are present.
func (cea *CEA) sanityCheck() error {
	if cea.ResultCode == 0 {
		return ErrMissingResultCode
	}
	if len(cea.OriginHost) == 0 {
		return ErrMissingOriginHost
	}
	if len(cea.OriginRealm) == 0 {
		return ErrMissingOriginRealm
	}
	return nil
}

// Applications return a list of supported Application IDs.
func (cea *CEA) Applications() []uint32 {
	return cea.appID
}
