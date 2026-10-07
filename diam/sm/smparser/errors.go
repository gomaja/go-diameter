// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package smparser

import (
	"fmt"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

var (
	// ErrMissingResultCode is returned by Parse when
	// the message does nt contain a Result-Code AVP.
	ErrMissingResultCode = base.ErrMissingResultCode

	// ErrMissingOriginHost identifies an absent Origin-Host AVP. CER.Parse
	// wraps it in a *diam.MessageError with ResultCode 5005 and a Failed-AVP
	// example (RFC 6733 §7.1.5); use errors.Is, not equality.
	ErrMissingOriginHost = base.ErrMissingOriginHost

	// ErrMissingOriginRealm identifies an absent Origin-Realm AVP. CER.Parse
	// wraps it in a *diam.MessageError with ResultCode 5005 and a Failed-AVP
	// example (RFC 6733 §7.1.5); use errors.Is, not equality.
	ErrMissingOriginRealm = base.ErrMissingOriginRealm

	// ErrMissingApplication is returned by Parse when
	// the CER does not contain any Acct-Application-Id or
	// Auth-Application-Id, or their embedded versions in
	// the Vendor-Specific-Application-Id AVP.
	ErrMissingApplication = base.ErrMissingApplication

	// ErrNoCommonSecurity reports that none of the CER security offers is
	// usable on this transport (RFC 6733 §§5.3, 6.10).
	ErrNoCommonSecurity = base.ErrNoCommonSecurity

	// ErrNoCommonApplication is returned by Parse when the
	// received application IDs do not intersect the local capabilities
	// selected by ParseOptions (RFC 6733 §5.3).
	ErrNoCommonApplication = base.ErrNoCommonApplication
)

// ErrUnexpectedAVP is returned by Parse when the code of the AVP passed
// as AcctApplicationID, AuthApplicationID or VendorSpecificApplicationID
// and its embedded AVPs do not match their names.
type ErrUnexpectedAVP struct {
	AVP *diam.AVP
}

// Error implements the error interface.
func (e *ErrUnexpectedAVP) Error() string {
	return fmt.Sprintf("unexpected AVP: %s", e.AVP)
}

func adaptError(err error) error {
	if unexpected, ok := err.(*base.ErrUnexpectedAVP); ok {
		return &ErrUnexpectedAVP{AVP: unexpected.AVP}
	}
	return err
}
