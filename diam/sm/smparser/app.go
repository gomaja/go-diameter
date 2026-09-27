// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package smparser

import (
	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

// Role stores information whether SM is initialized as a Client or a Server
type Role uint8

// ServerRole and ClientRole enums are passed to smparser for proper CER/CEA verification
const (
	Server Role = iota + 1
	Client
)

// Application validates accounting, auth, and vendor specific application IDs.
type Application struct {
	AcctApplicationID           []*diam.AVP
	AuthApplicationID           []*diam.AVP
	VendorSpecificApplicationID []*diam.AVP
	id                          []uint32 // List of supported application IDs.
}

// Parse ensures at least one common acct or auth applications in the CE
// exist in this server's dictionary.
func (app *Application) Parse(d *dict.Parser, localRole Role) (failedAVP *diam.AVP, err error) {
	parsed := &base.Application{
		AcctApplicationID:           app.AcctApplicationID,
		AuthApplicationID:           app.AuthApplicationID,
		VendorSpecificApplicationID: app.VendorSpecificApplicationID,
	}
	failedAVP, err = parsed.Parse(d, base.Role(localRole))
	app.id = append(app.id, parsed.ID()...)
	return failedAVP, adaptError(err)
}

// ID returns a list of supported application IDs.
// Must be called after Parse, otherwise it returns an empty array.
func (app *Application) ID() []uint32 {
	return app.id
}
