// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Dictionary parser, helper functions.  Part of go-diameter.

package dict

import (
	"errors"
	"fmt"

	"github.com/gomaja/go-diameter/diam/datatype"
)

// Apps returns the applications declared by the loaded dictionaries, in
// load order. Registering AVPs declares no application.
func (s *Snapshot) Apps() []*App {
	var apps []*App
	for _, f := range s.files {
		apps = append(apps, f.App...)
	}
	return apps
}

// Apps is Snapshot.Apps on the current Snapshot.
func (p *Parser) Apps() []*App { return p.Snapshot().Apps() }

// App returns a dictionary application for the given application code
// if exists.
func (s *Snapshot) App(code uint32, typ ...string) (*App, error) {
	var app *App
	if len(typ) > 0 {
		app = s.apptype[appIdTypeIdx{code, typ[0]}]
	}
	if app != nil {
		return app, nil
	}
	app = s.appcode[code]
	if app != nil && (len(app.Type) == 0 || len(typ) == 0 || app.Type == typ[0]) {
		return app, nil
	}
	return nil, ErrApplicationUnsupported
}

// App is Snapshot.App on the current Snapshot.
func (p *Parser) App(code uint32, typ ...string) (*App, error) {
	return p.Snapshot().App(code, typ...)
}

// ErrApplicationUnsupported indicates that the application requested
// does not exist in the dictionary Parser object.
var ErrApplicationUnsupported = errors.New("application unsupported")

// ErrNotFound indicates that a dictionary lookup has no matching definition.
var ErrNotFound = errors.New("dictionary entry not found")

// ErrParentCycle indicates a cycle in the application inheritance chain.
var ErrParentCycle = errors.New("dictionary parent application cycle")

// MakeUnknownAVP constructs an explicit placeholder for undecodable AVP data.
// It is independent of lookup: callers decide whether an unknown AVP is allowed.
func MakeUnknownAVP(appid, code, vendorID uint32) *AVP {
	return &AVP{
		Name:     fmt.Sprintf("Unknown-%d-%d", code, vendorID),
		Code:     code,
		VendorID: vendorID,
		Data: Data{
			Type:     datatype.UnknownType,
			TypeName: "Unknown",
		},
		App: &App{
			ID:     appid,
			Vendor: []*Vendor{&Vendor{ID: vendorID}},
		},
	}
}

// AVP returns the definition identified by code and vendorID in appid, or
// nil, false if it is absent. It uses the same inheritance order as FindAVP
// without allocating a diagnostic or placeholder on a miss.
// RFC 6733 (October 2012) §4.1: code and Vendor-Id together identify an AVP.
func (s *Snapshot) AVP(appid, code, vendorID uint32) (*AVP, bool) {
	a, err := s.lookupAVP(appid, code, vendorID)
	return a, err == nil
}

// AVP is Snapshot.AVP on the current Snapshot.
func (p *Parser) AVP(appid, code, vendorID uint32) (*AVP, bool) {
	return p.Snapshot().AVP(appid, code, vendorID)
}

// FindAVP returns the definition identified by code and vendorID in appid.
// RFC 6733 (October 2012) §4.1 identifies an AVP by (code, Vendor-Id);
// vendorID 0 selects the IETF code space. No vendor value is a wildcard.
// The application's own definitions take precedence over its nearest parent,
// then more distant ancestors and base application 0 (RFC 6733 §2).
// Undeclared applications fall back only to base. A miss returns nil and an error wrapping
// ErrNotFound. Inheritance cycles are rejected when loading the dictionary.
func (s *Snapshot) FindAVP(appid, code, vendorID uint32) (*AVP, error) {
	a, err := s.lookupAVP(appid, code, vendorID)
	if err == nil {
		return a, nil
	}
	return nil, fmt.Errorf("application %d: AVP code %d vendor %d: %w", appid, code, vendorID, err)
}

// lookupAVP is the allocation-free core shared by AVP and FindAVP.
func (s *Snapshot) lookupAVP(appid, code, vendorID uint32) (*AVP, error) {
	if a, ok := s.avpcode[codeIdx{appid, code, vendorID}]; ok {
		return a, nil
	}
	if a, ok := s.avpcode[codeIdx{0, code, vendorID}]; ok {
		return a, nil
	}
	return nil, ErrNotFound
}

// FindAVP is Snapshot.FindAVP on the current Snapshot. Lookups that must
// agree, such as those decoding one message, should share one Snapshot.
func (p *Parser) FindAVP(appid, code, vendorID uint32) (*AVP, error) {
	return p.Snapshot().FindAVP(appid, code, vendorID)
}

// FindAVPByName returns the AVP named name in appid, using the same
// inheritance order as FindAVP. Own names may shadow inherited names. For
// other names, all non-base direct parents that resolve the name must agree
// on its code/vendor in their final views, including ancestors and base.
// Base is not compared as a separate parent. Load and RegisterAVP validate
// this agreement without changing breadth-first code/vendor precedence.
// Rules use these names (RFC 6733 (October 2012) §§3.2, 4.4).
// A miss returns nil and an error wrapping ErrNotFound.
func (s *Snapshot) FindAVPByName(appid uint32, name string) (*AVP, error) {
	for _, app := range [...]uint32{appid, 0} {
		if a, ok := s.avpname[appNameIdx{app, name}]; ok {
			if resolved, found := s.AVP(appid, a.Code, a.VendorID); found && resolved.Name == name {
				return resolved, nil
			}
		}
	}
	return nil, fmt.Errorf("application %d: AVP name %q: %w", appid, name, ErrNotFound)
}

// FindAVPByName is Snapshot.FindAVPByName on the current Snapshot.
func (p *Parser) FindAVPByName(appid uint32, name string) (*AVP, error) {
	return p.Snapshot().FindAVPByName(appid, name)
}

// FindCommand returns a pre-loaded Command from the Parser.
func (s *Snapshot) FindCommand(appid, code uint32) (*Command, error) {
	if cmd, ok := s.command[commandIdx{appid, code}]; ok {
		return cmd, nil
	} else if cmd, ok = s.command[commandIdx{0, code}]; ok {
		// Always fall back to base dict.
		return cmd, nil
	}
	return nil, fmt.Errorf("application %d: command code %d: %w", appid, code, ErrNotFound)
}

// FindCommand is Snapshot.FindCommand on the current Snapshot.
func (p *Parser) FindCommand(appid, code uint32) (*Command, error) {
	return p.Snapshot().FindCommand(appid, code)
}

// Enum is a helper function that returns a pre-loaded Enum item for the
// given AVP appid, code, vendorID and n. (n is the enum code in the dictionary)
func (s *Snapshot) Enum(appid, code, vendorID uint32, n int32) (*Enum, error) {
	avp, err := s.FindAVP(appid, code, vendorID)
	if err != nil {
		return nil, err
	}
	if avp.Data.Type != datatype.EnumeratedType {
		return nil, fmt.Errorf(
			"application %d: AVP code %d vendor %d: expected Enumerated, got %s",
			appid, code, vendorID, avp.Data.TypeName)
	}
	for _, item := range avp.Data.Enum {
		if item.Code == n {
			return item, nil
		}
	}
	return nil, fmt.Errorf(
		"application %d: AVP code %d vendor %d: enum value %d: %w",
		appid, code, vendorID, n, ErrNotFound)
}

// Enum is Snapshot.Enum on the current Snapshot.
func (p *Parser) Enum(appid, code, vendorID uint32, n int32) (*Enum, error) {
	return p.Snapshot().Enum(appid, code, vendorID, n)
}

// Rule is a helper function that returns a pre-loaded Rule item for the
// given AVP appid, code, vendorID and member name.
func (s *Snapshot) Rule(appid, code, vendorID uint32, n string) (*Rule, error) {
	avp, err := s.FindAVP(appid, code, vendorID)
	if err != nil {
		return nil, err
	}
	if avp.Data.Type != datatype.GroupedType {
		return nil, fmt.Errorf(
			"application %d: AVP code %d vendor %d: expected Grouped, got %s",
			appid, code, vendorID, avp.Data.TypeName)
	}
	for _, item := range avp.Data.Rule {
		if item.AVP == n {
			return item, nil
		}
	}
	return nil, fmt.Errorf(
		"application %d: AVP code %d vendor %d: rule member %q: %w",
		appid, code, vendorID, n, ErrNotFound)
}

// Rule is Snapshot.Rule on the current Snapshot.
func (p *Parser) Rule(appid, code, vendorID uint32, n string) (*Rule, error) {
	return p.Snapshot().Rule(appid, code, vendorID, n)
}
