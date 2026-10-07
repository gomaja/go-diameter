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

// parentAppIds map allows for hierarchical AVP search dependencies
// If an AVP code was not found in the app's dictionary, the search will continue in the parent app
// dictionary and only then in base diameter dictionary
// Parent cycles are rejected during lookup and dictionary loading.
// Snapshots are indexed from it, so it must not change while Parsers are in use.
var parentAppIds map[uint32]uint32 = map[uint32]uint32{
	// TS 29.229 V19.1.0 §§6.3.13, 6.3.53-55 reuse NAS framed-address AVPs;
	// their current definitions are RFC 7155 §§4.4.10.5.1, 4.4.10.5.5-6.
	16777216: 1,
	// TS 29.329 V19.1.0 §§6.3.9, 6.3.11-15, 6.3.19-21 reuse Cx AVPs.
	16777217: 16777216,
	// 3GPP TS 29.338 V19.3.0 §§5.3.3.1, 6.3.3.1, Tables 5.3.3.1/2, 6.3.3.1/2.
	16777312: 4,
	16777313: 16777312,
	// S6a reuses TS 29.272 AVPs present in the S6c SMS dictionary.
	16777251: 16777312,
	16777238: 4,
	// 3GPP TS 29.214 V20.0.0 §5.4 reuses charging AVPs on Rx.
	16777236: 4,
	// 3GPP TS 29.219 V19.0.0 §5.2 reuses charging AVPs on Sy.
	16777302: 4,
	// 3GPP TS 29.273 V19.2.0 §8.2.3.0/Table 8.2.3.0/2 reuses S6a and charging AVPs on SWx.
	16777265: 16777251,
	4:        1,
}

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
// Undeclared applications inherit too. A miss returns nil and an error wrapping
// ErrNotFound. An inheritance cycle returns an error wrapping ErrParentCycle.
func (s *Snapshot) FindAVP(appid, code, vendorID uint32) (*AVP, error) {
	a, err := s.lookupAVP(appid, code, vendorID)
	if err == nil {
		return a, nil
	}
	if err == ErrParentCycle {
		return nil, fmt.Errorf("application %d: %w", appid, err)
	}
	return nil, fmt.Errorf("application %d: AVP code %d vendor %d: %w", appid, code, vendorID, err)
}

// lookupAVP is the allocation-free core shared by AVP and FindAVP.
func (s *Snapshot) lookupAVP(appid, code, vendorID uint32) (*AVP, error) {
	for app, steps := appid, 0; steps <= len(parentAppIds)+1; steps++ {
		if a, ok := s.avpcode[codeIdx{app, code, vendorID}]; ok {
			return a, nil
		}
		if app == 0 {
			return nil, ErrNotFound
		}
		app = parentAppIds[app]
	}
	return nil, ErrParentCycle
}

// FindAVP is Snapshot.FindAVP on the current Snapshot. Lookups that must
// agree, such as those decoding one message, should share one Snapshot.
func (p *Parser) FindAVP(appid, code, vendorID uint32) (*AVP, error) {
	return p.Snapshot().FindAVP(appid, code, vendorID)
}

// FindAVPByName returns the AVP named name in appid, using the same
// inheritance order as FindAVP. Names are unique within each application;
// rules use these names (RFC 6733 (October 2012) §§3.2, 4.4).
// A miss returns nil and an error wrapping ErrNotFound; an inheritance cycle
// returns an error wrapping ErrParentCycle.
func (s *Snapshot) FindAVPByName(appid uint32, name string) (*AVP, error) {
	for app, steps := appid, 0; steps <= len(parentAppIds)+1; steps++ {
		if avp, ok := s.avpname[appNameIdx{app, name}]; ok {
			// An inherited name cannot revive a wire identity renamed by a
			// nearer application. Resolve in the original application's scope.
			if resolved, found := s.AVP(appid, avp.Code, avp.VendorID); found && resolved.Name == name {
				return resolved, nil
			}
		}
		if app == 0 {
			return nil, fmt.Errorf("application %d: AVP name %q: %w", appid, name, ErrNotFound)
		}
		app = parentAppIds[app]
	}
	return nil, fmt.Errorf("application %d: %w", appid, ErrParentCycle)
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
