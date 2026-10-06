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
	// 3GPP TS 29.273 V19.2.0 §9.2 reuses S6a and charging AVPs on SWx.
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

// FindAVPWithVendor is a helper function that returns a pre-loaded AVP from the Parser, considering vendorID as filter.
// For no vendorID filter, use UndefinedVendorID constant
// If the AVP code is not found for the given appid it tries with appid=0
// before returning an error.
// Code can be either the AVP code (int, uint32) or name (string).
//
// Without a vendor filter a name resolves to the loaded AVP of that name
// or, when no loaded AVP has it, to the registered AVP of that name. A code
// without a vendor resolves only to a loaded AVP: an AVP is identified by
// its code and vendor together (RFC 6733 §4.1), and a registered AVP is
// found by both.
func (s *Snapshot) FindAVPWithVendor(appid uint32, code interface{}, vendorID uint32) (*AVP, error) {
	var (
		avp     *AVP
		ok      bool
		err     error
		visited = make(map[uint32]bool)
	)
	origAppID := appid
retry:
	if visited[appid] {
		return nil, fmt.Errorf("dictionary parent application cycle at %d", appid)
	}
	visited[appid] = true
	switch codeVal := code.(type) {
	case string:
		avp, ok = s.avpname[nameIdx{appid, codeVal, vendorID}]
		if !ok && vendorID == UndefinedVendorID {
			avp, ok = s.regname[appNameIdx{appid, codeVal}]
		}
		if !ok && appid == 0 {
			err = fmt.Errorf("could not find AVP %T(%q) for Vendor: %d", codeVal, codeVal, vendorID)
		}
	case uint32:
		avp, ok = s.avpcode[codeIdx{appid, codeVal, vendorID}]
		if !ok && appid == 0 {
			err = fmt.Errorf("could not find AVP %T(%d) for Vendor: %d", codeVal, codeVal, vendorID)
		}
	case int:
		avp, ok = s.avpcode[codeIdx{appid, uint32(codeVal), vendorID}]
		if !ok && appid == 0 {
			err = fmt.Errorf("could not find AVP %T(%d) for Vendor: %d", codeVal, codeVal, vendorID)
		}
	default:
		return nil, fmt.Errorf("unsupported AVP code type %T(%#v)", codeVal, code)
	}
	if ok {
		return avp, nil
	} else if appid != 0 {
		parentAppId, isScoppedApp := parentAppIds[appid]
		if isScoppedApp {
			// Try searching 'parent' dictionary
			appid = parentAppId
		} else {
			// Try searching the base dictionary.
			appid = 0
		}
		goto retry
	} else {
		if codeU32, isUint32 := code.(uint32); isUint32 {
			return MakeUnknownAVP(origAppID, codeU32, vendorID), err
		}
	}

	return nil, err
}

// FindAVPWithVendor is Snapshot.FindAVPWithVendor on the current Snapshot.
func (p *Parser) FindAVPWithVendor(appid uint32, code interface{}, vendorID uint32) (*AVP, error) {
	return p.Snapshot().FindAVPWithVendor(appid, code, vendorID)
}

// FindAVPByCode is a fast-path lookup that takes typed uint32 arguments,
// avoiding the interface{} boxing and type switch overhead of FindAVPWithVendor.
// It is intended for the hot decode path where code is always uint32.
//
// It finds what FindAVPWithVendor finds for a code and vendor. Because
// inherited AVPs are pre-merged into the index of every application with
// definitions when the Snapshot is built, a lookup that finds an AVP for
// such an application is a single map access.
func (s *Snapshot) FindAVPByCode(appid, code, vendorID uint32) (*AVP, error) {
	// Exact (appid, code, vendorID) match; inherited AVPs are pre-merged by mergeInheritedAVPs().
	// An absent vendor AVP resolves to Unknown, never cross-vendor (RFC 6733 §4.1/§11.1.1).
	if avp, ok := s.avpcode[codeIdx{appid, code, vendorID}]; ok {
		return avp, nil
	}
	// An application that no dictionary declares has no index of its own and
	// inherits like a declared one: from its parentAppIds ancestors, nearest
	// first, then from the base application, whose AVPs are common to all
	// Diameter messages (RFC 6733 §2). For an indexed application the walk
	// finds nothing more. parentAppIds is acyclic; the bound only guarantees
	// termination.
	for app, steps := appid, 0; app != 0 && steps <= len(parentAppIds); steps++ {
		app = parentAppIds[app] // 0, the base application, when app has no parent
		if avp, ok := s.avpcode[codeIdx{app, code, vendorID}]; ok {
			return avp, nil
		}
	}
	return MakeUnknownAVP(appid, code, vendorID),
		fmt.Errorf("could not find AVP %d for Vendor: %d", code, vendorID)
}

// FindAVPByCode is Snapshot.FindAVPByCode on the current Snapshot. Lookups
// that must agree, such as those decoding one message, should share one
// Snapshot instead.
func (p *Parser) FindAVPByCode(appid, code, vendorID uint32) (*AVP, error) {
	return p.Snapshot().FindAVPByCode(appid, code, vendorID)
}

// FindAVP is a helper function that returns a pre-loaded AVP from the Parser.
// If the AVP code is not found for the given appid it tries with appid=0
// before returning an error.
// Code can be either the AVP code (int, uint32) or name (string).
// It is FindAVPWithVendor without a vendor filter.
func (s *Snapshot) FindAVP(appid uint32, code interface{}) (*AVP, error) {
	return s.FindAVPWithVendor(appid, code, UndefinedVendorID)
}

// FindAVP is Snapshot.FindAVP on the current Snapshot.
func (p *Parser) FindAVP(appid uint32, code interface{}) (*AVP, error) {
	return p.Snapshot().FindAVP(appid, code)
}

// ScanAVP is a helper function that returns a pre-loaded AVP from the Dict.
// It's similar to FindAPI except that it scans the list of available AVPs
// instead of looking into one specific appid.
//
// ScanAVP is 20x or more slower than FindAVP. Use with care.
// Code can be either the AVP code (uint32) or name (string).
func (s *Snapshot) ScanAVP(code interface{}) (*AVP, error) {
	switch code := code.(type) {
	case string:
		for idx, avp := range s.avpname {
			if idx.name == code {
				return avp, nil
			}
		}
		return nil, fmt.Errorf("could not find AVP %s", code)
	case uint32:
		for idx, avp := range s.avpcode {
			if idx.code == code {
				return avp, nil
			}
		}
		return nil, fmt.Errorf("could not find AVP code %d", code)
	case int:
		for idx, avp := range s.avpcode {
			if idx.code == uint32(code) {
				return avp, nil
			}
		}
		return nil, fmt.Errorf("could not find AVP code %d", code)
	}
	return nil, fmt.Errorf("unsupported AVP code type %#v", code)
}

// ScanAVP is Snapshot.ScanAVP on the current Snapshot.
func (p *Parser) ScanAVP(code interface{}) (*AVP, error) {
	return p.Snapshot().ScanAVP(code)
}

// FindCommand returns a pre-loaded Command from the Parser.
func (s *Snapshot) FindCommand(appid, code uint32) (*Command, error) {
	if cmd, ok := s.command[commandIdx{appid, code}]; ok {
		return cmd, nil
	} else if cmd, ok = s.command[commandIdx{0, code}]; ok {
		// Always fall back to base dict.
		return cmd, nil
	}
	return nil, fmt.Errorf("could not find preloaded Command with code %d", code)
}

// FindCommand is Snapshot.FindCommand on the current Snapshot.
func (p *Parser) FindCommand(appid, code uint32) (*Command, error) {
	return p.Snapshot().FindCommand(appid, code)
}

// Enum is a helper function that returns a pre-loaded Enum item for the
// given AVP appid, code and n. (n is the enum code in the dictionary)
func (s *Snapshot) Enum(appid, code uint32, n int32) (*Enum, error) {
	avp, err := s.FindAVP(appid, code)
	if err != nil {
		return nil, err
	}
	if avp.Data.Type != datatype.EnumeratedType {
		return nil, fmt.Errorf(
			"data of AVP %s (%d) data is not Enumerated",
			avp.Name, avp.Code)
	}
	for _, item := range avp.Data.Enum {
		if item.Code == n {
			return item, nil
		}
	}
	return nil, fmt.Errorf(
		"could not find preload Enum %d for AVP %s (%d)",
		n, avp.Name, avp.Code)
}

// Enum is Snapshot.Enum on the current Snapshot.
func (p *Parser) Enum(appid, code uint32, n int32) (*Enum, error) {
	return p.Snapshot().Enum(appid, code, n)
}

// Rule is a helper function that returns a pre-loaded Rule item for the
// given AVP code and name.
func (s *Snapshot) Rule(appid, code uint32, n string) (*Rule, error) {
	avp, err := s.FindAVP(appid, code)
	if err != nil {
		return nil, err
	}
	if avp.Data.Type != datatype.GroupedType {
		return nil, fmt.Errorf(
			"data of AVP %s (%d) data is not Grouped",
			avp.Name, avp.Code)
	}
	for _, item := range avp.Data.Rule {
		if item.AVP == n {
			return item, nil
		}
	}
	return nil, fmt.Errorf(
		"could not find preload Rule for %s for AVP %s (%d)",
		n, avp.Name, avp.Code)
}

// Rule is Snapshot.Rule on the current Snapshot.
func (p *Parser) Rule(appid, code uint32, n string) (*Rule, error) {
	return p.Snapshot().Rule(appid, code, n)
}
