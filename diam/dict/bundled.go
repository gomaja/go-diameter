// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Bundled dictionaries.  Part of go-diameter.

package dict

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"slices"
)

//go:embed bundled/*.xml
var bundledFS embed.FS

// Bundled names one of the XML dictionaries embedded in this package. Its
// value is the dictionary's file name in the package's bundled directory.
// Pass Bundled values to New to build a Parser from a selection of them.
//
// Lookups for an application also see the AVPs of its ancestor
// applications (see parentAppIds), so a dictionary whose grammars use AVPs
// of other applications needs the dictionaries declaring those
// applications in the same Parser. Each value lists them. Selecting them
// also declares their applications, which a Diameter node then advertises
// in capability exchange (RFC 6733 §5.3).
type Bundled string

// The bundled dictionaries. Default loads all of them.
//
// To bundle another dictionary, add its XML file to the bundled directory
// and name it here; TestBundledConstants fails until both exist. The
// sentence "It builds on ..." of each lists the other dictionaries
// declaring its applications or their ancestors; TestBundledDependencies
// checks it.
const (
	// Base is the Diameter base protocol, RFC 6733: the common messages
	// (application 0) and Base Accounting (application 3).
	Base Bundled = "base.xml"
	// CreditControl is the Diameter Credit-Control Application, RFC 8506
	// (application 4). RoRf adds the 3GPP charging AVPs its grammar uses to
	// the same application. It builds on RoRf, NASREQ and Base.
	CreditControl Bundled = "credit_control.xml"
	// Sy is the 3GPP Sy reference point, TS 29.219 (application
	// 16777302). It builds on CreditControl, RoRf, NASREQ and Base.
	Sy Bundled = "diameter_sy.xml"
	// Gx is the 3GPP Gx reference point, TS 29.212 (application
	// 16777238). It builds on CreditControl, RoRf, NASREQ and Base.
	Gx Bundled = "gx_credit_control.xml"
	// NASREQ is the Diameter Network Access Server Application, RFC 7155
	// (application 1). It builds on Base.
	NASREQ Bundled = "network_access_server.xml"
	// Cx is the 3GPP Cx/Dx interface, TS 29.229 V19.1.0 (application
	// 16777216). It builds on NASREQ and Base.
	Cx Bundled = "tgpp_cx.xml"
	// RoRf adds the 3GPP charging AVPs of TS 32.299 to application 4. It
	// builds on CreditControl, NASREQ and Base.
	RoRf Bundled = "tgpp_ro_rf.xml"
	// Rx is the 3GPP Rx reference point, TS 29.214 (application
	// 16777236). It builds on CreditControl, RoRf, NASREQ and Base.
	Rx Bundled = "tgpp_rx.xml"
	// S13 is the 3GPP S13 interface, TS 29.272 (application 16777252). It
	// builds on Base.
	S13 Bundled = "tgpp_s13.xml"
	// S6a is the 3GPP S6a/S6d interface, TS 29.272 (application
	// 16777251). It builds on S6c, CreditControl, RoRf, NASREQ and Base.
	S6a Bundled = "tgpp_s6a.xml"
	// S6c is the 3GPP S6c interface, TS 29.338 (application 16777312). It
	// builds on CreditControl, RoRf, NASREQ and Base.
	S6c Bundled = "tgpp_s6c.xml"
	// SGd is the 3GPP SGd interface, TS 29.338 (application 16777313). It
	// builds on S6c, CreditControl, RoRf, NASREQ and Base.
	SGd Bundled = "tgpp_sgd.xml"
	// Sh is the 3GPP Sh interface, TS 29.329 V19.1.0 (application
	// 16777217). It builds on Cx, NASREQ and Base.
	Sh Bundled = "tgpp_sh.xml"
	// SWx is the 3GPP SWx interface, TS 29.273 (application 16777265). It
	// builds on S6a, S6c, CreditControl, RoRf, NASREQ and Base.
	SWx Bundled = "tgpp_swx.xml"
)

// AllBundled returns every bundled dictionary, in the order New loads them.
func AllBundled() []Bundled {
	entries, err := fs.ReadDir(bundledFS, "bundled")
	if err != nil {
		panic(err) // the directory is embedded at build time
	}
	all := make([]Bundled, 0, len(entries))
	for _, e := range entries {
		all = append(all, Bundled(e.Name()))
	}
	return all
}

// Default is a Parser with every bundled dictionary loaded.
var Default = New(AllBundled()...)

// New returns a Parser with the selected bundled dictionaries loaded and
// no others. It loads them in file name order whatever the order of dicts,
// so a selection behaves the same however it is written; a dictionary
// selected twice is loaded once. With no dictionaries it returns an empty
// Parser, as NewParser does.
//
// New panics if a value is not one of the bundled dictionaries.
func New(dicts ...Bundled) *Parser {
	dicts = slices.Clone(dicts)
	slices.Sort(dicts)
	dicts = slices.Compact(dicts)
	files := make([]*File, 0, len(dicts))
	for _, d := range dicts {
		data, err := bundledFS.ReadFile(path.Join("bundled", string(d)))
		if err != nil {
			panic(fmt.Sprintf("dict: %q is not a bundled dictionary", string(d)))
		}
		f, err := parseFile(bytes.NewReader(data))
		if err != nil {
			panic(fmt.Sprintf("dict: bundled dictionary %s: %v", string(d), err))
		}
		files = append(files, f)
	}
	p := new(Parser)
	if err := p.update(func(cur *Snapshot) (*Snapshot, error) {
		return cur.with(files, nil)
	}); err != nil {
		panic(fmt.Sprintf("dict: bundled dictionaries %v: %v", dicts, err))
	}
	return p
}
