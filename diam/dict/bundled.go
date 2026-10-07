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
	"sync"
)

//go:embed bundled/*.xml
var bundledFS embed.FS

// Bundled names one of the XML dictionaries embedded in this package. Its
// value is the dictionary's file name in the package's bundled directory.
// Pass Bundled values to New to build a Parser from a selection of them.
//
// New automatically includes the dependencies of every selected dictionary.
// Dependencies declare additional applications, which a Diameter node then
// advertises in capability exchange (RFC 6733 §5.3).
type Bundled string

// The bundled dictionaries. Default loads all of them.
//
// To bundle another dictionary, add its XML file to the bundled directory
// and name it here and in bundledDependencies. TestBundledDependencies
// derives the required dependencies from the XML command and Grouped rules.
const (
	// Base is the Diameter base protocol, RFC 6733 (applications 0 and 3).
	Base Bundled = "base.xml"
	// CreditControl is the Diameter Credit-Control Application, RFC 8506 (application 4).
	CreditControl Bundled = "credit_control.xml"
	// Sy is the 3GPP Sy reference point, TS 29.219 (application 16777302).
	Sy Bundled = "diameter_sy.xml"
	// Gx is the 3GPP Gx reference point, TS 29.212 (application 16777238).
	Gx Bundled = "gx_credit_control.xml"
	// NASREQ is the Diameter Network Access Server Application, RFC 7155 (application 1).
	NASREQ Bundled = "network_access_server.xml"
	// Cx is the 3GPP Cx/Dx interface, TS 29.229 V19.1.0 (application 16777216).
	Cx Bundled = "tgpp_cx.xml"
	// RoRf adds TS 32.299 charging AVPs and commands to Ro (4) and Rf (3).
	RoRf Bundled = "tgpp_ro_rf.xml"
	// Rx is the 3GPP Rx reference point, TS 29.214 (application 16777236).
	Rx Bundled = "tgpp_rx.xml"
	// S13 is the 3GPP S13 interface, TS 29.272 (application 16777252).
	S13 Bundled = "tgpp_s13.xml"
	// S6a is the 3GPP S6a/S6d interface, TS 29.272 (application 16777251).
	S6a Bundled = "tgpp_s6a.xml"
	// S6c is the 3GPP S6c interface, TS 29.338 (application 16777312).
	S6c Bundled = "tgpp_s6c.xml"
	// SGd is the 3GPP SGd interface, TS 29.338 (application 16777313).
	SGd Bundled = "tgpp_sgd.xml"
	// Sh is the 3GPP Sh interface, TS 29.329 V19.1.0 (application 16777217).
	Sh Bundled = "tgpp_sh.xml"
	// SWx is the 3GPP SWx interface, TS 29.273 (application 16777265).
	SWx Bundled = "tgpp_swx.xml"
)

// bundledDependencies names the providers of each dictionary's command and
// Grouped rule members, resolved in application inheritance order. New follows
// these edges transitively. CreditControl and RoRf depend on each other, so the
// complete selection is loaded atomically in file name order, not topologically.
var bundledDependencies = map[Bundled][]Bundled{
	Base:          {},
	CreditControl: {Base, NASREQ, RoRf},
	Sy:            {Base, CreditControl, RoRf},
	Gx:            {Base, CreditControl, NASREQ, RoRf},
	NASREQ:        {Base},
	Cx:            {Base, NASREQ},
	RoRf:          {Base, CreditControl, NASREQ},
	Rx:            {Base, CreditControl, NASREQ, RoRf},
	S13:           {Base},
	S6a:           {Base, CreditControl, RoRf, S6c},
	S6c:           {Base, RoRf},
	SGd:           {Base, RoRf, S6c},
	Sh:            {Base, Cx},
	SWx:           {Base, CreditControl, RoRf, S6a},
}

// Embedded definitions are immutable, like the definitions returned by Snapshot.
// Parse them once; each New still builds independent indexes and Parser state.
var bundledFiles = sync.OnceValue(func() map[Bundled]*File {
	files := make(map[Bundled]*File, len(bundledDependencies))
	for _, b := range AllBundled() {
		data, err := bundledFS.ReadFile(path.Join("bundled", string(b)))
		if err != nil {
			panic(err)
		}
		f, err := parseFile(bytes.NewReader(data))
		if err != nil {
			panic(fmt.Sprintf("dict: bundled dictionary %s: %v", b, err))
		}
		files[b] = f
	}
	return files
})

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

// bundledClosure returns dicts and their transitive dependencies, without
// duplicates, in file name order. It panics if a value is not a bundled
// dictionary.
func bundledClosure(dicts []Bundled) []Bundled {
	selected := make(map[Bundled]bool)
	var include func(Bundled)
	include = func(b Bundled) {
		deps, ok := bundledDependencies[b]
		if !ok {
			panic(fmt.Sprintf("dict: %q is not a bundled dictionary", b))
		}
		if selected[b] {
			return
		}
		selected[b] = true
		for _, dependency := range deps {
			include(dependency)
		}
	}
	for _, b := range dicts {
		include(b)
	}
	closure := make([]Bundled, 0, len(selected))
	for b := range selected {
		closure = append(closure, b)
	}
	slices.Sort(closure)
	return closure
}

// Default is a Parser with every bundled dictionary loaded.
var Default = New(AllBundled()...)

// New returns a Parser with the selected bundled dictionaries and their
// dependencies loaded. It loads the complete selection atomically in file name
// order, so order and duplicates in dicts do not affect the result. With no
// dictionaries it returns an empty Parser, as NewParser does.
//
// Any selection of Bundled constants is valid. New panics if a value is not a
// bundled dictionary. For custom XML streams or files, use Load or NewParser.
func New(dicts ...Bundled) *Parser {
	dicts = bundledClosure(dicts)
	files := make([]*File, 0, len(dicts))
	for _, b := range dicts {
		files = append(files, bundledFiles()[b])
	}
	p := new(Parser)
	if err := p.update(func(cur *Snapshot) (*Snapshot, error) {
		return cur.with(files, nil)
	}); err != nil {
		panic(fmt.Sprintf("dict: bundled dictionaries %v: %v", dicts, err))
	}
	return p
}
