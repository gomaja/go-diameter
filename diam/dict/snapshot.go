// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Dictionary snapshots.  Part of go-diameter.

package dict

import (
	"fmt"
	"slices"
)

// Snapshot is the state of a Parser at one point in time: its loaded
// dictionaries, registered AVPs and decoding policy. A Parser never changes
// a Snapshot it has published; every change publishes a new one. Lookups
// through one Snapshot therefore agree with each other however the Parser
// changes meanwhile, which is how the diam decoder reads a whole message
// against one version of the dictionary.
//
// A Snapshot is safe for concurrent use. The applications, commands, AVPs
// and rules it returns are shared by every reader and must not be modified.
type Snapshot struct {
	files []*File        // Loaded dictionaries, in load order
	regs  []registration // Registered AVPs, in registration order

	appcode map[uint32]*App       // Application index by code
	apptype map[appIdTypeIdx]*App // Application index by code and type
	command map[commandIdx]*Command
	// AVP indexes, own and inherited definitions. Loaded AVPs are also
	// indexed with UndefinedVendorID; registered AVPs never are.
	avpcode map[codeIdx]*AVP
	avpname map[nameIdx]*AVP
	// regname resolves a name without a vendor to a registered AVP, for
	// names that no loaded AVP of the application's scope resolves.
	regname map[appNameIdx]*AVP

	strict          bool
	maxGroupedDepth int // Zero means DefaultMaxGroupedDepth
}

// emptySnapshot is the state of a Parser before its first change.
var emptySnapshot = &Snapshot{strict: true}

// Strict reports whether a message decode fails on AVPs that cannot be
// decoded; see Parser.SetStrict.
func (s *Snapshot) Strict() bool { return s.strict }

// MaxGroupedDepth returns the Grouped AVP nesting limit the decoder
// applies; see Parser.SetMaxGroupedDepth.
func (s *Snapshot) MaxGroupedDepth() int {
	if s.maxGroupedDepth > 0 {
		return s.maxGroupedDepth
	}
	return DefaultMaxGroupedDepth
}

// with returns a Snapshot with files loaded and regs registered in addition
// to s's, and s's policy. s is left unchanged.
func (s *Snapshot) with(files []*File, regs []registration) (*Snapshot, error) {
	next := &Snapshot{
		files:           slices.Concat(s.files, files),
		regs:            slices.Concat(s.regs, regs),
		strict:          s.strict,
		maxGroupedDepth: s.maxGroupedDepth,
	}
	if err := next.build(s); err != nil {
		return nil, err
	}
	return next, nil
}

// build indexes s.files and s.regs. Each application first gets its own
// definitions: those of the dictionaries in load order, a later definition
// replacing an earlier one with the same key, then the registered AVPs.
// Each application then inherits, nearest ancestor first, the definitions
// of its ancestors (see parentAppIds) that it does not have itself, so
// that a lookup is a single map access.
//
// The index is rebuilt from the sources for every change rather than
// patched, so an application always sees its nearest ancestor's current
// definition whatever the order of the changes that produced it. The
// indexes are sized after those of prev, the Snapshot being changed.
func (s *Snapshot) build(prev *Snapshot) error {
	s.appcode = make(map[uint32]*App, len(prev.appcode))
	s.apptype = make(map[appIdTypeIdx]*App, len(prev.apptype))
	s.command = make(map[commandIdx]*Command, len(prev.command))
	s.avpcode = make(map[codeIdx]*AVP, len(prev.avpcode))
	s.avpname = make(map[nameIdx]*AVP, len(prev.avpname))
	s.regname = make(map[appNameIdx]*AVP, len(prev.regname))
	for _, f := range s.files {
		for _, app := range f.App {
			// Cache supported applications by ID.
			s.appcode[app.ID] = app
			s.apptype[appIdTypeIdx{app.ID, app.Type}] = app
			// Cache commands.
			for _, cmd := range app.Command {
				idx := commandIdx{app.ID, cmd.Code}
				if _, exist := s.command[idx]; exist {
					return fmt.Errorf("command %s cannot be added: index exists", cmd)
				}
				s.command[idx] = cmd
			}
			// Cache AVPs, also without vendorId.
			for _, avp := range app.AVP {
				s.avpcode[codeIdx{app.ID, avp.Code, avp.VendorID}] = avp
				s.avpcode[codeIdx{app.ID, avp.Code, UndefinedVendorID}] = avp
				s.avpname[nameIdx{app.ID, avp.Name, avp.VendorID}] = avp
				s.avpname[nameIdx{app.ID, avp.Name, UndefinedVendorID}] = avp
			}
		}
	}
	// A registered AVP is indexed by its code and vendor, and by its name
	// and vendor (RFC 6733 §4.1), never in the vendor-agnostic slots: an
	// application's code can belong to several vendors. Its name alone goes
	// to regname instead.
	for _, r := range s.regs {
		code := codeIdx{r.app, r.avp.Code, r.avp.VendorID}
		name := nameIdx{r.app, r.avp.Name, r.avp.VendorID}
		bare := appNameIdx{r.app, r.avp.Name}
		for _, have := range []*AVP{s.avpcode[code], s.avpname[name], s.regname[bare]} {
			if have != nil && !sameAVP(have, r.avp) {
				return conflictError(r.app, r.avp, have)
			}
		}
		s.avpcode[code] = r.avp
		s.avpname[name] = r.avp
		s.regname[bare] = r.avp
	}
	if err := s.mergeInheritedAVPs(); err != nil {
		return err
	}
	// A registration keeps its meaning in its application: a dictionary
	// loaded later that resolves its name to another AVP is refused.
	for _, r := range s.regs {
		if have := s.resolveName(r.app, r.avp.Name); !sameAVP(have, r.avp) {
			return conflictError(r.app, r.avp, have)
		}
	}
	return nil
}

// mergeInheritedAVPs copies the definitions of each application's
// ancestors into its own index, nearest ancestor first, where the
// application has no definition with the same key. A name without a vendor
// is inherited only when neither the application nor a nearer ancestor
// resolves that name already, by a loaded or a registered AVP.
//
// Only applications with definitions of their own, loaded or registered,
// get an index. Lookups for any other application walk its ancestors, so
// that it inherits all the same (FindAVPByCode, FindAVPWithVendor).
//
// Memory: ancestor definitions are duplicated per child application when
// the Snapshot is built, not per message; bounded by dictionary size.
func (s *Snapshot) mergeInheritedAVPs() error {
	// Own definitions of each application, before any is inherited. Every
	// declared application is included, so one that inherits all its AVPs
	// is still processed, as is any application that only owns AVPs.
	type ownDefs struct {
		codes   []codeIdx
		names   []nameIdx
		regname []appNameIdx
	}
	own := make(map[uint32]*ownDefs, len(s.appcode))
	defsOf := func(appID uint32) *ownDefs {
		d := own[appID]
		if d == nil {
			d = new(ownDefs)
			own[appID] = d
		}
		return d
	}
	for appID := range s.appcode {
		defsOf(appID)
	}
	for idx := range s.avpcode {
		d := defsOf(idx.appID)
		d.codes = append(d.codes, idx)
	}
	for idx := range s.avpname {
		d := defsOf(idx.appID)
		d.names = append(d.names, idx)
	}
	for idx := range s.regname {
		d := defsOf(idx.appID)
		d.regname = append(d.regname, idx)
	}

	for appID := range own {
		if appID == 0 {
			continue // base app has no parents
		}
		ancestors, err := ancestorApps(appID)
		if err != nil {
			return err
		}
		for _, ancestorID := range ancestors {
			from := own[ancestorID]
			if from == nil {
				continue
			}
			for _, idx := range from.codes {
				child := codeIdx{appID, idx.code, idx.vendorID}
				if _, exists := s.avpcode[child]; !exists {
					s.avpcode[child] = s.avpcode[idx]
				}
			}
			for _, idx := range from.names {
				child := nameIdx{appID, idx.name, idx.vendorID}
				if idx.vendorID == UndefinedVendorID && s.resolvesName(appID, idx.name) {
					continue
				}
				if _, exists := s.avpname[child]; !exists {
					s.avpname[child] = s.avpname[idx]
				}
			}
			for _, idx := range from.regname {
				if !s.resolvesName(appID, idx.name) {
					s.regname[appNameIdx{appID, idx.name}] = s.regname[idx]
				}
			}
		}
	}
	return nil
}

// ancestorApps returns the applications whose AVPs appID inherits, nearest
// first: its parentAppIds chain, then the base application. E.g. for app 4
// → [1, 0].
func ancestorApps(appID uint32) ([]uint32, error) {
	var ancestors []uint32
	visited := map[uint32]bool{appID: true}
	for cur := appID; ; {
		parent, hasParent := parentAppIds[cur]
		if !hasParent {
			if cur != 0 {
				ancestors = append(ancestors, 0)
			}
			return ancestors, nil
		}
		if visited[parent] {
			return nil, fmt.Errorf("dictionary parent application cycle at %d", parent)
		}
		visited[parent] = true
		ancestors = append(ancestors, parent)
		cur = parent
	}
}

// resolvesName reports whether the index of appID resolves name without a
// vendor.
func (s *Snapshot) resolvesName(appID uint32, name string) bool {
	return s.resolveName(appID, name) != nil
}

// resolveName returns the AVP that name denotes in the index of appID
// without a vendor: the loaded AVP of that name, or else the registered
// one, or nil.
func (s *Snapshot) resolveName(appID uint32, name string) *AVP {
	if avp, ok := s.avpname[nameIdx{appID, name, UndefinedVendorID}]; ok {
		return avp
	}
	return s.regname[appNameIdx{appID, name}]
}
