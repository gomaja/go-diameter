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
	files   []*File             // Loaded dictionaries, in load order
	regs    []registration      // Registered AVPs, in registration order
	parents map[uint32][]uint32 // Declared parent union, in load order

	appcode map[uint32]*App       // Application index by code
	apptype map[appIdTypeIdx]*App // Application index by code and type
	command map[commandIdx]*Command
	// AVP indexes contain own and inherited definitions. Codes always
	// include the vendor (RFC 6733 (October 2012) §4.1); name lookup selects
	// the nearest definition when one ancestor chain shadows a name.
	avpcode map[codeIdx]*AVP
	avpname map[appNameIdx]*AVP

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
// of its declared ancestors that it does not have itself, so
// that a lookup is a single map access.
//
// The index is rebuilt from the sources for every change rather than
// patched, so an application always sees its nearest ancestor's current
// definition whatever the order of the changes that produced it. The
// indexes are sized after those of prev, the Snapshot being changed.
func (s *Snapshot) build(prev *Snapshot) error {
	s.parents = make(map[uint32][]uint32)
	s.appcode = make(map[uint32]*App, len(prev.appcode))
	s.apptype = make(map[appIdTypeIdx]*App, len(prev.apptype))
	s.command = make(map[commandIdx]*Command, len(prev.command))
	s.avpcode = make(map[codeIdx]*AVP, len(prev.avpcode))
	s.avpname = make(map[appNameIdx]*AVP, len(prev.avpname))
	for _, f := range s.files {
		for _, app := range f.App {
			for _, parent := range app.Inherits {
				if !slices.Contains(s.parents[app.ID], parent) {
					s.parents[app.ID] = append(s.parents[app.ID], parent)
				}
			}
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
			// Resolve replacements by wire identity before considering names.
			// A load may rename an AVP and reuse its former name in either order.
			for _, avp := range app.AVP {
				s.avpcode[codeIdx{app.ID, avp.Code, avp.VendorID}] = avp
			}
		}
	}
	if err := s.validateParents(); err != nil {
		return err
	}
	// Names identify rules within an application; code/vendor identifies
	// the wire AVP (RFC 6733 (October 2012) §§3.2, 4.1, 4.4). Check the
	// final definitions, so intermediate names cannot cause a conflict.
	for code, avp := range s.avpcode {
		name := appNameIdx{code.appID, avp.Name}
		if have := s.avpname[name]; have != nil {
			return conflictError(code.appID, avp, have)
		}
		s.avpname[name] = avp
	}
	// Registered and loaded definitions use the same indexes.
	for _, r := range s.regs {
		code := codeIdx{r.app, r.avp.Code, r.avp.VendorID}
		name := appNameIdx{r.app, r.avp.Name}
		for _, have := range []*AVP{s.avpcode[code], s.avpname[name]} {
			if have != nil && !sameAVP(have, r.avp) {
				return conflictError(r.app, r.avp, have)
			}
		}
		s.avpcode[code] = r.avp
		s.avpname[name] = r.avp
	}
	if err := s.mergeInheritedAVPs(); err != nil {
		return err
	}
	return s.validateRules()
}

// validateRules checks each application's final scope, including inherited
// groups whose members may have been replaced by a child.
func (s *Snapshot) validateRules() error {
	for idx, avp := range s.avpcode {
		if err := s.resolveRules(idx.appID, avp.Data.Rule); err != nil {
			return fmt.Errorf("AVP %s in application %d: %w", avp.Name, idx.appID, err)
		}
	}
	// FindCommand falls back to base commands, whose AVP names are resolved
	// in the requesting application's scope. Include registered-only apps.
	apps := make(map[uint32]bool, len(s.appcode))
	for appID := range s.appcode {
		apps[appID] = true
	}
	for idx := range s.avpcode {
		apps[idx.appID] = true
	}
	for idx, cmd := range s.command {
		if err := s.resolveCommandRules(idx.appID, cmd); err != nil {
			return err
		}
		if idx.appID != 0 {
			continue
		}
		for appID := range apps {
			if appID == 0 || s.command[commandIdx{appID, idx.code}] != nil {
				continue
			}
			if err := s.resolveCommandRules(appID, cmd); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Snapshot) resolveCommandRules(appID uint32, cmd *Command) error {
	if err := s.resolveRules(appID, cmd.Request.Rule); err != nil {
		return fmt.Errorf("command %s (%d) request in application %d: %w", cmd.Name, cmd.Code, appID, err)
	}
	if err := s.resolveRules(appID, cmd.Answer.Rule); err != nil {
		return fmt.Errorf("command %s (%d) answer in application %d: %w", cmd.Name, cmd.Code, appID, err)
	}
	return nil
}

func (s *Snapshot) resolveRules(appID uint32, rules []*Rule) error {
	var wildcard int
	for _, rule := range rules {
		if rule.MustNot == "" {
			continue
		}
		flags, err := parseMemberProhibitions(rule.MustNot)
		if err != nil {
			return fmt.Errorf("%w: member %s must-not flags: %w", ErrAVPConflict, rule.AVP, err)
		}
		if rule.AVP == "AVP" {
			wildcard |= flags
		}
	}
	for _, rule := range rules {
		// RFC 6733 (October 2012) §§3.2, 4.4: named command and Grouped
		// members identify AVPs; the AVP wildcard admits arbitrary AVPs.
		if rule.AVP == "AVP" {
			continue
		}
		member, err := s.FindAVPByName(appID, rule.AVP)
		if err != nil {
			return fmt.Errorf("%w: member %s does not resolve in application %d; inherited definitions require the defining application in the inherits attribute: %w", ErrAVPConflict, rule.AVP, appID, err)
		}
		if wildcard == 0 && rule.MustNot == "" {
			continue
		}
		// Resolve the final application view before publishing it: inherited
		// rules must also remain compatible with a child's AVP replacements.
		forbidden, _ := parseMemberProhibitions(rule.MustNot) // checked above
		required, _ := parseFlags(member.Must)                // checked when loaded or registered
		if (wildcard|forbidden)&required != 0 {
			return fmt.Errorf("%w: member %s prohibition contradicts required flags %q", ErrAVPConflict, rule.AVP, member.Must)
		}
	}
	return nil
}

// mergeInheritedAVPs copies the definitions of each application's
// ancestors into its own index, nearest ancestor first, where the
// application has no definition with the same key. A name is inherited only
// when neither the application nor a nearer ancestor defines that name.
// A child may therefore shadow an ancestor's name with its own definition.
// For names the child does not define itself, its non-base direct parents
// must agree on the wire identity in their final views, including fallback.
// Replacing an inherited code/vendor with a new name also hides its old name.
//
// Only applications with definitions of their own, loaded or registered,
// get an index. Other applications fall back only to base (FindAVP, FindAVPByName).
//
// Memory: ancestor definitions are duplicated per child application when
// the Snapshot is built, not per message; bounded by dictionary size.
func (s *Snapshot) mergeInheritedAVPs() error {
	// Own definitions of each application, before any is inherited. Every
	// declared application is included, so one that inherits all its AVPs
	// is still processed, as is any application that only owns AVPs.
	type ownDefs struct {
		codes []codeIdx
		names []appNameIdx
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
	ownNames := make(map[appNameIdx]bool, len(s.avpname))
	for idx := range s.avpname {
		ownNames[idx] = true
		d := defsOf(idx.appID)
		d.names = append(d.names, idx)
	}

	for appID := range own {
		if appID == 0 {
			continue // base app has no parents
		}
		ancestors := s.ancestorApps(appID)
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
				avp := s.avpname[idx]
				// A nearer replacement may rename this wire identity. Its old
				// name must not capture Grouped rules in the child's scope.
				if resolved := s.avpcode[codeIdx{appID, avp.Code, avp.VendorID}]; resolved.Name != avp.Name {
					continue
				}
				child := appNameIdx{appID, idx.name}
				if _, exists := s.avpname[child]; !exists {
					s.avpname[child] = avp
				}
			}
		}
	}
	return s.validateInheritedNames(ownNames)
}

// validateInheritedNames compares final direct-parent views after every
// application has been merged. Own loaded or registered names are exempt.
// Base is not a separate parent here, but participates in each parent's
// fallback. Code/vendor precedence remains breadth-first.
func (s *Snapshot) validateInheritedNames(ownNames map[appNameIdx]bool) error {
	names := make(map[uint32][]string)
	for idx := range s.avpname {
		names[idx.appID] = append(names[idx.appID], idx.name)
	}
	type resolution struct {
		parent uint32
		avp    *AVP
	}
	for appID, parents := range s.parents {
		seen := make(map[string]resolution)
		for _, parent := range parents {
			if parent == 0 {
				continue
			}
			for _, name := range names[parent] {
				if ownNames[appNameIdx{appID, name}] {
					continue
				}
				// Resolve names, rather than enumerating wire identities:
				// shadowed and renamed ancestor names may no longer resolve.
				avp, err := s.FindAVPByName(parent, name)
				if err != nil {
					continue
				}
				if have, ok := seen[name]; ok && (have.avp.Code != avp.Code || have.avp.VendorID != avp.VendorID) {
					return fmt.Errorf("%w: application %d: name %s resolves in parent %d to (code %d, vendor %d), but in parent %d to (code %d, vendor %d)",
						ErrAVPConflict, appID, name, have.parent, have.avp.Code, have.avp.VendorID, parent, avp.Code, avp.VendorID)
				}
				seen[name] = resolution{parent, avp}
			}
		}
	}
	return nil
}

// validateParents checks the complete declared graph before any inheritance is
// merged. Parents may be declared by any file in the completed load, including
// previous loads. Diamonds are allowed; an active-path back edge is a cycle.
func (s *Snapshot) validateParents() error {
	if len(s.parents[0]) > 0 {
		return fmt.Errorf("%w: base application cannot inherit", ErrParentCycle)
	}
	for child, parents := range s.parents {
		for _, parent := range parents {
			// RFC 6733 §2.4: Relay advertises support for all applications;
			// it is not an application defining AVPs to inherit.
			if parent == 0xffffffff {
				return fmt.Errorf("application %d: parent %d is the Relay identifier, not an AVP application", child, parent)
			}
			if parent != 0 && s.appcode[parent] == nil {
				return fmt.Errorf("application %d: parent %d is not declared: %w", child, parent, ErrNotFound)
			}
		}
	}
	state := make(map[uint32]uint8)
	var visit func(uint32) error
	visit = func(id uint32) error {
		if state[id] == 1 {
			return fmt.Errorf("%w at application %d", ErrParentCycle, id)
		}
		if state[id] == 2 {
			return nil
		}
		state[id] = 1
		for _, parent := range s.parents[id] {
			if err := visit(parent); err != nil {
				return err
			}
		}
		state[id] = 2
		return nil
	}
	for id := range s.parents {
		if err := visit(id); err != nil {
			return err
		}
	}
	return nil
}

// ancestorApps returns a breadth-first traversal of the validated graph.
// Base is always the last fallback, even when explicitly named as a parent.
func (s *Snapshot) ancestorApps(appID uint32) []uint32 {
	if appID == 0 {
		return nil
	}
	seen := map[uint32]bool{appID: true, 0: true}
	var ancestors []uint32
	appendParents := func(id uint32) {
		for _, parent := range s.parents[id] {
			if !seen[parent] {
				seen[parent] = true
				ancestors = append(ancestors, parent)
			}
		}
	}
	appendParents(appID)
	for i := 0; i < len(ancestors); i++ {
		appendParents(ancestors[i])
	}
	return append(ancestors, 0)
}
