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
	// AVP indexes contain own and inherited definitions. Codes always
	// include the vendor (RFC 6733 (October 2012) §4.1); names are unique
	// within each application, whether loaded or registered.
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
	s.avpname = make(map[appNameIdx]*AVP, len(prev.avpname))
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
			// Resolve replacements by wire identity before considering names.
			// A load may rename an AVP and reuse its former name in either order.
			for _, avp := range app.AVP {
				s.avpcode[codeIdx{app.ID, avp.Code, avp.VendorID}] = avp
			}
		}
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
			return fmt.Errorf("%w: member %s does not resolve: %w", ErrAVPConflict, rule.AVP, err)
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
// Replacing an inherited code/vendor with a new name also hides its old name.
//
// Only applications with definitions of their own, loaded or registered,
// get an index. Lookups for any other application walk its ancestors, so
// that it inherits all the same (FindAVP, FindAVPByName).
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
	for idx := range s.avpname {
		d := defsOf(idx.appID)
		d.names = append(d.names, idx)
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
			return nil, fmt.Errorf("%w at application %d", ErrParentCycle, parent)
		}
		visited[parent] = true
		ancestors = append(ancestors, parent)
		cur = parent
	}
}
