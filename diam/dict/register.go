// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Programmatic AVP registration.  Part of go-diameter.

package dict

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/gomaja/go-diameter/diam/datatype"
)

// ErrAVPConflict is wrapped by the errors RegisterAVP, Load and LoadFile
// return when a definition would change the meaning of an AVP that an
// application already has, or leave a command or Grouped rule unresolved
// or contradicting a member's required flags.
var ErrAVPConflict = errors.New("conflicting AVP definition")

// registration is an AVP added by RegisterAVP to application app.
type registration struct {
	app uint32
	avp *AVP // Private copy, never modified once published
}

// RegisterAVP adds AVP definitions to application app without an XML
// dictionary, for example a vendor's AVPs needed while messages already
// flow. The definitions are copied, so changing avps afterwards has no
// effect.
//
// An AVP is identified by its code and vendor (RFC 6733 (October 2012)
// §4.1). Look it up with FindAVP, or use FindAVPByName for its unique name
// within the application's scope.
//
// The AVPs belong to app as if a dictionary declaring app had defined them,
// so the applications that inherit from app (see parentAppIds) see them
// too, in every lookup and when decoding, whether a dictionary declares
// them or not. Registering declares no application: app is not advertised in
// capability exchange because of it. Registrations stay in place when
// dictionaries are loaded later, and a dictionary that would change the
// meaning of one is refused.
//
// Each definition needs a name in the Diameter name format (RFC 6733 §3.2,
// §4.4), a non-zero code (§11.1.1), a type name from datatype.Available,
// flag rules naming only the M, P and V flags, enumerated items only if
// Enumerated and member rules only if Grouped. Member prohibitions allow
// only M/P and must not contradict resolved members' required flags. Every
// member rule must resolve by name in app once the definitions are registered,
// so register a Grouped AVP together with the
// members it introduces. A Rule is bounded when MaxSet is true or Max is
// positive.
//
// A definition that differs from an AVP app already has with the same code
// and vendor, or with the same name, is refused with an error wrapping
// ErrAVPConflict, even if app also has an identical one; otherwise a
// definition identical to one that app already has is ignored. RegisterAVP
// registers all the definitions or, returning an error, none.
func (p *Parser) RegisterAVP(app uint32, avps ...*AVP) error {
	owner := &App{ID: app}
	defs := make([]*AVP, 0, len(avps))
	for _, a := range avps {
		d, err := newRegisteredAVP(owner, a)
		if err != nil {
			return err
		}
		defs = append(defs, d)
	}
	return p.update(func(cur *Snapshot) (*Snapshot, error) {
		var regs []registration
	each:
		for _, d := range defs {
			for _, r := range regs {
				if r.avp.Name == d.Name || r.avp.Code == d.Code && r.avp.VendorID == d.VendorID {
					if sameAVP(r.avp, d) {
						continue each
					}
					return nil, conflictError(app, d, r.avp)
				}
			}
			identical := false
			if have, err := cur.FindAVP(app, d.Code, d.VendorID); err == nil {
				if !sameAVP(have, d) {
					return nil, conflictError(app, d, have)
				}
				identical = true
			}
			// The name must denote d in app as well, even when app already
			// has d by code: a nearer definition of the name would capture
			// the rules naming it (RFC 6733 §3.2, §4.4).
			if have, err := cur.FindAVPByName(app, d.Name); err == nil && !sameAVP(have, d) {
				return nil, conflictError(app, d, have)
			}
			if !identical { // An identical definition changes nothing.
				regs = append(regs, registration{app, d})
			}
		}
		if len(regs) == 0 {
			return nil, nil
		}
		return cur.with(nil, regs)
	})
}

// newRegisteredAVP checks a definition given to RegisterAVP and returns a
// private copy of it that belongs to owner.
func newRegisteredAVP(owner *App, a *AVP) (*AVP, error) {
	if a == nil {
		return nil, fmt.Errorf("register AVP in application %d: nil definition", owner.ID)
	}
	fail := func(format string, args ...interface{}) error {
		return fmt.Errorf("register AVP %q (code %d, vendor %d) in application %d: %s",
			a.Name, a.Code, a.VendorID, owner.ID, fmt.Sprintf(format, args...))
	}
	switch {
	case !isDiameterName(a.Name):
		return nil, fail("name is not in the Diameter name format (RFC 6733 §4.4)")
	case a.Name == "AVP":
		return nil, fail("name AVP stands for any AVP in rules (RFC 6733 §3.2)")
	case a.Code == 0:
		return nil, fail("AVP code 0 is not used (RFC 6733 §11.1.1)")
	}
	typ, ok := datatype.Available[a.Data.TypeName]
	if !ok {
		return nil, fail("unsupported data type %q", a.Data.TypeName)
	}
	if len(a.Data.Enum) > 0 && typ != datatype.EnumeratedType {
		return nil, fail("enumerated items need type Enumerated")
	}
	if len(a.Data.Rule) > 0 && typ != datatype.GroupedType {
		return nil, fail("member rules need type Grouped")
	}
	must, err := parseFlags(a.Must)
	if err != nil {
		return nil, fail("must flags: %v", err)
	}
	if _, err := parseFlags(a.May); err != nil {
		return nil, fail("may flags: %v", err)
	}
	mustNot, err := parseFlags(a.MustNot)
	if err != nil {
		return nil, fail("must-not flags: %v", err)
	}
	switch {
	case must&mustNot != 0:
		return nil, fail("a flag is both required and forbidden")
	// RFC 6733 §4.1: the V bit marks the presence of the Vendor-ID field,
	// and a vendor-specific AVP code belongs to its vendor's code space.
	case a.VendorID == 0 && must&flagV != 0:
		return nil, fail("the V flag is required but the AVP has no vendor (RFC 6733 §4.1)")
	case a.VendorID != 0 && mustNot&flagV != 0:
		return nil, fail("the V flag is forbidden but the AVP has a vendor (RFC 6733 §4.1)")
	}
	d := &AVP{
		Name:       a.Name,
		Code:       a.Code,
		Must:       a.Must,
		May:        a.May,
		MustNot:    a.MustNot,
		MayEncrypt: a.MayEncrypt,
		VendorID:   a.VendorID,
		Data:       Data{Type: typ, TypeName: a.Data.TypeName},
		App:        owner,
	}
	for _, item := range a.Data.Enum {
		if item == nil {
			return nil, fail("nil enumerated item")
		}
		c := *item
		d.Data.Enum = append(d.Data.Enum, &c)
	}
	members := make(map[string]bool, len(a.Data.Rule))
	for _, rule := range a.Data.Rule {
		// RFC 6733 §3.2 avp-name, qual and max.
		switch {
		case rule == nil:
			return nil, fail("nil member rule")
		case rule.AVP != "AVP" && !isDiameterName(rule.AVP):
			return nil, fail("member %q is not an AVP name (RFC 6733 §3.2)", rule.AVP)
		case members[rule.AVP]:
			return nil, fail("member %s has more than one rule", rule.AVP)
		case rule.Min < 0 || rule.Max < 0:
			return nil, fail("member %s has a negative occurrence bound", rule.AVP)
		case (rule.MaxSet || rule.Max > 0) && rule.Max < max(rule.Min, boolInt(rule.Required)):
			return nil, fail("member %s has a maximum below its minimum", rule.AVP)
		}
		if _, err := parseMemberProhibitions(rule.MustNot); err != nil {
			return nil, fail("member %s must-not flags: %v", rule.AVP, err)
		}
		members[rule.AVP] = true
		c := *rule
		d.Data.Rule = append(d.Data.Rule, &c)
	}
	return d, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// isDiameterName reports whether name has the format RFC 6733 gives AVP
// names: ALPHA *(ALPHA / DIGIT / "-") (§3.2 diameter-name, §4.4 name-fmt).
func isDiameterName(name string) bool {
	for i, c := range []byte(name) {
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z':
		case i > 0 && ('0' <= c && c <= '9' || c == '-'):
		default:
			return false
		}
	}
	return name != ""
}

// AVP flags as dictionary flag rules name them.
const (
	flagM = 1 << iota
	flagP
	flagV
)

// parseFlags parses a dictionary flag rule such as "M,V", the compact "MV"
// or "-" for none.
func parseFlags(rule string) (int, error) {
	var flags int
	for _, item := range strings.Split(rule, ",") {
		item = strings.TrimSpace(item)
		if item == "" || item == "-" {
			continue
		}
		for _, c := range item {
			switch c {
			case 'M':
				flags |= flagM
			case 'P':
				flags |= flagP
			case 'V':
				flags |= flagV
			default:
				return 0, fmt.Errorf("unknown flag %q in %q", c, rule)
			}
		}
	}
	return flags, nil
}

// parseMemberProhibitions accepts sending choices only. RFC 6733 §4.1:
// V identifies the Vendor-Id field and cannot be prohibited by a parent rule.
func parseMemberProhibitions(rule string) (int, error) {
	flags, err := parseFlags(rule)
	if err != nil {
		return 0, err
	}
	if flags&flagV != 0 {
		return 0, fmt.Errorf("member prohibitions allow only M and P; V describes the Vendor-Id field")
	}
	return flags, nil
}

// sameAVP reports whether a and b define the same AVP: the same code,
// vendor, name, flag rules, type, enumerated items and member rules.
func sameAVP(a, b *AVP) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Name == b.Name && a.Code == b.Code && a.VendorID == b.VendorID &&
		sameFlags(a.Must, b.Must) && sameFlags(a.May, b.May) && sameFlags(a.MustNot, b.MustNot) &&
		a.MayEncrypt == b.MayEncrypt &&
		a.Data.Type == b.Data.Type && a.Data.TypeName == b.Data.TypeName &&
		slices.EqualFunc(a.Data.Enum, b.Data.Enum, func(x, y *Enum) bool { return *x == *y }) &&
		slices.EqualFunc(a.Data.Rule, b.Data.Rule, sameRule)
}

func sameFlags(a, b string) bool {
	fa, errA := parseFlags(a)
	fb, errB := parseFlags(b)
	if errA != nil || errB != nil {
		return a == b
	}
	return fa == fb
}

// sameRule compares rules by meaning: an unbounded maximum is unbounded
// whether Max is zero or MaxSet is false.
func sameRule(a, b *Rule) bool {
	boundedA, boundedB := a.MaxSet || a.Max > 0, b.MaxSet || b.Max > 0
	return sameFlags(a.MustNot, b.MustNot) && a.AVP == b.AVP && a.Required == b.Required && a.Min == b.Min && a.Fixed == b.Fixed &&
		boundedA == boundedB && (!boundedA || a.Max == b.Max)
}

func conflictError(app uint32, want, have *AVP) error {
	if have == nil {
		return fmt.Errorf("%w: application %d: %s (code %d, vendor %d) is no longer resolved",
			ErrAVPConflict, app, want.Name, want.Code, want.VendorID)
	}
	return fmt.Errorf("%w: application %d: %s (code %d, vendor %d) differs from %s (code %d, vendor %d)",
		ErrAVPConflict, app, want.Name, want.Code, want.VendorID, have.Name, have.Code, have.VendorID)
}
