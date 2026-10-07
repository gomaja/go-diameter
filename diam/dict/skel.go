// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Skeleton of the dictionary file.  Part of go-diameter.

package dict

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"

	"github.com/gomaja/go-diameter/diam/datatype"
)

// File is the dictionary root element of a XML file.  See diam_base.xml.
type File struct {
	XMLName xml.Name `xml:"diameter"`
	App     []*App   `xml:"application"` // Support for multiple applications
}

// App defines a diameter application in XML and its multiple AVPs.
//
// Inherits lists the applications whose AVPs the application reuses, as
// whitespace-separated decimal uint32 IDs. Each non-base parent must be
// declared by a dictionary in the same Load or an earlier one; registering
// AVPs alone does not declare an application. An undeclared parent fails with
// ErrNotFound, naming the child and parent. Base 0 is valid without a base
// dictionary and remains the last fallback. Relay (0xffffffff, RFC 6733
// (October 2012) §2.4) cannot be a parent, even when declared. Cycles reject
// the entire Load with ErrParentCycle; published Snapshots keep their
// relationships.
//
// Repeated declarations unite their parent lists in load order, without
// duplicates. Own AVPs win, then ancestors in breadth-first declaration order,
// then base application 0. Commands and vendors are not inherited; command
// lookup keeps its separate fallback to base commands. For every name the
// child does not define in its own loaded or registered AVPs, its non-base
// direct parents that resolve the name must agree on its code/vendor. Each
// parent's final view includes ancestors and base fallback. Disagreement fails
// with ErrAVPConflict, naming the child, name, both parents and both identities.
// Base is not compared as a separate parent, whether explicit or implicit.
// Single-chain name shadowing remains allowed. An application no dictionary
// declares falls back only to base.
type App struct {
	Inherits ApplicationIDs `xml:"inherits,attr"`
	ID       uint32         `xml:"id,attr"`   // Application Id
	Type     string         `xml:"type,attr"` // "acct" selects accounting; all other values default to auth during capabilities exchange.
	Name     string         `xml:"name,attr"` // Application name
	Vendor   []*Vendor      `xml:"vendor"`    // Ordered vendor declarations; see ApplicationVendor.
	Command  []*Command     `xml:"command"`   // Diameter commands
	AVP      []*AVP         `xml:"avp"`       // Each application support multiple AVPs
}

// ApplicationIDs is an ordered XML list of decimal application identifiers.
// An omitted attribute means no parents; an explicitly empty list is invalid.
type ApplicationIDs []uint32

// UnmarshalXMLAttr accepts one or more whitespace-separated decimal uint32 IDs.
func (ids *ApplicationIDs) UnmarshalXMLAttr(attr xml.Attr) error {
	fields := strings.Fields(attr.Value)
	if len(fields) == 0 {
		return fmt.Errorf("invalid inherits %q: expected application IDs", attr.Value)
	}
	parsed := make(ApplicationIDs, 0, len(fields))
	for _, field := range fields {
		if strings.ContainsFunc(field, func(r rune) bool { return r < '0' || r > '9' }) {
			return fmt.Errorf("invalid inherits %q: expected decimal uint32", attr.Value)
		}
		id, err := strconv.ParseUint(field, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid inherits %q: %w", attr.Value, err)
		}
		parsed = append(parsed, uint32(id))
	}
	*ids = parsed
	return nil
}

// MarshalXMLAttr omits an absent list and writes decimal IDs separated by spaces.
func (ids ApplicationIDs) MarshalXMLAttr(name xml.Name) (xml.Attr, error) {
	if len(ids) == 0 {
		return xml.Attr{}, nil
	}
	fields := make([]string, len(ids))
	for i, id := range ids {
		fields[i] = strconv.FormatUint(uint64(id), 10)
	}
	return xml.Attr{Name: name, Value: strings.Join(fields, " ")}, nil
}

// IsVendorSpecificApplication reports whether id belongs to the IANA AAA
// registry's vendor-specific Application IDs range:
// https://www.iana.org/assignments/aaa-parameters
// The reserved relay ID 0xffffffff is separate (RFC 6733 §2.4).
func IsVendorSpecificApplication(id uint32) bool {
	return id >= 16777216 && id != 0xffffffff
}

// ApplicationVendor returns the author candidate from this declaration. For
// vendor-specific applications, capabilities exchange uses the first vendor of
// the first-loaded declaration of that application, even if absent. All other
// declared vendors are AVP suppliers; later declarations cannot change the author.
// Bundled dictionaries load in filename order, followed by subsequent Load calls.
// Standard applications and relay have no vendor author (RFC 6733 §§2.4, 6.11).
func (app *App) ApplicationVendor() uint32 {
	if IsVendorSpecificApplication(app.ID) && len(app.Vendor) != 0 {
		return app.Vendor[0].ID
	}
	return 0
}

// Vendor declares an AVP supplier. The first vendor of the first-loaded
// declaration also identifies a vendor-specific application's author; see
// ApplicationVendor. Suppliers contribute to inferred Supported-Vendor-Id.
type Vendor struct {
	ID   uint32 `xml:"id,attr"`
	Name string `xml:"name,attr"`
}

// Command defines a diameter command (CE, CC, etc)
type Command struct {
	Code    uint32      `xml:"code,attr"`
	Name    string      `xml:"name,attr"`
	Short   string      `xml:"short,attr"`
	Request CommandRule `xml:"request"`
	Answer  CommandRule `xml:"answer"`
}

func (cmd *Command) String() string {
	if cmd == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s (%s) CODE: %d", cmd.Name, cmd.Short, cmd.Code)
}

// CommandRule contains rules for a given command.
type CommandRule struct {
	// Proxiable, when specified, is the P bit required by the command ABNF.
	Proxiable *bool   `xml:"proxiable,attr"`
	Rule      []*Rule `xml:"rule"`
}

// AVP represents a dictionary AVP that is loaded from XML.
type AVP struct {
	Name       string `xml:"name,attr"`
	Code       uint32 `xml:"code,attr"`
	Must       string `xml:"must,attr"`
	May        string `xml:"may,attr"`
	MustNot    string `xml:"must-not,attr"`
	MayEncrypt string `xml:"may-encrypt,attr"`
	VendorID   uint32 `xml:"vendor-id,attr"`
	Data       Data   `xml:"data"`
	App        *App   `xml:"-"` // Link back to diameter application
}

// Data of an AVP can be EnumItem or a Parser of multiple AVPs.
type Data struct {
	Type     datatype.TypeID `xml:"-"`
	TypeName string          `xml:"type,attr"`
	Enum     []*Enum         `xml:"item"` // In case of Enumerated AVP data
	Rule     []*Rule         `xml:"rule"` // In case of Grouped AVPs
}

// Enum contains the code and name of Enumerated items.
type Enum struct {
	// rfc6733 (section 4.3.1):
	// The Enumerated format is derived from the Integer32 Basic AVP Format.
	Code int32  `xml:"code,attr"`
	Name string `xml:"name,attr"`
}

// Rule defines the usage rules of an AVP.
type Rule struct {
	// MustNot adds outgoing M/P flag prohibitions for this member in its parent.
	// An AVP wildcard prohibition also applies to explicitly named members.
	// Prohibitions must not contradict a resolved member's required flags.
	// For example, TS 29.212 V20.0.0 Table 5.4.0.1 clears M inside Load.
	MustNot  string `xml:"must-not,attr"`
	AVP      string `xml:"avp,attr"` // AVP Name
	Required bool   `xml:"required,attr"`
	Min      int    `xml:"min,attr"`
	Max      int    `xml:"max,attr"`
	// MaxSet distinguishes an explicit zero maximum from an unbounded rule.
	MaxSet bool `xml:"-"`
	// Fixed marks an AVP that must occur in the command or group prefix.
	Fixed bool `xml:"fixed,attr"`
}

// MarshalXML writes only the attributes that differ from their defaults, and
// max only for a rule with a maximum, so that UnmarshalXML reads back the
// same rule. encoding/xml alone would write an unbounded rule as max="0", an
// explicit maximum of zero. An invalid negative bound is written as it is.
// The value receiver covers both Rule and *Rule.
func (r Rule) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "avp"}, Value: r.AVP})
	if r.MustNot != "" {
		start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "must-not"}, Value: r.MustNot})
	}
	if r.Required {
		start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "required"}, Value: "true"})
	}
	if r.Min != 0 {
		start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "min"}, Value: strconv.Itoa(r.Min)})
	}
	if r.MaxSet || r.Max != 0 {
		start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "max"}, Value: strconv.Itoa(r.Max)})
	}
	if r.Fixed {
		start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "fixed"}, Value: "true"})
	}
	return e.EncodeElement(struct{}{}, start)
}

func (r *Rule) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type rawRule struct {
		MustNot  string `xml:"must-not,attr"`
		AVP      string `xml:"avp,attr"`
		Required bool   `xml:"required,attr"`
		Min      int    `xml:"min,attr"`
		Max      string `xml:"max,attr"`
		Fixed    bool   `xml:"fixed,attr"`
	}
	var raw rawRule
	if err := d.DecodeElement(&raw, &start); err != nil {
		return err
	}
	if _, err := parseMemberProhibitions(raw.MustNot); err != nil {
		return fmt.Errorf("member %s must-not flags: %w", raw.AVP, err)
	}
	r.MustNot = raw.MustNot
	r.AVP, r.Required, r.Min, r.Fixed = raw.AVP, raw.Required, raw.Min, raw.Fixed
	if raw.Max != "" {
		max, err := strconv.Atoi(raw.Max)
		if err != nil {
			return fmt.Errorf("invalid maximum for %s: %w", raw.AVP, err)
		}
		r.Max, r.MaxSet = max, true
	}
	return nil
}
