// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Skeleton of the dictionary file.  Part of go-diameter.

package dict

import (
	"encoding/xml"
	"fmt"
	"strconv"

	"github.com/gomaja/go-diameter/diam/datatype"
)

// File is the dictionary root element of a XML file.  See diam_base.xml.
type File struct {
	XMLName xml.Name `xml:"diameter"`
	App     []*App   `xml:"application"` // Support for multiple applications
}

// App defines a diameter application in XML and its multiple AVPs.
type App struct {
	ID      uint32     `xml:"id,attr"`   // Application Id
	Type    string     `xml:"type,attr"` // "acct" selects accounting; all other values default to auth during capabilities exchange.
	Name    string     `xml:"name,attr"` // Application name
	Vendor  []*Vendor  `xml:"vendor"`    // Ordered vendor declarations; see ApplicationVendor.
	Command []*Command `xml:"command"`   // Diameter commands
	AVP     []*AVP     `xml:"avp"`       // Each application support multiple AVPs
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
	App        *App   `xml:"none"` // Link back to diameter application
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
	AVP      string `xml:"avp,attr"` // AVP Name
	Required bool   `xml:"required,attr"`
	Min      int    `xml:"min,attr"`
	Max      int    `xml:"max,attr"`
	// MaxSet distinguishes an explicit zero maximum from an unbounded rule.
	MaxSet bool `xml:"-"`
	// Fixed marks an AVP that must occur in the command or group prefix.
	Fixed bool `xml:"fixed,attr"`
}

func (r *Rule) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type rawRule struct {
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
