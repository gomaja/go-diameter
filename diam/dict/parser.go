// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Dictionary parser.  Part of go-diameter.

package dict

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"github.com/gomaja/go-diameter/diam/datatype"
)

// Parser is the root element for dictionaries and supports multiple XML
// dictionary files loaded together. Diameter applications use dictionaries
// to parse messages received from peers as well as to encode crafted
// messages before sending them over the wire.
//
// Parser can load multiple XML dictionary files, which in turn support
// multiple applications that are composed by multiple AVPs. AVPs can also
// be registered without XML, see Register.
//
// All methods of Parser are safe for concurrent use, so definitions may be
// added while other goroutines decode messages with the same Parser. Each
// change is published as a new Snapshot that replaces the previous one
// atomically: a lookup sees the definitions as they were before a change or
// after it, never part of it, and lookups take no lock. Changes are
// serialized and each rebuilds the Parser's index, so it costs time
// proportional to the size of the dictionaries; changes are meant for
// configuration, not for every message.
//
// The zero Parser is empty and ready to use, like the one NewParser returns.
// A Parser must not be copied after first use.
type Parser struct {
	mu  sync.Mutex               // Serializes changes
	cur atomic.Pointer[Snapshot] // Published state; nil means emptySnapshot
}

// DefaultMaxGroupedDepth is the Grouped AVP nesting limit used unless
// Parser.SetMaxGroupedDepth sets another. The named rules of the shipped
// dictionaries nest at most 8 levels. A *[ AVP ] wildcard admits any AVP,
// including the Grouped AVP that contains it, so the grammar does not bound
// nesting; the limit is a decoding policy with room above the named rules.
const DefaultMaxGroupedDepth = 32

type codeIdx struct {
	appID    uint32
	code     uint32
	vendorID uint32
}

type appNameIdx struct {
	appID uint32
	name  string
}

type commandIdx struct {
	appID uint32
	code  uint32
}

type appIdTypeIdx struct {
	appID uint32
	typ   string
}

// NewParser allocates a new Parser optionally loading dictionary XML files.
// The files are loaded together: if one fails to load, NewParser returns
// the error and no Parser. See Load for replacement and rule validation.
func NewParser(filenames ...string) (*Parser, error) {
	p := new(Parser)
	if err := p.LoadFile(filenames...); err != nil {
		return nil, err
	}
	return p, nil
}

// LoadFile loads dictionary XML files together as one atomic change. Files
// may depend on definitions in later files. See Load. No filenames is a no-op.
func (p *Parser) LoadFile(filenames ...string) error {
	files := make([]*File, 0, len(filenames))
	for _, name := range filenames {
		f, err := parseFileNamed(name)
		if err != nil {
			return err
		}
		files = append(files, f)
	}
	return p.add(files...)
}

// Load loads XML streams together as one atomic change. Streams may depend
// on definitions in later streams. No readers is a no-op.
//
// A definition replaces an earlier loaded definition in the same application
// with the same code and vendor, removing the earlier name if it changes.
// Names must be unique in the final state of the load: a replacement may
// rename an AVP and another definition may reuse its former name in either
// order. A remaining name clash is refused with ErrAVPConflict. A child
// application may shadow an ancestor's name. Every command request/answer
// rule and Grouped member rule must resolve by name after replacements and
// inheritance, except the AVP wildcard (RFC 6733 (October 2012) §§3.2, 4.4).
// Member prohibitions allow only M/P and must not contradict resolved
// members' required flags; contradictions return ErrAVPConflict.
// An unresolved rule returns an error wrapping ErrAVPConflict and ErrNotFound.
// A dictionary that changes a registered definition is refused with
// ErrAVPConflict. Duplicate commands in one application are refused as well.
// Load either publishes all streams or, on any error, nothing.
func (p *Parser) Load(readers ...io.Reader) error {
	files := make([]*File, 0, len(readers))
	for _, r := range readers {
		f, err := parseFile(r)
		if err != nil {
			return err
		}
		files = append(files, f)
	}
	return p.add(files...)
}

func (p *Parser) add(files ...*File) error {
	if len(files) == 0 {
		return nil
	}
	return p.update(func(cur *Snapshot) (*Snapshot, error) {
		return cur.with(files, nil)
	})
}

func parseFileNamed(filename string) (*File, error) {
	fd, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	f, err := parseFile(fd)
	if closeErr := fd.Close(); err == nil {
		err = closeErr
	}
	return f, err
}

// parseFile decodes a dictionary and resolves its data types and AVP
// application links. It runs before the File is published, which is what
// lets readers use the File without synchronization afterwards.
func parseFile(r io.Reader) (*File, error) {
	f := new(File)
	d := xml.NewTokenDecoder(&strictDictionaryXML{source: xml.NewDecoder(r)})
	if err := d.Decode(f); err != nil {
		return nil, err
	}
	// Decode stops at the closing root. Read the rest so a second document,
	// malformed trailing XML, or an I/O error cannot be ignored by Load.
	for {
		_, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	for _, app := range f.App {
		for _, avp := range app.AVP {
			for _, rule := range []struct{ name, value string }{{"must", avp.Must}, {"may", avp.May}, {"must-not", avp.MustNot}} {
				if _, err := parseFlags(rule.value); err != nil {
					return nil, fmt.Errorf("AVP %s %s flags: %w", avp.Name, rule.name, err)
				}
			}
			// Link AVP to its Application
			avp.App = app
			if err := updateType(avp); err != nil {
				return nil, err
			}
		}
	}
	return f, nil
}

func updateType(a *AVP) error {
	id, exists := datatype.Available[a.Data.TypeName]
	if !exists {
		return fmt.Errorf("unsupported data type: %s", a.Data.TypeName)
	}
	a.Data.Type = id
	return nil
}

// Snapshot returns the Parser's current state. Lookups through the
// returned Snapshot keep answering from that state while the Parser
// changes, so a sequence of lookups that must agree, such as decoding one
// message, should use one Snapshot.
func (p *Parser) Snapshot() *Snapshot {
	if s := p.cur.Load(); s != nil {
		return s
	}
	return emptySnapshot
}

// update applies change to the current Snapshot and publishes the result.
// change returns nil and no error when there is nothing to publish.
func (p *Parser) update(change func(cur *Snapshot) (*Snapshot, error)) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	next, err := change(p.Snapshot())
	if err != nil {
		return err
	}
	if next != nil {
		p.cur.Store(next)
	}
	return nil
}

// SetStrict sets whether ReadMessage returns an error when one or more AVPs
// are invalid or empty and cannot be properly decoded. A new Parser is
// strict. When it is not, the decoding errors found are stored in the
// Message's DecodeErr field, which is accessible from a request handler.
//
// A message decode uses the setting in effect when it starts.
func (p *Parser) SetStrict(strict bool) {
	_ = p.update(func(cur *Snapshot) (*Snapshot, error) {
		if cur.strict == strict {
			return nil, nil
		}
		next := *cur
		next.strict = strict
		return &next, nil
	})
}

// Strict reports the setting made by SetStrict.
func (p *Parser) Strict() bool { return p.Snapshot().Strict() }

// SetMaxGroupedDepth sets how many levels of Grouped AVPs the decoder
// descends into, counting the outermost Grouped AVP as level 1. A Grouped
// AVP nested deeper keeps its payload as datatype.Unknown and the decode
// returns a DecodeError. Zero or a negative value restores
// DefaultMaxGroupedDepth; no value turns the limit off.
//
// Raise it only for a custom dictionary that nests deeper than the default:
// decoding cost grows quadratically with depth, and the limit is what
// bounds it for messages from untrusted peers, so a very high value gives
// that protection up. A message decode uses the limit in effect when it
// starts.
func (p *Parser) SetMaxGroupedDepth(depth int) {
	depth = max(depth, 0)
	_ = p.update(func(cur *Snapshot) (*Snapshot, error) {
		if cur.maxGroupedDepth == depth {
			return nil, nil
		}
		next := *cur
		next.maxGroupedDepth = depth
		return &next, nil
	})
}

// MaxGroupedDepth returns the Grouped AVP nesting limit the decoder applies.
func (p *Parser) MaxGroupedDepth() int { return p.Snapshot().MaxGroupedDepth() }

// String returns the Parser represented in a human readable form.
func (p *Parser) String() string { return p.Snapshot().String() }

// String returns the Snapshot represented in a human readable form.
func (s *Snapshot) String() string {
	var b bytes.Buffer
	for _, f := range s.files {
		for _, app := range f.App {
			writef(&b, "Application Id: %d\n", app.ID)
			writef(&b, "\tVendors:\n")
			for _, vendor := range app.Vendor {
				writef(&b, "\t\tId=%d Name=%s\n", vendor.ID, vendor.Name)
			}
			writef(&b, "\tCommands:\n")
			for _, cmd := range app.Command {
				printCommand(&b, cmd)
			}
			writef(&b, "\tAVPs:\n")
			for _, avp := range app.AVP {
				printAVP(&b, avp)
			}
		}
	}
	for _, r := range s.regs {
		writef(&b, "Registered in Application Id: %d\n", r.app)
		printAVP(&b, r.avp)
	}
	return b.String()
}

func writef(w io.Writer, format string, args ...interface{}) {
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		panic(err)
	}
}

func printCommand(w io.Writer, cmd *Command) {
	writef(w, "\t\t%-4d %s-Request (%sR)\n", cmd.Code, cmd.Name, cmd.Short)
	printCommandRules(w, cmd.Request.Rule)
	writef(w, "\t\t%-4d %s-Answer (%sA)\n", cmd.Code, cmd.Name, cmd.Short)
	printCommandRules(w, cmd.Answer.Rule)
}

func printCommandRules(w io.Writer, rules []*Rule) {
	for _, rule := range rules {
		// Print the effective minimum without changing the shared rule.
		min := rule.Min
		if rule.Required && min == 0 {
			min = 1
		}
		writef(w, "\t\t\t% -40s required=%-5t min=%d max=%d must-not=%q\n",
			rule.AVP, rule.Required, min, rule.Max, rule.MustNot)
	}
}

func printAVP(w io.Writer, avp *AVP) {
	writef(w, "\t%-4d %s: %s\n",
		avp.Code, avp.Name, avp.Data.TypeName)
	if avp.VendorID != 0 {
		writef(w, "\t\tVendorID: %d\n", avp.VendorID)
	}
	// Enumerated
	if len(avp.Data.Enum) > 0 {
		writef(w, "\t\tItems:\n")
		for _, item := range avp.Data.Enum {
			writef(w, "\t\t\t% -2d %s\n", item.Code, item.Name)
		}
	}
	// Grouped AVPs
	if len(avp.Data.Rule) > 0 {
		writef(w, "\t\tRules:\n")
		for _, rule := range avp.Data.Rule {
			writef(w, "\t\t\t% -40s required=%-5t min=%d max=%d must-not=%q\n",
				rule.AVP, rule.Required, rule.Min, rule.Max, rule.MustNot)
		}
	}
}
