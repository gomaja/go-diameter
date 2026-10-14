// Copyright 2013-2026 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package dict

import (
	_ "embed"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// Dictionary is an immutable selection of embedded XML sources and their
// prerequisites. Application packages return these values from Dictionary.
// Copies share a lazy parse cache, never mutable Parser state. The zero value
// is invalid; use Combine() for an empty selection.
type Dictionary struct {
	node *dictionaryNode
}

type dictionaryNode struct {
	source *dictionarySource
	deps   []Dictionary
}

type dictionarySource struct {
	name  string
	parse func() (*File, error)
}

// ErrDictionaryConflict reports distinct sources claiming the same identifier.
var ErrDictionaryConflict = errors.New("dict: conflicting dictionary sources")

// Embedded describes an immutable XML source with its prerequisites. The name
// identifies the source and sets its position in canonical filename order.
// XML is parsed lazily by New, once per returned descriptor; errors are cached.
// Prerequisites are copied, so changing the caller's slice cannot alter d.
// Invalid names, XML and prerequisites are reported by New.
func Embedded(name, text string, prerequisites ...Dictionary) Dictionary {
	return Dictionary{node: &dictionaryNode{
		source: &dictionarySource{
			name: name,
			parse: sync.OnceValues(func() (*File, error) {
				return parseFile(strings.NewReader(text))
			}),
		},
		deps: slices.Clone(prerequisites),
	}}
}

// Combine describes the union of dictionaries without parsing or publishing
// them. New loads the union atomically. An empty union is valid.
func Combine(dictionaries ...Dictionary) Dictionary {
	return Dictionary{node: &dictionaryNode{deps: slices.Clone(dictionaries)}}
}

//go:embed base.xml
var baseXML string

var baseDictionary = Embedded("base.xml", baseXML)

// Base describes the Diameter base protocol (RFC 6733, applications 0 and 3).
func Base() Dictionary { return baseDictionary }

// Default is the shared, base-only Parser used when a Diameter API receives a
// nil dictionary. Application imports never add definitions to it. Construct
// an independent Parser with New before loading custom definitions or policy.
var Default = func() *Parser {
	p, err := New(Base())
	if err != nil {
		panic(fmt.Sprintf("dict: base dictionary: %v", err))
	}
	return p
}()

// dictionarySources flattens the selection by source identity. Shared nodes
// are visited once, so overlapping prerequisite graphs need no repeated work.
func dictionarySources(dictionaries []Dictionary) ([]*dictionarySource, error) {
	visited := make(map[*dictionaryNode]bool)
	byName := make(map[string]*dictionarySource)
	var include func(Dictionary) error
	include = func(d Dictionary) error {
		if d.node == nil {
			return errors.New("dict: invalid zero Dictionary")
		}
		if visited[d.node] {
			return nil
		}
		visited[d.node] = true
		if source := d.node.source; source != nil {
			if source.name == "" {
				return errors.New("dict: dictionary source has an empty name")
			}
			if previous := byName[source.name]; previous != nil && previous != source {
				return fmt.Errorf("%w: %q", ErrDictionaryConflict, source.name)
			}
			byName[source.name] = source
		}
		for _, dependency := range d.node.deps {
			if err := include(dependency); err != nil {
				return err
			}
		}
		return nil
	}
	for _, d := range dictionaries {
		if err := include(d); err != nil {
			return nil, err
		}
	}
	sources := make([]*dictionarySource, 0, len(byName))
	for _, source := range byName {
		sources = append(sources, source)
	}
	slices.SortFunc(sources, func(a, b *dictionarySource) int {
		return strings.Compare(a.name, b.name)
	})
	return sources, nil
}

// New builds an independent Parser from dictionaries and all their declared
// prerequisites. Source identifiers, rather than Application-Ids, identify
// duplicates: several XML sources can contribute to one application.
//
// All sources load together in canonical filename order, so caller order and
// repeated selections cannot alter replacement or inheritance precedence.
// A rule or source error returns no Parser. With no dictionaries New returns
// an empty Parser, as NewParser does. Custom XML updates still use Load.
//
// Loaded prerequisites participate in capability inference (RFC 6733 §5.3).
func New(dictionaries ...Dictionary) (*Parser, error) {
	sources, err := dictionarySources(dictionaries)
	if err != nil {
		return nil, err
	}
	files := make([]*File, 0, len(sources))
	for _, source := range sources {
		file, err := source.parse()
		if err != nil {
			return nil, fmt.Errorf("dict: source %q: %w", source.name, err)
		}
		files = append(files, file)
	}
	p := new(Parser)
	if err := p.add(files...); err != nil {
		return nil, fmt.Errorf("dict: selected dictionaries: %w", err)
	}
	return p, nil
}
