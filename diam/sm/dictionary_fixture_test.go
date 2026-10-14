package sm

import (
	"strings"

	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"
	"github.com/gomaja/go-diameter/diam/dict/cx"
	"github.com/gomaja/go-diameter/diam/dict/gx"
	"github.com/gomaja/go-diameter/diam/dict/nasreq"
	"github.com/gomaja/go-diameter/diam/dict/rorf"
	"github.com/gomaja/go-diameter/diam/dict/rx"
	"github.com/gomaja/go-diameter/diam/dict/s13"
	"github.com/gomaja/go-diameter/diam/dict/s6a"
	"github.com/gomaja/go-diameter/diam/dict/s6c"
	"github.com/gomaja/go-diameter/diam/dict/sgd"
	"github.com/gomaja/go-diameter/diam/dict/sh"
	"github.com/gomaja/go-diameter/diam/dict/swx"
	"github.com/gomaja/go-diameter/diam/dict/sy"
)

// newTestDictionary constructs an independent parser for embedded test fixtures.
func newTestDictionary(dictionaries ...dict.Dictionary) *dict.Parser {
	parser, err := dict.New(dictionaries...)
	if err != nil {
		panic(err)
	}

	return parser
}

func newSMTestDictionary(dictionaries ...dict.Dictionary) *dict.Parser {
	parser := newTestDictionary(dictionaries...)
	for _, fixture := range []string{acctDictionary, authDictionary} {
		if err := parser.Load(strings.NewReader(fixture)); err != nil {
			panic(err)
		}
	}
	return parser
}

func testDictionaryDescriptors() []struct {
	name       string
	dictionary dict.Dictionary
} {
	return []struct {
		name       string
		dictionary dict.Dictionary
	}{
		{"base", dict.Base()},
		{"creditcontrol", creditcontrol.Dictionary()},
		{"rorf", rorf.Dictionary()},
		{"nasreq", nasreq.Dictionary()},
		{"sy", sy.Dictionary()},
		{"gx", gx.Dictionary()},
		{"rx", rx.Dictionary()},
		{"cx", cx.Dictionary()},
		{"sh", sh.Dictionary()},
		{"s6a", s6a.Dictionary()},
		{"s13", s13.Dictionary()},
		{"s6c", s6c.Dictionary()},
		{"sgd", sgd.Dictionary()},
		{"swx", swx.Dictionary()},
	}
}
