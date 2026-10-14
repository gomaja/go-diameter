package smparser

import (
	"strings"

	"github.com/gomaja/go-diameter/diam/dict"
)

// newTestDictionary constructs an independent parser for embedded test fixtures.
func newTestDictionary(dictionaries ...dict.Dictionary) *dict.Parser {
	parser, err := dict.New(dictionaries...)
	if err != nil {
		panic(err)
	}

	return parser
}

func newParserTestDictionary(dictionaries ...dict.Dictionary) *dict.Parser {
	parser := newTestDictionary(dictionaries...)
	for _, fixture := range []string{acctDictionary, authDictionary} {
		if err := parser.Load(strings.NewReader(fixture)); err != nil {
			panic(err)
		}
	}

	return parser
}
