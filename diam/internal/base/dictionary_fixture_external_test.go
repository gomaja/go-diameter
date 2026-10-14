package base_test

import "github.com/gomaja/go-diameter/diam/dict"

// newTestDictionary constructs an independent parser for embedded test fixtures.
func newTestDictionary(dictionaries ...dict.Dictionary) *dict.Parser {
	parser, err := dict.New(dictionaries...)
	if err != nil {
		panic(err)
	}

	return parser
}
