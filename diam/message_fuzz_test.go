// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diam

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-diameter/diam/dict"
)

var malformedAVPMessages = []struct {
	name string
	wire []byte
}{
	{
		name: "truncated AVP header",
		wire: []byte{
			0x01, 0x00, 0x00, 0x18,
			0x80, 0x00, 0x01, 0x01,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x01, 0x0a,
		},
	},
	{
		name: "AVP length exceeds body",
		wire: []byte{
			0x01, 0x00, 0x00, 0x1c,
			0x80, 0x00, 0x01, 0x01,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x01, 0x0a,
			0x00, 0x00, 0x00, 0x09,
		},
	},
	{
		name: "zero AVP length",
		wire: []byte{
			0x01, 0x00, 0x00, 0x1c,
			0x80, 0x00, 0x01, 0x01,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x01, 0x0a,
			0x00, 0x00, 0x00, 0x00,
		},
	},
	{
		name: "short vendor header",
		wire: []byte{
			0x01, 0x00, 0x00, 0x1c,
			0x80, 0x00, 0x01, 0x01,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x01,
			0x80, 0x00, 0x00, 0x08,
		},
	},
}

func TestReadMessageRejectsMalformedAVPFraming(t *testing.T) {
	permissive, err := dict.NewParser("dict/testdata/base.xml")
	if err != nil {
		t.Fatal(err)
	}
	permissive.Strict = false
	parsers := []struct {
		name       string
		dictionary *dict.Parser
	}{
		{name: "strict", dictionary: dict.Default},
		{name: "permissive", dictionary: permissive},
	}

	for _, parser := range parsers {
		t.Run(parser.name, func(t *testing.T) {
			for _, tt := range malformedAVPMessages {
				t.Run(tt.name, func(t *testing.T) {
					if _, err := ReadMessage(bytes.NewReader(tt.wire), parser.dictionary); err == nil {
						t.Fatal("ReadMessage accepted malformed AVP framing")
					}
				})
			}
		})
	}
}

func TestDecodeAVPsRejectsMissingPadding(t *testing.T) {
	body := []byte{
		0x00, 0x00, 0x01, 0x08,
		0x40, 0x00, 0x00, 0x09,
		'x',
	}
	m := NewRequest(CapabilitiesExchange, 0, dict.Default)
	if err := m.decodeAVPs(body); err == nil {
		t.Fatal("decodeAVPs accepted an AVP without its required padding")
	}
	if len(m.AVP) != 0 {
		t.Fatalf("decoded AVPs = %d, want 0", len(m.AVP))
	}
}

func FuzzReadMessage(f *testing.F) {
	f.Add(testMessage)
	f.Add(testMessageWithVendorID)
	f.Add(testMismatchMessage)
	for _, seed := range malformedAVPMessages {
		f.Add(seed.wire)
	}
	f.Add([]byte{
		0x01, 0x00, 0x00, 0x01,
		0x80, 0x00, 0x01, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x01,
	})

	f.Fuzz(func(t *testing.T, wire []byte) {
		_, _ = ReadMessage(bytes.NewReader(wire), dict.Default)
	})
}
