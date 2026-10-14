// Copyright 2013-2026 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Package swx supplies its application dictionary and prerequisites.
package swx

import (
	_ "embed"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/dict/s6a"
)

//go:embed tgpp_swx.xml
var xml string

var dictionary = dict.Embedded("tgpp_swx.xml", xml, dict.Base(), s6a.Dictionary())

// Dictionary returns the immutable application dictionary selection.
func Dictionary() dict.Dictionary { return dictionary }
