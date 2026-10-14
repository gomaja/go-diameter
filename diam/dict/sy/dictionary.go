// Copyright 2013-2026 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Package sy supplies its application dictionary and prerequisites.
package sy

import (
	_ "embed"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/dict/internal/charging"
)

//go:embed diameter_sy.xml
var xml string

var dictionary = dict.Embedded("diameter_sy.xml", xml, dict.Base(), charging.Dictionary())

// Dictionary returns the immutable application dictionary selection.
func Dictionary() dict.Dictionary { return dictionary }
