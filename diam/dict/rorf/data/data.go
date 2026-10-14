// Copyright 2013-2026 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Package data provides the rorf XML for the shared charging selection.
package data

import _ "embed"

//go:embed tgpp_ro_rf.xml
var xml string

// XML returns the immutable dictionary source.
func XML() string { return xml }
