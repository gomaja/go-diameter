// Copyright 2013-2026 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Package data provides the creditcontrol XML for the shared charging selection.
package data

import _ "embed"

//go:embed credit_control.xml
var xml string

// XML returns the immutable dictionary source.
func XML() string { return xml }
