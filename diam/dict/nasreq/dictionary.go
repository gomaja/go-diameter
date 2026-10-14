// Copyright 2013-2026 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Package nasreq supplies its application dictionary and prerequisites.
package nasreq

import (
	_ "embed"
	"github.com/gomaja/go-diameter/diam/dict"
)

//go:embed network_access_server.xml
var xml string

var dictionary = dict.Embedded("network_access_server.xml", xml, dict.Base())

// Dictionary returns the immutable application dictionary selection.
func Dictionary() dict.Dictionary { return dictionary }
