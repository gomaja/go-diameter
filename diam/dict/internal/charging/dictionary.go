// Copyright 2013-2026 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Package charging joins the mutually dependent Credit-Control and Ro/Rf sources.
package charging

import (
	"github.com/gomaja/go-diameter/diam/dict"
	creditdata "github.com/gomaja/go-diameter/diam/dict/creditcontrol/data"
	"github.com/gomaja/go-diameter/diam/dict/nasreq"
	rodata "github.com/gomaja/go-diameter/diam/dict/rorf/data"
)

var dictionary = dict.Combine(
	dict.Embedded("credit_control.xml", creditdata.XML(), dict.Base(), nasreq.Dictionary()),
	dict.Embedded("tgpp_ro_rf.xml", rodata.XML(), dict.Base(), nasreq.Dictionary()),
)

// Dictionary returns both charging sources and their prerequisites.
func Dictionary() dict.Dictionary { return dictionary }
