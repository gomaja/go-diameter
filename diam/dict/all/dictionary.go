// Copyright 2013-2026 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Package all explicitly selects every shipped dictionary.
// Core Diameter packages do not import it.
package all

import (
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

var dictionary = dict.Combine(dict.Base(), creditcontrol.Dictionary(), cx.Dictionary(), gx.Dictionary(), nasreq.Dictionary(), rorf.Dictionary(), rx.Dictionary(), s13.Dictionary(), s6a.Dictionary(), s6c.Dictionary(), sgd.Dictionary(), sh.Dictionary(), swx.Dictionary(), sy.Dictionary())

// Dictionary returns the immutable selection of all shipped dictionaries.
func Dictionary() dict.Dictionary { return dictionary }
