// Copyright 2013-2026 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Package gx supplies its application dictionary and prerequisites.
package gx

import (
	_ "embed"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/dict/internal/charging"
)

//go:embed gx_credit_control.xml
var xml string

var dictionary = dict.Embedded("gx_credit_control.xml", xml, dict.Base(), charging.Dictionary())

// Dictionary returns the immutable application dictionary selection.
func Dictionary() dict.Dictionary { return dictionary }
