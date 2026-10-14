// Copyright 2013-2026 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Package rorf supplies Credit-Control and Ro/Rf with their prerequisites.
package rorf

import (
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/dict/internal/charging"
)

// Dictionary returns the shared Credit-Control and Ro/Rf selection.
// Their Grouped rules require both XML sources, loaded atomically.
func Dictionary() dict.Dictionary { return charging.Dictionary() }
