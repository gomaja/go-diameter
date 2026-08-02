// Copyright 2013-2014 go-diameter authors.  All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Dictionary parser.  Part of go-diameter.

package main

import (
	"encoding/xml"
	"io"
)

func load(r io.Reader) (*File, error) {
	var (
		d = xml.NewDecoder(r)
		f = new(File)
	)
	if err := d.Decode(f); err != nil {
		return nil, err
	}
	return f, nil
}
