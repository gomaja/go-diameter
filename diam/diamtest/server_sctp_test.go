//go:build linux && !386

// Copyright 2013-2020 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diamtest

import (
	"testing"

	"github.com/gomaja/go-diameter/diam"
)

func requireSCTP(t *testing.T) {
	t.Helper()
	ln, err := diam.MultistreamListen("sctp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("close SCTP listener: %v", err)
	}
}

func TestNewServerSCTP(t *testing.T) {
	requireSCTP(t)
	srv := NewServerNetwork("sctp", nil, nil)
	srv.Close()
}
