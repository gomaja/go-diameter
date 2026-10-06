// Copyright 2013-2020 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package diam

import "syscall"

// setReuseTcpAddr leaves the socket unchanged on platforms without the
// Unix SO_REUSEADDR semantics network_unix.go relies on.
func setReuseTcpAddr(network, address string, c syscall.RawConn) error {
	return nil
}
