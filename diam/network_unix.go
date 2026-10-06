// Copyright 2013-2020 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package diam

import (
	"fmt"
	"strings"
	"syscall"
)

// setReuseTcpAddr sets SO_REUSEADDR on a TCP socket that a dial binds to a
// caller-chosen local address, so the address can be bound again while an
// earlier connection from it is in TIME_WAIT. It runs as the net.Dialer
// Control function: a failure is returned, which closes the socket and fails
// the dial, instead of letting the bind fail later for an unstated reason.
func setReuseTcpAddr(network, address string, c syscall.RawConn) error {
	if c == nil || len(address) == 0 || !strings.HasPrefix(network, "tcp") {
		return nil
	}
	var sockErr error
	if err := c.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	}); err != nil {
		return err
	}
	if sockErr != nil {
		// address is the remote address being dialed (net.Dialer.Control).
		return fmt.Errorf("diam: set SO_REUSEADDR dialing %s %s: %w", network, address, sockErr)
	}
	return nil
}
