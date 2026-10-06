//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package diam

import (
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
)

// fdRawConn runs Control on a fixed descriptor.
type fdRawConn struct {
	fd         uintptr
	controlErr error
}

func (c fdRawConn) Control(f func(fd uintptr)) error {
	if c.controlErr != nil {
		return c.controlErr
	}
	f(c.fd)
	return nil
}
func (fdRawConn) Read(func(uintptr) bool) error  { return syscall.EINVAL }
func (fdRawConn) Write(func(uintptr) bool) error { return syscall.EINVAL }

func TestSetReuseTcpAddrReturnsSetsockoptFailure(t *testing.T) {
	// No descriptor has number -1, so setsockopt fails with EBADF.
	err := setReuseTcpAddr("tcp4", "192.0.2.1:3868", fdRawConn{fd: ^uintptr(0)})
	if !errors.Is(err, syscall.EBADF) {
		t.Fatalf("setReuseTcpAddr = %v, want EBADF", err)
	}
	if !strings.Contains(err.Error(), "SO_REUSEADDR") {
		t.Errorf("error %q does not name SO_REUSEADDR", err)
	}

	controlErr := errors.New("control failed")
	if err := setReuseTcpAddr("tcp4", "192.0.2.1:3868", fdRawConn{controlErr: controlErr}); !errors.Is(err, controlErr) {
		t.Fatalf("setReuseTcpAddr = %v, want %v", err, controlErr)
	}

	// Sockets it does not apply to are left alone, whatever their state.
	for _, tc := range []struct{ network, address string }{
		{"udp4", "192.0.2.1:3868"},
		{"tcp4", ""},
	} {
		if err := setReuseTcpAddr(tc.network, tc.address, fdRawConn{fd: ^uintptr(0)}); err != nil {
			t.Errorf("setReuseTcpAddr(%q, %q) = %v, want nil", tc.network, tc.address, err)
		}
	}
}

func TestBoundTCPDialSetsReuseAddr(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	laddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
	conn, err := getMultistreamDialer("tcp", 0, laddr).Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var reuse int
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		reuse, sockErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR)
	}); err != nil {
		t.Fatal(err)
	}
	if sockErr != nil {
		t.Fatal(sockErr)
	}
	if reuse == 0 {
		t.Fatal("SO_REUSEADDR is off on a dial bound to a local address")
	}
}
