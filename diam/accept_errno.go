//go:build unix || windows || js || wasip1

package diam

import (
	"errors"
	"syscall"
)

func retryAcceptSystemError(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	// Resource pressure, interrupted calls and peers disappearing from the
	// accept queue can all recover without replacing the listening socket.
	switch errno {
	case syscall.EINTR, syscall.EMFILE, syscall.ENFILE,
		syscall.ECONNABORTED, syscall.ECONNRESET, syscall.ENOBUFS, syscall.ENOMEM:
		return true
	}
	return retryAcceptPlatformError(errno)
}
