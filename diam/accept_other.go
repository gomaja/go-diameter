//go:build (unix && !linux) || js || wasip1

package diam

import "syscall"

func retryAcceptPlatformError(syscall.Errno) bool { return false }
