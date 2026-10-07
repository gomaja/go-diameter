package diam

import (
	"syscall"

	"golang.org/x/sys/windows"
)

func retryAcceptPlatformError(err syscall.Errno) bool {
	// Winsock uses WSA error numbers rather than the POSIX errno values.
	// accept, "Return value": resource exhaustion and a reset before accept
	// leave the listener usable. Cancellation/closed-socket errors are terminal.
	// Go internal/poll.FD.Accept also retries ERROR_NETNAME_DELETED when
	// a reset arrives before AcceptEx completes.
	// https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-accept
	switch err {
	case windows.WSAEMFILE, windows.WSAEWOULDBLOCK,
		windows.WSAENOBUFS, windows.WSAECONNABORTED, windows.WSAECONNRESET,
		windows.WSAETIMEDOUT, windows.ERROR_NETNAME_DELETED, windows.ERROR_CONNECTION_ABORTED:
		return true
	}
	return false
}
