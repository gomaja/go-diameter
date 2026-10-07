package diam

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestServeRetriesWindowsAcceptErrors(t *testing.T) {
	testRetryAcceptErrors(t, []error{windows.WSAEMFILE, windows.WSAEWOULDBLOCK, windows.WSAENOBUFS, windows.WSAECONNABORTED, windows.WSAECONNRESET, windows.WSAETIMEDOUT, windows.ERROR_NETNAME_DELETED, windows.ERROR_CONNECTION_ABORTED})
}

func TestWindowsTerminalAcceptErrors(t *testing.T) {
	for _, err := range []error{windows.WSAEINTR, windows.WSAENOTSOCK, windows.WSAEINVAL, windows.WSAEACCES, windows.ERROR_OPERATION_ABORTED} {
		if retryAcceptError(acceptError(err)) {
			t.Errorf("retrying terminal error %v", err)
		}
	}
}
