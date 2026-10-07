package diam

import (
	"errors"
	"net"
)

// retryAcceptError recognizes failures that leave a listener usable. Unlike
// net.Error.Temporary, this classification is specific to accepting connections.
func retryAcceptError(err error) bool {
	if errors.Is(err, net.ErrClosed) || errors.Is(err, ErrServerClosed) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return retryAcceptSystemError(err)
}
