package diam

import "syscall"

func retryAcceptPlatformError(err syscall.Errno) bool {
	// Linux accept(2), "Error handling": pending network errors on the new
	// socket can clear when accepting the next connection. Unlike those errors,
	// EOPNOTSUPP also denotes a permanently unsuitable socket type, so it must
	// remain terminal. These differ from BSD accept errors.
	// https://man7.org/linux/man-pages/man2/accept.2.html
	switch err {
	case syscall.ENETDOWN, syscall.EPROTO, syscall.ENOPROTOOPT, syscall.EHOSTDOWN,
		syscall.ENONET, syscall.EHOSTUNREACH, syscall.ENETUNREACH:
		return true
	}
	return false
}
