// Package testutil provides shared helpers for transport tests.
package testutil

import "time"

// SCTPTimeout allows one lost packet on a fresh local association to be
// retransmitted, with scheduling margin. Linux net.sctp.rto_initial/rto_min
// measured 3s/1s; dropping the first DATA packet produced a 3.06s retransmission.
// RFC 9260 §§6.3.1-6.3.3, 16 specify RTO calculation and backoff (and suggest
// a 1s initial RTO). The measured rto_max of 60s caps later backoff; this bound
// covers a single loss on these fresh local associations, not repeated loss.
const SCTPTimeout = 10 * time.Second

// NetworkTimeout preserves other transports' bounds while allowing SCTP
// retransmission. It is a deadline, not a delay on successful exchanges.
func NetworkTimeout(network string, fallback time.Duration) time.Duration {
	switch network {
	case "sctp", "sctp4", "sctp6":
		return max(SCTPTimeout, fallback)
	default:
		return fallback
	}
}
