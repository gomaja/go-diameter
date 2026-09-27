package peer

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"time"
)

var processStartSeconds = uint32(time.Now().Unix())

type endToEndAllocator struct{ next atomic.Uint32 }

func (a *endToEndAllocator) init() error {
	var seed [4]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return fmt.Errorf("peer: End-to-End seed: %w", err)
	}
	// RFC 6733 §3 permits a reboot-time 12-bit seconds prefix with a random
	// low 20-bit start. Incrementing the whole word advances the prefix when
	// the low counter wraps. The caller may inject a durable generator instead.
	a.next.Store(((processStartSeconds & 0xfff) << 20) | (binary.BigEndian.Uint32(seed[:]) & 0xfffff))
	return nil
}

func (a *endToEndAllocator) allocate() uint32 { return a.next.Add(1) - 1 }
