package peer

import (
	"sync/atomic"
	"testing"
)

func TestManagerOpenReceiveAvoidsPendingDrainScanTCP(t *testing.T) {
	p := newCoreActivityWire(t, false)
	var scans atomic.Int64
	p.a.commit(event{testHook: func() {
		p.s.beforeInFlightScan = func() { scans.Add(1) }
	}}, newProtocolDelivery())
	write(t, p.c, watchdogRequest(t))
	_ = read(t, p.c)
	p.fence(t)
	if got := scans.Load(); got != 0 {
		t.Fatalf("Open receive scanned pending drain set %d times", got)
	}
}
