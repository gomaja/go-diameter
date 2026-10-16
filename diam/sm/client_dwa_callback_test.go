package sm

import (
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

// The Client publishes a rejected DWA warning before its watchdog callback.
// A callback may inspect that synchronous diagnostic or block its own return.
func TestClientRejectedDWALogPrecedesCallback(t *testing.T) {
	logs := logtest.New()
	observed := make(chan int, 1)
	p := newProtocolClientWire(t, func(c *Client) {
		c.EnableWatchdog = true
		c.WatchdogInterval = 200 * time.Millisecond
		c.watchdogTiming = &watchdogTiming{floor: time.Millisecond}
		c.Logger = logs.Logger()
		c.OnWatchdogEvent = func(e WatchdogEvent) {
			if e == WatchdogInvalidAnswer {
				observed <- len(logs.RecordsWithMessage("sm: rejected DWA"))
			}
		}
	})
	p.send(t, protocolClientCEA(p.cer, diam.Success))
	if result := p.dialResult(t); result.err != nil {
		t.Fatal(result.err)
	}
	probe := acceptedWatchdogOnWire(t, p.peer)
	m := acceptedDWA(t, probe, diam.UnableToComply)
	setWireIdentity(t, m, avp.OriginHost, "peer.example")
	setWireIdentity(t, m, avp.OriginRealm, "example")
	p.send(t, m)
	select {
	case n := <-observed:
		if n != 1 {
			t.Fatalf("rejected DWA log records when callback ran = %d; want 1", n)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no watchdog callback")
	}
}
