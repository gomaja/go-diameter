package protocol

import (
	"fmt"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
)

func TestBodyCallbackResetsWatchdogDeadlineWithoutHealthCredit(t *testing.T) {
	for _, pending := range []bool{false, true} {
		for _, fatal := range []bool{false, true} {
			for _, header := range []bool{false, true} {
				t.Run(fmt.Sprintf("pending=%t/fatal=%t/invalid-header=%t", pending, fatal, header), func(t *testing.T) {
					c := opened(t, func(cfg *Config) {
						cfg.ReaderOwnsMessageErrorClosure = true
						cfg.Watchdog, cfg.QueueWrites = true, true
						cfg.WatchdogInterval = 6 * time.Second
					})
					at := epoch.Add(time.Second)
					if pending {
						probe(t, c)
						tick(t, c)
						at = epoch.Add(13 * time.Second)
					}
					before := c.Snapshot().Timer(WatchdogTimer)
					health := c.Snapshot().Watchdog()
					controls := c.Snapshot().Controls()
					in := receive(request(t, diam.DeviceWatchdog))
					in.At = at
					in.ErrorInput = true
					in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPLength, Fatal: fatal}
					if header {
						in.Message.Header.CommandFlags |= diam.ProxiableFlag
					}
					sent := find(t, c.Handle(in), Send)
					if sent.CloseAfter || !sent.Required || c.Phase() != Open {
						t.Fatal("callback transferred transport closure to the core")
					}
					after := c.Snapshot().Timer(WatchdogTimer)
					if after.Token == before.Token || !after.Deadline.Equal(in.At.Add(6*time.Second)) {
						t.Fatalf("eligible decoded activity did not reset Tw: %+v", after)
					}
					if c.Snapshot().Watchdog() != health {
						t.Fatalf("decoder activity changed watchdog health: %+v", c.Snapshot().Watchdog())
					}
					retained := c.Snapshot().Controls()
					if len(retained) != len(controls) {
						t.Fatal("decoder activity changed pending control ownership")
					}
					for i := range controls {
						if retained[i] != controls[i] {
							t.Fatal("decoder activity changed pending control")
						}
					}
				})
			}
		}
	}
}
