package protocol

import (
	"fmt"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
)

func TestFatalBodyCallbackPreservesWatchdogDeadline(t *testing.T) {
	for _, fatal := range []bool{false, true} {
		for _, header := range []bool{false, true} {
			t.Run(fmt.Sprintf("fatal=%t/invalid-header=%t", fatal, header), func(t *testing.T) {
				c := opened(t, func(cfg *Config) {
					cfg.ReaderOwnsMessageErrorClosure = true
					cfg.FatalBodyErrorKeepsWatchdogDeadline = true
					cfg.Watchdog, cfg.QueueWrites = true, true
					cfg.WatchdogInterval = 6 * time.Second
				})
				before := c.Snapshot().Timer(WatchdogTimer)
				in := receive(request(t, diam.DeviceWatchdog))
				in.At = epoch.Add(time.Second)
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
				if fatal && !header {
					if after != before {
						t.Fatalf("fatal body callback extended deadline: before=%+v after=%+v", before, after)
					}
				} else if after.Token == before.Token || !after.Deadline.Equal(in.At.Add(6*time.Second)) {
					t.Fatalf("eligible decoded activity did not reset Tw: %+v", after)
				}
			})
		}
	}
}
