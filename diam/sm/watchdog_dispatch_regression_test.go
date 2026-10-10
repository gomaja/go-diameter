package sm

import (
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/dict"
)

// RFC 3539 §3.4: a blocked outgoing DWR must not prevent ordinary received
// traffic from being dispatched. The event mutex must not gate activity.
func TestAcceptedWatchdogBlockedDWRWriteAllowsInboundDispatch(t *testing.T) {
	cfg := newAcceptedWatchdogSettings()
	cfg.WatchdogInterval = 20 * time.Millisecond
	cfg.HandshakeTimeout = time.Hour
	sm := mustNewStateMachine(t, &cfg)
	c := newAcceptedWatchdogProbeConn()
	entered, release := make(chan struct{}), make(chan struct{})
	c.afterWrite = func(seq int32) {
		if seq == 2 {
			close(entered)
			<-release
		}
	}
	cleanup := sm.HandleAccept(c)
	defer cleanup()
	sm.ServeDIAM(c, regressionCER(t, dict.Default, 1001))
	w := acceptedWatchdogState(t, sm, c)
	<-c.writes // CEA
	<-entered  // DWR write now blocked inside publishDWR, holding w.mu
	<-c.writes // DWR bytes
	routed := make(chan struct{})
	sm.Handle("ALL", diam.HandlerFunc(func(diam.Conn, *diam.Message) { close(routed) }))
	go sm.ServeDIAM(c, diam.NewRequest(999, 42, dict.Default).Answer(diam.Success))
	select {
	case <-routed:
	case <-time.After(500 * time.Millisecond):
		t.Errorf("inbound answer not dispatched while the DWR write was blocked")
	}
	close(release)
	<-routed
	close(c.done)
	<-w.exited
}
