package sm

import (
	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// testHandshakeNotifications installs the observer before any connection starts.
// Two entries cover the largest legacy test and every notification is retained.
func testHandshakeNotifications(sm *StateMachine) <-chan diam.Conn {
	settings := *sm.cfg
	notifications := make(chan diam.Conn, 2)
	settings.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { notifications <- c }
	sm.cfg = &settings
	return notifications
}
