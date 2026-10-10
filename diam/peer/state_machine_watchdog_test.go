package peer

import (
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/sm"
)

func TestNewRejectsStateMachineWatchdogSettings(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*sm.Settings)
	}{
		{"EnableWatchdog", func(s *sm.Settings) { s.EnableWatchdog = true }},
		{"WatchdogInterval", func(s *sm.Settings) { s.WatchdogInterval = time.Second }},
		{"WatchdogStream", func(s *sm.Settings) { s.WatchdogStream = 3 }},
		{"OnWatchdogConnEvent", func(s *sm.Settings) { s.OnWatchdogConnEvent = func(diam.Conn, sm.WatchdogEvent) {} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{Settings: testSettings("local.example.net")}
			tc.set(&cfg.Settings)
			_, err := New(cfg)
			want := "peer: Settings." + tc.name + " is not supported; Manager supervises every peer (use Timers.TwInit and OnPeerEvent)"
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("New error = %v, want %q", err, want)
			}
		})
	}
}
