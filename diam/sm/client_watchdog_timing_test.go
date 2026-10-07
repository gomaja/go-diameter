package sm

import (
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
)

func TestWatchdogIntervalValidation(t *testing.T) {
	for _, tc := range []struct {
		interval, want time.Duration
		invalid        bool
	}{
		{0, 30 * time.Second, false},
		{6 * time.Second, 6 * time.Second, false},
		{6*time.Second - time.Nanosecond, 0, true},
		{-time.Second, 0, true},
	} {
		cli := &Client{Handler: mustNewStateMachine(t, clientSettings), EnableWatchdog: true, WatchdogInterval: tc.interval}
		err := cli.validate()
		if tc.invalid {
			if err == nil || !strings.Contains(err.Error(), "minimum") {
				t.Fatalf("interval %s: error = %v, want minimum error", tc.interval, err)
			}
		} else if err != nil || cli.WatchdogInterval != tc.want {
			t.Fatalf("interval %s: got %s, error %v, want %s", tc.interval, cli.WatchdogInterval, err, tc.want)
		}
	}
	// The minimum governs the watchdog only; a disabled watchdog never sends
	// DWRs, so a short leftover interval must not fail validation.
	disabled := &Client{Handler: mustNewStateMachine(t, clientSettings), WatchdogInterval: time.Second}
	if err := disabled.validate(); err != nil {
		t.Fatalf("disabled watchdog with 1s interval rejected: %v", err)
	}
	cli := &Client{Handler: mustNewStateMachine(t, clientSettings), EnableWatchdog: true, WatchdogInterval: 50 * time.Millisecond,
		watchdogTiming: &watchdogTiming{floor: time.Millisecond}}
	if err := cli.validate(); err != nil {
		t.Fatalf("private test timing override rejected: %v", err)
	}
}

func TestWatchdogJitterBounds(t *testing.T) {
	cli := &Client{WatchdogInterval: 30 * time.Second}
	seen := map[time.Duration]bool{}
	for i := 0; i < 1000; i++ {
		interval := cli.nextWatchdogInterval()
		if interval < 28*time.Second || interval > 32*time.Second {
			t.Fatalf("jittered Tw = %s, want [28s,32s]", interval)
		}
		seen[interval] = true
	}
	if len(seen) < 2 {
		t.Fatal("jitter was not applied")
	}
}

func TestWatchdogTrafficSuppressesDWRAndIdleSendsIt(t *testing.T) {
	dwr := make(chan struct{}, 4)
	settings := *serverSettings
	settings.OnDWR = func(diam.Conn, *diam.Message) { dwr <- struct{}{} }
	ssm := mustNewStateMachine(t, &settings)
	ssmHandshakes := testHandshakeNotifications(ssm)
	srv := diamtest.NewServer(ssm, dict.Default)
	defer srv.Close()
	cli := newLivenessClient(t)
	cli.WatchdogInterval = 120 * time.Millisecond
	c, err := cli.Dial(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var peer diam.Conn
	select {
	case peer = <-ssmHandshakes:
	case <-time.After(2 * time.Second):
		t.Fatal("server handshake timeout")
	}
	for i := 0; i < 20; i++ {
		m := diam.NewRequest(diam.DeviceWatchdog, 0, dict.Default)
		if _, err := m.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("server")); err != nil {
			t.Fatal(err)
		}
		if _, err := m.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("test")); err != nil {
			t.Fatal(err)
		}
		if _, err := m.WriteTo(peer); err != nil {
			t.Fatal(err)
		}
		select {
		case <-dwr:
			t.Fatal("client sent DWR while receiving traffic")
		case <-time.After(20 * time.Millisecond):
		}
	}
	select {
	case <-dwr:
		t.Fatal("client sent DWR while receiving traffic")
	default:
	}
	select {
	case <-dwr:
	case <-time.After(time.Second):
		t.Fatal("idle client did not send DWR")
	}
}
