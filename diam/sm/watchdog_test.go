package sm

import (
	"log/slog"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

func TestJitteredTwBounds(t *testing.T) {
	const twinit, jitter = 30 * time.Second, 2 * time.Second
	var seenLow, seenHigh bool
	for range 1000 {
		got := jitteredTw(twinit, jitter)
		if got < twinit-jitter || got > twinit+jitter {
			t.Fatalf("jittered Tw = %s, want [%s,%s] (RFC 3539 §3.4.1 [1])", got, twinit-jitter, twinit+jitter)
		}
		seenLow = seenLow || got < twinit
		seenHigh = seenHigh || got > twinit
	}
	if !seenLow || !seenHigh {
		t.Fatal("Tw jitter did not vary on both sides of Twinit")
	}
	if got := jitteredTw(twinit, 0); got != twinit {
		t.Fatalf("zero-jitter Tw = %s, want %s", got, twinit)
	}
}

type watchdogDispatchConn struct {
	*watchdogProbeConn
	dispatched <-chan struct{}
}

func (c watchdogDispatchConn) DispatchDone() <-chan struct{} { return c.dispatched }

type watchdogOuterCloseNotifier struct {
	diam.Conn
	closed <-chan struct{}
}

func (c watchdogOuterCloseNotifier) CloseNotify() <-chan struct{} { return c.closed }
func (c watchdogOuterCloseNotifier) Unwrap() diam.Conn            { return c.Conn }

func TestConnectionDoneWrapperPrecedence(t *testing.T) {
	inner := watchdogDispatchConn{newWatchdogProbeConn(), make(chan struct{})}
	outerClose := make(chan struct{})
	for _, tc := range []struct {
		name string
		conn diam.Conn
		want <-chan struct{}
	}{
		{"direct", inner, inner.dispatched},
		{"unwrapped", unwrapTestConn{inner}, inner.dispatched},
		{"outer close notifier", watchdogOuterCloseNotifier{inner, outerClose}, outerClose},
		{"close notifier fallback", inner.watchdogProbeConn, inner.closed},
		{"opaque wrapper", struct{ diam.Conn }{inner}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := connectionDone(tc.conn); got != tc.want {
				t.Fatalf("connectionDone(%T) = %v, want %v", tc.conn, got, tc.want)
			}
		})
	}
}

func TestAcceptedWatchdogWarnsWithoutLifecycleNotifier(t *testing.T) {
	testDict := newSMTestDictionary(dict.Base())
	serverSettings := cloneTestSettings(serverSettings,
		testDict,
	)

	cfg := *serverSettings
	cfg.EnableWatchdog = true
	cfg.HostIPAddresses = []datatype.Address{localhostAddress}
	logs := logtest.New()
	inner := newWatchdogProbeConn()
	// Embedding diam.Conn hides the optional lifecycle methods on inner.
	c := loggedWatchdogConn{Conn: struct{ diam.Conn }{inner}, logger: slog.New(logs)}
	sm := mustNewStateMachine(t, &cfg, testDict)
	startAcceptedTestWatchdog(t, sm, c)
	if records := logs.Records(); len(records) != 1 || records[0].Level != slog.LevelWarn ||
		records[0].Message != "sm: watchdog disabled: connection exposes neither DispatchDone nor CloseNotifier" {
		t.Fatalf("watchdog warning records = %v", records)
	}
	if _, ok := sm.watchdogs.Load(c); ok {
		t.Fatal("watchdog registered without a lifecycle notifier")
	}
}

type blockingPublishWatchdogConn struct {
	*watchdogProbeConn
	entered chan struct{}
	release chan struct{}
	written chan []byte
}

func (c *blockingPublishWatchdogConn) WriteStream(b []byte, stream uint) (int, error) {
	if c.written != nil {
		c.written <- append([]byte(nil), b...)
	}
	close(c.entered)
	<-c.release
	return c.watchdogProbeConn.WriteStream(b, stream)
}

var _ diam.Conn = (*watchdogProbeConn)(nil)
