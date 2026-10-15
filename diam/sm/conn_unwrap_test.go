package sm

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam/internal/logtest"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

type unwrapTestConn struct{ diam.Conn }

func (c unwrapTestConn) Unwrap() diam.Conn { return c.Conn }

type writableNotifyConn struct {
	*blockingDisconnectConn
	ctx context.Context
}

func (c *writableNotifyConn) Context() context.Context { return c.ctx }

func (*writableNotifyConn) Write(b []byte) (int, error)                 { return len(b), nil }
func (c *writableNotifyConn) WriteStream(b []byte, _ uint) (int, error) { return c.Write(b) }

func TestOptionalConnThroughWrappers(t *testing.T) {
	testDict := newSMTestDictionary(dict.Base())
	serverSettings := cloneTestSettings(serverSettings,
		testDict)

	for _, tc := range []struct {
		name  string
		depth int
	}{{"direct", 0}, {"one", 1}, {"two", 2}, {"opaque", -1}} {
		wrap := func(c diam.Conn) diam.Conn {
			for range tc.depth {
				c = unwrapTestConn{c}
			}
			if tc.depth < 0 {
				c = struct{ diam.Conn }{c}
			}
			return c
		}
		t.Run("disconnect/"+tc.name, func(t *testing.T) {
			sm := mustNewStateMachine(t, serverSettings, testDict)
			inner := &blockingDisconnectConn{dictionary: testDict, closed: make(chan struct{})}
			inner.Close()
			err := sm.Disconnect(wrap(inner), DisconnectBusy, time.Second)
			if tc.depth < 0 {
				if err == nil || !strings.Contains(err.Error(), "requires CloseNotifier") {
					t.Fatalf("opaque: %v", err)
				}
			} else if !errors.Is(err, ErrDisconnectClosed) {
				t.Fatalf("Disconnect = %v, want closed", err)
			}
		})
		t.Run("dpr/"+tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := *serverSettings
				cfg.DPRCloseTimeout = time.Second
				sm := mustNewStateMachine(t, &cfg, testDict)
				inner := &writableNotifyConn{blockingDisconnectConn: &blockingDisconnectConn{dictionary: testDict, closed: make(chan struct{})}, ctx: smpeer.NewContext(context.Background(), &smpeer.Metadata{OriginHost: serverSettings.OriginHost, OriginRealm: serverSettings.OriginRealm})}
				defer inner.Close()
				msg, err := base.BuildDPR(inner.Dictionary(), baseSettings(sm.cfg), uint32(DisconnectBusy))
				if err != nil {
					t.Fatal(err)
				}
				handleDPR(sm)(wrap(inner), msg)
				time.Sleep(2 * time.Second)
				synctest.Wait()
				closed := false
				select {
				case <-inner.closed:
					closed = true
				default:
				}
				if closed != (tc.depth >= 0) {
					t.Fatalf("DPR closed = %v", closed)
				}
			})
		})
		t.Run("watchdog/"+tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				defer func() {
					if p := recover(); p != nil {
						t.Fatalf("wrapped watchdog panicked: %v", p)
					}
				}()
				sm := mustNewStateMachine(t, serverSettings, testDict)
				cli := &Client{Handler: sm, WatchdogInterval: time.Hour, Dict: testDict}
				inner := &observedNotifyConn{blockingDisconnectConn: &blockingDisconnectConn{dictionary: testDict, closed: make(chan struct{})}}
				inner.Close()
				cli.watchdog(wrap(inner), newWatchdogActivity())
				if inner.observed != (tc.depth >= 0) {
					t.Fatalf("watchdog discovered CloseNotifier = %v", inner.observed)
				}
			})
		})
	}
}

type observedNotifyConn struct {
	*blockingDisconnectConn
	observed bool
}

func (c *observedNotifyConn) CloseNotify() <-chan struct{} { c.observed = true; return c.closed }

func mustConnAs[T any](t *testing.T, c diam.Conn) T {
	t.Helper()
	v, ok := diam.ConnAs[T](c)
	if !ok {
		t.Fatalf("connection %T does not expose %T", c, (*T)(nil))
	}
	return v
}

type loggedWatchdogConn struct {
	diam.Conn
	logger *slog.Logger
}

func (c loggedWatchdogConn) Logger() *slog.Logger { return c.logger }

func TestWatchdogWarnsWithoutCloseNotifier(t *testing.T) {
	testDict := newSMTestDictionary(dict.Base())
	serverSettings := cloneTestSettings(serverSettings,
		testDict)

	logs := logtest.New()
	inner := &blockingDisconnectConn{dictionary: testDict, closed: make(chan struct{})}
	c := loggedWatchdogConn{inner, slog.New(logs).With("connection", "wrapped")}
	cli := &Client{Handler: mustNewStateMachine(t, serverSettings, testDict), Dict: testDict}
	cli.watchdog(c, newWatchdogActivity())
	records := logs.Records()
	if len(records) != 1 {
		t.Fatalf("got %d records, want one warning", len(records))
	}
	r := records[0]
	if r.Level != slog.LevelWarn || r.Message != "sm: watchdog disabled: connection does not expose CloseNotifier" {
		t.Fatalf("record = %v", r)
	}
	if logtest.Attr(r, "connection").String() != "wrapped" {
		t.Fatal("warning did not use the connection logger")
	}
}

type loggedNotifyingWatchdogConn struct {
	loggedWatchdogConn
	closed <-chan struct{}
}

func (c loggedNotifyingWatchdogConn) CloseNotify() <-chan struct{} { return c.closed }

func TestWatchdogDoesNotWarnWithCloseNotifier(t *testing.T) {
	testDict := newSMTestDictionary(dict.Base())
	serverSettings := cloneTestSettings(serverSettings,
		testDict)

	logs := logtest.New()
	inner := &blockingDisconnectConn{dictionary: testDict, closed: make(chan struct{})}
	inner.Close()
	c := loggedNotifyingWatchdogConn{loggedWatchdogConn{inner, slog.New(logs)}, inner.closed}
	// A long interval keeps the timer from racing the closed CloseNotify
	// channel, which would send a DWR on the closed connection.
	cli := &Client{Handler: mustNewStateMachine(t, serverSettings, testDict), WatchdogInterval: time.Hour, Dict: testDict}
	cli.watchdog(unwrapTestConn{c}, newWatchdogActivity())
	if records := logs.Records(); len(records) != 0 {
		t.Fatalf("unexpected watchdog warnings: %v", records)
	}
}
