package sm

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

type blockingSMLog struct {
	slog.Handler
	entered, release chan struct{}
}

func (h blockingSMLog) Handle(ctx context.Context, r slog.Record) error {
	close(h.entered)
	<-h.release
	return h.Handler.Handle(ctx, r)
}

type loggerHandshakeConn struct {
	*handshakeConn
	logger *slog.Logger
}

func (c loggerHandshakeConn) Logger() *slog.Logger { return c.logger }
func TestStateMachineRecordsAreSynchronous(t *testing.T) {
	records := logtest.New()
	entered, release := make(chan struct{}), make(chan struct{})
	c := loggerHandshakeConn{newHandshakeConn(), slog.New(blockingSMLog{records, entered, release})}
	cfg := testMessageErrorSettings()
	cfg.HandshakeTimeout = -1
	sm := mustNewStateMachine(t, cfg)
	cleanup := sm.HandleAccept(c)
	defer cleanup()
	done := make(chan struct{})
	go func() { sm.ServeDIAM(c, regressionDWR(t)); close(done) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("log handler not called")
	}
	if c.closed.Load() {
		t.Error("connection closed before log completed")
	}
	select {
	case <-done:
		t.Error("dispatch returned before log completed")
	default:
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("dispatch remained blocked")
	}
	if !c.closed.Load() || len(records.Records()) != 1 {
		t.Fatalf("close=%t records=%v", c.closed.Load(), records.Records())
	}
}

// Publishing a Wait-I-CEA failure wakes Client.handshake, which may close the
// connection. The decision record must complete before that publication.
func TestWaitICEARecordsBeforePublishingFailure(t *testing.T) {
	records := logtest.New()
	entered, release := make(chan struct{}), make(chan struct{})
	c := loggerHandshakeConn{newHandshakeConn(), slog.New(blockingSMLog{records, entered, release})}
	activity := newWatchdogActivity()
	sm := mustNewStateMachine(t, testMessageErrorSettings())
	h := activityHandler{StateMachine: sm, activity: activity}
	closed := make(chan struct{})
	go func() { <-activity.ceac; c.Close(); close(closed) }()
	done := make(chan struct{})
	go func() { h.rejectHandshake(c, errors.New("non-CEA")); close(done) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("close decision not logged")
	}
	// No failure can be consumed, even by a concurrently running dial goroutine.
	select {
	case <-closed:
		t.Error("handshake closed before decision log finished")
	case <-time.After(20 * time.Millisecond):
	}
	if c.closed.Load() {
		t.Error("rejectHandshake closed before decision log finished")
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("rejectHandshake did not complete")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("handshake failure was not published")
	}
	if len(records.Records()) != 1 {
		t.Fatalf("records=%v", records.Records())
	}
}
