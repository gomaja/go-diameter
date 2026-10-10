package diam

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

// Model the interval between a socket deadline firing and the context timer
// publishing its error. The context still reports nil Err during that interval.
type pendingDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (c pendingDeadlineContext) Deadline() (time.Time, bool) { return c.deadline, true }

func TestDialContextError(t *testing.T) {
	timeout := &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name      string
		ctx       context.Context
		err, want error
	}{
		{"cancelled", cancelled, net.ErrClosed, context.Canceled},
		{"deadline pending", pendingDeadlineContext{context.Background(), time.Now().Add(-time.Second)}, timeout, context.DeadlineExceeded},
		{"connect timeout", context.Background(), timeout, timeout},
		{"earlier connect timeout", pendingDeadlineContext{context.Background(), time.Now().Add(time.Hour)}, timeout, timeout},
		{"unrelated error", pendingDeadlineContext{context.Background(), time.Now().Add(-time.Second)}, net.ErrClosed, net.ErrClosed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := dialContextError(tc.ctx, tc.err); !errors.Is(got, tc.want) {
				t.Fatalf("dialContextError = %v, want %v", got, tc.want)
			}
		})
	}
}
