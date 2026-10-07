//go:build unix || windows || js || wasip1

package diam

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

type acceptResult struct {
	c   net.Conn
	err error
}
type retryListener struct {
	results []acceptResult
	calls   []time.Time
}

func (l *retryListener) Accept() (net.Conn, error) {
	l.calls = append(l.calls, time.Now())
	if len(l.results) == 0 {
		return nil, net.ErrClosed
	}
	r := l.results[0]
	l.results = l.results[1:]
	return r.c, r.err
}
func (*retryListener) Close() error   { return nil }
func (*retryListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3868} }
func acceptError(err error) error {
	return &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept", err)}
}

func TestServeRetriesAcceptErrors(t *testing.T) {
	testRetryAcceptErrors(t, []error{syscall.EMFILE, syscall.ENFILE, syscall.ECONNABORTED, syscall.ECONNRESET, syscall.EINTR, syscall.ENOBUFS, syscall.ENOMEM, syscall.EAGAIN, syscall.ETIMEDOUT, timeoutError{}})
}

func testRetryAcceptErrors(t *testing.T, errs []error) {
	t.Helper()
	for _, errno := range errs {
		t.Run(errno.Error(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				logger, logs := newTestLogger(slog.LevelDebug)
				var handled atomic.Int32
				srv := &Server{Logger: logger, Handler: HandlerFunc(func(Conn, *Message) { handled.Add(1) })}
				defer func() { _ = srv.Close() }()
				l := &retryListener{}
				failure := acceptError(errno)
				delays := []time.Duration{5, 10, 20, 40, 80, 160, 320, 640, 1000, 1000}
				for range delays {
					l.results = append(l.results, acceptResult{err: failure})
				}
				addConn := func() {
					a, b := net.Pipe()
					t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
					l.results = append(l.results, acceptResult{c: a})
					var wire bytes.Buffer
					writeTestCER(t, &wire)
					go func() { defer func() { _ = b.Close() }(); _, _ = b.Write(wire.Bytes()) }()
				}
				addConn()
				l.results = append(l.results, acceptResult{err: failure})
				addConn()
				if err := srv.Serve(l); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("Serve returned %v; want closed listener after retrying", err)
				}
				synctest.Wait()
				if handled.Load() != 2 {
					t.Fatalf("handled %d messages, want 2", handled.Load())
				}
				records := logs.records(t)
				if len(records) != len(delays)+1 {
					t.Fatalf("got %d records, want %d", len(records), len(delays)+1)
				}
				for i, delay := range append(delays, 5) {
					delay *= time.Millisecond
					call := i
					if i == len(delays) {
						call++
					}
					if got := l.calls[call+1].Sub(l.calls[call]); got != delay {
						t.Errorf("retry %d slept %v, want %v", i, got, delay)
					}
					wantRecord(t, records[i], map[string]any{"level": "WARN", "msg": "diam: accept failed; retrying", logKeyError: failure.Error(), logKeyRetryIn: float64(delay), logKeyNetwork: "tcp", logKeyLocalAddr: l.Addr().String()})
				}
			})
		})
	}
}

func TestServeClosedListener(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	logger, logs := newTestLogger(slog.LevelDebug)
	if err = (&Server{Logger: logger}).Serve(l); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Serve = %v, want net.ErrClosed", err)
	}
	if len(logs.records(t)) != 0 {
		t.Fatal("closed listener was retried")
	}
}

// A Temporary-only error is not enough to establish that Accept can recover.
type temporaryOnlyError struct{}

func (temporaryOnlyError) Error() string   { return "terminal" }
func (temporaryOnlyError) Timeout() bool   { return false }
func (temporaryOnlyError) Temporary() bool { panic("Temporary must not be called") }

func TestServeTerminalAcceptErrors(t *testing.T) {
	for _, err := range []error{syscall.EBADF, syscall.EINVAL, syscall.ENOTSOCK, syscall.EACCES, temporaryOnlyError{}, closedTimeoutError{}, errors.Join(net.ErrClosed, timeoutError{}), ErrServerClosed} {
		t.Run(err.Error(), func(t *testing.T) {
			logger, logs := newTestLogger(slog.LevelDebug)
			failure := acceptError(err)
			l := &retryListener{results: []acceptResult{{err: failure}}}
			if got := (&Server{Logger: logger}).Serve(l); got != failure {
				t.Fatalf("Serve = %v, want original %v", got, failure)
			}
			if len(l.calls) != 1 || len(logs.records(t)) != 0 {
				t.Fatal("terminal error was retried")
			}
		})
	}
}

type closedTimeoutError struct{ timeoutError }

func (closedTimeoutError) Unwrap() error { return net.ErrClosed }

func TestRetryAcceptWrappedError(t *testing.T) {
	for _, err := range []error{syscall.EMFILE, syscall.ENFILE, syscall.ECONNABORTED, timeoutError{}} {
		if !retryAcceptError(fmt.Errorf("listener: %w", acceptError(err))) {
			t.Errorf("did not retry wrapped %v", err)
		}
	}
}
