package diam

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
)

// recordBuffer collects the JSON records of a test logger.
type recordBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *recordBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *recordBuffer) records(t *testing.T) []map[string]any {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(b.buf.Bytes()))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var rec map[string]any
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("log record %q: %v", sc.Text(), err)
		}
		out = append(out, rec)
	}
	return out
}

// wait returns the records once there are at least n.
func (b *recordBuffer) wait(t *testing.T, n int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		recs := b.records(t)
		if len(recs) >= n {
			return recs
		}
		if time.Now().After(deadline) {
			t.Fatalf("logged %d records after 2s, want %d: %v", len(recs), n, recs)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func newTestLogger(level slog.Level) (*slog.Logger, *recordBuffer) {
	buf := &recordBuffer{}
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: level})), buf
}

func wantRecord(t *testing.T, rec map[string]any, want map[string]any) {
	t.Helper()
	for k, v := range want {
		if got, ok := rec[k]; !ok || got != v {
			t.Errorf("record %s = %v, want %v (record %v)", k, got, v, rec)
		}
	}
}

func writeTestCER(t *testing.T, w io.Writer) {
	t.Helper()
	m := NewRequest(CapabilitiesExchange, 0, nil)
	if _, err := m.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("cli")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example.net")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.WriteTo(w); err != nil {
		t.Fatal(err)
	}
}

// panicsServing is a handler whose name the recorded stack must contain.
func panicsServing(Conn, *Message) { panic("handler boom") }

func TestServerLogsHandlerPanicWithStack(t *testing.T) {
	for _, tc := range []struct {
		name          string
		maxConcurrent int
	}{
		{"sequential", 0},
		{"concurrent", 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger, logs := newTestLogger(slog.LevelDebug)
			mux := NewServeMux()
			mux.HandleFunc("CER", panicsServing)
			srv := &Server{Handler: mux, Logger: logger, MaxConcurrentHandlers: tc.maxConcurrent}
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = srv.Close() }()
			go func() { _ = srv.Serve(l) }()
			cli, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cli.Close() }()
			writeTestCER(t, cli)

			rec := logs.wait(t, 1)[0]
			wantRecord(t, rec, map[string]any{
				"level":          "ERROR",
				"msg":            "diam: panic serving connection",
				logKeyPanic:      "handler boom",
				logKeyNetwork:    "tcp",
				logKeyLocalAddr:  l.Addr().String(),
				logKeyRemoteAddr: cli.LocalAddr().String(),
			})
			stack, _ := rec[logKeyStack].(string)
			if !strings.Contains(stack, "diam.panicsServing") || !strings.Contains(stack, "panic(") {
				t.Errorf("stack does not show the panicking handler:\n%s", stack)
			}
		})
	}
}

// scriptedListener returns the errors sent to errs from Accept, then
// net.ErrClosed once closed.
type scriptedListener struct {
	errs     chan error
	closed   chan struct{}
	once     sync.Once
	closeErr error
}

func newScriptedListener(closeErr error) *scriptedListener {
	return &scriptedListener{errs: make(chan error, 1), closed: make(chan struct{}), closeErr: closeErr}
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	select {
	case err := <-l.errs:
		return nil, err
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *scriptedListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return l.closeErr
}

func (l *scriptedListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3868}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "accept timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestServerLogsRetriedAcceptFailure(t *testing.T) {
	logger, logs := newTestLogger(slog.LevelDebug)
	srv := &Server{Logger: logger}
	l := newScriptedListener(nil)
	l.errs <- timeoutError{}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(l) }()

	rec := logs.wait(t, 1)[0]
	wantRecord(t, rec, map[string]any{
		"level":         "WARN",
		"msg":           "diam: accept failed; retrying",
		logKeyError:     "accept timed out",
		logKeyRetryIn:   float64(5 * time.Millisecond),
		logKeyNetwork:   "tcp",
		logKeyLocalAddr: "127.0.0.1:3868",
	})
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-served:
		if !errors.Is(err, ErrServerClosed) {
			t.Fatalf("Serve returned %v, want ErrServerClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after Close")
	}
}

func TestServerReturnsTerminalAcceptFailureWithoutLogging(t *testing.T) {
	logger, logs := newTestLogger(slog.LevelDebug)
	srv := &Server{Logger: logger}
	l := newScriptedListener(nil)
	acceptErr := errors.New("accept broken")
	l.errs <- acceptErr
	if err := srv.Serve(l); !errors.Is(err, acceptErr) {
		t.Fatalf("Serve returned %v, want %v", err, acceptErr)
	}
	if recs := logs.records(t); len(recs) != 0 {
		t.Fatalf("a returned accept error was logged as well: %v", recs)
	}
}

// closeErrConn fails every Close with err after closing the pipe it wraps.
type closeErrConn struct {
	net.Conn
	err error
}

func (c *closeErrConn) Close() error {
	_ = c.Conn.Close()
	return c.err
}

func TestConnLogsCloseFailureAtDebug(t *testing.T) {
	for _, tc := range []struct {
		name     string
		level    slog.Level
		closeErr error
		want     int
	}{
		{"failure", slog.LevelDebug, errors.New("close failed"), 2},
		{"below logger level", slog.LevelInfo, errors.New("close failed"), 0},
		{"already closed", slog.LevelDebug, fmt.Errorf("close pipe: %w", net.ErrClosed), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger, logs := newTestLogger(tc.level)
			local, remote := net.Pipe()
			defer func() { _ = remote.Close() }()
			srv := &Server{Handler: NewServeMux(), Logger: logger}
			c, err := srv.NewConn(&closeErrConn{Conn: local, err: tc.closeErr})
			if err != nil {
				t.Fatal(err)
			}
			// Both the caller's Close and the read loop's final Close fail.
			c.Close()
			select {
			case <-c.(interface{ DispatchDone() <-chan struct{} }).DispatchDone():
			case <-time.After(2 * time.Second):
				t.Fatal("read loop did not end after Close")
			}
			recs := logs.records(t)
			if len(recs) != tc.want {
				t.Fatalf("logged %d records, want %d: %v", len(recs), tc.want, recs)
			}
			for _, rec := range recs {
				wantRecord(t, rec, map[string]any{
					"level":          "DEBUG",
					"msg":            "diam: close connection",
					logKeyError:      "close failed",
					logKeyNetwork:    "pipe",
					logKeyRemoteAddr: "pipe",
				})
			}
		})
	}
}

// fakeMultistreamConn is a MultistreamConn over a pipe whose Close fails.
type fakeMultistreamConn struct {
	net.Conn
	closeErr error
	mu       sync.Mutex
	onError  MutistreamConnErrorHandler
}

func (c *fakeMultistreamConn) Close() error                          { _ = c.Conn.Close(); return c.closeErr }
func (c *fakeMultistreamConn) ReadAny([]byte) (int, uint, error)     { return 0, 0, io.EOF }
func (c *fakeMultistreamConn) ReadStream([]byte, uint) (int, error)  { return 0, io.EOF }
func (c *fakeMultistreamConn) CurrentStream() uint                   { return 0 }
func (c *fakeMultistreamConn) ResetCurrentStream()                   {}
func (c *fakeMultistreamConn) SetCurrentStream(uint) uint            { return 0 }
func (c *fakeMultistreamConn) WriteStream([]byte, uint) (int, error) { return 0, io.EOF }
func (c *fakeMultistreamConn) CurrentWriterStream() uint             { return 0 }
func (c *fakeMultistreamConn) ResetWriterStream()                    {}
func (c *fakeMultistreamConn) SetWriterStream(uint) uint             { return 0 }
func (c *fakeMultistreamConn) ReadAtLeast([]byte, int, uint) (int, uint, error) {
	return 0, 0, io.EOF
}
func (c *fakeMultistreamConn) SetErrorHandler(h MutistreamConnErrorHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onError = h
}

func TestMultistreamConnLogsCloseFailureAfterReadError(t *testing.T) {
	logger, logs := newTestLogger(slog.LevelDebug)
	local, remote := net.Pipe()
	defer func() { _ = remote.Close() }()
	msc := &fakeMultistreamConn{Conn: local, closeErr: errors.New("close failed")}
	srv := &Server{Logger: logger}
	c := srv.newConn(msc)
	gone := c.closeNotify()
	msc.mu.Lock()
	onError := msc.onError
	msc.mu.Unlock()
	if onError == nil {
		t.Fatal("closeNotify installed no multistream error handler")
	}
	onError(msc, io.ErrUnexpectedEOF)
	select {
	case <-gone:
	default:
		t.Fatal("CloseNotify channel still open after the read error")
	}
	recs := logs.records(t)
	if len(recs) != 1 {
		t.Fatalf("logged %d records, want 1: %v", len(recs), recs)
	}
	wantRecord(t, recs[0], map[string]any{
		"level":         "DEBUG",
		"msg":           "diam: close connection after read error",
		logKeyError:     "close failed",
		logKeyReadError: "unexpected EOF",
		logKeyNetwork:   "pipe",
	})
}

// setDefaultLogger makes l the slog default until the test ends.
// slog.SetDefault also points the log package at l's handler and clears its
// flags, and setting the previous default back does not undo that, so the
// log package's writer, flags and prefix are restored as well.
func setDefaultLogger(t *testing.T, l *slog.Logger) {
	t.Helper()
	previous := slog.Default()
	writer, flags, prefix := log.Writer(), log.Flags(), log.Prefix()
	t.Cleanup(func() {
		slog.SetDefault(previous)
		log.SetOutput(writer)
		log.SetFlags(flags)
		log.SetPrefix(prefix)
	})
	slog.SetDefault(l)
}

func TestSetDefaultLoggerRestoresLogPackage(t *testing.T) {
	writer, flags, prefix := log.Writer(), log.Flags(), log.Prefix()
	t.Run("set", func(t *testing.T) {
		logger, _ := newTestLogger(slog.LevelInfo)
		setDefaultLogger(t, logger)
		if log.Writer() == writer {
			t.Fatal("slog.SetDefault left the log package's writer alone; nothing to restore")
		}
	})
	if log.Writer() != writer || log.Flags() != flags || log.Prefix() != prefix {
		t.Fatalf("log package left at writer %T, flags %d, prefix %q; want %T, %d, %q",
			log.Writer(), log.Flags(), log.Prefix(), writer, flags, prefix)
	}
}

func TestServerNilLoggerUsesSlogDefault(t *testing.T) {
	// The Server exists before slog.SetDefault: the default is looked up
	// for every record, not when the Server is configured.
	srv := &Server{Handler: NewServeMux()}
	logger, logs := newTestLogger(slog.LevelDebug)
	setDefaultLogger(t, logger)

	local, remote := net.Pipe()
	defer func() { _ = remote.Close() }()
	c, err := srv.NewConn(&closeErrConn{Conn: local, err: errors.New("close failed")})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	<-c.(interface{ DispatchDone() <-chan struct{} }).DispatchDone()
	var found bool
	for _, rec := range logs.records(t) {
		if rec["msg"] == "diam: close connection" && rec[logKeyError] == "close failed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("slog.Default did not receive the close failure: %v", logs.records(t))
	}
}

func TestServerNewConnRejectsNilConn(t *testing.T) {
	if _, err := (&Server{}).NewConn(nil); !errors.Is(err, errNilConn) {
		t.Fatalf("NewConn(nil) = %v, want %v", err, errNilConn)
	}
	if _, err := NewConn(nil, "", nil, nil); !errors.Is(err, errNilConn) {
		t.Fatalf("diam.NewConn(nil) = %v, want %v", err, errNilConn)
	}
}

// serveUntilTracked runs srv.Serve(l) until Close and waits until the
// server tracks l.
func serveUntilTracked(t *testing.T, srv *Server, l net.Listener) <-chan error {
	t.Helper()
	served := make(chan error, 1)
	go func() { served <- srv.Serve(l) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		srv.mu.Lock()
		_, tracked := srv.listeners[l]
		srv.mu.Unlock()
		if tracked {
			return served
		}
		if time.Now().After(deadline) {
			t.Fatal("Serve did not track the listener")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestServerCloseReportsEveryListenerFailureOnce serves two listeners as
// ListenAndServe does, so that Server.Close is the first to close each.
func TestServerCloseReportsEveryListenerFailureOnce(t *testing.T) {
	errA := errors.New("listener A failed")
	errB := errors.New("listener B failed")
	a := &onceCloseListener{Listener: newScriptedListener(errA)}
	b := &onceCloseListener{Listener: newScriptedListener(errB)}
	srv := &Server{}
	servedA := serveUntilTracked(t, srv, a)
	servedB := serveUntilTracked(t, srv, b)

	closeErr := srv.Close()
	for _, want := range []error{errA, errB} {
		if !errors.Is(closeErr, want) {
			t.Errorf("Server.Close = %v: close failure lost: %v", closeErr, want)
		}
	}
	// ListenAndServe's own close of each listener adds nothing more.
	for _, s := range []struct {
		l      net.Listener
		served <-chan error
	}{{a, servedA}, {b, servedB}} {
		err := <-s.served
		closeOwnedListener(s.l, &err)
		if err != ErrServerClosed {
			t.Errorf("ListenAndServe would return %v, want only ErrServerClosed", err)
		}
	}
}

func TestCloseOwnedListenerReportsEachFailureOnce(t *testing.T) {
	closeErr := errors.New("listener close failed")

	// Serve ended on its own: the deferred close is the first and its
	// failure is joined to Serve's error.
	l := &onceCloseListener{Listener: newScriptedListener(closeErr)}
	serveErr := errors.New("accept broken")
	err := serveErr
	closeOwnedListener(l, &err)
	if !errors.Is(err, serveErr) || !errors.Is(err, closeErr) {
		t.Fatalf("joined error = %v, want both %v and %v", err, serveErr, closeErr)
	}

	// Server.Close closed the listener first and returned the failure; the
	// deferred close then reports net.ErrClosed and adds nothing.
	l = &onceCloseListener{Listener: newScriptedListener(closeErr)}
	srv := &Server{}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(l) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		srv.mu.Lock()
		tracked := len(srv.listeners) == 1
		srv.mu.Unlock()
		if tracked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Serve did not track the listener")
		}
		time.Sleep(time.Millisecond)
	}
	if err := srv.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("Server.Close = %v, want %v", err, closeErr)
	}
	err = <-served
	closeOwnedListener(l, &err)
	if err != ErrServerClosed {
		t.Fatalf("ListenAndServe would return %v, want only ErrServerClosed", err)
	}
	if again := l.Close(); !errors.Is(again, net.ErrClosed) {
		t.Fatalf("second Close = %v, want net.ErrClosed", again)
	}
}
