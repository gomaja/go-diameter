package diam

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestServeRetriesLinuxAcceptErrors(t *testing.T) {
	testRetryAcceptErrors(t, []error{syscall.ENETDOWN, syscall.EPROTO, syscall.ENOPROTOOPT, syscall.EHOSTDOWN, syscall.ENONET, syscall.EHOSTUNREACH, syscall.ENETUNREACH})
}

type releaseFDHandler struct {
	slog.Handler
	release func()
}

func (h releaseFDHandler) Handle(ctx context.Context, r slog.Record) error {
	err := h.Handler.Handle(ctx, r)
	if r.Level == slog.LevelWarn && r.Message == "diam: accept failed; retrying" {
		h.release()
	}
	return err
}

func TestServeRealEMFILE(t *testing.T) {
	if os.Getenv("DIAM_TEST_EMFILE_CHILD") != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, executable, "-test.run=^TestServeRealEMFILE$", "-test.v")
		cmd.Env = append(os.Environ(), "DIAM_TEST_EMFILE_CHILD=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("EMFILE subprocess: %v\n%s", err, output)
		}
		t.Logf("%s", output)
		return
	}
	// Only the subprocess changes its resource limit. Queue a real TCP connection
	// before filling the descriptor table, so the next accept must allocate an FD.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	var limit syscall.Rlimit
	if err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	old := limit
	if limit.Cur > 128 {
		limit.Cur = 128
	}
	if err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &old); err != nil {
			t.Error(err)
		}
	}()
	var fds []int
	release := func() {
		for _, fd := range fds {
			_ = syscall.Close(fd)
		}
		fds = nil
	}
	defer release()
	for {
		fd, err := syscall.Open("/dev/null", syscall.O_RDONLY, 0)
		if errors.Is(err, syscall.EMFILE) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		fds = append(fds, fd)
	}
	logger, logs := newTestLogger(slog.LevelDebug)
	accepted := make(chan struct{})
	srv := &Server{Logger: slog.New(releaseFDHandler{logger.Handler(), release})}
	srv.OnNewConnection = func(Conn) { close(accepted); _ = srv.Close() }
	defer func() { _ = srv.Close() }()
	if err = srv.Serve(l); !errors.Is(err, ErrServerClosed) {
		t.Fatalf("Serve stopped during FD exhaustion: %v", err)
	}
	select {
	case <-accepted:
	default:
		t.Fatal("connection never accepted after FDs released")
	}
	records := logs.records(t)
	if len(records) != 1 {
		t.Fatalf("got %d records, want one EMFILE retry", len(records))
	}
	wantRecord(t, records[0], map[string]any{"level": "WARN", "msg": "diam: accept failed; retrying", logKeyRetryIn: float64(5 * time.Millisecond)})
	var got error
	logs.Records()[0].Attrs(func(a slog.Attr) bool {
		if a.Key == logKeyError {
			got, _ = a.Value.Any().(error)
		}
		return true
	})
	if !errors.Is(got, syscall.EMFILE) {
		t.Fatalf("accept returned %v, want real EMFILE", got)
	}
}

// A datagram descriptor can pass net.FileListener's address checks, but accept
// cannot turn it into a connection-oriented listener by retrying.
func TestServeRejectsDatagramListener(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), "datagram")
	defer func() { _ = f.Close() }()
	l, err := net.FileListener(f)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	logger, logs := newTestLogger(slog.LevelDebug)
	srv := &Server{Logger: logger}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(l) }()
	select {
	case err := <-done:
		if !errors.Is(err, syscall.EOPNOTSUPP) {
			t.Fatalf("Serve = %v, want EOPNOTSUPP", err)
		}
	case <-time.After(200 * time.Millisecond):
		_ = srv.Close()
		<-done
		t.Fatal("Serve kept retrying a datagram listener's permanent EOPNOTSUPP")
	}
	if len(logs.records(t)) != 0 {
		t.Fatal("permanent accept error logged as a retry")
	}
}
