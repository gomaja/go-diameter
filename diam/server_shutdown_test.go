package diam

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/dict"
)

func shutdownTestServer(t *testing.T, srv *Server) (string, <-chan error) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close(); _ = l.Close() })
	return l.Addr().String(), done
}

func waitShutdownConns(t *testing.T, srv *Server) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		srv.mu.Lock()
		remaining := len(srv.conns)
		srv.mu.Unlock()
		if remaining == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("connection serve goroutine did not exit")
}

func TestServerShutdownDrainsInFlightHandler(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	answers := make(chan struct{}, 1)
	callback := make(chan struct{}, 1)
	srv := &Server{Handler: HandlerFunc(func(c Conn, m *Message) {
		close(entered)
		<-release
		if _, err := m.Answer(Success).WriteTo(c); err != nil {
			t.Errorf("write answer: %v", err)
		}
	})}
	srv.OnShutdownConnection = func(_ context.Context, c Conn) {
		select {
		case <-c.(CloseNotifier).CloseNotify():
			t.Error("connection closed before shutdown action")
		default:
		}
		callback <- struct{}{}
	}
	addr, serveDone := shutdownTestServer(t, srv)
	mux := NewServeMux()
	mux.HandleFunc("DWA", func(Conn, *Message) { answers <- struct{}{} })
	client, err := Dial(addr, mux, dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	request := NewRequest(DeviceWatchdog, 0, dict.Default)
	if _, err := request.WriteTo(client); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	done := make(chan error, 1)
	go func() { done <- srv.Shutdown(context.Background()) }()
	select {
	case err := <-serveDone:
		if !errors.Is(err, ErrServerClosed) {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("listener remained open")
	}
	if c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond); err == nil {
		_ = c.Close()
		t.Fatal("new connection accepted during shutdown")
	}
	select {
	case <-done:
		t.Fatal("Shutdown returned while handler was active")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	select {
	case <-answers:
	case <-time.After(time.Second):
		t.Fatal("in-flight answer was lost")
	}
	select {
	case <-callback:
	case <-time.After(time.Second):
		t.Fatal("shutdown action was not called")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Shutdown did not finish")
	}
	select {
	case <-client.(CloseNotifier).CloseNotify():
	case <-time.After(time.Second):
		t.Fatal("connection remained open")
	}
	waitShutdownConns(t, srv)
}

func TestServerShutdownClosesIdleConnection(t *testing.T) {
	accepted := make(chan struct{}, 1)
	srv := &Server{OnNewConnection: func(Conn) { accepted <- struct{}{} }}
	addr, serveDone := shutdownTestServer(t, srv)
	client, err := Dial(addr, NewServeMux(), dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("connection not accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.(CloseNotifier).CloseNotify():
	case <-time.After(time.Second):
		t.Fatal("idle connection remained open")
	}
	select {
	case err := <-serveDone:
		if !errors.Is(err, ErrServerClosed) {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not exit")
	}
	waitShutdownConns(t, srv)
}

func TestServerShutdownDeadlineForcesTransportClose(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	srv := &Server{Handler: HandlerFunc(func(Conn, *Message) {
		close(entered)
		<-release
	})}
	addr, serveDone := shutdownTestServer(t, srv)
	client, err := Dial(addr, NewServeMux(), dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := NewRequest(DeviceWatchdog, 0, dict.Default).WriteTo(client); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	if err := srv.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown returned %v, want deadline", err)
	}
	select {
	case <-client.(CloseNotifier).CloseNotify():
	case <-time.After(time.Second):
		t.Fatal("deadline did not force transport close")
	}
	close(release)
	waitShutdownConns(t, srv)
	select {
	case err := <-serveDone:
		if !errors.Is(err, ErrServerClosed) {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not exit")
	}
}

func TestServerShutdownWaitsForActionAfterPeerClose(t *testing.T) {
	accepted := make(chan struct{}, 1)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := &Server{OnNewConnection: func(Conn) { accepted <- struct{}{} }}
	srv.OnShutdownConnection = func(context.Context, Conn) {
		entered <- struct{}{}
		<-release
	}
	addr, _ := shutdownTestServer(t, srv)
	client, err := Dial(addr, NewServeMux(), dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("connection not accepted")
	}
	done := make(chan error, 1)
	go func() { done <- srv.Shutdown(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("shutdown action not entered")
	}
	client.Close()
	select {
	case <-done:
		t.Fatal("Shutdown returned before action completed")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Shutdown did not finish after action")
	}
	waitShutdownConns(t, srv)
}
