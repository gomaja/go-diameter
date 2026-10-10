package diam_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
)

func TestServerDialTLSContextHandshakeComplete(t *testing.T) {
	_, _, cert := newTestCertificateFiles(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	serverDone := make(chan error, 1)
	serverExit := make(chan struct{})
	go func() {
		defer close(serverExit)
		c, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer func() { _ = c.Close() }()
		config := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { close(entered); <-release; return nil, nil }}
		serverDone <- tls.Server(c, config).Handshake()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result := make(chan error, 1)
	dialExit := make(chan struct{})
	t.Cleanup(func() { cancel(); unblock(); _ = ln.Close(); <-dialExit; <-serverExit })
	go func() {
		defer close(dialExit)
		srv := &diam.Server{Network: "tcp", Addr: ln.Addr().String(), TLSConfig: &tls.Config{InsecureSkipVerify: true}} // #nosec G402 -- local test certificate
		c, err := srv.DialTLSContext(ctx, "", "")
		if c != nil {
			if state := c.Connection().(*tls.Conn).ConnectionState(); !state.HandshakeComplete {
				err = errors.New("TLS handshake incomplete on return")
			}
			c.Close()
		}
		result <- err
	}()
	select {
	case <-entered:
	case err := <-result:
		t.Fatalf("DialTLSContext returned before ClientHello: %v", err)
	case <-time.After(time.Second):
		t.Fatal("ClientHello did not arrive")
	}
	select {
	case err := <-result:
		t.Errorf("DialTLSContext returned before TLS peer was released: %v", err)
		unblock()
		<-serverDone
		return
	case <-time.After(20 * time.Millisecond):
	}
	unblock()
	select {
	case err := <-result:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(time.Second):
		t.Error("DialTLSContext did not finish handshake")
		cancel()
		<-result
	}
	if err := <-serverDone; err != nil {
		t.Error(err)
	}
}

func TestServerDialTLSContextCancellation(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = ln.Close() }()
			ctx, cancel := context.WithCancel(context.Background())
			if mode == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 200*time.Millisecond)
			}
			defer cancel()
			done := make(chan error, 1)
			go func() {
				srv := &diam.Server{Network: "tcp", Addr: ln.Addr().String()}
				c, err := srv.DialTLSContext(ctx, "", "")
				if c != nil {
					c.Close()
				}
				done <- err
			}()
			peer, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = peer.Close() }()
			if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			var b [1]byte
			if _, err := io.ReadFull(peer, b[:]); err != nil {
				t.Fatal(err)
			}
			want := error(context.Canceled)
			if mode == "cancel" {
				cancel()
			} else {
				<-ctx.Done()
				want = context.DeadlineExceeded
			}
			select {
			case err := <-done:
				if !errors.Is(err, want) {
					t.Errorf("TLS dial = %v, want %v", err, want)
				}
			case <-time.After(500 * time.Millisecond):
				t.Error("TLS handshake did not stop within 500ms of context completion")
				_ = peer.Close()
				<-done
			}
			// Drain the rest of ClientHello to observe transport closure.
			_, err = io.Copy(io.Discard, peer)
			if err != nil {
				t.Errorf("peer did not observe close: %v", err)
			}
		})
	}
}
