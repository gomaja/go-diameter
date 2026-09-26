//go:build linux

package diam

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-sctp"
)

func TestSCTPDialTimeout(t *testing.T) {
	for _, tc := range []struct {
		name   string
		dialer Dialer
	}{
		{"multistream", getMultistreamDialer("sctp", 120*time.Millisecond, nil)},
		{"single stream", getDialer("sctp", 120*time.Millisecond, nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			result := make(chan struct {
				conn net.Conn
				err  error
			}, 1)
			go func() {
				conn, err := tc.dialer.Dial("sctp", "192.0.2.1:3868")
				result <- struct {
					conn net.Conn
					err  error
				}{conn, err}
			}()
			var conn net.Conn
			var err error
			select {
			case r := <-result:
				conn, err = r.conn, r.err
			case <-time.After(620 * time.Millisecond):
				t.Fatal("SCTP connect exceeded timeout plus 500ms margin")
			}
			if conn != nil {
				_ = conn.Close()
				t.Skip("192.0.2.1 answered; the silent-peer timeout needs an OUTPUT blackhole")
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Skipf("192.0.2.1 did not remain silent (error %v); install an OUTPUT DROP rule", err)
			}
			if elapsed := time.Since(start); elapsed > 620*time.Millisecond {
				t.Fatalf("connect timed out after %s, want at most 620ms", elapsed)
			}
		})
	}
}

func TestResponseWriteStreamDeadline(t *testing.T) {
	listener, err := MultistreamListen("sctp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("SCTP unavailable: %v", err)
	}
	defer func() { _ = listener.Close() }()

	accepted := make(chan net.Conn, 1)
	go func() {
		peer, err := listener.Accept()
		if err == nil {
			accepted <- peer
		}
	}()
	client, err := getMultistreamDialer("sctp", time.Second, nil).Dial("sctp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.(*SCTPConn).Abort() }()
	var peer net.Conn
	select {
	case peer = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("listener did not accept")
	}
	defer func() { _ = peer.(*SCTPConn).Abort() }()
	if err := client.(*SCTPConn).SetWriteBuffer(4096); err != nil {
		t.Fatal(err)
	}
	if err := peer.(*SCTPConn).SetReadBuffer(4096); err != nil {
		t.Fatal(err)
	}

	w := &response{conn: &conn{server: &Server{WriteTimeout: 50 * time.Millisecond}, rwc: client}}
	payload := make([]byte, 1024)
	if _, err := w.WriteStream(payload, 2); err != nil {
		t.Fatal(err)
	}
	time.Sleep(75 * time.Millisecond)
	if _, err := w.WriteStream(payload, 2); err != nil {
		t.Fatalf("write deadline was not renewed: %v", err)
	}
	// The peer never reads. Repeated messages eventually exhaust the send
	// window, at which point the current write must obey its fresh deadline.
	result := make(chan error, 1)
	go func() {
		for i := 0; i < 100000; i++ {
			_, err := w.WriteStream(payload, 2)
			if err != nil {
				result <- err
				return
			}
		}
		result <- errors.New("100000 writes succeeded against a peer that stopped reading")
	}()
	select {
	case err := <-result:
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("write error = %v, want timeout", err)
		}
	case <-time.After(4 * time.Second):
		_ = client.(*SCTPConn).Abort()
		t.Fatal("WriteStream remained blocked after its write timeout")
	}
}

func TestSCTPWirePPID(t *testing.T) {
	for _, tc := range []struct {
		name   string
		multi  bool
		stream uint16
	}{
		{"plain Write on Listen", false, 0},
		{"response WriteStream", true, 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var listener net.Listener
			var err error
			if tc.multi {
				listener, err = MultistreamListen("sctp", "127.0.0.1:0")
			} else {
				listener, err = Listen("sctp", "127.0.0.1:0")
			}
			if err != nil {
				t.Skipf("SCTP unavailable: %v", err)
			}
			defer func() { _ = listener.Close() }()
			t.Logf("sender port %d", listener.Addr().(*sctp.Addr).Port)
			written := make(chan error, 1)
			go func() {
				peer, err := listener.Accept()
				if err != nil {
					written <- err
					return
				}
				defer func() { _ = peer.Close() }()
				if tc.multi {
					w := &response{conn: &conn{server: &Server{}, rwc: peer}}
					_, err = w.WriteStream([]byte("diam-stream-ppid-46"), uint(tc.stream))
				} else {
					_, err = peer.Write([]byte("diam-plain-ppid-46"))
				}
				written <- err
			}()
			client, err := sctp.Dial(context.Background(), "sctp", nil, listener.Addr().(*sctp.Addr))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = client.Abort() }()
			if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 64)
			n, info, err := client.RecvMsg(buf)
			if err != nil {
				t.Fatal(err)
			}
			if n == 0 || info.Rcv.PPID != DiameterPPID || info.Rcv.Stream != tc.stream {
				t.Fatalf("received %d bytes on stream %d with PPID %d", n, info.Rcv.Stream, info.Rcv.PPID)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
		})
	}
}
