package sm

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

type blockingDisconnectConn struct {
	mu     sync.Once
	closed chan struct{}
}

func (c *blockingDisconnectConn) Write([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}
func (c *blockingDisconnectConn) WriteStream(b []byte, _ uint) (int, error) { return c.Write(b) }
func (c *blockingDisconnectConn) Close()                                    { c.mu.Do(func() { close(c.closed) }) }
func (c *blockingDisconnectConn) CloseNotify() <-chan struct{}              { return c.closed }
func (c *blockingDisconnectConn) LocalAddr() net.Addr                       { return nil }
func (c *blockingDisconnectConn) RemoteAddr() net.Addr                      { return nil }
func (c *blockingDisconnectConn) TLS() *tls.ConnectionState                 { return nil }
func (c *blockingDisconnectConn) Dictionary() *dict.Parser                  { return dict.Default }
func (c *blockingDisconnectConn) Context() context.Context {
	return smpeer.NewContext(context.Background(), &smpeer.Metadata{})
}
func (c *blockingDisconnectConn) SetContext(context.Context) {}
func (c *blockingDisconnectConn) Connection() net.Conn       { return nil }

func TestDisconnectTimeoutBoundsBlockedWrite(t *testing.T) {
	sm := New(serverSettings)
	c := &blockingDisconnectConn{closed: make(chan struct{})}
	result := make(chan error, 1)
	go func() { result <- sm.Disconnect(c, DisconnectBusy, 40*time.Millisecond) }()
	select {
	case err := <-result:
		if err != ErrDisconnectTimeout {
			t.Fatalf("blocked write returned %v, want timeout", err)
		}
	case <-time.After(250 * time.Millisecond):
		c.Close()
		t.Fatal("blocked DPR write exceeded timeout")
	}
}

func addDPAIdentity(t *testing.T, m *diam.Message, code string, value datatype.DiameterIdentity) {
	t.Helper()
	if _, err := m.NewAVP(code, 0, 0, value); err != nil {
		t.Errorf("add %s: %v", code, err)
	}
}

func writeTestDPA(t *testing.T, m *diam.Message, c diam.Conn) {
	t.Helper()
	if _, err := m.WriteTo(c); err != nil {
		t.Errorf("write DPA: %v", err)
	}
}

func TestDisconnectReceivesDPAAndCloses(t *testing.T) {
	sm := New(serverSettings)
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	received := make(chan *diam.Message, 1)
	client := dialHandshakeForDPR(t, "DPR", diam.HandlerFunc(func(c diam.Conn, m *diam.Message) {
		received <- m
		answer := m.Answer(diam.Success)
		addDPAIdentity(t, answer, "Origin-Host", clientSettings.OriginHost)
		addDPAIdentity(t, answer, "Origin-Realm", clientSettings.OriginRealm)
		writeTestDPA(t, answer, c)
	}), srv.Addr)
	peer := <-sm.HandshakeNotify()
	result := make(chan error, 1)
	go func() { result <- sm.Disconnect(peer, DisconnectBusy, time.Second) }()
	select {
	case m := <-received:
		if _, err := validateDPR(m); err != nil {
			t.Fatalf("outbound DPR invalid: %v", err)
		}
		if err := m.Validate(); err != nil {
			t.Fatalf("outbound DPR violates dictionary: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("no DPR")
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Disconnect did not finish after DPA")
	}
	select {
	case <-client.(diam.CloseNotifier).CloseNotify():
	case <-time.After(time.Second):
		t.Fatal("transport remained open after DPA")
	}
}

func TestDisconnectTimesOutAndCloses(t *testing.T) {
	sm := New(serverSettings)
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	received := make(chan struct{}, 1)
	client := dialHandshakeForDPR(t, "DPR", diam.HandlerFunc(func(_ diam.Conn, _ *diam.Message) { received <- struct{}{} }), srv.Addr)
	peer := <-sm.HandshakeNotify()
	start := time.Now()
	result := make(chan error, 1)
	go func() { result <- sm.Disconnect(peer, DisconnectRebooting, 80*time.Millisecond) }()
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("no DPR")
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("timeout returned nil")
		}
		if time.Since(start) < 70*time.Millisecond {
			t.Fatal("closed before timeout")
		}
	case <-time.After(time.Second):
		t.Fatal("Disconnect did not time out")
	}
	select {
	case <-client.(diam.CloseNotifier).CloseNotify():
	case <-time.After(time.Second):
		t.Fatal("transport remained open after timeout")
	}
}

func TestDisconnectClosedConnectionReturnsError(t *testing.T) {
	sm := New(serverSettings)
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	client := dialHandshakeForDPR(t, "", nil, srv.Addr)
	peer := <-sm.HandshakeNotify()
	client.Close()
	select {
	case <-peer.(diam.CloseNotifier).CloseNotify():
	case <-time.After(time.Second):
		t.Fatal("server did not observe transport closure")
	}
	if err := sm.Disconnect(peer, DisconnectBusy, time.Second); err == nil {
		t.Fatal("Disconnect on closed connection returned nil")
	}
}

func TestDisconnectIgnoresWrongHopID(t *testing.T) {
	sm := New(serverSettings)
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	received := make(chan struct{}, 1)
	client := dialHandshakeForDPR(t, "DPR", diam.HandlerFunc(func(c diam.Conn, m *diam.Message) {
		answer := m.Answer(diam.Success)
		answer.Header.HopByHopID++
		addDPAIdentity(t, answer, "Origin-Host", clientSettings.OriginHost)
		addDPAIdentity(t, answer, "Origin-Realm", clientSettings.OriginRealm)
		writeTestDPA(t, answer, c)
		received <- struct{}{}
	}), srv.Addr)
	peer := <-sm.HandshakeNotify()
	result := make(chan error, 1)
	go func() { result <- sm.Disconnect(peer, DisconnectBusy, 80*time.Millisecond) }()
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("no DPR")
	}
	select {
	case err := <-result:
		if err != ErrDisconnectTimeout {
			t.Fatalf("wrong-hop DPA ended disconnect: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("no timeout after wrong-hop DPA")
	}
	select {
	case <-client.(diam.CloseNotifier).CloseNotify():
	case <-time.After(time.Second):
		t.Fatal("transport remained open after timeout")
	}
}

func TestDisconnectRejectsMalformedDPA(t *testing.T) {
	sm := New(serverSettings)
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	received := make(chan struct{}, 1)
	client := dialHandshakeForDPR(t, "DPR", diam.HandlerFunc(func(c diam.Conn, m *diam.Message) {
		answer := m.Answer(diam.Success)
		addDPAIdentity(t, answer, "Origin-Realm", clientSettings.OriginRealm)
		writeTestDPA(t, answer, c)
		received <- struct{}{}
	}), srv.Addr)
	peer := <-sm.HandshakeNotify()
	result := make(chan error, 1)
	go func() { result <- sm.Disconnect(peer, DisconnectBusy, 80*time.Millisecond) }()
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("no DPR")
	}
	select {
	case err := <-result:
		if err != ErrDisconnectTimeout {
			t.Fatalf("malformed DPA ended disconnect: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("no timeout after malformed DPA")
	}
	select {
	case <-client.(diam.CloseNotifier).CloseNotify():
	case <-time.After(time.Second):
		t.Fatal("transport remained open after timeout")
	}
}

func TestDisconnectIgnoresDPAOnAnotherConnection(t *testing.T) {
	sm := New(serverSettings)
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	received := make(chan struct{}, 1)
	var other diam.Conn
	first := dialHandshakeForDPR(t, "DPR", diam.HandlerFunc(func(_ diam.Conn, m *diam.Message) {
		answer := m.Answer(diam.Success)
		addDPAIdentity(t, answer, "Origin-Host", clientSettings.OriginHost)
		addDPAIdentity(t, answer, "Origin-Realm", clientSettings.OriginRealm)
		writeTestDPA(t, answer, other)
		received <- struct{}{}
	}), srv.Addr)
	peer := <-sm.HandshakeNotify()
	other = dialHandshakeForDPR(t, "", nil, srv.Addr)
	<-sm.HandshakeNotify()
	result := make(chan error, 1)
	go func() { result <- sm.Disconnect(peer, DisconnectBusy, 80*time.Millisecond) }()
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("no DPR")
	}
	select {
	case err := <-result:
		if err != ErrDisconnectTimeout {
			t.Fatalf("other connection's DPA ended disconnect: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("no timeout after other connection's DPA")
	}
	select {
	case <-first.(diam.CloseNotifier).CloseNotify():
	case <-time.After(time.Second):
		t.Fatal("first transport remained open after timeout")
	}
}
