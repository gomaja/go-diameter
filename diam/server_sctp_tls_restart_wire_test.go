//go:build linux && !386 && sctptlsrestart

package diam

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-sctp"
)

// TestBuiltInSCTPTLSRestartWireServer exercises ListenAndServeTLS itself. The
// companion client runs in a separate privileged namespace; see
// testdata/sctptlsrestart/README.md. RFC 9260 §5.2.4 covers SCTP restart and
// RFC 9846 §6.2 covers failed TLS closure. Go 1.27.2's readRecordOrCCS caches
// non-temporary transport read errors, so that TLS reader cannot resume.
func TestBuiltInSCTPTLSRestartWireServer(t *testing.T) {
	addr := os.Getenv("SCTP_TLS_RESTART_SERVER_ADDR")
	if addr == "" {
		t.Skip("requires the two-container SCTP/TLS restart harness")
	}
	requireSCTP(t)
	cert := generationCertificate(t)
	var accepts, replacements atomic.Int32
	admitted := make(chan Conn, 1)
	h := &generationHandler{handle: func(c Conn, m *Message) {
		if _, err := m.Answer(Success).WriteTo(c); err != nil {
			t.Errorf("CEA: %v", err)
		}
		admitted <- c
	}}
	srv := &Server{Network: "sctp4", Addr: addr, Handler: h,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }},
		OnNewConnection: func(c Conn) {
			accepts.Add(1)
			tlsConn, ok := c.Connection().(*tls.Conn)
			if !ok {
				t.Errorf("built-in listener returned %T", c.Connection())
				return
			}
			t.Logf("TLS_UNDERLYING type=%T", tlsConn.NetConn())
		},
		OnConnectionRestart: func(Conn, Conn, RetirementReason) { replacements.Add(1) },
	}
	served := make(chan error, 1)
	go func() { served <- srv.ListenAndServeTLS("", "") }()
	t.Cleanup(func() {
		_ = srv.Close()
		select {
		case err := <-served:
			if err != nil && !errors.Is(err, ErrServerClosed) {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("built-in listener did not terminate")
		}
	})
	var old Conn
	select {
	case old = <-admitted:
	case err := <-served:
		t.Fatalf("built-in SCTP/TLS listener: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("real TLS CER/CEA did not finish")
	}
	if err := os.WriteFile("/tmp/sctp-tls-restart-admitted", []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	// No ReadTimeout is configured. The restarted peer sends no DATA, so a
	// lost association notification cannot be hidden by a TLS-record failure.
	select {
	case <-old.(CloseNotifier).CloseNotify():
	case <-time.After(5 * time.Second):
		t.Fatal("built-in SCTP/TLS swallowed restart notification; old connection remains open")
	}
	select {
	case <-old.(interface{ DispatchDone() <-chan struct{} }).DispatchDone():
	case <-time.After(2 * time.Second):
		t.Fatal("TLS restart did not complete old dispatch")
	}
	if n, err := old.Write([]byte("old session")); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("old TLS write escaped: n=%d err=%v", n, err)
	}
	if !old.Closed() || accepts.Load() != 1 || replacements.Load() != 0 {
		t.Fatalf("TLS restart state: closed=%v accepts=%d successors=%d", old.Closed(), accepts.Load(), replacements.Load())
	}
	t.Log("TLS_RESTART_CLOSED old_write_fenced=true physical_accepts=1 successors=0")
}

func TestBuiltInSCTPTLSRestartWireClient(t *testing.T) {
	testDict := newTestDictionary(dict.Base())

	addr, local, phase := os.Getenv("SCTP_TLS_RESTART_SERVER_ADDR"), os.Getenv("SCTP_TLS_RESTART_CLIENT_ADDR"), os.Getenv("SCTP_TLS_RESTART_PHASE")
	if addr == "" || local == "" || phase == "" {
		t.Skip("requires the two-container SCTP/TLS restart harness")
	}
	requireSCTP(t)
	ra, err := sctp.ResolveAddr("sctp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	la, err := sctp.ResolveAddr("sctp4", local)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cfg := &sctp.Config{NoDelay: new(true), InitMsg: sctp.InitMsg{OutStreams: 16, MaxInStreams: 16}}
	raw, err := cfg.Dial(ctx, "sctp4", la, ra)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	if phase == "restart" {
		// Only association establishment is sent. An old TLS session must be
		// rejected based on the actual restart notification, not new TLS DATA.
		t.Log("RESTART_ASSOCIATION_ESTABLISHED no_DATA=true")
		if err := raw.SetReadDeadline(time.Now().Add(7 * time.Second)); err != nil {
			t.Fatal(err)
		}
		_, err := raw.Read(make([]byte, 1))
		t.Logf("RESTART_PEER_READ result=%v", err)
		return
	}
	rc, err := raw.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var lingerErr error
	if err := rc.Control(func(fd uintptr) {
		lingerErr = syscall.SetsockoptLinger(int(fd), syscall.SOL_SOCKET, syscall.SO_LINGER, &syscall.Linger{Onoff: 1})
	}); err != nil {
		t.Fatal(err)
	}
	if lingerErr != nil {
		t.Fatal(lingerErr)
	}
	client := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) // #nosec G402 -- synthetic local certificate
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	m := generationCER(t)
	if _, err := m.WriteTo(client); err != nil {
		t.Fatal(err)
	}
	answer, err := ReadMessage(client, testDict)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Header.CommandCode != CapabilitiesExchange || answer.Header.CommandFlags&RequestFlag != 0 || answer.Header.HopByHopID != m.Header.HopByHopID || answer.Header.EndToEndID != m.Header.EndToEndID {
		t.Fatal("TLS CEA identifiers do not match")
	}
	t.Log("INITIAL_TLS_CER_CEA_COMPLETE SO_LINGER=0")
	if err := os.WriteFile("/tmp/sctp-tls-restart-client-ready", []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	select {}
}
