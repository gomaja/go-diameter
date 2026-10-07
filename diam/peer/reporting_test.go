package peer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/sm"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

func TestManagerRejectsIgnoredSettingsHooks(t *testing.T) {
	for _, name := range []string{"OnCER", "OnCEA", "OnDWR", "OnDWA", "OnDPR", "OnHandshake"} {
		t.Run(name, func(t *testing.T) {
			cfg := Config{Settings: testSettings("local.example.net")}
			hook := diam.HandlerFunc(func(diam.Conn, *diam.Message) {})
			switch name {
			case "OnCER":
				cfg.Settings.OnCER = hook
			case "OnCEA":
				cfg.Settings.OnCEA = hook
			case "OnDWR":
				cfg.Settings.OnDWR = hook
			case "OnDWA":
				cfg.Settings.OnDWA = hook
			case "OnHandshake":
				cfg.Settings.OnHandshake = func(diam.Conn, *smpeer.Metadata) {}
			case "OnDPR":
				cfg.Settings.OnDPR = func(diam.Conn, sm.DisconnectCause) {}
			}
			m, err := New(cfg)
			if err == nil {
				closeManager(t, m, nil)
				t.Fatalf("Settings.%s was silently accepted", name)
			}
			if !strings.Contains(err.Error(), "Settings."+name) {
				t.Fatalf("error does not name ignored hook: %v", err)
			}
		})
	}
}

func TestManagerLogsEveryUnhandledMessage(t *testing.T) {
	const total = 1200
	for _, limit := range []int{0, -1} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			records := logtest.New()
			m, err := New(Config{Settings: testSettings("local.example.net"), Logger: records.Logger(), Limits: Limits{Events: 8192}})
			if err != nil {
				t.Fatal(err)
			}
			if err = m.AddPeer(PeerConfig{Host: "known.example.net"}); err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := &diam.Server{Dict: dict.Default, MaxConcurrentHandlers: limit}
			if err = m.BindServer(server); err != nil {
				t.Fatal(err)
			}
			go func() { _ = server.Serve(listener) }()
			defer closeManager(t, m, server)
			c, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			write(t, c, reviewCER(t))
			if code(t, read(t, c)) != diam.Success {
				t.Fatal("handshake failed")
			}
			for i := uint32(1); i <= total; i++ {
				req := diam.NewMessage(999, diam.RequestFlag, 0, i, i+total, dict.Default)
				write(t, c, req)
				ans := read(t, c)
				if code(t, ans) != diam.CommandUnsupported || ans.Header.CommandFlags&diam.ErrorFlag == 0 || ans.Header.CommandFlags&diam.RequestFlag != 0 || ans.Header.HopByHopID != i || ans.Header.EndToEndID != i+total {
					t.Fatalf("unmatched request answer: %+v", ans.Header)
				}
				write(t, c, req.Answer(diam.Success))
			}
			// DWA is a wire barrier after the final answer was admitted to the actor.
			write(t, c, reviewDWR(t))
			read(t, c)
			got := records.Records()
			if len(got) != 2*total {
				t.Fatalf("records=%d want %d", len(got), 2*total)
			}
			counts := make(map[string]int)
			for _, r := range got {
				if r.Level != slog.LevelWarn {
					t.Fatalf("level=%s", r.Level)
				}
				hop := logtest.Attr(r, "message.hop_by_hop_id").Uint64()
				counts[fmt.Sprint(hop, "/", logtest.Attr(r, "message.request").Bool())]++
				if logtest.Attr(r, "peer_host").String() != "known.example.net" || logtest.Attr(r, "remote_addr").String() != c.LocalAddr().String() || logtest.Attr(r, "error").Any() == nil {
					t.Fatalf("missing report attributes: %v", r)
				}
			}
			for i := 1; i <= total; i++ {
				for _, request := range []bool{true, false} {
					if n := counts[fmt.Sprint(i, "/", request)]; n != 1 {
						t.Fatalf("hop %d request %v count %d", i, request, n)
					}
				}
			}
		})
	}
}

type blockingReportHandler struct {
	*logtest.Recorder
	entered, release chan struct{}
	once             sync.Once
}

func (h *blockingReportHandler) Handle(ctx context.Context, r slog.Record) error {
	h.once.Do(func() { close(h.entered) })
	<-h.release
	return h.Recorder.Handle(ctx, r)
}
func TestManagerRecordsAreSynchronous(t *testing.T) {
	h := &blockingReportHandler{Recorder: logtest.New(), entered: make(chan struct{}), release: make(chan struct{})}
	m, err := New(Config{Settings: testSettings("local.example.net"), Logger: slog.New(h)})
	if err != nil {
		t.Fatal(err)
	}
	defer closeManager(t, m, nil)
	returned := make(chan struct{})
	failure := &diam.MessageError{ResultCode: diam.InvalidAVPLength}
	go func() { m.report(nil, diam.NewRequest(999, 0, dict.Default), failure); close(returned) }()
	select {
	case <-h.entered:
	case <-time.After(time.Second):
		t.Fatal("report did not call logger")
	}
	select {
	case <-returned:
		t.Fatal("report returned while logger was blocked")
	default:
	}
	close(h.release)
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("report did not complete")
	}
	got := h.Records()
	var retained *diam.MessageError
	if len(got) != 1 || !errors.As(logtest.Attr(got[0], "error").Any().(error), &retained) || retained != failure {
		t.Fatalf("original error lost: %v", got)
	}
}
func TestManagerLogsEventQueueOverflow(t *testing.T) {
	records := logtest.New()
	// No consumer: every overflow must be recorded synchronously.
	m := &Manager{cfg: Config{Logger: records.Logger()}, callbackQ: make(chan PeerEvent, 1)}
	reason := errors.New("event reason")
	m.notify(PeerEvent{})
	for range 1200 {
		m.notify(PeerEvent{Peer: PeerSnapshot{Host: "peer.example.net"}, Reason: reason})
	}
	got := records.Records()
	if len(got) != 1200 {
		t.Fatalf("overflow records=%d", len(got))
	}
	for _, r := range got {
		if r.Level != slog.LevelWarn || r.Message != "peer: event queue full; event dropped" || logtest.Attr(r, "peer_host").String() != "peer.example.net" || logtest.Attr(r, "error").Any() != reason {
			t.Fatalf("overflow record: %v", r)
		}
	}
}

func TestManagerLogsBeforeClosingWaitICEA(t *testing.T) {
	records := logtest.New()
	m, err := New(Config{Settings: testSettings("local.example.net"), Logger: records.Logger()})
	if err != nil {
		t.Fatal(err)
	}
	defer closeManager(t, m, nil)
	c := &reviewWireConn{newFakeConn()}
	defer c.Close()
	defer func() { _ = c.other.Close() }()
	s := &session{m: m, c: c, gen: 1, writes: make(chan writeRequest, 8), closed: make(chan struct{})}
	a := &actor{m: m, cfg: PeerConfig{Host: "known.example.net", NoAutoReconnect: true}, state: WaitICEA, i: s, events: make(chan event, 8)}
	if err = c.other.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	a.onWire(event{kind: wireEvent, s: s, msg: reviewDWR(t)})
	var b [1]byte
	if _, err = c.other.Read(b[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF: %v", err)
	}
	got := records.Records()
	if len(got) != 1 || !strings.Contains(logtest.Attr(got[0], "error").Any().(error).Error(), "non-CEA before handshake") {
		t.Fatalf("close decision missing at EOF: %v", got)
	}
}

func TestManagerConnLoggerOwnership(t *testing.T) {
	for _, mode := range []string{"dialed", "bound", "nil-dialed", "nil-bound"} {
		t.Run(mode, func(t *testing.T) {
			configured, serverRecords, defaults, later := logtest.New(), logtest.New(), logtest.New(), logtest.New()
			previous := slog.Default()
			slog.SetDefault(defaults.Logger())
			defer slog.SetDefault(previous)
			cfg := Config{Settings: testSettings("local.example.net"), Logger: configured.Logger()}
			if strings.HasPrefix(mode, "nil") {
				cfg.Logger = nil
			}
			var other net.Conn
			cfg.Dial = func(context.Context, Endpoint) (net.Conn, error) {
				local, remote := net.Pipe()
				other = remote
				return local, nil
			}
			m, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer closeManager(t, m, nil)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			var c diam.Conn
			var s *session
			expected := configured
			if strings.HasSuffix(mode, "dialed") {
				s, err = m.dialEndpoint(ctx, Endpoint{Network: "tcp", Address: "peer.example.net:3868"}, nil, 1)
				if err != nil {
					t.Fatal(err)
				}
				c = s.c
			} else {
				ready := make(chan diam.Conn, 1)
				srv := &diam.Server{Logger: serverRecords.Logger(), OnNewConnection: func(c diam.Conn) { ready <- c }}
				if strings.HasPrefix(mode, "nil") {
					srv.Logger = nil
				}
				if err = m.BindServer(srv); err != nil {
					t.Fatal(err)
				}
				local, remote := net.Pipe()
				other = remote
				c, err = srv.NewConn(local)
				if err != nil {
					t.Fatal(err)
				}
				<-ready
				expected = serverRecords
			}
			defer c.Close()
			defer func() { _ = other.Close() }()
			// Resolution occurs at each Logger call, not at construction.
			slog.SetDefault(later.Logger())
			if strings.HasPrefix(mode, "nil") {
				expected = later
			}
			c.Logger().Warn("connection marker")
			got := expected.RecordsWithMessage("connection marker")
			if len(got) != 1 || got[0].Message != "connection marker" {
				t.Fatalf("wrong logger ownership: %v", got)
			}
			for _, key := range []string{"network", "local_addr", "remote_addr"} {
				if !logtest.HasAttr(got[0], key) {
					t.Fatalf("missing %s", key)
				}
			}
			for _, recorder := range []*logtest.Recorder{configured, serverRecords, defaults, later} {
				if recorder != expected && len(recorder.RecordsWithMessage("connection marker")) != 0 {
					t.Fatalf("marker leaked to another logger: %v", recorder.RecordsWithMessage("connection marker"))
				}
			}
		})
	}
}

func TestManagerMessageErrorAdmissionFailures(t *testing.T) {
	for _, managed := range []bool{false, true} {
		t.Run(fmt.Sprint(managed), func(t *testing.T) {
			records := logtest.New()
			m, err := New(Config{Settings: testSettings("local.example.net"), Logger: records.Logger()})
			if err != nil {
				t.Fatal(err)
			}
			defer closeManager(t, m, nil)
			c := newFakeConn()
			defer c.Close()
			if managed {
				s := &session{m: m, c: c, ingress: make(chan incoming, 1), closed: make(chan struct{})}
				s.ingress <- incoming{}
				m.sessions[c] = s
			}
			msg := diam.NewRequest(999, 0, dict.Default)
			err = m.HandleMessageError(c, msg, &diam.MessageError{ResultCode: diam.InvalidAVPLength})
			if !managed {
				if !errors.Is(err, errors.ErrUnsupported) {
					t.Fatalf("unmanaged error=%v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("closed managed connection was not handled: %v", err)
			}
			select {
			case <-c.CloseNotify():
			default:
				t.Fatal("full ingress connection remained open")
			}
			got := records.Records()
			if len(got) != 1 || !errors.Is(logtest.Attr(got[0], "error").Any().(error), errQueueFull) {
				t.Fatalf("queue closure unreported: %v", got)
			}
		})
	}
}

func TestManagerMessageErrorAdmissionFailureOwnsServerClose(t *testing.T) {
	records := logtest.New()
	m, err := New(Config{Settings: testSettings("local.example.net"), Logger: records.Logger()})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		closeManager(t, m, nil)
		t.Fatal(err)
	}
	ready := make(chan diam.Conn, 1)
	srv := &diam.Server{Dict: dict.Default, Handler: m, Logger: records.Logger(), OnNewConnection: func(c diam.Conn) {
		// A full queue with no consumer makes admission failure deterministic.
		s := &session{m: m, c: c, ingress: make(chan incoming, 1), closed: make(chan struct{})}
		s.ingress <- incoming{}
		m.mu.Lock()
		m.sessions[c] = s
		m.mu.Unlock()
		ready <- c
	}}
	go func() { _ = srv.Serve(listener) }()
	defer closeManager(t, m, srv)
	remote, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = remote.Close() }()
	c := <-ready
	// A complete frame with a one-byte Unsigned32 is recoverably malformed.
	msg := diam.NewRequest(diam.DeviceWatchdog, 0, dict.Default)
	msg.AddAVP(diam.NewAVP(avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(1)))
	wire, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	wire[25], wire[26], wire[27] = 0, 0, 9
	if _, err = remote.Write(wire); err != nil {
		t.Fatal(err)
	}
	if err = remote.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err = remote.Read(b[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("connection was not closed: %v", err)
	}
	done, ok := diam.ConnAs[interface{ DispatchDone() <-chan struct{} }](c)
	if !ok {
		t.Fatal("Server connection has no dispatch completion barrier")
	}
	select {
	case <-done.DispatchDone():
	case <-time.After(time.Second):
		t.Fatal("Server did not finish handling the malformed message")
	}
	got := records.Records()
	if len(got) != 2 {
		t.Fatalf("records=%d want malformed Warn and one local Error: %v", len(got), got)
	}
	if got[0].Level != slog.LevelWarn || got[0].Message != "diam: malformed message" {
		t.Errorf("initial record=%v", got[0])
	}
	if got[1].Level != slog.LevelError || got[1].Message != "peer: ingress failed; closing connection" || !errors.Is(logtest.Attr(got[1], "error").Any().(error), errQueueFull) {
		t.Errorf("close record=%v", got[1])
	}
}
