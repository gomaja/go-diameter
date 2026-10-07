package diam

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

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

func reportingTCPServer(t *testing.T, srv *Server) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(listener) }()
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	})
	return listener.Addr().String()
}

func reportingDial(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestServeMuxLogsEveryUnhandledMessage(t *testing.T) {
	for _, limit := range []int{0, -1} {
		t.Run(fmt.Sprintf("concurrency_%d", limit), func(t *testing.T) {
			const count = 5000
			const idle = 30 * time.Second
			ctx := t.Context()
			if deadline, ok := t.Deadline(); ok {
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, deadline)
				defer cancel()
			}
			records := logtest.New()
			accepted := make(chan Conn, 4)
			srv := &Server{Handler: NewServeMux(), Dict: dict.Default, Logger: records.Logger(), MaxConcurrentHandlers: limit, OnNewConnection: func(c Conn) { accepted <- c }}
			addr := reportingTCPServer(t, srv)
			conns := make([]net.Conn, 4)
			for i := range conns {
				conns[i] = reportingDial(t, addr)
			}
			var wg sync.WaitGroup
			for index, c := range conns {
				wg.Go(func() {
					for id := index + 1; id <= count; id += len(conns) {
						if err := c.SetDeadline(logtest.Deadline(ctx, idle)); err != nil {
							t.Error(err)
							return
						}
						m := NewRequest(CapabilitiesExchange, 0, dict.Default)
						m.Header.HopByHopID = uint32(id)
						m.Header.EndToEndID = uint32(id + count)
						if _, err := m.WriteTo(c); err != nil {
							t.Errorf("write %d: %v", id, err)
							return
						}
					}
				})
			}
			wg.Wait()
			got, err := records.WaitProgress(ctx, count, idle)
			if err != nil {
				t.Fatalf("records=%d, want %d: %v", len(got), count, err)
			}
			// Join the read loops and dispatch workers before asserting the exact
			// final count, so a late duplicate cannot hide behind Wait's threshold.
			for _, c := range conns {
				if err := c.Close(); err != nil {
					t.Fatal(err)
				}
			}
			for range conns {
				select {
				case c := <-accepted:
					select {
					case <-mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, c).DispatchDone():
					case <-ctx.Done():
						t.Fatal("dispatch did not finish")
					}
				case <-ctx.Done():
					t.Fatal("connection was not accepted")
				}
			}
			got = records.Records()
			if len(got) != count {
				t.Fatalf("records=%d, want %d", len(got), count)
			}
			seen := make(map[uint64]bool, count)
			for _, record := range got {
				if record.Level != slog.LevelWarn || record.Message != "diam: unhandled message" {
					t.Fatalf("unexpected record: %+v", record)
				}
				id := logtest.Attr(record, "message.hop_by_hop_id").Uint64()
				if id < 1 || id > count || seen[id] {
					t.Fatalf("invalid or duplicate hop-by-hop ID %d", id)
				}
				seen[id] = true
				if logtest.Attr(record, "message.end_to_end_id").Uint64() != id+count {
					t.Fatal("end-to-end ID lost")
				}
				for _, key := range []string{"network", "local_addr", "remote_addr"} {
					if logtest.Attr(record, key).String() == "" {
						t.Errorf("missing %s", key)
					}
				}
			}
		})
	}
}

type blockingRecordHandler struct {
	*logtest.Recorder
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (h *blockingRecordHandler) Handle(ctx context.Context, r slog.Record) error {
	h.once.Do(func() { close(h.entered) })
	<-h.release
	return h.Recorder.Handle(ctx, r)
}

// WithAttrs must retain the blocking behavior when Conn.Logger binds addresses.
func (h *blockingRecordHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &blockingDerivedHandler{Handler: h.Recorder.WithAttrs(attrs), owner: h}
}
func (h *blockingRecordHandler) WithGroup(name string) slog.Handler {
	return &blockingDerivedHandler{Handler: h.Recorder.WithGroup(name), owner: h}
}

type blockingDerivedHandler struct {
	slog.Handler
	owner *blockingRecordHandler
}

func (h *blockingDerivedHandler) Handle(ctx context.Context, r slog.Record) error {
	h.owner.once.Do(func() { close(h.owner.entered) })
	<-h.owner.release
	return h.Handler.Handle(ctx, r)
}
func (h *blockingDerivedHandler) WithAttrs(a []slog.Attr) slog.Handler {
	return &blockingDerivedHandler{Handler: h.Handler.WithAttrs(a), owner: h.owner}
}
func (h *blockingDerivedHandler) WithGroup(g string) slog.Handler {
	return &blockingDerivedHandler{Handler: h.Handler.WithGroup(g), owner: h.owner}
}

func TestRecordsAreSynchronous(t *testing.T) {
	logs := &blockingRecordHandler{Recorder: logtest.New(), entered: make(chan struct{}), release: make(chan struct{})}
	defer func() {
		select {
		case <-logs.release:
		default:
			close(logs.release)
		}
	}()
	next := make(chan struct{})
	mux := NewServeMux()
	mux.HandleFunc("DWR", func(Conn, *Message) { close(next) })
	addr := reportingTCPServer(t, &Server{Handler: mux, Dict: dict.Default, Logger: slog.New(logs)})
	c := reportingDial(t, addr)
	first, _ := NewRequest(CapabilitiesExchange, 0, dict.Default).Serialize()
	second, _ := NewRequest(DeviceWatchdog, 0, dict.Default).Serialize()
	if _, err := c.Write(append(first, second...)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-logs.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("record handler not called")
	}
	select {
	case <-next:
		t.Fatal("next message dispatched while log handler blocked")
	case <-time.After(50 * time.Millisecond):
	}
	close(logs.release)
	select {
	case <-next:
	case <-time.After(5 * time.Second):
		t.Fatal("next message not dispatched after log handler returned")
	}
}

func TestMessageLogValueContainsOnlyHeader(t *testing.T) {
	const secret = "subscriber-secret-that-must-never-be-logged"
	m := NewRequest(CapabilitiesExchange, 0, dict.Default)
	m.Header.HopByHopID = 42
	m.Header.EndToEndID = 84
	m.AddAVP(NewAVP(avp.UserName, avp.Mbit, 0, datatype.UTF8String(secret)))
	records := logtest.New()
	records.Logger().Info("message", slog.Any("message", m))
	r := records.Records()[0]
	group := logtest.Attr(r, "message")
	if group.Kind() != slog.KindGroup {
		t.Fatalf("message kind=%s", group.Kind())
	}
	want := map[string]bool{"command": true, "application_id": true, "command_code": true, "request": true, "hop_by_hop_id": true, "end_to_end_id": true}
	for _, a := range group.Group() {
		if !want[a.Key] {
			t.Fatalf("unexpected message attr %s", a.Key)
		}
		delete(want, a.Key)
	}
	if len(want) != 0 {
		t.Fatalf("missing header attrs %v", want)
	}
	if logtest.Attr(r, "message.command").String() != "CER" || logtest.Attr(r, "message.command_code").Uint64() != CapabilitiesExchange || !logtest.Attr(r, "message.request").Bool() || logtest.Attr(r, "message.hop_by_hop_id").Uint64() != 42 || logtest.Attr(r, "message.end_to_end_id").Uint64() != 84 {
		t.Fatalf("wrong header metadata: %v", group)
	}
	if strings.Contains(fmt.Sprint(group), secret) {
		t.Fatal("log contains AVP value")
	}
}

type responsibilityHandler struct {
	records *logtest.Recorder
	result  error
	called  chan bool
}

func (*responsibilityHandler) ServeDIAM(Conn, *Message) {}
func (h *responsibilityHandler) HandleMessageError(_ Conn, _ *Message, _ *MessageError) error {
	records := h.records.Records()
	h.called <- len(records) == 1 && records[0].Message == "diam: malformed message"
	return h.result
}

func TestServerLogsBeforeClosing(t *testing.T) {
	for _, tc := range []struct {
		name      string
		result    error
		fatal     bool
		noHandler bool
		level     slog.Level
	}{
		{name: "unsupported", result: fmt.Errorf("declined: %w", errors.ErrUnsupported), level: slog.LevelWarn},
		{name: "failed", result: errors.New("answer unavailable"), level: slog.LevelError},
		{name: "fatal", fatal: true, level: slog.LevelWarn},
		{name: "missing handler", noHandler: true, level: slog.LevelWarn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records := logtest.New()
			target := &responsibilityHandler{records: records, result: tc.result, called: make(chan bool, 1)}
			var handler Handler = target
			if tc.noHandler {
				handler = HandlerFunc(func(Conn, *Message) {})
			}
			addr := reportingTCPServer(t, &Server{Handler: handler, Logger: records.Logger(), Dict: dict.Default})
			remote := reportingDial(t, addr)
			malformed := testFramedMessage(t, RequestFlag, []byte{0, 0, 1, 2, avp.Mbit, 0xff, 0xff, 0xff})
			if tc.fatal {
				malformed = testMessageHeader(2, HeaderLength, RequestFlag)
			}
			if _, err := remote.Write(malformed); err != nil {
				t.Fatal(err)
			}
			var b [1]byte
			if _, err := remote.Read(b[:]); !errors.Is(err, io.EOF) {
				t.Fatalf("read=%v, want EOF", err)
			}
			// The peer has seen EOF: no Wait is permitted for the closing record.
			got := records.Records()
			if len(got) != 2 {
				t.Fatalf("records already present at EOF=%d, want 2", len(got))
			}
			if got[0].Level != slog.LevelWarn || got[0].Message != "diam: malformed message" {
				t.Fatalf("read record=%+v", got[0])
			}
			if got[1].Level != tc.level || !strings.Contains(got[1].Message, "closing connection") {
				t.Fatalf("close record=%+v", got[1])
			}
			var malformedErr *MessageError
			if !errors.As(logtest.Attr(got[0], "error").Any().(error), &malformedErr) {
				t.Fatal("read record lost MessageError")
			}
			if logtest.Attr(got[0], "result_code").Uint64() != uint64(malformedErr.ResultCode) || logtest.Attr(got[0], "fatal").Bool() != tc.fatal {
				t.Fatal("malformed attrs disagree with error")
			}
			for _, r := range got {
				if logtest.HasAttr(r, "handled") {
					t.Fatal("record contains obsolete handled attribute")
				}
			}
			if tc.result != nil && !errors.Is(logtest.Attr(got[1], "error").Any().(error), tc.result) {
				t.Fatal("close record lost handler error")
			}
			if !tc.noHandler {
				select {
				case before := <-target.called:
					if !before {
						t.Fatal("initial malformed record was not written before calling handler")
					}
				default:
					t.Fatal("handler was not called")
				}
			}
		})
	}
}

func TestConnLoggerAcceptedAndLateDefault(t *testing.T) {
	for _, useDefault := range []bool{false, true} {
		t.Run(fmt.Sprintf("default_%t", useDefault), func(t *testing.T) {
			records := logtest.New()
			var configured *slog.Logger
			if !useDefault {
				configured = records.Logger()
			}
			handled := make(chan Conn, 1)
			srv := &Server{Logger: configured, Dict: dict.Default, Handler: HandlerFunc(func(c Conn, m *Message) { c.Logger().InfoContext(m.Context(), "connection marker"); handled <- c })}
			// Resolve a nil Server.Logger at use, after construction and Serve start.
			addr := reportingTCPServer(t, srv)
			if useDefault {
				previous := slog.Default()
				slog.SetDefault(records.Logger())
				defer slog.SetDefault(previous)
			}
			remote := reportingDial(t, addr)
			if _, err := NewRequest(CapabilitiesExchange, 0, dict.Default).WriteTo(remote); err != nil {
				t.Fatal(err)
			}
			var c Conn
			select {
			case c = <-handled:
			case <-time.After(5 * time.Second):
				t.Fatal("message not handled")
			}
			got := records.RecordsWithMessage("connection marker")
			if len(got) != 1 || got[0].Message != "connection marker" {
				t.Fatalf("records=%v", got)
			}
			for key, want := range map[string]string{"network": "tcp", "local_addr": remote.RemoteAddr().String(), "remote_addr": remote.LocalAddr().String()} {
				if got := logtest.Attr(got[0], key).String(); got != want {
					t.Fatalf("%s=%q, want %q", key, got, want)
				}
			}
			if useDefault {
				replacement := logtest.New()
				slog.SetDefault(replacement.Logger())
				c.Logger().Info("late default marker")
				if got := replacement.RecordsWithMessage("late default marker"); len(got) != 1 || got[0].Message != "late default marker" {
					t.Fatalf("Conn.Logger cached old default: %v", got)
				}
			}
		})
	}
}

func TestServeMuxPreservesMessageContext(t *testing.T) {
	records := logtest.New()
	local, remote := net.Pipe()
	defer func() { _ = local.Close() }()
	defer func() { _ = remote.Close() }()
	srv := &Server{Logger: records.Logger()}
	c := srv.newConn(local)
	type contextKey struct{}
	ctx := context.WithValue(context.Background(), contextKey{}, "message span")
	m := NewRequest(CapabilitiesExchange, 0, dict.Default)
	m.SetContext(ctx)
	NewServeMux().ServeDIAM(c.writer, m)
	if records := records.Records(); len(records) != 1 || logtest.HasAttr(records[0], "error") {
		t.Fatalf("unhandled message record has a redundant error: %v", records)
	}
	if contexts := records.Contexts(); len(contexts) != 1 || contexts[0] != ctx {
		t.Fatalf("record contexts=%v, want message context", contexts)
	}
}
