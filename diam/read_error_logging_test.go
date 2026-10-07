package diam

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

type bodyTimeout struct{}

func (bodyTimeout) Error() string   { return "body read timed out" }
func (bodyTimeout) Timeout() bool   { return true }
func (bodyTimeout) Temporary() bool { return true }

type failingBodyReader struct{ err error }

func (r failingBodyReader) Read([]byte) (int, error) { return 0, r.err }
func TestReadBodyPreservesTransportError(t *testing.T) {
	header := (&Header{Version: 1, MessageLength: HeaderLength + 8, CommandCode: CapabilitiesExchange, CommandFlags: RequestFlag}).Serialize()
	_, err := ReadMessage(io.MultiReader(bytes.NewReader(header), failingBodyReader{bodyTimeout{}}), dict.Default)
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("body timeout identity lost: %v", err)
	}
}
func TestReadErrorRecordLevels(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		level slog.Level
		count int
	}{
		{"EOF", io.EOF, 0, 0}, {"closed", net.ErrClosed, 0, 0},
		{"wrapped EOF", fmt.Errorf("read body error: %w, 0 bytes read", io.EOF), slog.LevelDebug, 1},
		{"nested EOF", fmt.Errorf("body: %w", fmt.Errorf("read: %w", io.EOF)), slog.LevelDebug, 1},
		{"wrapped closed", fmt.Errorf("body: %w", net.ErrClosed), 0, 0},
		{"TCP closed", &net.OpError{Op: "read", Net: "tcp", Err: net.ErrClosed}, 0, 0},
		{"nested TCP closed", fmt.Errorf("body: %w", &net.OpError{Op: "read", Net: "tcp", Err: net.ErrClosed}), 0, 0},
		{"wrapped timeout", fmt.Errorf("body: %w", bodyTimeout{}), slog.LevelDebug, 1},
		{"wrapped truncated", fmt.Errorf("body: %w", io.ErrUnexpectedEOF), slog.LevelDebug, 1},
		{"timeout", bodyTimeout{}, slog.LevelDebug, 1},
		{"truncated", io.ErrUnexpectedEOF, slog.LevelDebug, 1},
		{"pipe", io.ErrClosedPipe, slog.LevelDebug, 1},
		{"decode", errors.New("bad dictionary payload"), slog.LevelWarn, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := logtest.New()
			local, remote := net.Pipe()
			defer func() { _ = local.Close(); _ = remote.Close() }()
			c := (&Server{Logger: logs.Logger()}).newConn(local)
			if c.handleReadError(nil, tc.err) {
				t.Fatal("transport error continued reading")
			}
			records := logs.Records()
			if len(records) != tc.count {
				t.Fatalf("records=%d want%d", len(records), tc.count)
			}
			if tc.count > 0 && (records[0].Level != tc.level || logtest.Attr(records[0], "error").Any() != tc.err) {
				t.Fatalf("record=%v", records[0])
			}
		})
	}
}

func TestMessageErrorTakesPrecedenceOverOrderlyClose(t *testing.T) {
	for _, cause := range []error{io.EOF, net.ErrClosed} {
		for _, wrapped := range []bool{false, true} {
			t.Run(fmt.Sprintf("%v/wrapped=%t", cause, wrapped), func(t *testing.T) {
				h := newRecordingMessageErrorHandler()
				local, remote := net.Pipe()
				defer func() { _ = local.Close(); _ = remote.Close() }()
				c := (&Server{Handler: h, Logger: h.records.Logger()}).newConn(local)
				m := NewRequest(DeviceWatchdog, 0, dict.Default)
				me := &MessageError{ResultCode: InvalidAVPValue, Err: cause}
				var err error = me
				if wrapped {
					err = fmt.Errorf("decode: %w", me)
				}
				if !c.handleReadError(m, err) {
					t.Fatal("recoverable MessageError closed without being handled")
				}
				select {
				case got := <-h.messageErrors:
					if got != me {
						t.Fatalf("handled %v, want original", got)
					}
				default:
					t.Fatal("MessageError handler was not called")
				}
				records := h.records.Records()
				if len(records) != 1 || records[0].Level != slog.LevelWarn || !errors.Is(logtest.Attr(records[0], "error").Any().(error), me) {
					t.Fatalf("records=%v", records)
				}
			})
		}
	}
}

func TestServerLogsEOFBeforeMessageBody(t *testing.T) {
	logs := logtest.New()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{Handler: NewServeMux(), Logger: logs.Logger()}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	defer func() { _ = srv.Close(); <-done }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	header := (&Header{Version: 1, MessageLength: HeaderLength + 8, CommandCode: DeviceWatchdog, CommandFlags: RequestFlag, HopByHopID: 0x11223344}).Serialize()
	if _, err := c.Write(header); err != nil {
		t.Fatal(err)
	}
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := c.Read(b[:]); err != io.EOF {
		t.Fatalf("read=%v, want EOF without answer", err)
	}
	records := logs.Records()
	if len(records) != 1 {
		t.Fatalf("truncated message records=%d, want 1", len(records))
	}
	if records[0].Level != slog.LevelDebug || !errors.Is(logtest.Attr(records[0], "error").Any().(error), io.EOF) {
		t.Fatalf("record=%v", records[0])
	}
	if logtest.Attr(records[0], "message.hop_by_hop_id").Uint64() != 0x11223344 {
		t.Fatalf("header identity missing: %v", records[0])
	}
}

func TestServerLocalCloseIsQuiet(t *testing.T) {
	for _, fromHandler := range []bool{false, true} {
		t.Run(fmt.Sprintf("handler=%t", fromHandler), func(t *testing.T) {
			records := logtest.New()
			accepted := make(chan Conn, 1)
			srv := &Server{Logger: records.Logger(), Dict: dict.Default,
				OnNewConnection: func(c Conn) {
					accepted <- c
					if !fromHandler {
						c.Close()
					}
				},
				Handler: HandlerFunc(func(c Conn, _ *Message) { c.Close() }),
			}
			addr := reportingTCPServer(t, srv)
			remote := reportingDial(t, addr)
			if fromHandler {
				if _, err := NewRequest(DeviceWatchdog, 0, dict.Default).WriteTo(remote); err != nil {
					t.Fatal(err)
				}
			}
			var buf [1]byte
			if _, err := remote.Read(buf[:]); !errors.Is(err, io.EOF) {
				t.Fatalf("local close: %v, want EOF", err)
			}
			c := <-accepted
			select {
			case <-c.(interface{ DispatchDone() <-chan struct{} }).DispatchDone():
			case <-time.After(5 * time.Second):
				t.Fatal("local close did not finish dispatch")
			}
			if got := records.Records(); len(got) != 0 {
				t.Fatalf("local close emitted records: %v", got)
			}
		})
	}
}
