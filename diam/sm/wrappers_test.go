package sm

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

type plainHandlerWrapper struct{ inner diam.Handler }

func (w plainHandlerWrapper) ServeDIAM(c diam.Conn, m *diam.Message) { w.inner.ServeDIAM(c, m) }
func (w plainHandlerWrapper) Unwrap() diam.Handler                   { return w.inner }

type opaqueHandlerWrapper struct{ inner diam.Handler }

func (w opaqueHandlerWrapper) ServeDIAM(c diam.Conn, m *diam.Message) { w.inner.ServeDIAM(c, m) }

var stateMachineWrappers = []struct {
	name string
	wrap func(diam.Handler) diam.Handler
}{
	{"direct", func(h diam.Handler) diam.Handler { return h }},
	{"unwrap", func(h diam.Handler) diam.Handler { return plainHandlerWrapper{h} }},
	{"nested", func(h diam.Handler) diam.Handler { return plainHandlerWrapper{plainHandlerWrapper{h}} }},
}

// An opaque wrapper intentionally hides optional interfaces; a plain Unwrap
// wrapper retains RFC 6733 §5.6.1 admission and its handshake timer.
func TestWrappedStateMachineAdmission(t *testing.T) {
	for _, variant := range stateMachineWrappers {
		for _, mode := range []string{"malformed pre-CER", "valid pre-CER", "timeout"} {
			t.Run(variant.name+"/"+mode, func(t *testing.T) {
				records := logtest.New()
				cfg := testMessageErrorSettings()
				cfg.HandshakeTimeout = time.Second
				if mode == "timeout" {
					cfg.HandshakeTimeout = 30 * time.Millisecond
				}
				sm := mustNewStateMachine(t, cfg)
				srv := diamtest.NewUnstartedServer(variant.wrap(sm), dict.Default)
				srv.Config.Logger = records.Logger()
				srv.Start()
				defer srv.Close()
				c, err := net.Dial("tcp", srv.Addr)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = c.Close() }()
				if err = c.SetDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "malformed pre-CER":
					wire := testSMErrorMessage(t, diam.RequestFlag, []byte{0, 0, 1, 2, avp.Mbit, 255, 255, 255})
					wire[5], wire[6], wire[7] = 0, 1, 24 // DWR (280), not CER.
					writeSMErrorWire(t, c, wire)
				case "valid pre-CER":
					if _, err = regressionDWR(t).WriteTo(c); err != nil {
						t.Fatal(err)
					}
				}
				if m, err := diam.ReadMessage(c, dict.Default); !errors.Is(err, io.EOF) {
					t.Fatalf("before CER: %v, %v; want EOF without answer", m, err)
				}
				// C3: no waiting after peer EOF; the closing component already logged.
				want := "sm: message before CER; closing connection"
				if mode == "timeout" {
					want = "sm: handshake timeout; closing connection"
				}
				found := false
				for _, r := range records.Records() {
					if r.Message == want && r.Level == slog.LevelWarn {
						found = true
					}
				}
				if !found {
					t.Fatalf("EOF before close decision %q: %v", want, records.Records())
				}
			})
		}
	}
}
func TestOpaqueWrapperHidesStateMachineInterfaces(t *testing.T) {
	records := logtest.New()
	cfg := testMessageErrorSettings()
	cfg.HandshakeTimeout = 20 * time.Millisecond
	sm := mustNewStateMachine(t, cfg)
	srv := diamtest.NewUnstartedServer(opaqueHandlerWrapper{sm}, dict.Default)
	srv.Config.Logger = records.Logger()
	srv.Start()
	defer srv.Close()
	c, err := net.Dial("tcp", srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err = c.SetReadDeadline(time.Now().Add(70 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	_, err = c.Read(b[:])
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("opaque wrapper unexpectedly retained timeout: %v", err)
	}
	if err = c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	writeSMErrorWire(t, c, testSMErrorMessage(t, diam.RequestFlag, []byte{0, 0, 1, 2, avp.Mbit, 255, 255, 255}))
	if _, err = diam.ReadMessage(c, dict.Default); !errors.Is(err, io.EOF) {
		t.Fatalf("opaque malformed read: %v", err)
	}
	var found bool
	for _, r := range records.Records() {
		if errors.Is(logError(r), errors.ErrUnsupported) && r.Level == slog.LevelWarn {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing unsupported warning: %v", records.Records())
	}
}

type interceptingErrorWrapper struct {
	plainHandlerWrapper
	calls atomic.Int32
	err   error
}

func (w *interceptingErrorWrapper) HandleMessageError(c diam.Conn, m *diam.Message, e *diam.MessageError) error {
	w.calls.Add(1)
	if w.err != nil {
		return w.err
	}
	h, ok := diam.HandlerAs[diam.MessageErrorHandler](w.inner)
	if !ok {
		return errors.ErrUnsupported
	}
	return h.HandleMessageError(c, m, e)
}
func TestInterceptingStateMachineWrapper(t *testing.T) {
	for _, failure := range []error{nil, fmt.Errorf("wrapper: %w", errors.ErrUnsupported), errors.New("wrapper failure")} {
		t.Run(fmt.Sprint(failure), func(t *testing.T) {
			records := logtest.New()
			sm := mustNewStateMachine(t, testMessageErrorSettings())
			h := &interceptingErrorWrapper{plainHandlerWrapper: plainHandlerWrapper{sm}, err: failure}
			srv := diamtest.NewUnstartedServer(h, dict.Default)
			srv.Config.Logger = records.Logger()
			srv.Start()
			defer srv.Close()
			c, err := net.Dial("tcp", srv.Addr)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			writeSMErrorWire(t, c, testSMErrorMessage(t, diam.RequestFlag, []byte{0, 0, 1, 2, avp.Mbit, 255, 255, 255}))
			if failure == nil {
				a, e := diam.ReadMessage(c, dict.Default)
				if e != nil {
					t.Fatal(e)
				}
				assertMessageErrorAnswer(t, a, sm.cfg, diam.InvalidAVPLength, 0, true)
			}
			if _, err = diam.ReadMessage(c, dict.Default); !errors.Is(err, io.EOF) {
				t.Fatalf("want EOF after exactly one answer: %v", err)
			}
			if h.calls.Load() != 1 {
				t.Fatalf("interception count %d", h.calls.Load())
			}
			if failure != nil {
				want := slog.LevelError
				if errors.Is(failure, errors.ErrUnsupported) {
					want = slog.LevelWarn
				}
				found := false
				for _, r := range records.Records() {
					if errors.Is(logError(r), failure) && r.Level == want {
						found = true
					}
				}
				if !found {
					t.Fatalf("missing %s outcome: %v", want, records.Records())
				}
			}
		})
	}
}
