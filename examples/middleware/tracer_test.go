package middleware

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
)

var _ diam.AcceptHandler = (*Tracer)(nil)

func newRecorder(t *testing.T) (*tracetest.SpanRecorder, trace.TracerProvider) {
	t.Helper()
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	t.Cleanup(func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return sr, tp
}

// endedSpans waits for n spans to end: a handler's span ends after the
// handler has written its answer, so the peer can see the answer first.
func endedSpans(t *testing.T, sr *tracetest.SpanRecorder, n int) []sdktrace.ReadOnlySpan {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		spans := sr.Ended()
		if len(spans) >= n {
			if len(spans) > n {
				t.Fatalf("recorded %d spans, want %d", len(spans), n)
			}
			return spans
		}
		if time.Now().After(deadline) {
			t.Fatalf("recorded %d spans after 2s, want %d", len(spans), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func attrs(span sdktrace.ReadOnlySpan) map[attribute.Key]attribute.Value {
	m := make(map[attribute.Key]attribute.Value)
	for _, kv := range span.Attributes() {
		m[kv.Key] = kv.Value
	}
	return m
}

func wantAttrs(t *testing.T, span sdktrace.ReadOnlySpan, want ...attribute.KeyValue) {
	t.Helper()
	got := attrs(span)
	for _, kv := range want {
		v, ok := got[kv.Key]
		if !ok {
			t.Errorf("span %q has no %s attribute, want %s", span.Name(), kv.Key, kv.Value.String())
			continue
		}
		if v != kv.Value {
			t.Errorf("span %q %s = %s, want %s", span.Name(), kv.Key, v.String(), kv.Value.String())
		}
	}
}

func noAttrs(t *testing.T, span sdktrace.ReadOnlySpan, keys ...attribute.Key) {
	t.Helper()
	got := attrs(span)
	for _, k := range keys {
		if v, ok := got[k]; ok {
			t.Errorf("span %q has %s = %s, want none", span.Name(), k, v.String())
		}
	}
}

// exchangeCER runs a CER/CEA exchange between a server serving CERs with cer
// and a client handling the CEA with cea, and returns the CER sent. The
// handlers report failures on errc; cea closes wait once it has the CEA.
func exchangeCER(t *testing.T, errc chan error, wait chan struct{}, cer, cea diam.Handler) *diam.Message {
	t.Helper()
	smux := diam.NewServeMux()
	smux.Handle("CER", cer)

	srv := diamtest.NewServer(smux, nil)
	defer srv.Close()

	cmux := diam.NewServeMux()
	cmux.HandleIdx(diam.CommandIndex{AppID: 0, Code: diam.CapabilitiesExchange, Request: false}, cea)

	cli, err := diam.Dial(srv.Addr, cmux, nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := sendCER(cli)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-wait:
	case err := <-errc:
		t.Fatal(err)
	case err := <-smux.ErrorReports():
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("Timed out: no CER or CEA received")
	}
	return m
}

func TestTracerRecordsRequestSpan(t *testing.T) {
	sr, tp := newRecorder(t)
	errc, wait := make(chan error, 1), make(chan struct{})
	cer := exchangeCER(t, errc, wait,
		NewTracer(newCERHandler(errc), WithTracerProvider(tp)), handleCEA(errc, wait))

	span := endedSpans(t, sr, 1)[0]
	if span.Name() != "Capabilities-Exchange-Request" {
		t.Errorf("span name = %q, want Capabilities-Exchange-Request", span.Name())
	}
	if span.SpanKind() != trace.SpanKindServer {
		t.Errorf("span kind = %s, want server", span.SpanKind())
	}
	if span.Status().Code != codes.Unset {
		t.Errorf("span status = %v, want unset", span.Status())
	}
	if span.InstrumentationScope().Name != ScopeName {
		t.Errorf("instrumentation scope = %q, want %q", span.InstrumentationScope().Name, ScopeName)
	}
	wantAttrs(t, span,
		ApplicationIDKey.Int64(0),
		CommandCodeKey.Int64(diam.CapabilitiesExchange),
		CommandNameKey.String("Capabilities-Exchange"),
		CommandRequestKey.Bool(true),
		HopByHopIDKey.Int64(int64(cer.Header.HopByHopID)),
		EndToEndIDKey.Int64(int64(cer.Header.EndToEndID)),
		semconv.NetworkPeerAddress("127.0.0.1"),
	)
	if _, ok := attrs(span)[semconv.NetworkPeerPortKey]; !ok {
		t.Error("span has no network.peer.port")
	}
	noAttrs(t, span, ResultCodeKey, ExperimentalResultCodeKey, semconv.ErrorTypeKey)
}

func TestTracerFuncRecordsAnswerSpan(t *testing.T) {
	sr, tp := newRecorder(t)
	errc, wait := make(chan error, 1), make(chan struct{})
	cer := exchangeCER(t, errc, wait,
		handleCER(errc), TracerFunc(handleCEA(errc, wait), WithTracerProvider(tp)))

	span := endedSpans(t, sr, 1)[0]
	if span.Name() != "Capabilities-Exchange-Answer" {
		t.Errorf("span name = %q, want Capabilities-Exchange-Answer", span.Name())
	}
	if span.SpanKind() != trace.SpanKindInternal {
		t.Errorf("span kind = %s, want internal", span.SpanKind())
	}
	if span.Status().Code != codes.Unset {
		t.Errorf("span status = %v, want unset for DIAMETER_SUCCESS", span.Status())
	}
	wantAttrs(t, span,
		CommandCodeKey.Int64(diam.CapabilitiesExchange),
		CommandRequestKey.Bool(false),
		HopByHopIDKey.Int64(int64(cer.Header.HopByHopID)),
		ResultCodeKey.Int64(diam.Success),
	)
	noAttrs(t, span, semconv.ErrorTypeKey)
}

func TestTracerStartsChildOfMessageContext(t *testing.T) {
	sr, tp := newRecorder(t)
	parentCtx, parent := tp.Tracer("test").Start(context.Background(), "parent")
	var inHandler trace.SpanContext
	h := NewTracer(diam.HandlerFunc(func(_ diam.Conn, m *diam.Message) {
		inHandler = trace.SpanContextFromContext(m.Context())
	}), WithTracerProvider(tp))

	m := diam.NewRequest(diam.CapabilitiesExchange, 0, dict.Default)
	m.SetContext(parentCtx)
	h.ServeDIAM(nil, m)
	parent.End()

	spans := endedSpans(t, sr, 2)
	span := spans[0]
	if span.Parent().SpanID() != parent.SpanContext().SpanID() {
		t.Errorf("span parent = %s, want %s", span.Parent().SpanID(), parent.SpanContext().SpanID())
	}
	if span.SpanContext().TraceID() != parent.SpanContext().TraceID() {
		t.Error("span is not in its parent's trace")
	}
	if inHandler.SpanID() != span.SpanContext().SpanID() {
		t.Errorf("handler saw span %s in the message context, want %s", inHandler.SpanID(), span.SpanContext().SpanID())
	}
}

func TestTracerMarksFailedAnswers(t *testing.T) {
	request := diam.NewRequest(diam.CapabilitiesExchange, 0, dict.Default)
	experimental := request.Answer(0)
	experimental.AddAVP(diam.NewAVP(avp.ExperimentalResult, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{
		diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(10415)),
		diam.NewAVP(avp.ExperimentalResultCode, avp.Mbit, 0, datatype.Unsigned32(5001)),
	}}))
	experimentalSuccess := request.Answer(0)
	experimentalSuccess.AddAVP(diam.NewAVP(avp.ExperimentalResult, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{
		diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(10415)),
		diam.NewAVP(avp.ExperimentalResultCode, avp.Mbit, 0, datatype.Unsigned32(2001)),
	}}))

	for _, tc := range []struct {
		name    string
		answer  *diam.Message
		key     attribute.Key
		code    int64
		failure string // error.type and status, "" when the answer succeeded
	}{
		{"informational", request.Answer(diam.MultiRoundAuth), ResultCodeKey, diam.MultiRoundAuth, ""},
		{"success", request.Answer(diam.Success), ResultCodeKey, diam.Success, ""},
		{"protocol error", request.Answer(diam.UnableToDeliver), ResultCodeKey, diam.UnableToDeliver, "3002"},
		{"transient failure", request.Answer(diam.AuthenticationRejected), ResultCodeKey, diam.AuthenticationRejected, "4001"},
		{"permanent failure", request.Answer(diam.NoCommonApplication), ResultCodeKey, diam.NoCommonApplication, "5010"},
		{"experimental failure", experimental, ExperimentalResultCodeKey, 5001, "5001"},
		{"experimental success", experimentalSuccess, ExperimentalResultCodeKey, 2001, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sr, tp := newRecorder(t)
			NewTracer(diam.HandlerFunc(func(diam.Conn, *diam.Message) {}), WithTracerProvider(tp)).ServeDIAM(nil, tc.answer)
			span := endedSpans(t, sr, 1)[0]
			wantAttrs(t, span, tc.key.Int64(tc.code))
			if tc.failure == "" {
				noAttrs(t, span, semconv.ErrorTypeKey)
				if span.Status().Code != codes.Unset {
					t.Errorf("span status = %v, want unset", span.Status())
				}
				return
			}
			wantAttrs(t, span, semconv.ErrorTypeKey.String(tc.failure))
			if span.Status().Code != codes.Error || span.Status().Description != "Diameter result "+tc.failure {
				t.Errorf("span status = %+v, want Error %q", span.Status(), "Diameter result "+tc.failure)
			}
		})
	}
}

func TestTracerNamesUnknownCommands(t *testing.T) {
	sr, tp := newRecorder(t)
	h := NewTracer(diam.HandlerFunc(func(diam.Conn, *diam.Message) {}), WithTracerProvider(tp))
	h.ServeDIAM(nil, diam.NewRequest(9999, 16777251, dict.Default))
	span := endedSpans(t, sr, 1)[0]
	if span.Name() != "Unknown-Request" {
		t.Errorf("span name = %q, want Unknown-Request", span.Name())
	}
	wantAttrs(t, span, ApplicationIDKey.Int64(16777251), CommandCodeKey.Int64(9999))
	noAttrs(t, span, CommandNameKey)
}

// handlerError is a panic value whose error.type the span must name.
type handlerError struct{}

func (handlerError) Error() string { return "handler failed" }

func TestTracerMarksHandlerPanic(t *testing.T) {
	for _, tc := range []struct {
		name      string
		value     any
		errorType string
		message   string
	}{
		{"string", "boom", "string", "boom"},
		{"error", handlerError{}, "github.com/gomaja/go-diameter/examples/middleware.handlerError", "handler failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sr, tp := newRecorder(t)
			// An answer whose Result-Code is a failure: the panic, which
			// ended the handler, decides error.type and the status.
			answer := diam.NewRequest(diam.CapabilitiesExchange, 0, dict.Default).Answer(diam.UnableToDeliver)
			h := NewTracer(diam.HandlerFunc(func(diam.Conn, *diam.Message) { panic(tc.value) }), WithTracerProvider(tp))
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				h.ServeDIAM(nil, answer)
			}()
			if recovered != tc.value {
				t.Fatalf("panic value after the tracer = %v, want %v", recovered, tc.value)
			}
			span := endedSpans(t, sr, 1)[0]
			if span.Status().Code != codes.Error || span.Status().Description != tc.message {
				t.Errorf("span status = %+v, want Error %q", span.Status(), tc.message)
			}
			wantAttrs(t, span, semconv.ErrorTypeKey.String(tc.errorType), ResultCodeKey.Int64(diam.UnableToDeliver))
			events := span.Events()
			if len(events) != 1 || events[0].Name != semconv.ExceptionEventName {
				t.Fatalf("span events = %+v, want one %q event", events, semconv.ExceptionEventName)
			}
			event := map[attribute.Key]attribute.Value{}
			for _, kv := range events[0].Attributes {
				event[kv.Key] = kv.Value
			}
			if got := event[semconv.ExceptionTypeKey].AsString(); got != tc.errorType {
				t.Errorf("exception.type = %q, want %q", got, tc.errorType)
			}
			if got := event[semconv.ExceptionMessageKey].AsString(); got != tc.message {
				t.Errorf("exception.message = %q, want %q", got, tc.message)
			}
			if got := event[semconv.ExceptionStacktraceKey].AsString(); !strings.Contains(got, "TestTracerMarksHandlerPanic") {
				t.Errorf("exception.stacktrace lacks the panicking handler:\n%s", got)
			}
		})
	}
}

// TestTracerPanicReachesServerLogger serves a panicking handler through
// diam.Server: the span is marked failed, and the panic, with the handler's
// frames, is recorded once, by the server's Logger.
func TestTracerPanicReachesServerLogger(t *testing.T) {
	sr, tp := newRecorder(t)
	logs := &lockedBuffer{}
	smux := diam.NewServeMux()
	smux.Handle("CER", NewTracer(diam.HandlerFunc(panicsHandlingCER), WithTracerProvider(tp)))
	srv := diamtest.NewUnstartedServer(smux, nil)
	srv.Config.Logger = slog.New(slog.NewJSONHandler(logs, nil))
	srv.Start()
	defer srv.Close()

	cli, err := diam.Dial(srv.Addr, diam.NewServeMux(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, err := sendCER(cli); err != nil {
		t.Fatal(err)
	}

	span := endedSpans(t, sr, 1)[0]
	if span.Status().Code != codes.Error || span.Status().Description != "CER handler failed" {
		t.Errorf("span status = %+v, want Error %q", span.Status(), "CER handler failed")
	}
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(logs.String(), "panicsHandlingCER") {
		if time.Now().After(deadline) {
			t.Fatalf("server log lacks the handler's panic stack:\n%s", logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := strings.Count(logs.String(), `"level":"ERROR"`); n != 1 {
		t.Errorf("server logged %d Error records, want 1:\n%s", n, logs.String())
	}
}

func panicsHandlingCER(diam.Conn, *diam.Message) { panic("CER handler failed") }

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// copy from diam/server_test.go
func sendCER(w io.Writer) (*diam.Message, error) {
	m := diam.NewRequest(diam.CapabilitiesExchange, 0, nil)
	if _, err := m.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.OctetString("cli")); err != nil {
		return nil, err
	}
	if _, err := m.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.OctetString("localhost")); err != nil {
		return nil, err
	}
	if _, err := m.NewAVP(avp.HostIPAddress, avp.Mbit, 0, datatype.AddressFromIP(netip.MustParseAddr("127.0.0.1"))); err != nil {
		return nil, err
	}
	if _, err := m.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(99)); err != nil {
		return nil, err
	}
	if _, err := m.NewAVP(avp.ProductName, avp.Mbit, 0, datatype.UTF8String("go-diameter")); err != nil {
		return nil, err
	}
	if _, err := m.NewAVP(avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(1234)); err != nil {
		return nil, err
	}
	if _, err := m.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1)); err != nil {
		return nil, err
	}
	_, err := m.WriteTo(w)
	return m, err
}

type CER struct {
	OriginHost        string    `avp:"Origin-Host"`
	OriginRealm       string    `avp:"Origin-Realm"`
	VendorID          int       `avp:"Vendor-Id"`
	ProductName       string    `avp:"Product-Name"`
	OriginStateID     *diam.AVP `avp:"Origin-State-Id"`
	AcctApplicationID *diam.AVP `avp:"Acct-Application-Id"`
}

type cerHandler struct {
	errc chan error
}

func newCERHandler(errc chan error) diam.Handler {
	return &cerHandler{errc: errc}
}

func (h *cerHandler) ServeDIAM(c diam.Conn, m *diam.Message) {
	if !trace.SpanContextFromContext(m.Context()).IsValid() {
		h.errc <- errors.New("message context holds no span")
		return
	}
	var req CER
	err := m.Unmarshal(&req)
	if err != nil {
		h.errc <- err
		return
	}
	a := m.Answer(diam.Success)
	_, err = sendCEA(c, a, req.OriginStateID, req.AcctApplicationID)
	if err != nil {
		h.errc <- err
	}
}

func handleCER(errc chan error) diam.HandlerFunc {
	return func(c diam.Conn, m *diam.Message) {
		var req CER
		err := m.Unmarshal(&req)
		if err != nil {
			errc <- err
			return
		}
		a := m.Answer(diam.Success)
		_, err = sendCEA(c, a, req.OriginStateID, req.AcctApplicationID)
		if err != nil {
			errc <- err
		}
	}
}

func sendCEA(w io.Writer, m *diam.Message, OriginStateID, AcctApplicationID *diam.AVP) (n int64, err error) {
	if _, err := m.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.OctetString("srv")); err != nil {
		return 0, err
	}
	if _, err := m.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.OctetString("localhost")); err != nil {
		return 0, err
	}
	if _, err := m.NewAVP(avp.HostIPAddress, avp.Mbit, 0, datatype.AddressFromIP(netip.MustParseAddr("127.0.0.1"))); err != nil {
		return 0, err
	}
	if _, err := m.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(99)); err != nil {
		return 0, err
	}
	if _, err := m.NewAVP(avp.ProductName, avp.Mbit, 0, datatype.UTF8String("go-diameter")); err != nil {
		return 0, err
	}
	m.AddAVP(OriginStateID)
	m.AddAVP(AcctApplicationID)
	return m.WriteTo(w)
}

func handleCEA(errc chan error, wait chan struct{}) diam.HandlerFunc {
	type CEA struct {
		OriginHost        string `avp:"Origin-Host"`
		OriginRealm       string `avp:"Origin-Realm"`
		VendorID          int    `avp:"Vendor-Id"`
		ProductName       string `avp:"Product-Name"`
		OriginStateID     int    `avp:"Origin-State-Id"`
		AcctApplicationID int    `avp:"Acct-Application-Id"`
	}
	return func(c diam.Conn, m *diam.Message) {
		var resp CEA
		err := m.Unmarshal(&resp)
		if err != nil {
			errc <- err
			return
		}
		close(wait)
		c.Close()
	}
}

type acceptObserver struct {
	diam.Handler
	accepted diam.Conn
	cleaned  bool
}

func (h *acceptObserver) HandleAccept(c diam.Conn) func() {
	h.accepted = c
	return func() { h.cleaned = true }
}

func TestTracerForwardsAcceptLifecycle(t *testing.T) {
	wrapped := &acceptObserver{}
	tracer := NewTracer(wrapped)
	// An opaque connection verifies that the wrapper passes the original value.
	c := &struct{ diam.Conn }{}
	cleanup := tracer.HandleAccept(c)
	if wrapped.accepted != c {
		t.Fatal("wrapped handler did not receive accepted connection")
	}
	if cleanup == nil {
		t.Fatal("wrapped cleanup was lost")
	}
	cleanup()
	if !wrapped.cleaned {
		t.Fatal("wrapped cleanup was not called")
	}
	plain := NewTracer(diam.HandlerFunc(func(diam.Conn, *diam.Message) {}))
	if plain.HandleAccept(c) != nil {
		t.Fatal("plain handler returned an accept cleanup")
	}
}
