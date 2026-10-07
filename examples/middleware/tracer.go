// Package middleware traces Diameter handlers with OpenTelemetry: a span
// per message, and an exception log record when a handler panics.
package middleware

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"strconv"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otellog "go.opentelemetry.io/otel/log"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
)

// ScopeName is the instrumentation scope of the tracer that starts the spans
// and of the logger that records a panic in the wrapped handler.
const ScopeName = "github.com/gomaja/go-diameter/examples/middleware"

// Attribute keys of the Diameter header fields and result. OpenTelemetry's
// semantic conventions define no Diameter attributes (none up to release
// v1.44.0, and its rpc.system.name has no Diameter member), so these keys
// use a diameter namespace. The peer's address uses the semantic
// conventions' network.peer.address and network.peer.port, and a failed
// answer sets error.type to its result code.
const (
	ApplicationIDKey          = attribute.Key("diameter.application.id")
	CommandCodeKey            = attribute.Key("diameter.command.code")
	CommandNameKey            = attribute.Key("diameter.command.name")
	CommandRequestKey         = attribute.Key("diameter.command.request")
	HopByHopIDKey             = attribute.Key("diameter.hop_by_hop_id")
	EndToEndIDKey             = attribute.Key("diameter.end_to_end_id")
	ResultCodeKey             = attribute.Key("diameter.result_code")
	ExperimentalResultCodeKey = attribute.Key("diameter.experimental_result_code")
)

// Option configures a Tracer.
type Option func(*config)

type config struct {
	provider       trace.TracerProvider
	loggerProvider otellog.LoggerProvider
}

// WithTracerProvider sets the provider of the tracer that starts the spans.
// The default is the global provider, otel.GetTracerProvider.
func WithTracerProvider(tp trace.TracerProvider) Option {
	return func(c *config) { c.provider = tp }
}

// WithLoggerProvider sets the provider of the logger that records a panic in
// the wrapped handler. The default is the global provider,
// otel.GetLoggerProvider.
func WithLoggerProvider(lp otellog.LoggerProvider) Option {
	return func(c *config) { c.loggerProvider = lp }
}

// Tracer is a diam.Handler that starts a span for every message it serves,
// as a child of the span in the message's Context, and serves the message
// with the wrapped handler while the message's Context holds the new span.
//
// A request is traced by a SERVER span. An answer is traced by an INTERNAL
// span, since the outgoing request it answers belongs to whoever sent it;
// its Result-Code, or Experimental-Result-Code, is recorded, and a code
// outside the informational (1xxx) and success (2xxx) classes sets the
// span's status to Error (RFC 6733 §§7.1, 7.7). A panic in the wrapped
// handler marks the span failed and is recorded as an exception log record
// (see ServeDIAM).
type Tracer struct {
	h      diam.Handler
	tracer trace.Tracer
	logger otellog.Logger
}

// NewTracer returns a Tracer that serves messages with h.
func NewTracer(h diam.Handler, opts ...Option) *Tracer {
	var cfg config
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.provider == nil {
		cfg.provider = otel.GetTracerProvider()
	}
	if cfg.loggerProvider == nil {
		cfg.loggerProvider = otel.GetLoggerProvider()
	}
	return &Tracer{
		h:      h,
		tracer: cfg.provider.Tracer(ScopeName, trace.WithSchemaURL(semconv.SchemaURL)),
		logger: cfg.loggerProvider.Logger(ScopeName, otellog.WithSchemaURL(semconv.SchemaURL)),
	}
}

// TracerFunc traces f as NewTracer traces a handler.
func TracerFunc(f diam.HandlerFunc, opts ...Option) diam.HandlerFunc {
	return NewTracer(f, opts...).ServeDIAM
}

// ServeDIAM implements diam.Handler.
//
// When the wrapped handler panics, ServeDIAM follows the OpenTelemetry
// semantic conventions for recording errors
// (https://opentelemetry.io/docs/specs/semconv/general/recording-errors/):
// the span gets status Error, with the panic message as description, and
// error.type classifying the panic value. The exception itself is recorded
// as one log record (see logException), not as a span event: exceptions on
// spans are deprecated in favour of exceptions in logs. The span then ends,
// and the panic continues with its value unchanged, for diam.Server to
// recover and log.
//
// The span is ended here rather than by a deferred span.End, whose recover
// would record the panic as a span event in the Go SDK. While a panic is
// handled, nothing done here can replace its value or leave the span open:
// the application code it runs, the panic value's Error or String method and
// its classification, is contained (fmt recovers a panicking Error or String
// method itself), and so are the logging pipeline and the span pipeline that
// span.End runs, such as a synchronous exporter.
func (t *Tracer) ServeDIAM(c diam.Conn, m *diam.Message) {
	ctx, span := t.start(c, m)
	defer func() {
		v := recover()
		if v == nil {
			span.End()
			return
		}
		message := fmt.Sprint(v)
		span.SetAttributes(semconv.ErrorTypeKey.String(classify(v)))
		span.SetStatus(codes.Error, message)
		t.logException(ctx, v, message)
		endSpan(span)
		panic(v)
	}()
	m.SetContext(ctx)
	t.h.ServeDIAM(c, m)
}

// endSpan ends span while a handler panic is handled. A panic from the span
// pipeline is dropped, so that it cannot replace the handler's panic value.
func endSpan(span trace.Span) {
	defer func() { _ = recover() }()
	span.End()
}

// exceptionEventName is the event name of the exception log record. The
// semantic conventions for exceptions in logs name a record after the
// instrumented operation, with an ".exception" suffix. No semantic
// convention defines a Diameter operation, and this middleware wraps any
// Diameter handler, so it uses "exception", the name the conventions give
// to instrumentation that is not specific to an operation.
const exceptionEventName = "exception"

// logException emits the exception log record of panic value v, with ctx,
// following the OpenTelemetry semantic conventions for exceptions in logs
// (Stable, https://opentelemetry.io/docs/specs/semconv/exceptions/exceptions-logs/):
//   - severity ERROR (17), for an exception the application code did not
//     handle and that does not shut the application down;
//   - event name exceptionEventName;
//   - exception.type (v's dynamic Go type), exception.message and
//     exception.stacktrace;
//   - ctx holds the span, so the record carries the span's context.
//
// An error panic value is also given to the Logs API as the record's error,
// as the conventions ask. The Go SDK would derive exception.message from it
// and exception.type from the error's ErrorType method or unwrapped type;
// because both are set here, it derives neither, and runs no application
// code while the panic is handled.
//
// A panic in the logging pipeline is dropped, so that it cannot replace v.
func (t *Tracer) logException(ctx context.Context, v any, message string) {
	defer func() { _ = recover() }()
	if !t.logger.Enabled(ctx, otellog.EnabledParameters{Severity: otellog.SeverityError, EventName: exceptionEventName}) {
		return
	}
	stack := make([]byte, 64<<10)
	stack = stack[:runtime.Stack(stack, false)]
	var r otellog.Record
	r.SetTimestamp(time.Now())
	r.SetEventName(exceptionEventName)
	r.SetSeverity(otellog.SeverityError)
	r.SetSeverityText("ERROR")
	r.AddAttributes(
		semconv.ExceptionType(typeName(v)),
		semconv.ExceptionMessage(message),
		semconv.ExceptionStacktrace(string(stack)),
	)
	if err, ok := v.(error); ok {
		r.SetErr(err)
	}
	t.logger.Emit(ctx, r)
}

// typeName returns the dynamic Go type of v, as exception.type names it: the
// package path and name of a named type, or the type's own spelling, such as
// *fs.PathError or string, for a pointer, predeclared or unnamed type.
func typeName(v any) string {
	t := reflect.TypeOf(v)
	if t.PkgPath() != "" && t.Name() != "" {
		return t.PkgPath() + "." + t.Name()
	}
	return t.String()
}

// classify returns the error.type of panic value v. For an error it is
// semconv.ErrorType's, which uses the error's own ErrorType method and looks
// through fmt.Errorf wrappers; otherwise it is v's Go type. ErrorType, and
// the Unwrap and As methods semconv.ErrorType calls, are application code
// running while a panic is handled: if one of them panics, v's Go type is
// used instead.
func classify(v any) (errorType string) {
	err, ok := v.(error)
	if !ok {
		return typeName(v)
	}
	defer func() {
		if recover() != nil {
			errorType = typeName(v)
		}
	}()
	return semconv.ErrorType(err).Value.AsString()
}

// Unwrap returns the traced handler, so Server and ServeMux can discover its
// optional interfaces through diam.HandlerAs.
func (t *Tracer) Unwrap() diam.Handler { return t.h }

// start starts the span of m, received on c.
func (t *Tracer) start(c diam.Conn, m *diam.Message) (context.Context, trace.Span) {
	h := m.Header
	request := h.CommandFlags&diam.RequestFlag != 0
	attrs := []attribute.KeyValue{
		ApplicationIDKey.Int64(int64(h.ApplicationID)),
		CommandCodeKey.Int64(int64(h.CommandCode)),
		CommandRequestKey.Bool(request),
		HopByHopIDKey.Int64(int64(h.HopByHopID)),
		EndToEndIDKey.Int64(int64(h.EndToEndID)),
	}
	name := "Unknown"
	if cmd, err := m.Dictionary().FindCommand(h.ApplicationID, h.CommandCode); err == nil {
		name = cmd.Name
		attrs = append(attrs, CommandNameKey.String(cmd.Name))
	}
	kind := trace.SpanKindServer
	var failure string
	if request {
		name += "-Request"
	} else {
		name += "-Answer"
		kind = trace.SpanKindInternal
		if key, code, ok := result(m); ok {
			attrs = append(attrs, key.Int64(int64(code)))
			// 1xxx is informational and 2xxx success; 3xxx, 4xxx and 5xxx
			// are protocol errors, transient and permanent failures
			// (RFC 6733 §7.1). §7.7 recommends the same classes for
			// vendor-specific codes.
			if code >= 3000 {
				failure = strconv.FormatUint(uint64(code), 10)
				attrs = append(attrs, semconv.ErrorTypeKey.String(failure))
			}
		}
	}
	if c != nil {
		attrs = append(attrs, peerAttrs(c.RemoteAddr())...)
	}
	ctx, span := t.tracer.Start(m.Context(), name, trace.WithSpanKind(kind), trace.WithAttributes(attrs...))
	if failure != "" {
		span.SetStatus(codes.Error, "Diameter result "+failure)
	}
	return ctx, span
}

// result returns the result of answer m: its Result-Code (RFC 6733 §7.1)
// or, when it has none, the Experimental-Result-Code inside its
// Experimental-Result (§§7.6, 7.7), with the key that records it.
func result(m *diam.Message) (attribute.Key, uint32, bool) {
	if code, ok := unsigned32(m, diam.AVPRef{Code: avp.ResultCode}); ok {
		return ResultCodeKey, code, true
	}
	code, ok := unsigned32(m, diam.AVPRef{Code: avp.ExperimentalResult}, diam.AVPRef{Code: avp.ExperimentalResultCode})
	return ExperimentalResultCodeKey, code, ok
}

// unsigned32 returns the value of the first AVP at path in m, if it is an
// Unsigned32.
func unsigned32(m *diam.Message, path ...diam.AVPRef) (uint32, bool) {
	avps := m.FindAVPsWithPath(path...)
	if len(avps) == 0 {
		return 0, false
	}
	v, ok := avps[0].Data.(datatype.Unsigned32)
	return uint32(v), ok
}

// peerAttrs records addr when it is a single IP address and port. A
// multihomed SCTP peer has several addresses, which network.peer.address
// cannot hold, so it is left out.
func peerAttrs(addr net.Addr) []attribute.KeyValue {
	if addr == nil {
		return nil
	}
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return nil
	}
	return []attribute.KeyValue{
		semconv.NetworkPeerAddress(ap.Addr().Unmap().String()),
		semconv.NetworkPeerPort(int(ap.Port())),
	}
}
