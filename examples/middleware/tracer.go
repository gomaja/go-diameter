// Package middleware traces Diameter handlers with OpenTelemetry.
package middleware

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"strconv"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
)

// ScopeName is the instrumentation scope of the tracer that starts the spans.
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
	provider trace.TracerProvider
}

// WithTracerProvider sets the provider of the tracer that starts the spans.
// The default is the global provider, otel.GetTracerProvider.
func WithTracerProvider(tp trace.TracerProvider) Option {
	return func(c *config) { c.provider = tp }
}

// Tracer is a diam.Handler that starts a span for every message it serves,
// as a child of the span in the message's Context, and serves the message
// with the wrapped handler while the message's Context holds the new span.
//
// A request is traced by a SERVER span. An answer is traced by an INTERNAL
// span, since the outgoing request it answers belongs to whoever sent it;
// its Result-Code, or Experimental-Result-Code, is recorded, and a code
// outside the informational (1xxx) and success (2xxx) classes sets the
// span's status to Error (RFC 6733 §§7.1, 7.7).
type Tracer struct {
	h      diam.Handler
	tracer trace.Tracer
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
	return &Tracer{
		h:      h,
		tracer: cfg.provider.Tracer(ScopeName, trace.WithSchemaURL(semconv.SchemaURL)),
	}
}

// TracerFunc traces f as NewTracer traces a handler.
func TracerFunc(f diam.HandlerFunc, opts ...Option) diam.HandlerFunc {
	return NewTracer(f, opts...).ServeDIAM
}

// ServeDIAM implements diam.Handler. When the wrapped handler panics, the
// span records the failure and ends, and the panic continues with its value
// unchanged, for diam.Server to recover and log.
func (t *Tracer) ServeDIAM(c diam.Conn, m *diam.Message) {
	ctx, span := t.start(c, m)
	defer func() {
		if v := recover(); v != nil {
			recordPanic(span, v)
			span.End()
			panic(v)
		}
		span.End()
	}()
	m.SetContext(ctx)
	t.h.ServeDIAM(c, m)
}

// recordPanic marks span as ended by the panic value v, following the
// OpenTelemetry semantic conventions on recording errors: status Error with
// the panic message as description, and error.type naming v's type. It also
// adds the exception event the Go SDK adds for a panic, with the stack of
// the panicking goroutine.
//
// span.End is not deferred directly, so the SDK's own panic recording in End
// does not run and the panic is recorded once.
func recordPanic(span trace.Span, v any) {
	errorType := panicType(v)
	message := fmt.Sprint(v)
	stack := make([]byte, 64<<10)
	stack = stack[:runtime.Stack(stack, false)]
	span.AddEvent(semconv.ExceptionEventName, trace.WithAttributes(
		semconv.ExceptionType(errorType),
		semconv.ExceptionMessage(message),
		semconv.ExceptionStacktrace(string(stack)),
	))
	span.SetAttributes(semconv.ErrorTypeKey.String(errorType))
	span.SetStatus(codes.Error, message)
}

// panicType names the type of panic value v as error.type names an error:
// for an error, as semconv.ErrorType does; otherwise its package-qualified
// type name, or the type itself for a predeclared or unnamed type.
func panicType(v any) string {
	if err, ok := v.(error); ok {
		return semconv.ErrorType(err).Value.AsString()
	}
	t := reflect.TypeOf(v)
	if t.PkgPath() != "" && t.Name() != "" {
		return t.PkgPath() + "." + t.Name()
	}
	return t.String()
}

// HandleAccept preserves the wrapped handler's RFC 6733 §5.6.1 admission lifecycle.
func (t *Tracer) HandleAccept(c diam.Conn) func() {
	if h, ok := t.h.(diam.AcceptHandler); ok {
		return h.HandleAccept(c)
	}
	return nil
}

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
	avps, err := m.FindAVPsWithPath(path...)
	if err != nil || len(avps) == 0 {
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
