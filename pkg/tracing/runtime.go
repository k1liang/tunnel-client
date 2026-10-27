package tracing

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/openai/tunnel-client/pkg/localfiles"
	"github.com/openai/tunnel-client/pkg/runtimeconfig"
)

const (
	Dispatch        = "tunnel.client.dispatch"
	MCP             = "tunnel.client.mcp"
	Upload          = "tunnel.client.upload"
	UploadAttempt   = "tunnel.client.upload_attempt"
	queueCapacity   = 1024
	fileLimit       = 64 * 1024 * 1024
	shutdownTimeout = time.Second
)

type uploadTraceKey struct{}

type uploadTrace struct {
	runtime *Runtime
	spanID  trace.SpanID
}

type Runtime struct {
	provider  *sdktrace.TracerProvider
	tracer    trace.Tracer
	processor *fileProcessor
	commands  atomic.Uint64
	missing   atomic.Uint64
	invalid   atomic.Uint64
	unsampled atomic.Uint64
}

type Stats struct {
	Commands  uint64
	Missing   uint64
	Invalid   uint64
	Unsampled uint64
	Exported  uint64
	Dropped   uint64
	Failed    uint64
}

func New(cfg runtimeconfig.TracingConfig) (*Runtime, error) {
	runtime, err := newRuntime(cfg)
	if err != nil {
		return nil, err
	}
	if err := runtime.open(cfg.File); err != nil {
		return nil, err
	}
	return runtime, nil
}

func newRuntime(cfg runtimeconfig.TracingConfig) (*Runtime, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	runtime := &Runtime{}
	if !cfg.Enabled {
		return runtime, nil
	}
	runtime.processor = newFileProcessor(queueCapacity, fileLimit)
	runtime.provider = sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.NeverSample())),
		sdktrace.WithSpanProcessor(runtime.processor),
		// Only the three fixed upload-attempt fields are read by the exporter.
		// Events, links, and arbitrary attributes are never written to disk.
		sdktrace.WithRawSpanLimits(sdktrace.SpanLimits{
			AttributeCountLimit: 3, AttributeValueLengthLimit: 32,
		}),
	)
	runtime.tracer = runtime.provider.Tracer("tunnel-client")
	return runtime, nil
}

func (runtime *Runtime) open(path string) error {
	if !runtime.Enabled() {
		return nil
	}
	directory, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return errors.New("cannot open local trace directory")
	}
	defer func() { _ = directory.Close() }()
	file, err := localfiles.OpenRegular(directory, filepath.Base(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("cannot create new local trace file")
	}
	runtime.processor.start(file)
	return nil
}

func (runtime *Runtime) Enabled() bool {
	return runtime != nil && runtime.provider != nil
}

func (runtime *Runtime) StartCommand(ctx context.Context, traceparent string) (context.Context, trace.Span) {
	ctx = baggage.ContextWithoutBaggage(ctx)
	ctx = trace.ContextWithSpanContext(ctx, trace.SpanContext{})
	if !runtime.Enabled() {
		return ctx, trace.SpanFromContext(ctx)
	}
	runtime.commands.Add(1)
	if traceparent == "" {
		runtime.missing.Add(1)
		return ctx, trace.SpanFromContext(ctx)
	}
	if len(traceparent) != 55 || !strings.HasPrefix(traceparent, "00-") {
		runtime.invalid.Add(1)
		return ctx, trace.SpanFromContext(ctx)
	}
	ctx = (propagation.TraceContext{}).Extract(ctx, propagation.MapCarrier{"traceparent": traceparent})
	parent := trace.SpanContextFromContext(ctx)
	if !parent.IsValid() {
		runtime.invalid.Add(1)
		return ctx, trace.SpanFromContext(ctx)
	}
	if !parent.IsSampled() {
		runtime.unsampled.Add(1)
	}
	return runtime.tracer.Start(ctx, Dispatch)
}

func (runtime *Runtime) Start(ctx context.Context, name string) (context.Context, trace.Span) {
	parent := trace.SpanContextFromContext(ctx)
	if !runtime.Enabled() || !parent.IsValid() || !allowedName(name) {
		ctx = trace.ContextWithSpanContext(ctx, trace.SpanContext{})
		return ctx, trace.SpanFromContext(ctx)
	}
	ctx, span := runtime.tracer.Start(ctx, name)
	if name == Upload && span.IsRecording() {
		ctx = context.WithValue(ctx, uploadTraceKey{}, uploadTrace{runtime: runtime, spanID: span.SpanContext().SpanID()})
	}
	return ctx, span
}

// StartUploadAttempt times only the HTTP request, excluding any subsequent retry
// wait. It returns nil when local upload tracing is inactive. The callback
// accepts fixed, bounded outcome categories; it never records response bodies,
// headers, URLs, or error strings.
func StartUploadAttempt(ctx context.Context, attempt int) func(int, string) {
	state, ok := ctx.Value(uploadTraceKey{}).(uploadTrace)
	if !ok || attempt < 1 {
		return nil
	}
	parent := trace.SpanFromContext(ctx)
	if !parent.IsRecording() || parent.SpanContext().SpanID() != state.spanID {
		return nil
	}
	_, span := state.runtime.tracer.Start(ctx, UploadAttempt,
		trace.WithAttributes(attribute.Int("attempt", attempt)))
	return func(httpStatus int, outcome string) {
		if httpStatus >= 100 && httpStatus <= 599 {
			span.SetAttributes(attribute.Int("http_status", httpStatus))
		}
		if !allowedUploadOutcome(outcome) {
			outcome = "request_error"
		}
		span.SetAttributes(attribute.String("outcome", outcome))
		if outcome != "accepted" && outcome != "already_fulfilled_or_unknown" {
			span.SetStatus(codes.Error, "")
		}
		span.End()
	}
}

func allowedUploadOutcome(outcome string) bool {
	switch outcome {
	case "accepted", "already_fulfilled_or_unknown", "http_error", "timeout", "canceled", "network_error", "request_error":
		return true
	default:
		return false
	}
}

func (runtime *Runtime) Shutdown(ctx context.Context) error {
	if !runtime.Enabled() {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, shutdownTimeout)
	defer cancel()
	providerErr := runtime.provider.Shutdown(ctx)
	processorErr := runtime.processor.Shutdown(ctx)
	return errors.Join(providerErr, processorErr)
}

func (runtime *Runtime) Stats() Stats {
	if !runtime.Enabled() {
		return Stats{}
	}
	return Stats{
		Commands: runtime.commands.Load(), Missing: runtime.missing.Load(),
		Invalid: runtime.invalid.Load(), Unsampled: runtime.unsampled.Load(),
		Exported: runtime.processor.exported.Load(), Dropped: runtime.processor.dropped.Load(),
		Failed: runtime.processor.failed.Load(),
	}
}

func allowedName(name string) bool {
	return name == Dispatch || name == MCP || name == Upload || name == UploadAttempt
}
