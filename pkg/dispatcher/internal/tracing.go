package dispatcherinternal

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/openai/tunnel-client/pkg/controlplane"
	"github.com/openai/tunnel-client/pkg/tracing"
	"github.com/openai/tunnel-client/pkg/types"
)

type commandTraceKey struct{}

type commandTrace struct {
	dispatch trace.Span
	target   trace.Span
}

func (p *mcpProcessor) startCommandTrace(ctx context.Context, cmd controlplane.PolledCommand) (context.Context, func(error)) {
	if !p.tracing.Enabled() {
		return ctx, func(error) {}
	}
	parent := ""
	var carrier *types.TraceContext
	if provider, ok := cmd.(controlplane.CommandTraceContextProvider); ok {
		carrier = provider.CommandTraceContext()
	} else if provider, ok := cmd.(controlplane.TraceContextProvider); ok {
		carrier = provider.TraceContext()
	}
	if carrier != nil && len(carrier.Tracestate) <= 512 {
		parent = carrier.Traceparent
	}
	ctx, span := p.tracing.StartCommand(ctx, parent)
	ctx = context.WithValue(ctx, commandTraceKey{}, &commandTrace{dispatch: span})
	return ctx, func(err error) {
		if err != nil || ctx.Err() != nil {
			span.SetStatus(codes.Error, "")
		}
		span.End()
	}
}

func (p *mcpProcessor) startTargetTrace(ctx context.Context) (context.Context, func()) {
	state, _ := ctx.Value(commandTraceKey{}).(*commandTrace)
	if state == nil {
		return ctx, func() {}
	}
	ctx, state.target = p.tracing.Start(ctx, tracing.MCP)
	return ctx, func() {
		if ctx.Err() != nil {
			markCommandTraceFailed(ctx)
		}
		state.target.End()
	}
}

func (p *mcpProcessor) startUploadTrace(ctx context.Context, response *types.TunnelResponse) (context.Context, func()) {
	state, _ := ctx.Value(commandTraceKey{}).(*commandTrace)
	if state == nil {
		return ctx, func() {}
	}
	if response.ResponseCode() >= http.StatusBadRequest {
		markCommandTraceFailed(ctx)
	}
	if state.target != nil && response.Type() != types.ResponseTypeJSONRPCNotification {
		state.target.End()
	}
	ctx = trace.ContextWithSpan(ctx, state.dispatch)
	ctx, span := p.tracing.Start(ctx, tracing.Upload)
	return ctx, func() { span.End() }
}

func markCommandTraceFailed(ctx context.Context) {
	state, _ := ctx.Value(commandTraceKey{}).(*commandTrace)
	if state == nil {
		return
	}
	state.dispatch.SetStatus(codes.Error, "")
	trace.SpanFromContext(ctx).SetStatus(codes.Error, "")
}

func commandTraceCarrier(ctx context.Context) *types.TraceContext {
	carrier := propagation.MapCarrier{}
	propagation.TraceContext{}.Inject(ctx, carrier)
	if carrier["traceparent"] == "" {
		return nil
	}
	return &types.TraceContext{Traceparent: carrier["traceparent"]}
}
