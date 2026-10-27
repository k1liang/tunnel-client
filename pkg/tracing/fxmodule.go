package tracing

import (
	"context"

	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.uber.org/fx"

	"github.com/openai/tunnel-client/pkg/runtimeconfig"
)

var Module = fx.Module("tracing", fx.Provide(newLifecycleRuntime))

type runtimeParams struct {
	fx.In
	Lifecycle     fx.Lifecycle
	Config        *runtimeconfig.TracingConfig
	MeterProvider *sdkmetric.MeterProvider `optional:"true"`
}

func newLifecycleRuntime(params runtimeParams) (*Runtime, error) {
	runtime, err := newRuntime(*params.Config)
	if err != nil {
		return nil, err
	}
	if !runtime.Enabled() {
		return runtime, nil
	}
	if params.MeterProvider != nil {
		if err := runtime.registerMetrics(params.MeterProvider); err != nil {
			return nil, err
		}
	}
	params.Lifecycle.Append(fx.Hook{
		OnStart: func(context.Context) error { return runtime.open(params.Config.File) },
		OnStop:  runtime.Shutdown,
	})
	return runtime, nil
}

func (runtime *Runtime) registerMetrics(provider *sdkmetric.MeterProvider) error {
	meter := provider.Meter("tunnel-client/tracing")
	for _, counter := range []struct {
		name  string
		value func(Stats) uint64
	}{
		{"commands", func(stats Stats) uint64 { return stats.Commands }},
		{"missing", func(stats Stats) uint64 { return stats.Missing }},
		{"invalid", func(stats Stats) uint64 { return stats.Invalid }},
		{"unsampled", func(stats Stats) uint64 { return stats.Unsampled }},
		{"exported", func(stats Stats) uint64 { return stats.Exported }},
		{"dropped", func(stats Stats) uint64 { return stats.Dropped }},
		{"failed", func(stats Stats) uint64 { return stats.Failed }},
	} {
		_, err := meter.Int64ObservableCounter("tunnel.client.tracing."+counter.name,
			metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
				observer.Observe(int64(counter.value(runtime.Stats())))
				return nil
			}))
		if err != nil {
			return err
		}
	}
	return nil
}
