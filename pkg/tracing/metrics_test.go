package tracing

import (
	"context"
	"path/filepath"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/openai/tunnel-client/pkg/runtimeconfig"
)

func TestTracingMetricsHaveNoRequestLabels(t *testing.T) {
	t.Parallel()
	runtime, err := New(runtimeconfig.TracingConfig{Enabled: true, File: filepath.Join(t.TempDir(), "trace.jsonl")})
	if err != nil {
		t.Fatal(err)
	}
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	if err := runtime.registerMetrics(provider); err != nil {
		t.Fatal(err)
	}
	for _, parent := range []string{sampledParent, "", "invalid"} {
		_, span := runtime.StartCommand(context.Background(), parent)
		span.End()
	}
	if err := runtime.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	var data metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &data); err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"commands": 3, "missing": 1, "invalid": 1, "unsampled": 0, "exported": 1, "dropped": 0, "failed": 0}
	seen := 0
	for _, scope := range data.ScopeMetrics {
		for _, metric := range scope.Metrics {
			for name, value := range want {
				if metric.Name != "tunnel.client.tracing."+name {
					continue
				}
				sum, ok := metric.Data.(metricdata.Sum[int64])
				if !ok || len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != value || sum.DataPoints[0].Attributes.Len() != 0 {
					t.Fatalf("unexpected %s metric: %+v", name, metric.Data)
				}
				seen++
			}
		}
	}
	if seen != len(want) {
		t.Fatalf("observed %d counters, want %d", seen, len(want))
	}
}
