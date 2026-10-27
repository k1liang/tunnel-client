package app

import (
	"context"
	"io"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.uber.org/fx"

	"github.com/openai/tunnel-client/pkg/config"
	"github.com/openai/tunnel-client/pkg/runtimeapp"
	"github.com/openai/tunnel-client/pkg/runtimeconfig"
)

func TestCloudflaredStartTimeoutIncludesManagedRuntimeFetchBudget(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		ControlPlane: config.ControlPlaneConfig{
			PollTimeout:           2 * time.Second,
			PollDeadlineGuardrail: time.Second,
		},
		Cloudflared: config.CloudflaredConfig{
			Managed:      true,
			ReadyTimeout: 7 * time.Second,
		},
	}

	got := cloudflaredStartTimeout(cfg)
	want := fx.DefaultTimeout + 7*time.Second + 3*time.Second
	if got != want {
		t.Fatalf("expected managed startup timeout %s, got %s", want, got)
	}
}

func TestOptionsDeriveTracingWithoutMutatingCallerConfig(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, full := range []bool{false, true} {
			env := map[string]string{
				"CONTROL_PLANE_TUNNEL_ID": "tunnel_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"CONTROL_PLANE_API_KEY":   "synthetic-key", "MCP_COMMAND": "echo",
			}
			lookup := func(name string) (string, bool) { value, exists := env[name]; return value, exists }
			var originalControlPlane *runtimeconfig.ControlPlaneConfig
			var originalMCP *runtimeconfig.MCPConfig
			var suppliedControlPlane *runtimeconfig.ControlPlaneConfig
			var suppliedMCP *runtimeconfig.MCPConfig
			provider := sdkmetric.NewMeterProvider()
			t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
			opts := []fx.Option{
				fx.NopLogger, fx.Replace(provider),
				fx.Provide(func() io.Writer { return io.Discard }),
				fx.Populate(&suppliedControlPlane, &suppliedMCP),
			}
			var app *fx.App
			if full {
				cfg, err := config.Load(nil, lookup)
				if err != nil {
					t.Fatal(err)
				}
				cfg.Tracing = config.TracingConfig{Enabled: enabled, File: "unused.jsonl"}
				cfg.ControlPlane.TraceContextEnabled = !enabled
				cfg.MCP.TraceContextEnabled = !enabled
				originalControlPlane, originalMCP = &cfg.ControlPlane, &cfg.MCP
				app = NewWithRuntime(cfg, RuntimeOptions{DisableHealthAdmin: true}, opts...)
			} else {
				cfg, err := runtimeconfig.Load(nil, runtimeconfig.FlavorRuntime, lookup)
				if err != nil {
					t.Fatal(err)
				}
				cfg.Tracing = runtimeconfig.TracingConfig{Enabled: enabled, File: "unused.jsonl"}
				cfg.ControlPlane.TraceContextEnabled = !enabled
				cfg.MCP.TraceContextEnabled = !enabled
				originalControlPlane, originalMCP = &cfg.ControlPlane, &cfg.MCP
				app = runtimeapp.New(cfg, opts...)
			}
			if err := app.Err(); err != nil {
				t.Fatal(err)
			}
			if suppliedControlPlane.TraceContextEnabled != enabled || suppliedMCP.TraceContextEnabled != enabled {
				t.Fatalf("full=%v enabled=%v: derived configuration disagrees", full, enabled)
			}
			if originalControlPlane.TraceContextEnabled == enabled || originalMCP.TraceContextEnabled == enabled {
				t.Fatal("caller configuration was mutated")
			}
		}
	}
}

func TestCloudflaredStartTimeoutSkipsFetchBudgetForStaticToken(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		ControlPlane: config.ControlPlaneConfig{
			PollTimeout:           2 * time.Second,
			PollDeadlineGuardrail: time.Second,
		},
		Cloudflared: config.CloudflaredConfig{
			Token:        "configured-token",
			Managed:      true,
			ReadyTimeout: 7 * time.Second,
		},
	}

	got := cloudflaredStartTimeout(cfg)
	want := fx.DefaultTimeout + 7*time.Second
	if got != want {
		t.Fatalf("expected static-token startup timeout %s, got %s", want, got)
	}
}
