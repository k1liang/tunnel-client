package tunnelclient

import "testing"

func TestSDKTracingConfiguration(t *testing.T) {
	t.Parallel()
	for _, enabled := range []bool{false, true} {
		cfg, err := buildConfig(Config{
			TunnelID: "tunnel_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", APIKey: "synthetic-key",
			Tracing:             TracingConfig{Enabled: enabled, File: "local.jsonl"},
			ForwardTraceContext: enabled,
		})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Tracing.Enabled != enabled || cfg.Tracing.File != "local.jsonl" || cfg.ControlPlane.TraceContextEnabled != enabled || cfg.MCP.TraceContextEnabled != enabled || cfg.MCP.ForwardTraceContext != enabled {
			t.Fatal("SDK did not preserve tracing configuration and derived capability")
		}
	}
	if _, err := buildConfig(Config{
		TunnelID: "tunnel_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", APIKey: "synthetic-key",
		Tracing: TracingConfig{Enabled: true},
	}); err == nil {
		t.Fatal("SDK accepted enabled tracing without a destination")
	}
}
