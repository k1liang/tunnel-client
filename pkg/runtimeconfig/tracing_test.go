package runtimeconfig

import (
	"maps"
	"strings"
	"testing"
)

func TestTracingPrecedenceAcrossFlavors(t *testing.T) {
	t.Parallel()
	for _, flavor := range []Flavor{FlavorFull, FlavorRuntime, FlavorRuntimeCloudflared} {
		for _, test := range []struct {
			name    string
			yaml    string
			env     map[string]string
			args    []string
			enabled bool
			file    string
		}{
			{name: "default"},
			{name: "path-does-not-enable", env: map[string]string{"TRACING_FILE": "env.jsonl"}, file: "env.jsonl"},
			{name: "yaml", yaml: "  enabled: true\n  file: yaml.jsonl\n", enabled: true, file: "yaml.jsonl"},
			{name: "environment", yaml: "  enabled: false\n  file: yaml.jsonl\n", env: map[string]string{"TRACING_ENABLED": "true", "TRACING_FILE": "env.jsonl"}, enabled: true, file: "env.jsonl"},
			{name: "environment-false", yaml: "  enabled: true\n  file: yaml.jsonl\n", env: map[string]string{"TRACING_ENABLED": "false"}, file: "yaml.jsonl"},
			{name: "flag-false", yaml: "  enabled: true\n  file: yaml.jsonl\n", env: map[string]string{"TRACING_ENABLED": "true"}, args: []string{"--tracing.enabled=false"}, file: "yaml.jsonl"},
			{name: "flag-true", env: map[string]string{"TRACING_ENABLED": "false", "TRACING_FILE": "env.jsonl"}, args: []string{"--tracing.enabled", "--tracing.file=flag.jsonl"}, enabled: true, file: "flag.jsonl"},
			{name: "flag-clears-file", env: map[string]string{"TRACING_FILE": "env.jsonl"}, args: []string{"--tracing.file="}},
		} {
			t.Run(string(flavor)+"/"+test.name, func(t *testing.T) {
				t.Parallel()
				env := map[string]string{"CONTROL_PLANE_TUNNEL_ID": testTunnelID, "CONTROL_PLANE_API_KEY": testAPIKey, "MCP_COMMAND": "echo"}
				maps.Copy(env, test.env)
				args := append([]string{}, test.args...)
				if test.yaml != "" {
					args = append(args, "--config", writeRuntimeConfig(t, "tracing:\n"+test.yaml))
				}
				cfg, err := Load(args, flavor, lookupEnvMap(env))
				if err != nil {
					t.Fatal(err)
				}
				if cfg.Tracing.Enabled != test.enabled || cfg.Tracing.File != test.file || cfg.ControlPlane.TraceContextEnabled != test.enabled || cfg.MCP.TraceContextEnabled != test.enabled {
					t.Fatalf("unexpected tracing/capability configuration: %+v %v", cfg.Tracing, cfg.ControlPlane.TraceContextEnabled)
				}
			})
		}
	}
}

func TestTracingRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()
	for _, flavor := range []Flavor{FlavorFull, FlavorRuntime, FlavorRuntimeCloudflared} {
		t.Run(string(flavor), func(t *testing.T) {
			t.Parallel()
			env := map[string]string{"CONTROL_PLANE_TUNNEL_ID": testTunnelID, "CONTROL_PLANE_API_KEY": testAPIKey, "MCP_COMMAND": "echo", "TRACING_ENABLED": "invalid"}
			if _, err := Load(nil, flavor, lookupEnvMap(env)); err == nil || !strings.Contains(err.Error(), "TRACING_ENABLED") {
				t.Fatalf("expected invalid boolean: %v", err)
			}
			if _, err := Load([]string{"--tracing.enabled=false"}, flavor, lookupEnvMap(env)); err != nil {
				t.Fatal(err)
			}
			env["TRACING_ENABLED"] = "true"
			for _, file := range []string{"", "  "} {
				env["TRACING_FILE"] = file
				if _, err := Load(nil, flavor, lookupEnvMap(env)); err == nil || !strings.Contains(err.Error(), "tracing.file") {
					t.Fatalf("expected missing file: %v", err)
				}
			}
		})
	}
}
