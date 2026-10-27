package runtimeconfig

import (
	"strings"
	"testing"
)

func TestStdioFailurePolicyPrecedenceAcrossFlavors(t *testing.T) {
	t.Parallel()

	for _, flavor := range []Flavor{FlavorFull, FlavorRuntime, FlavorRuntimeCloudflared} {
		for _, tc := range []struct {
			name, yaml, flag string
			env              *string
			want             StdioFailurePolicy
		}{
			{name: "default", want: StdioFailurePolicyRestart},
			{name: "yaml-exit", yaml: "exit", want: StdioFailurePolicyExit},
			{name: "yaml-restart", yaml: "restart", want: StdioFailurePolicyRestart},
			{name: "environment-exit", yaml: "restart", env: stdioPolicyEnvValue("exit"), want: StdioFailurePolicyExit},
			{name: "environment-restart", yaml: "exit", env: stdioPolicyEnvValue("restart"), want: StdioFailurePolicyRestart},
			{name: "environment-empty", yaml: "exit", env: stdioPolicyEnvValue(""), want: StdioFailurePolicyRestart},
			{name: "flag-exit", yaml: "restart", env: stdioPolicyEnvValue("restart"), flag: "exit", want: StdioFailurePolicyExit},
			{name: "flag-restart", yaml: "exit", env: stdioPolicyEnvValue("exit"), flag: "restart", want: StdioFailurePolicyRestart},
		} {
			t.Run(string(flavor)+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				var args []string
				if tc.yaml != "" {
					args = append(args, "--config", writeRuntimeConfig(t, "mcp:\n  stdio_failure_policy: "+tc.yaml+"\n"))
				}
				if tc.flag != "" {
					args = append(args, "--mcp.stdio-failure-policy="+tc.flag)
				}
				env := map[string]string{"CONTROL_PLANE_TUNNEL_ID": testTunnelID, "CONTROL_PLANE_API_KEY": testAPIKey, "MCP_COMMAND": "echo"}
				if tc.env != nil {
					env["MCP_STDIO_FAILURE_POLICY"] = *tc.env
				}
				cfg, err := Load(args, flavor, lookupEnvMap(env))
				if err != nil {
					t.Fatal(err)
				}
				if cfg.MCP.StdioFailurePolicy != tc.want {
					t.Fatalf("StdioFailurePolicy = %q, want %q", cfg.MCP.StdioFailurePolicy, tc.want)
				}
			})
		}
	}
}

func TestStdioFailurePolicyRejectsInvalidValueUnlessOverridden(t *testing.T) {
	t.Parallel()

	for _, flavor := range []Flavor{FlavorFull, FlavorRuntime, FlavorRuntimeCloudflared} {
		t.Run(string(flavor), func(t *testing.T) {
			t.Parallel()
			env := map[string]string{
				"CONTROL_PLANE_TUNNEL_ID":  testTunnelID,
				"CONTROL_PLANE_API_KEY":    testAPIKey,
				"MCP_COMMAND":              "echo",
				"MCP_STDIO_FAILURE_POLICY": "unknown",
			}
			if _, err := Load(nil, flavor, lookupEnvMap(env)); err == nil || !strings.Contains(err.Error(), "MCP_STDIO_FAILURE_POLICY") {
				t.Fatalf("expected invalid environment policy error, got %v", err)
			}
			cfg, err := Load([]string{"--mcp.stdio-failure-policy=restart"}, flavor, lookupEnvMap(env))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.MCP.StdioFailurePolicy != StdioFailurePolicyRestart {
				t.Fatalf("StdioFailurePolicy = %q, want restart", cfg.MCP.StdioFailurePolicy)
			}
			if _, err := Load([]string{"--mcp.stdio-failure-policy=unknown"}, flavor, lookupEnvMap(env)); err == nil || !strings.Contains(err.Error(), "--mcp.stdio-failure-policy") {
				t.Fatalf("expected invalid flag policy error, got %v", err)
			}

			delete(env, "MCP_STDIO_FAILURE_POLICY")
			args := []string{"--config", writeRuntimeConfig(t, "mcp:\n  stdio_failure_policy: unknown\n")}
			if _, err := Load(args, flavor, lookupEnvMap(env)); err == nil || !strings.Contains(err.Error(), "MCP_STDIO_FAILURE_POLICY") {
				t.Fatalf("expected invalid YAML policy error, got %v", err)
			}
			args = append(args, "--mcp.stdio-failure-policy=exit")
			cfg, err = Load(args, flavor, lookupEnvMap(env))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.MCP.StdioFailurePolicy != StdioFailurePolicyExit {
				t.Fatalf("StdioFailurePolicy = %q, want exit", cfg.MCP.StdioFailurePolicy)
			}
		})
	}
}

func stdioPolicyEnvValue(value string) *string { return &value }
