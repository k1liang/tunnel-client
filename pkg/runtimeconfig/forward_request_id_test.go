package runtimeconfig

import (
	"strings"
	"testing"
)

func TestForwardRequestIDPrecedenceAcrossFlavors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		yaml string
		env  *string
		flag *string
		want RequestIDForwarding
	}{
		{name: "default", want: ForwardRequestIDMCP},
		{name: "yaml scalar", yaml: "forward_request_id: mcp,harpoon\n", want: ForwardRequestIDMCP | ForwardRequestIDHarpoon},
		{name: "yaml list", yaml: "forward_request_id: [harpoon]\n", want: ForwardRequestIDHarpoon},
		{name: "yaml oauth only", yaml: "forward_request_id: [oauth]\n", want: ForwardRequestIDOAuth},
		{name: "yaml all named surfaces", yaml: "forward_request_id: [mcp, harpoon, oauth]\n", want: ForwardRequestIDMCP | ForwardRequestIDHarpoon | ForwardRequestIDOAuth},
		{name: "yaml none", yaml: "forward_request_id: none\n", want: ForwardRequestIDNone},
		{name: "environment oauth only", env: requestIDForwardingValue("oauth"), want: ForwardRequestIDOAuth},
		{name: "environment oauth replaces yaml", yaml: "forward_request_id: [mcp, harpoon]\n", env: requestIDForwardingValue("oauth"), want: ForwardRequestIDOAuth},
		{name: "environment replaces yaml", yaml: "forward_request_id: mcp,harpoon\n", env: requestIDForwardingValue("harpoon"), want: ForwardRequestIDHarpoon},
		{name: "environment overrides invalid yaml", yaml: "forward_request_id: [none, mcp]\n", env: requestIDForwardingValue("harpoon"), want: ForwardRequestIDHarpoon},
		{name: "flag replaces environment", yaml: "forward_request_id: harpoon\n", env: requestIDForwardingValue("mcp,harpoon"), flag: requestIDForwardingValue("none"), want: ForwardRequestIDNone},
		{name: "flag overrides invalid yaml", yaml: "forward_request_id: [none, mcp]\n", flag: requestIDForwardingValue("none"), want: ForwardRequestIDNone},
		{name: "flag harpoon only", flag: requestIDForwardingValue("harpoon"), want: ForwardRequestIDHarpoon},
		{name: "flag both with duplicates", flag: requestIDForwardingValue("mcp, harpoon,mcp"), want: ForwardRequestIDMCP | ForwardRequestIDHarpoon},
		{name: "flag oauth only", flag: requestIDForwardingValue("oauth"), want: ForwardRequestIDOAuth},
		{name: "flag oauth replaces environment", env: requestIDForwardingValue("mcp,harpoon"), flag: requestIDForwardingValue("oauth"), want: ForwardRequestIDOAuth},
		{name: "flag oauth with duplicates", flag: requestIDForwardingValue("mcp,oauth, oauth"), want: ForwardRequestIDMCP | ForwardRequestIDOAuth},
	}
	for _, flavor := range []Flavor{FlavorFull, FlavorRuntime, FlavorRuntimeCloudflared} {
		for _, test := range tests {
			t.Run(string(flavor)+"/"+test.name, func(t *testing.T) {
				t.Parallel()
				args := []string{}
				if test.yaml != "" {
					args = append(args, "--config", writeRuntimeConfig(t, test.yaml))
				}
				if test.flag != nil {
					args = append(args, "--forward-request-id="+*test.flag)
				}
				env := map[string]string{
					"CONTROL_PLANE_TUNNEL_ID": testTunnelID,
					"CONTROL_PLANE_API_KEY":   testAPIKey,
					"MCP_COMMAND":             "echo",
				}
				if test.env != nil {
					env["FORWARD_REQUEST_ID"] = *test.env
				}
				cfg, err := Load(args, flavor, lookupEnvMap(env))
				if err != nil {
					t.Fatal(err)
				}
				if cfg.MCP.ForwardRequestID != test.want {
					t.Fatalf("ForwardRequestID = %v, want %v", cfg.MCP.ForwardRequestID, test.want)
				}
			})
		}
	}
}

func TestForwardRequestIDRejectsInvalidValuesAcrossFlavors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		flag *string
		env  *string
		yaml string
	}{
		{name: "empty flag", flag: requestIDForwardingValue("")},
		{name: "unknown flag", flag: requestIDForwardingValue("other")},
		{name: "all is unsupported", flag: requestIDForwardingValue("all")},
		{name: "none mixed", flag: requestIDForwardingValue("none,mcp")},
		{name: "none mixed with oauth", flag: requestIDForwardingValue("none,oauth")},
		{name: "empty list member", flag: requestIDForwardingValue("mcp,")},
		{name: "empty environment", env: requestIDForwardingValue("")},
		{name: "unknown environment", env: requestIDForwardingValue("other")},
		{name: "empty yaml scalar", yaml: "forward_request_id: ''\n"},
		{name: "null yaml", yaml: "forward_request_id: null\n"},
		{name: "empty yaml list", yaml: "forward_request_id: []\n"},
		{name: "unknown yaml", yaml: "forward_request_id: [mcp, other]\n"},
		{name: "none mixed in yaml", yaml: "forward_request_id: [none, harpoon]\n"},
		{name: "none mixed with oauth in yaml", yaml: "forward_request_id: [oauth, none]\n"},
	}
	for _, flavor := range []Flavor{FlavorFull, FlavorRuntime, FlavorRuntimeCloudflared} {
		for _, test := range tests {
			t.Run(string(flavor)+"/"+test.name, func(t *testing.T) {
				t.Parallel()
				args := []string{}
				if test.yaml != "" {
					args = append(args, "--config", writeRuntimeConfig(t, test.yaml))
				}
				if test.flag != nil {
					args = append(args, "--forward-request-id="+*test.flag)
				}
				env := map[string]string{
					"CONTROL_PLANE_TUNNEL_ID": testTunnelID,
					"CONTROL_PLANE_API_KEY":   testAPIKey,
					"MCP_COMMAND":             "echo",
				}
				if test.env != nil {
					env["FORWARD_REQUEST_ID"] = *test.env
				}
				_, err := Load(args, flavor, lookupEnvMap(env))
				if err == nil || !strings.Contains(err.Error(), "forward_request_id") && !strings.Contains(err.Error(), "FORWARD_REQUEST_ID") {
					t.Fatalf("expected request ID forwarding error, got %v", err)
				}
			})
		}
	}
}

func TestForwardRequestIDFlagOverridesInvalidEnvironment(t *testing.T) {
	t.Parallel()

	for _, flavor := range []Flavor{FlavorFull, FlavorRuntime, FlavorRuntimeCloudflared} {
		t.Run(string(flavor), func(t *testing.T) {
			t.Parallel()
			cfg, err := Load([]string{"--forward-request-id=none"}, flavor, lookupEnvMap(map[string]string{
				"CONTROL_PLANE_TUNNEL_ID": testTunnelID,
				"CONTROL_PLANE_API_KEY":   testAPIKey,
				"MCP_COMMAND":             "echo",
				"FORWARD_REQUEST_ID":      "invalid",
			}))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.MCP.ForwardRequestID != ForwardRequestIDNone {
				t.Fatalf("ForwardRequestID = %v, want none", cfg.MCP.ForwardRequestID)
			}
		})
	}
}

func TestRequestIDForwardingZeroValuePreservesMCP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value   RequestIDForwarding
		mcp     bool
		harpoon bool
		oauth   bool
	}{
		{value: 0, mcp: true},
		{value: ForwardRequestIDMCP, mcp: true},
		{value: ForwardRequestIDHarpoon, harpoon: true},
		{value: ForwardRequestIDMCP | ForwardRequestIDHarpoon, mcp: true, harpoon: true},
		{value: ForwardRequestIDOAuth, oauth: true},
		{value: ForwardRequestIDMCP | ForwardRequestIDHarpoon | ForwardRequestIDOAuth, mcp: true, harpoon: true, oauth: true},
		{value: ForwardRequestIDNone},
	}
	for _, test := range tests {
		if test.value.AllowsMCP() != test.mcp || test.value.AllowsHarpoon() != test.harpoon || test.value.AllowsOAuth() != test.oauth {
			t.Errorf("forwarding %v: MCP=%v, Harpoon=%v, OAuth=%v; want MCP=%v, Harpoon=%v, OAuth=%v", test.value, test.value.AllowsMCP(), test.value.AllowsHarpoon(), test.value.AllowsOAuth(), test.mcp, test.harpoon, test.oauth)
		}
	}
}

func requestIDForwardingValue(value string) *string { return &value }
