package e2e_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/openai/tunnel-client/pkg/config"
	"github.com/openai/tunnel-client/pkg/runtimeconfig"
	harnesspkg "github.com/openai/tunnel-client/testsupport/e2e"
	"github.com/openai/tunnel-client/testsupport/mockmcpserver"
	"github.com/openai/tunnel-client/testsupport/mocktunnelservice"
)

// These scenarios exercise the actual poll, dispatch, and outbound HTTP paths.
// The queue and JSON-RPC IDs deliberately differ from the incoming HTTP ID.
func TestRequestIDForwardingMCPE2E(t *testing.T) {

	for _, tc := range []struct {
		name     string
		surfaces runtimeconfig.RequestIDForwarding
		want     string
	}{
		{name: "default MCP", want: "original-mcp"},
		{name: "none", surfaces: runtimeconfig.ForwardRequestIDNone},
		{name: "harpoon only", surfaces: runtimeconfig.ForwardRequestIDHarpoon},
		{name: "MCP and Harpoon", surfaces: runtimeconfig.ForwardRequestIDMCP | runtimeconfig.ForwardRequestIDHarpoon, want: "original-mcp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			commands := []mocktunnelservice.CommandResponse{
				requestIDMCPCommand("original", http.Header{"X-Request-Id": {"original-mcp"}}),
				requestIDMCPCommand("missing", nil),
			}
			h := harnesspkg.NewHarness(t,
				harnesspkg.WithClientConfig(func(cfg *config.Config) {
					cfg.MCP.ForwardRequestID = tc.surfaces
				}),
				harnesspkg.WithControlPlaneOptions(
					mocktunnelservice.WithSessionHeaderPropagation(),
					mocktunnelservice.WithInitializationPhaseCommands(),
					mocktunnelservice.WithCommandResponses(commands...),
				),
				harnesspkg.WithMCPOptions(mockmcpserver.WithCalls(
					mockmcpserver.Call{Tool: "echo", Result: json.RawMessage(`{"ok":true}`)},
					mockmcpserver.Call{Tool: "echo", Result: json.RawMessage(`{"ok":true}`)},
				)),
			)
			h.ExecuteScenarious(t)

			got := make(map[string]string)
			for _, req := range h.MCP.ReceivedRequests() {
				var args struct {
					Name string `json:"name"`
				}
				if err := json.Unmarshal(req.Arguments, &args); err != nil {
					t.Fatalf("decode MCP tool arguments: %v", err)
				}
				if _, exists := got[args.Name]; exists {
					t.Fatalf("duplicate MCP tool call for %q", args.Name)
				}
				got[args.Name] = req.Headers.Get("X-Request-Id")
			}
			if len(got) != 2 || got["original"] != tc.want || got["missing"] != "" {
				t.Fatalf("MCP tool request IDs = %v, want original %q and missing empty", got, tc.want)
			}
			assertNoOriginalRequestIDOnControlPlane(t, h.ControlPlane.ReceivedHTTPRequests(), "original-mcp")
		})
	}
}

func requestIDMCPCommand(name string, headers http.Header) mocktunnelservice.CommandResponse {
	queueID := "cmd-mcp-" + name
	rpcID := "rpc-mcp-" + name
	payload := json.RawMessage(fmt.Sprintf(`{"jsonrpc":"2.0","id":%q,"method":"tools/call","params":{"name":"echo","arguments":{"name":%q}}}`, rpcID, name))
	return mocktunnelservice.CommandResponse{
		Command: mocktunnelservice.NewCommand(queueID, payload, headers),
		ExpectedResponses: []mocktunnelservice.ExpectedResponse{{
			RequestID: queueID,
			Assert: func(tb testing.TB, resp mocktunnelservice.ReceivedResponse) {
				tb.Helper()
				if resp.ResponseCode != http.StatusOK || len(resp.JSONResponse) == 0 {
					tb.Fatalf("MCP %s response: status %d, JSON %s", name, resp.ResponseCode, resp.JSONResponse)
				}
			},
		}},
	}
}

func TestRequestIDForwardingHarpoonE2E(t *testing.T) {

	for _, tc := range []struct {
		name     string
		surfaces runtimeconfig.RequestIDForwarding
		want     string
	}{
		{name: "default MCP"},
		{name: "none", surfaces: runtimeconfig.ForwardRequestIDNone},
		{name: "Harpoon only", surfaces: runtimeconfig.ForwardRequestIDHarpoon, want: "original-harpoon"},
		{name: "MCP and Harpoon", surfaces: runtimeconfig.ForwardRequestIDMCP | runtimeconfig.ForwardRequestIDHarpoon, want: "original-harpoon"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			type outbound struct{ path, requestID string }
			seen := make(chan outbound, 3)
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				seen <- outbound{path: req.URL.Path, requestID: req.Header.Get("X-Request-Id")}
				_, _ = w.Write([]byte("ok"))
			}))
			defer target.Close()

			commands := []mocktunnelservice.CommandResponse{
				requestIDHarpoonCommand("original", http.Header{"X-Request-Id": {"original-harpoon"}}, nil),
				requestIDHarpoonCommand("missing", nil, nil),
				requestIDHarpoonCommand("caller", http.Header{"X-Request-Id": {"original-caller"}}, map[string]string{"x-request-id": "caller-owned"}),
			}
			h := harnesspkg.NewHarness(t,
				harnesspkg.WithHarpoonInMemoryTransport(),
				harnesspkg.WithClientConfig(func(cfg *config.Config) {
					cfg.MCP.ForwardRequestID = tc.surfaces
					cfg.Harpoon.AllowPlaintextHTTP = true
					cfg.Harpoon.MaxResponseBytes = config.DefaultHarpoonMaxResponseBytes
					cfg.Harpoon.MaxRedirects = config.DefaultHarpoonMaxRedirects
					for _, name := range []string{"original", "missing", "caller"} {
						cfg.Harpoon.Targets = append(cfg.Harpoon.Targets, config.HarpoonTarget{
							Label: name, BaseURL: mustParseURL(t, target.URL+"/"+name),
						})
					}
				}),
				harnesspkg.WithControlPlaneOptions(
					mocktunnelservice.WithInitializationPhaseCommandsWithoutSessionHeaders(),
					mocktunnelservice.WithCommandResponses(commands...),
				),
			)
			h.ExecuteScenarious(t)

			got := make(map[string]string)
			for range commands {
				request := <-seen
				if _, exists := got[request.path]; exists {
					t.Fatalf("duplicate Harpoon egress at %q", request.path)
				}
				got[request.path] = request.requestID
			}
			if len(got) != 3 || got["/original"] != tc.want || got["/missing"] != "" || got["/caller"] != "caller-owned" {
				t.Fatalf("Harpoon request IDs = %v, want original %q, missing empty, caller caller-owned", got, tc.want)
			}
			assertNoOriginalRequestIDOnControlPlane(t, h.ControlPlane.ReceivedHTTPRequests(), "original-harpoon")
		})
	}
}

func requestIDHarpoonCommand(name string, headers http.Header, callerHeaders map[string]string) mocktunnelservice.CommandResponse {
	queueID := "cmd-harpoon-" + name
	rpcID := "rpc-harpoon-" + name
	args := map[string]any{"label": name, "method": http.MethodGet}
	if len(callerHeaders) > 0 {
		args["headers"] = callerHeaders
	}
	payload, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": rpcID, "method": "tools/call",
		"params": map[string]any{
			"name": "call_target", "arguments": args,
			"_meta": map[string]any{
				"io.modelcontextprotocol/protocolVersion":    "2026-07-28",
				"io.modelcontextprotocol/clientInfo":         map[string]any{"name": "request-id-e2e", "version": "test"},
				"io.modelcontextprotocol/clientCapabilities": map[string]any{},
			},
		},
	})
	return mocktunnelservice.CommandResponse{
		Command: newChannelCommand(queueID, "harpoon", payload, headers),
		ExpectedResponses: []mocktunnelservice.ExpectedResponse{{
			RequestID: queueID,
			Assert: func(tb testing.TB, resp mocktunnelservice.ReceivedResponse) {
				tb.Helper()
				if resp.ResponseCode != http.StatusOK || len(resp.JSONResponse) == 0 || strings.Contains(string(resp.JSONResponse), `"error"`) {
					tb.Fatalf("Harpoon %s response: status %d, JSON %s", name, resp.ResponseCode, resp.JSONResponse)
				}
			},
		}},
	}
}

func TestRequestIDForwardingQueuedOAuthE2E(t *testing.T) {

	for _, tc := range []struct {
		name     string
		surfaces runtimeconfig.RequestIDForwarding
		original string
		want     string
	}{
		{name: "default MCP", original: "original-oauth"},
		{name: "none", surfaces: runtimeconfig.ForwardRequestIDNone, original: "original-oauth"},
		{name: "OAuth opt in", surfaces: runtimeconfig.ForwardRequestIDOAuth, original: "original-oauth", want: "original-oauth"},
		{name: "OAuth without original", surfaces: runtimeconfig.ForwardRequestIDOAuth},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var headers http.Header
			if tc.original != "" {
				headers = http.Header{"X-Request-Id": {tc.original}}
			}
			const queueID = "cmd-oauth-discovery"
			h := harnesspkg.NewHarness(t,
				harnesspkg.WithClientConfig(func(cfg *config.Config) {
					cfg.MCP.ForwardRequestID = tc.surfaces
				}),
				harnesspkg.WithControlPlaneOptions(mocktunnelservice.WithCommandResponses(mocktunnelservice.CommandResponse{
					Command: mocktunnelservice.NewOAuthDiscoveryCommand(queueID, headers),
					ExpectedResponses: []mocktunnelservice.ExpectedResponse{{
						RequestID: queueID,
						Assert: func(tb testing.TB, resp mocktunnelservice.ReceivedResponse) {
							tb.Helper()
							if resp.ResponseCode != http.StatusOK {
								tb.Fatalf("OAuth discovery status = %d, want 200", resp.ResponseCode)
							}
						},
					}},
				})),
				harnesspkg.WithMCPOptions(mockmcpserver.WithHostHandler("127.0.0.1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/.well-known/oauth-protected-resource" {
						w.Header().Set("Content-Type", "application/json")
						_, _ = fmt.Fprintf(w, `{"resource":"http://%s"}`, r.Host)
						return
					}
					w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="http://%s/.well-known/oauth-protected-resource"`, r.Host))
					w.WriteHeader(http.StatusUnauthorized)
				}))),
			)
			h.ExecuteScenarious(t)

			var metadataIDs []string
			for _, req := range h.MCP.ReceivedHTTPRequests() {
				if req.Path != "/.well-known/oauth-protected-resource" {
					continue
				}
				metadataIDs = append(metadataIDs, req.Headers.Get("X-Request-Id"))
			}
			if len(metadataIDs) == 0 {
				t.Fatal("queued OAuth command made no protected-resource metadata request")
			}
			if tc.want != "" && !slices.Contains(metadataIDs, tc.want) {
				t.Fatalf("OAuth metadata request IDs = %q, want queued request %q", metadataIDs, tc.want)
			}
			for _, got := range metadataIDs {
				if got != "" && got != tc.want {
					t.Fatalf("OAuth metadata request ID = %q, want empty startup ID or %q", got, tc.want)
				}
			}
			assertNoOriginalRequestIDOnControlPlane(t, h.ControlPlane.ReceivedHTTPRequests(), tc.original)
		})
	}
}

func assertNoOriginalRequestIDOnControlPlane(t *testing.T, requests []mocktunnelservice.IncomingHTTPRequest, original string) {
	t.Helper()
	if len(requests) == 0 {
		t.Fatal("client made no control-plane HTTP requests")
	}
	if original == "" {
		return
	}
	for _, req := range requests {
		if got := req.Headers.Get("X-Request-Id"); got == original {
			t.Fatalf("client sent original request ID to control-plane %s %s", req.Method, req.Path)
		}
	}
}
