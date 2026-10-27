package dispatcherinternal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"github.com/openai/tunnel-client/pkg/mcpclient"
	"github.com/openai/tunnel-client/pkg/runtimeconfig"
	"github.com/openai/tunnel-client/pkg/runtimeharpoon"
	"github.com/openai/tunnel-client/pkg/types"
)

func TestProcessorSelectsMCPRequestIDForwarding(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		surfaces runtimeconfig.RequestIDForwarding
		id       string
		wantID   string
	}{
		{name: "default", id: "original-default", wantID: "original-default"},
		{name: "mcp", surfaces: runtimeconfig.ForwardRequestIDMCP, id: "original-mcp", wantID: "original-mcp"},
		{name: "both", surfaces: runtimeconfig.ForwardRequestIDMCP | runtimeconfig.ForwardRequestIDHarpoon, id: "original-both", wantID: "original-both"},
		{name: "harpoon only", surfaces: runtimeconfig.ForwardRequestIDHarpoon, id: "original-harpoon-only"},
		{name: "none", surfaces: runtimeconfig.ForwardRequestIDNone, id: "original-none"},
		{name: "missing original", id: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			id, err := jsonrpc.MakeID("rpc-id")
			require.NoError(t, err)
			conn := &stubForwardingConnection{
				statusCode: http.StatusOK,
				response:   &jsonrpc.Response{ID: id, Result: json.RawMessage(`{"ok":true}`)},
			}
			transport := &stubForwardingTransport{conn: conn}
			bindings := newTestChannelBindings(transport)
			main := bindings[types.DefaultChannel]
			main.TransportKind = runtimeconfig.MCPTransportHTTPStreamable
			bindings[types.DefaultChannel] = main
			cfg := newTestMCPConfig(t, time.Second)
			cfg.ForwardRequestID = tc.surfaces
			responder := newRecordingResponder()
			processor, err := NewProcessor(processorParams{
				Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
				ChannelBindings: bindings,
				TunnelResponder: responder,
				MCPConfig:       cfg,
				OAuthHTTPClient: &http.Client{},
				ControlPlaneCfg: newTestControlPlaneConfig(t),
				MeterProvider:   newTestMeterProvider(t),
			})
			require.NoError(t, err)

			headers := http.Header{"X-Test": {"keep"}}
			if tc.id != "" {
				headers.Set("X-Request-Id", tc.id)
			}
			command := &fakePolledCommand{
				id:         "cmd_queue_id_must_not_be_forwarded",
				message:    &jsonrpc.Request{ID: id, Method: "ping"},
				enqueuedAt: time.Now(),
				polledAt:   time.Now(),
				headers:    headers,
				shardToken: "shard-request-id",
			}
			require.NoError(t, processor.Process(context.Background(), command))
			_ = responder.waitForResponse(t)
			require.Equal(t, tc.wantID, conn.writeHeaders.Get("X-Request-Id"))
			require.Equal(t, "keep", conn.writeHeaders.Get("X-Test"))
			require.Equal(t, tc.id, headers.Get("X-Request-Id"), "command headers must remain unchanged")
		})
	}
}

func TestProcessorSelectsSessionTerminationRequestIDForwarding(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		surfaces runtimeconfig.RequestIDForwarding
		wantID   string
	}{
		{name: "default", wantID: "original-id"},
		{name: "none", surfaces: runtimeconfig.ForwardRequestIDNone},
		{name: "harpoon only", surfaces: runtimeconfig.ForwardRequestIDHarpoon},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			transport := &sessionTerminatingForwardingTransport{statusCode: http.StatusOK}
			bindings := newTestChannelBindings(transport)
			cfg := newTestMCPConfig(t, time.Second)
			cfg.ForwardRequestID = tc.surfaces
			responder := newRecordingResponder()
			processor, err := NewProcessor(processorParams{
				Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
				ChannelBindings: bindings,
				TunnelResponder: responder,
				MCPConfig:       cfg,
				OAuthHTTPClient: &http.Client{},
				ControlPlaneCfg: newTestControlPlaneConfig(t),
				MeterProvider:   newTestMeterProvider(t),
			})
			require.NoError(t, err)
			headers := http.Header{"X-Request-Id": {"original-id"}, "Mcp-Session-Id": {"session-id"}}
			command := &fakeSessionTerminationCommand{
				id: "cmd_queue_id", enqueuedAt: time.Now(), polledAt: time.Now(),
				headers: headers, shardToken: "shard-request-id",
			}
			require.NoError(t, processor.Process(context.Background(), command))
			_ = responder.waitForResponse(t)
			require.Equal(t, tc.wantID, transport.terminationHeaders.Get("X-Request-Id"))
			require.Equal(t, "session-id", transport.terminationHeaders.Get("Mcp-Session-Id"))
			require.Equal(t, "original-id", headers.Get("X-Request-Id"))
		})
	}
}

func TestProcessorSelectsQueuedOAuthDiscoveryRequestID(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		surfaces runtimeconfig.RequestIDForwarding
		original string
		want     string
	}{
		{name: "default excludes oauth", original: "original-default"},
		{name: "oauth only", surfaces: runtimeconfig.ForwardRequestIDOAuth, original: "original-oauth", want: "original-oauth"},
		{name: "mcp and oauth", surfaces: runtimeconfig.ForwardRequestIDMCP | runtimeconfig.ForwardRequestIDOAuth, original: "original-both", want: "original-both"},
		{name: "missing original", surfaces: runtimeconfig.ForwardRequestIDOAuth},
		{name: "none", surfaces: runtimeconfig.ForwardRequestIDNone, original: "original-none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			seen := make(chan string, 2)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Header.Get("X-Request-Id")
				if r.URL.Path == "/mcp" {
					w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="http://%s/metadata"`, r.Host))
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"resource":"http://%s/mcp"}`, r.Host)
			}))
			t.Cleanup(server.Close)
			endpoint, err := url.Parse(server.URL + "/mcp")
			require.NoError(t, err)
			cfg := newTestMCPConfig(t, time.Second)
			cfg.ServerURL = endpoint
			cfg.ForwardRequestID = tc.surfaces
			responder := newRecordingResponder()
			processor, err := NewProcessor(processorParams{
				Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
				ChannelBindings: newTestChannelBindings(&stubForwardingTransport{conn: &stubForwardingConnection{}}),
				TunnelResponder: responder,
				MCPConfig:       cfg,
				OAuthHTTPClient: server.Client(),
				ControlPlaneCfg: newTestControlPlaneConfig(t),
				MeterProvider:   newTestMeterProvider(t),
			})
			require.NoError(t, err)
			headers := make(http.Header)
			if tc.original != "" {
				headers.Set("X-Request-Id", tc.original)
			}
			cmd := &fakeOauthDiscoveryCommand{
				id: "cmd_queue_id_must_not_be_forwarded", enqueuedAt: time.Now(), polledAt: time.Now(),
				headers: headers, shardToken: "shard-oauth-request-id",
			}
			require.NoError(t, processor.Process(context.Background(), cmd))
			_ = responder.waitForResponse(t)
			require.Len(t, seen, 2)
			require.Equal(t, tc.want, <-seen)
			require.Equal(t, tc.want, <-seen)
		})
	}
}

func TestProcessorOAuthOnlyDoesNotForwardHarpoonCallTargetRequestID(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		surfaces runtimeconfig.RequestIDForwarding
		original string
		want     string
	}{
		{name: "oauth only without original ID", surfaces: runtimeconfig.ForwardRequestIDOAuth},
		{name: "oauth only with original ID", surfaces: runtimeconfig.ForwardRequestIDOAuth, original: "req_original"},
		{name: "harpoon without original ID", surfaces: runtimeconfig.ForwardRequestIDHarpoon},
		{name: "harpoon with original ID", surfaces: runtimeconfig.ForwardRequestIDHarpoon, original: "req_original", want: "req_original"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			seen := make(chan string, 1)
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Header.Get("X-Request-Id")
				w.WriteHeader(http.StatusNoContent)
			}))
			t.Cleanup(target.Close)
			endpoint, err := url.Parse(target.URL + "/oauth/token")
			require.NoError(t, err)
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			registry, err := runtimeharpoon.NewRegistry(logger, true, []runtimeharpoon.Target{{
				Label: "oauth-token", BaseURL: endpoint,
			}})
			require.NoError(t, err)
			harpoonServer, err := runtimeharpoon.NewServer(&runtimeconfig.HarpoonConfig{
				AllowPlaintextHTTP: true, MaxResponseBytes: 1024,
			}, registry, logger)
			require.NoError(t, err)
			serverCtx, stopServer := context.WithCancel(context.Background())
			t.Cleanup(stopServer)
			bindings := newTestChannelBindings(&stubForwardingTransport{conn: &stubForwardingConnection{}})
			bindings[types.ChannelHarpoon] = ChannelBinding{
				Transport: mcpclient.NewForwardingTransport(runtimeharpoon.NewRestartableInMemoryTransport(
					serverCtx, harpoonServer.MCPServer(), logger,
				)),
				Routable:    func() bool { return registry.Count() > 0 },
				SupportsMCP: true,
			}
			cfg := newTestMCPConfig(t, 5*time.Second)
			cfg.ForwardRequestID = tc.surfaces
			responder := newRecordingResponder()
			processor, err := NewProcessor(processorParams{
				Logger: logger, ChannelBindings: bindings, TunnelResponder: responder,
				MCPConfig: cfg, OAuthHTTPClient: &http.Client{},
				ControlPlaneCfg: newTestControlPlaneConfig(t), MeterProvider: newTestMeterProvider(t),
			})
			require.NoError(t, err)

			// A service OAuth shim arrives as a Harpoon tools/call command. Without
			// additional protocol provenance, its OAuth-shaped arguments do not
			// grant the oauth surface permission to forward an ID to REST egress.
			params, err := json.Marshal(map[string]any{
				"name": "call_target",
				"arguments": map[string]any{
					"label": "oauth-token", "method": http.MethodPost,
				},
				"_meta": map[string]any{
					mcp.MetaKeyProtocolVersion:    "2026-07-28",
					mcp.MetaKeyClientInfo:         map[string]any{"name": "oauth-shim", "version": "test"},
					mcp.MetaKeyClientCapabilities: map[string]any{},
				},
			})
			require.NoError(t, err)
			rpcID, err := jsonrpc.MakeID("rpc_id_must_not_be_forwarded")
			require.NoError(t, err)
			headers := make(http.Header)
			if tc.original != "" {
				headers.Set("X-Request-Id", tc.original)
			}
			command := &fakePolledCommand{
				id: "cmd_queue_id_must_not_be_forwarded", message: &jsonrpc.Request{
					ID: rpcID, Method: "tools/call", Params: params,
				},
				enqueuedAt: time.Now(), polledAt: time.Now(), headers: headers,
				shardToken: "shard-oauth-shim", channel: types.ChannelHarpoon,
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			require.NoError(t, processor.Process(ctx, command))
			posted := responder.waitForResponse(t)
			require.Equal(t, command.id, posted.requestID)
			require.Nil(t, decodeJSONRPCResponse(t, posted.response.Payload()).Error)
			select {
			case outboundID := <-seen:
				require.Equal(t, tc.want, outboundID)
			case <-ctx.Done():
				t.Fatal("Harpoon target did not receive the OAuth-shaped call")
			}
		})
	}
}
