package runtimeharpoon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"github.com/openai/tunnel-client/pkg/runtimeconfig"
	"github.com/openai/tunnel-client/pkg/tunnelctx"
	"github.com/openai/tunnel-client/pkg/types"
)

func TestHarpoonRequestIDBridgeIsPerWrittenCommand(t *testing.T) {
	t.Parallel()
	seen := make(chan string, 5)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get(forwardedRequestIDHeader)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)
	server := newRuntimeHarpoonSecurityServer(t, []Target{{Label: "target", BaseURL: runtimeHarpoonSecurityURL(t, target.URL)}})
	rootCtx, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	transport := newRestartableInMemoryTransport(rootCtx, server.MCPServer(), runtimeRegistryTestLogger())

	for _, tc := range []struct {
		name, originalID, queueID, want string
		enabled                         bool
	}{
		{name: "enabled", originalID: "req-original", queueID: "cmd-one", want: "req-original", enabled: true},
		{name: "disabled", originalID: "req-original", queueID: "cmd-two"},
		{name: "missing", queueID: "cmd-three", enabled: true},
		{name: "invalid", originalID: "bad\r\nid", queueID: "cmd-four", enabled: true},
		{name: "later request", originalID: "req-later", queueID: "cmd-five", want: "req-later", enabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ctx = tunnelctx.ContextWithRequestID(ctx, tc.queueID)
			ctx = tunnelctx.ContextWithControlPlaneCommandRequestID(ctx, types.ControlPlaneRequestID(tc.originalID))
			if tc.enabled {
				ctx = ContextWithForwardRequestID(ctx)
			}
			require.NoError(t, writeHarpoonCall(ctx, transport, tc.queueID, "target", nil))
			require.Equal(t, tc.want, <-seen)
		})
	}
}

func TestHarpoonRequestIDConcurrentConnectionsAreIsolated(t *testing.T) {
	t.Parallel()
	type observation struct{ path, id string }
	seen := make(chan observation, 2)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- observation{r.URL.Path, r.Header.Get(forwardedRequestIDHeader)}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)
	server := newRuntimeHarpoonSecurityServer(t, []Target{
		{Label: "first", BaseURL: runtimeHarpoonSecurityURL(t, target.URL+"/first")},
		{Label: "second", BaseURL: runtimeHarpoonSecurityURL(t, target.URL+"/second")},
	})
	rootCtx, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	transport := newRestartableInMemoryTransport(rootCtx, server.MCPServer(), runtimeRegistryTestLogger())
	var group sync.WaitGroup
	errs := make(chan error, 2)
	for _, tc := range []struct{ id, label string }{{"req-first", "first"}, {"req-second", "second"}} {
		group.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ctx = ContextWithForwardRequestID(tunnelctx.ContextWithControlPlaneCommandRequestID(ctx, types.ControlPlaneRequestID(tc.id)))
			errs <- writeHarpoonCall(ctx, transport, tc.id, tc.label, nil)
		})
	}
	group.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	first, second := <-seen, <-seen
	require.ElementsMatch(t, []observation{{"/first", "req-first"}, {"/second", "req-second"}}, []observation{first, second})
}

func TestHarpoonRequestIDSameConnectionClearsStaleValue(t *testing.T) {
	t.Parallel()
	seen := make(chan string, 3)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get(forwardedRequestIDHeader)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)
	server := newRuntimeHarpoonSecurityServer(t, []Target{{Label: "target", BaseURL: runtimeHarpoonSecurityURL(t, target.URL)}})
	rootCtx, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	transport := newRestartableInMemoryTransport(rootCtx, server.MCPServer(), runtimeRegistryTestLogger())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := transport.Connect(ctx)
	require.NoError(t, err)
	defer func() { require.NoError(t, connection.Close()) }()
	for _, tc := range []struct {
		id, want string
	}{
		{id: "req-first", want: "req-first"},
		{id: "", want: ""},
		{id: "req-third", want: "req-third"},
	} {
		callCtx := ContextWithForwardRequestID(ctx)
		if tc.id != "" {
			callCtx = tunnelctx.ContextWithControlPlaneCommandRequestID(callCtx, types.ControlPlaneRequestID(tc.id))
		}
		require.NoError(t, writeHarpoonCallOnConnection(callCtx, connection, "rpc-"+tc.id, "target", nil))
		require.Equal(t, tc.want, <-seen)
	}
}

func TestHarpoonRequestIDExactHeadersAndRedirectOrigins(t *testing.T) {
	t.Parallel()
	seen := make(chan struct{ path, id string }, 6)
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- struct{ path, id string }{r.URL.Path, r.Header.Get(forwardedRequestIDHeader)}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(other.Close)
	var sameURL string
	same := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- struct{ path, id string }{r.URL.Path, r.Header.Get(forwardedRequestIDHeader)}
		switch r.URL.Path {
		case "/same":
			http.Redirect(w, r, sameURL+"/final", http.StatusFound)
		case "/cross":
			http.Redirect(w, r, other.URL+"/final", http.StatusFound)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(same.Close)
	sameURL = same.URL
	server := newRuntimeHarpoonSecurityServer(t, []Target{
		{Label: "same", BaseURL: runtimeHarpoonSecurityURL(t, same.URL+"/same")},
		{Label: "cross", BaseURL: runtimeHarpoonSecurityURL(t, same.URL+"/cross")},
		{Label: "same-final", BaseURL: runtimeHarpoonSecurityURL(t, same.URL+"/final")},
		{Label: "other-final", BaseURL: runtimeHarpoonSecurityURL(t, other.URL+"/final")},
	})
	ctx := contextWithOutboundRequestID(context.Background(), "req-original")
	for _, tc := range []struct {
		label, explicit string
		wantSecond      string
	}{
		{label: "same", wantSecond: "req-original"},
		{label: "cross", wantSecond: ""},
		{label: "cross", explicit: "caller-owned", wantSecond: "caller-owned"},
	} {
		var headers map[string]string
		if tc.explicit != "" {
			headers = map[string]string{"x-request-id": tc.explicit}
		}
		follow := true
		_, err := server.callTarget(ctx, callTargetRequest{Label: tc.label, Method: http.MethodGet, Headers: headers, FollowRedirects: &follow})
		require.NoError(t, err)
		first, second := <-seen, <-seen
		wantFirst := "req-original"
		if tc.explicit != "" {
			wantFirst = tc.explicit
		}
		require.Equal(t, wantFirst, first.id)
		require.Equal(t, tc.wantSecond, second.id)
	}
}

func TestHarpoonRequestIDTemplateHeaderOwnership(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, fixed, caller, want string
	}{
		{name: "automatic", want: "req-original"},
		{name: "fixed", fixed: "operator-owned", want: "operator-owned"},
		{name: "caller", caller: "caller-owned", want: "caller-owned"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := templateTestConfig()
			if tc.fixed != "" {
				cfg.Headers = map[string]string{"X-Request-Id": tc.fixed}
			} else if tc.caller != "" {
				cfg.AllowedHeaders = []string{"X-Request-Id"}
			}
			logger := runtimeRegistryTestLogger()
			registry, err := NewRegistry(logger, false, []Target{{Label: "template", Template: cfg}})
			require.NoError(t, err)
			observed := ""
			server, err := NewServer(&runtimeconfig.HarpoonConfig{MaxResponseBytes: 1024}, registry, logger,
				WithHTTPTransport(templateServerTransport(func(req *http.Request) (*http.Response, error) {
					observed = req.Header.Get(forwardedRequestIDHeader)
					return &http.Response{StatusCode: http.StatusNoContent, Header: http.Header{}, Body: http.NoBody, Request: req}, nil
				})))
			require.NoError(t, err)
			var headers map[string]string
			if tc.caller != "" {
				headers = map[string]string{"X-Request-Id": tc.caller}
			}
			ctx := contextWithOutboundRequestID(context.Background(), "req-original")
			_, err = server.callTargetTemplate(ctx, callTargetTemplateRequest{
				Label: "template", Parameters: map[string]any{"resourceId": "item-1"}, Headers: headers,
			})
			require.NoError(t, err)
			require.Equal(t, tc.want, observed)
		})
	}
}

func writeHarpoonCall(ctx context.Context, transport mcp.Transport, rpcID, label string, headers map[string]string) error {
	connection, err := transport.Connect(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = connection.Close() }()
	return writeHarpoonCallOnConnection(ctx, connection, rpcID, label, headers)
}

func writeHarpoonCallOnConnection(ctx context.Context, connection mcp.Connection, rpcID, label string, headers map[string]string) error {
	id, err := jsonrpc.MakeID(rpcID)
	if err != nil {
		return err
	}
	arguments := map[string]any{"label": label, "method": http.MethodGet}
	if len(headers) > 0 {
		arguments["headers"] = headers
	}
	params, err := json.Marshal(map[string]any{
		"name": "call_target", "arguments": arguments,
		"_meta": map[string]any{
			mcp.MetaKeyProtocolVersion:    "2026-07-28",
			mcp.MetaKeyClientInfo:         map[string]any{"name": "request-id-test", "version": "test"},
			mcp.MetaKeyClientCapabilities: map[string]any{},
		},
	})
	if err != nil {
		return err
	}
	if err := connection.Write(ctx, &jsonrpc.Request{ID: id, Method: "tools/call", Params: params}); err != nil {
		return err
	}
	message, err := connection.Read(ctx)
	if err != nil {
		return err
	}
	response, ok := message.(*jsonrpc.Response)
	if !ok {
		return fmt.Errorf("unexpected Harpoon response %T", message)
	}
	if response.Error != nil {
		return errors.New(response.Error.Error())
	}
	return nil
}
