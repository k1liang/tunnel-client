package e2e_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openai/tunnel-client/pkg/config"
	"github.com/openai/tunnel-client/pkg/controlplane/wiretypes"
	harnesspkg "github.com/openai/tunnel-client/testsupport/e2e"
	"github.com/openai/tunnel-client/testsupport/mocktunnelservice"
)

const retryingStartupProbeLog = "retrying MCP startup probe"

// A temporary startup failure must not leave a poller consuming OAuth work
// before its dynamically discovered Harpoon targets have been registered.
func TestStartupDiscoveryRecoveryDelaysPollingUntilHarpoonTargetsRegistered(t *testing.T) {
	t.Parallel()

	const requestID = "cmd-startup-oauth-token"
	const tokenResponse = `{"access_token":"fixture-token","token_type":"Bearer"}`
	var recovered atomic.Bool
	var tokenCalls atomic.Int32
	metadataSeen := make(chan struct{})
	var metadataOnce sync.Once
	mcpUnavailableSeen := make(chan struct{})
	var mcpUnavailableOnce sync.Once
	var mcpProxy *httputil.ReverseProxy
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseURL := "http://" + r.Host
		switch r.URL.Path {
		case "/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource":
			w.Header().Set("Content-Type", "application/json")
			if !recovered.Load() {
				_, _ = w.Write([]byte(`{"resource":`))
				metadataOnce.Do(func() { close(metadataSeen) })
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"resource": baseURL + "/mcp", "authorization_servers": []string{baseURL},
			})
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": baseURL, "authorization_endpoint": baseURL + "/authorize",
				"token_endpoint": baseURL + "/token",
			})
		case "/token":
			if r.Method != http.MethodPost {
				t.Errorf("token request method = %s, want POST", r.Method)
			}
			tokenCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(tokenResponse))
		case "/mcp":
			if !recovered.Load() {
				http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
				mcpUnavailableOnce.Do(func() { close(mcpUnavailableSeen) })
				return
			}
			mcpProxy.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(upstream.Close)

	command, err := json.Marshal(map[string]any{
		"command_type": "jsonrpc", "channel": "harpoon", "request_id": requestID,
		"created_at": time.Now().UTC().Format(time.RFC3339), "shard_token": requestID,
		"jsonrpc": map[string]any{
			"jsonrpc": "2.0", "id": requestID, "method": "tools/call",
			"params": map[string]any{
				"name": "call_target",
				"arguments": map[string]any{
					"label": "oauth-token-endpoint-0", "method": "POST",
					"body": "grant_type=authorization_code",
				},
				"_meta": map[string]any{
					"io.modelcontextprotocol/protocolVersion":    "2026-07-28",
					"io.modelcontextprotocol/clientInfo":         map[string]any{"name": "startup-test", "version": "1"},
					"io.modelcontextprotocol/clientCapabilities": map[string]any{},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal Harpoon command: %v", err)
	}

	healthURLFile := filepath.Join(t.TempDir(), "health.url")
	h := harnesspkg.NewHarness(t,
		harnesspkg.WithPreserveClientURLs(),
		harnesspkg.WithScenarioTimeout(10*time.Second),
		harnesspkg.WithClientConfig(func(cfg *config.Config) {
			cfg.Logging.Level = slog.LevelDebug
			cfg.Health.URLFile = healthURLFile
			cfg.MCP.ServerURL = mustParseURL(t, upstream.URL+"/mcp")
			// Exercise the default MCP startup mode; OAuth startup recovery
			// must not require opting into the separate listener-wait feature.
			cfg.MCP.StartupWaitTimeout = 0
			cfg.Harpoon.AllowPlaintextHTTP = true
			cfg.Harpoon.HostClassifier.IncludeLoopback = true
			cfg.Harpoon.MaxResponseBytes = config.DefaultHarpoonMaxResponseBytes
			cfg.Harpoon.MaxRedirects = config.DefaultHarpoonMaxRedirects
		}),
		harnesspkg.WithControlPlaneOptions(mocktunnelservice.WithCommandResponses(mocktunnelservice.CommandResponse{
			Command: command,
			ExpectedResponses: []mocktunnelservice.ExpectedResponse{{
				RequestID: requestID,
				Assert: func(tb testing.TB, response mocktunnelservice.ReceivedResponse) {
					if tb == nil {
						tb = t
					}
					if response.ResponseCode != http.StatusOK || response.ResponseType != string(wiretypes.ResponsePayloadJSONRPC) {
						tb.Fatalf("token command response = (%d, %s), want JSON-RPC 200", response.ResponseCode, response.ResponseType)
					}
					var payload struct {
						Error  json.RawMessage `json:"error"`
						Result struct {
							IsError           bool `json:"isError"`
							StructuredContent struct {
								StatusCode int    `json:"status_code"`
								BodyBase64 string `json:"body_base64"`
							} `json:"structuredContent"`
						} `json:"result"`
					}
					if err := json.Unmarshal(response.JSONResponse, &payload); err != nil {
						tb.Fatalf("decode token command response: %v", err)
					}
					if len(payload.Error) != 0 || payload.Result.IsError || payload.Result.StructuredContent.StatusCode != http.StatusOK {
						tb.Fatalf("token target call failed after startup recovered: %s", response.JSONResponse)
					}
					if got := payload.Result.StructuredContent.BodyBase64; got != base64.StdEncoding.EncodeToString([]byte(tokenResponse)) {
						tb.Fatalf("token response body = %q, want encoded fixture response", got)
					}
				},
			}},
		})),
		harnesspkg.WithBeforeClientStart(func(h *harnesspkg.Harness) {
			mcpProxy = httputil.NewSingleHostReverseProxy(h.MCP.BaseURL())
		}),
		harnesspkg.WithAfterClientStart(func(h *harnesspkg.Harness) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			select {
			case <-metadataSeen:
			case <-ctx.Done():
				t.Fatal("startup did not request the malformed OAuth metadata")
			}
			select {
			case <-mcpUnavailableSeen:
			case <-ctx.Done():
				t.Fatal("startup did not encounter the MCP 503")
			}
			pollCtx, pollCancel := context.WithTimeout(ctx, 250*time.Millisecond)
			defer pollCancel()
			if err := h.ControlPlane.WaitForHTTPRequests(pollCtx, 1, func(request mocktunnelservice.IncomingHTTPRequest) bool {
				return request.Method == http.MethodGet && strings.HasSuffix(request.Path, "/poll")
			}); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("client polled while startup OAuth metadata was invalid: %v", err)
			}
			if got := len(h.ControlPlane.DeliveredCommands()); got != 0 {
				t.Fatalf("delivered %d commands before startup recovered, want 0", got)
			}
			recovered.Store(true)
		}),
		harnesspkg.WithBeforeClientStop(func(h *harnesspkg.Harness) {
			waitHealthStartup(t, h)
			client, base := healthTestClient(t, healthURLFile)
			assertLegacyHealthProbes(t, client, base)
		}),
	)
	h.ExecuteScenarious(t)
	if got := tokenCalls.Load(); got != 1 {
		t.Fatalf("token endpoint calls = %d, want exactly one after startup recovery", got)
	}
}

// TestStartupWaitDelaysPollingUntilMCPListenerBinds covers the sidecar startup
// race where tunnel-client starts before its pod-local MCP proxy has bound.
func TestStartupWaitDelaysPollingUntilMCPListenerBinds(t *testing.T) {
	t.Parallel()

	delayedAddr := reserveLoopbackAddr(t)
	delayedURL := mustParseURL(t, "http://"+delayedAddr)
	retryLog := newSubstringSignalWriter(retryingStartupProbeLog)

	h := runSimpleToolScenarioWithHarnessOptions(
		t,
		[]harnesspkg.HarnessOption{
			harnesspkg.WithPreserveClientURLs(),
			harnesspkg.WithLogWriter(retryLog),
			harnesspkg.WithClientConfig(func(cfg *config.Config) {
				cfg.Logging.Level = slog.LevelDebug
				cfg.MCP.ServerURL = delayedURL
				cfg.MCP.StartupWaitTimeout = 10 * time.Second
			}),
			harnesspkg.WithAfterClientStart(func(h *harnesspkg.Harness) {
				waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				select {
				case <-retryLog.Seen():
				case <-waitCtx.Done():
					t.Fatalf("did not observe %q before listener bind: %v", retryingStartupProbeLog, waitCtx.Err())
				}

				if h.MCPProbeState == nil {
					t.Fatal("MCP probe state was not populated")
				}
				if h.MCPProbeState.IsDone() {
					t.Fatal("MCP probe completed before delayed listener bound")
				}

				client := h.PrimaryClient()
				if client == nil {
					t.Fatal("primary tunnel-client was not started")
				}
				if got := client.PollCount(); got != 0 {
					t.Fatalf("poll count before delayed listener bind = %d, want 0", got)
				}
				if got := len(h.ControlPlane.DeliveredCommands()); got != 0 {
					t.Fatalf("delivered commands before delayed listener bind = %d, want 0", got)
				}
				if got := len(h.ControlPlane.ReceivedResponses(mocktunnelservice.ResponseMatchAll)); got != 0 {
					t.Fatalf("responses before delayed listener bind = %d, want 0", got)
				}

				startDelayedMCPProxy(t, delayedAddr, h.MCP.BaseURL())
			}),
		},
		nil,
	)

	for _, response := range h.ControlPlane.ReceivedResponses(mocktunnelservice.ResponseMatchAll) {
		if response.ResponseCode == http.StatusBadGateway {
			t.Fatalf("received early terminal 502 for request %q", response.RequestID)
		}
	}
}

func reserveLoopbackAddr(t testing.TB) string {
	t.Helper()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve delayed MCP listener address: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release delayed MCP listener address: %v", err)
	}
	return addr
}

func startDelayedMCPProxy(t testing.TB, addr string, target *url.URL) {
	t.Helper()
	if target == nil {
		t.Fatal("mock MCP server URL is nil")
	}

	listener, err := net.Listen("tcp4", addr)
	if err != nil {
		t.Fatalf("bind delayed MCP listener %q: %v", addr, err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	server := &http.Server{Handler: proxy}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(listener)
	}()

	t.Cleanup(func() {
		if err := server.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("close delayed MCP proxy: %v", err)
		}
		select {
		case err := <-serveErr:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("serve delayed MCP proxy: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("delayed MCP proxy did not stop")
		}
	})
}

type substringSignalWriter struct {
	needle []byte
	seen   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	buf    []byte
}

func newSubstringSignalWriter(needle string) *substringSignalWriter {
	return &substringSignalWriter{
		needle: []byte(needle),
		seen:   make(chan struct{}),
	}
}

func (w *substringSignalWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.buf = append(w.buf, p...)
	if bytes.Contains(w.buf, w.needle) {
		w.once.Do(func() { close(w.seen) })
	}
	if keep := len(w.needle) - 1; keep > 0 && len(w.buf) > keep {
		w.buf = append(w.buf[:0], w.buf[len(w.buf)-keep:]...)
	}
	return len(p), nil
}

func (w *substringSignalWriter) Seen() <-chan struct{} {
	return w.seen
}
