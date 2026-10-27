package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/openai/tunnel-client/pkg/tunnelctx"
	"github.com/openai/tunnel-client/pkg/types"
)

func oauthRequestIDContext(ctx context.Context, origin *url.URL, id string, enabled bool) context.Context {
	if id != "" {
		ctx = tunnelctx.ContextWithControlPlaneCommandRequestID(ctx, types.ControlPlaneRequestID(id))
	}
	if enabled {
		ctx = ContextWithForwardRequestID(ctx, origin)
	}
	return ctx
}

func TestOAuthRequestIDDiscoveryProbeAndMetadata(t *testing.T) {
	for _, tc := range []struct {
		name    string
		id      string
		enabled bool
		want    string
	}{
		{name: "default", id: "original-default"},
		{name: "opt in", id: "original-oauth", enabled: true, want: "original-oauth"},
		{name: "missing original", enabled: true},
		{name: "invalid original", id: "bad\r\nvalue", enabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var received []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received = append(received, r.Header.Get(forwardedRequestIDHeader))
				if r.URL.Path == "/mcp" {
					w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="http://%s/metadata"`, r.Host))
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"resource":"http://%s/mcp"}`, r.Host)
			}))
			t.Cleanup(server.Close)
			origin := mustParseURL(t, server.URL+"/mcp")
			ctx := oauthRequestIDContext(t.Context(), origin, tc.id, tc.enabled)
			if tc.id == "" {
				ctx = tunnelctx.ContextWithRequestID(ctx, "cmd_queue-only")
			}
			candidates, _, err := BuildOAuthDiscoveryCandidates(ctx, server.Client(), origin, testLogger())
			if err != nil {
				t.Fatal(err)
			}
			if len(candidates) == 0 {
				t.Fatal("no discovery candidates")
			}
			if _, _, _, err := FetchOAuthMetadata(ctx, server.Client(), candidates, testLogger()); err != nil {
				t.Fatal(err)
			}
			if len(received) != 2 || received[0] != tc.want || received[1] != tc.want {
				t.Fatalf("probe and metadata request IDs = %q, want %q", received, tc.want)
			}
		})
	}
}

func TestOAuthRequestIDStaysAtConfiguredMCPOrigin(t *testing.T) {
	var outsideRequests atomic.Int32
	var outsideID string
	var outside *httptest.Server
	outside = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outsideRequests.Add(1)
		outsideID = r.Header.Get(forwardedRequestIDHeader)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"resource":%q}`, outside.URL)
	}))
	t.Cleanup(outside.Close)

	var sameOriginIDs []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sameOriginIDs = append(sameOriginIDs, r.Header.Get(forwardedRequestIDHeader))
		switch r.URL.Path {
		case "/same":
			http.Redirect(w, r, "/metadata", http.StatusFound)
		case "/cross":
			http.Redirect(w, r, outside.URL+"/metadata", http.StatusFound)
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"resource":"http://%s/mcp"}`, r.Host)
		}
	}))
	t.Cleanup(server.Close)
	origin := mustParseURL(t, server.URL+"/mcp")
	ctx := oauthRequestIDContext(t.Context(), origin, "original-oauth", true)
	for _, path := range []string{"/same", "/cross"} {
		candidate := mustParseURL(t, server.URL+path)
		_, _, _, err := FetchOAuthMetadata(ctx, server.Client(), []DiscoveryCandidate{{URL: candidate}}, nil, origin)
		if path == "/same" && err != nil {
			t.Fatalf("same-origin discovery: %v", err)
		}
		if path == "/cross" && err == nil {
			t.Fatal("cross-origin redirect was followed")
		}
	}
	if got := strings.Join(sameOriginIDs, ","); got != "original-oauth,original-oauth,original-oauth" {
		t.Fatalf("same-origin request IDs = %q", got)
	}
	if outsideRequests.Load() != 0 {
		t.Fatalf("cross-origin redirect sent %d requests", outsideRequests.Load())
	}

	// A separately configured trusted metadata origin remains reachable, but the
	// original ID is tied to the MCP origin rather than every trusted origin.
	outsideURL := mustParseURL(t, outside.URL)
	if _, _, _, err := FetchOAuthMetadata(ctx, server.Client(), []DiscoveryCandidate{{URL: outsideURL}}, nil, outsideURL); err != nil {
		t.Fatal(err)
	}
	if outsideID != "" {
		t.Fatalf("trusted cross-origin metadata received original request ID %q", outsideID)
	}
}

func TestOAuthRequestIDDoesNotFollowMutatedRedirect(t *testing.T) {
	var outsideRequests atomic.Int32
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		outsideRequests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(outside.Close)
	outsideURL := mustParseURL(t, outside.URL+"/redirected")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/same-origin", http.StatusFound)
	}))
	t.Cleanup(server.Close)
	origin := mustParseURL(t, server.URL+"/mcp")
	client := server.Client()
	client.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		req.URL = outsideURL
		return nil
	}
	ctx := oauthRequestIDContext(t.Context(), origin, "original-oauth", true)
	if _, err := tryWWWAuthenticateProbe(ctx, client, origin, nil, http.MethodGet); err == nil {
		t.Fatal("probe followed a redirect mutated to a different origin")
	}
	if _, _, _, err := FetchOAuthMetadata(ctx, client, []DiscoveryCandidate{{URL: origin}}, nil, origin, outsideURL); err == nil {
		t.Fatal("metadata fetch followed a redirect mutated to a different origin")
	}
	if got := outsideRequests.Load(); got != 0 {
		t.Fatalf("cross-origin server received %d redirected requests", got)
	}
}

func TestOAuthRequestIDAuthServerMetadataOnlyAtMCPOrigin(t *testing.T) {
	var otherID string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherID = r.Header.Get(forwardedRequestIDHeader)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"issuer":%q}`, "http://"+r.Host)
	}))
	t.Cleanup(other.Close)
	var sameID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sameID = r.Header.Get(forwardedRequestIDHeader)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"issuer":%q}`, "http://"+r.Host)
	}))
	t.Cleanup(server.Close)
	origin := mustParseURL(t, server.URL)
	ctx := oauthRequestIDContext(t.Context(), origin, "original-oauth", true)
	if _, err := FetchAuthServerMetadata(ctx, server.Client(), server.URL, origin); err != nil {
		t.Fatal(err)
	}
	otherURL := mustParseURL(t, other.URL)
	if _, err := FetchAuthServerMetadata(ctx, server.Client(), other.URL, otherURL); err != nil {
		t.Fatal(err)
	}
	if sameID != "original-oauth" || otherID != "" {
		t.Fatalf("authorization metadata IDs = same %q, other %q", sameID, otherID)
	}
}

func TestOAuthRequestIDConcurrentCommandsAreIsolated(t *testing.T) {
	const count = 24
	var mismatches atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		index, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/metadata/"))
		if err != nil || r.Header.Get(forwardedRequestIDHeader) != fmt.Sprintf("original-%d", index) {
			mismatches.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"resource":"http://%s/mcp"}`, r.Host)
	}))
	t.Cleanup(server.Close)
	origin := mustParseURL(t, server.URL)
	client := server.Client()
	var wg sync.WaitGroup
	for i := range count {
		candidate := mustParseURL(t, fmt.Sprintf("%s/metadata/%d", server.URL, i))
		wg.Go(func() {
			ctx := oauthRequestIDContext(t.Context(), origin, fmt.Sprintf("original-%d", i), true)
			if _, _, _, err := FetchOAuthMetadata(ctx, client, []DiscoveryCandidate{{URL: candidate}}, nil, origin); err != nil {
				mismatches.Add(1)
			}
		})
	}
	wg.Wait()
	if got := mismatches.Load(); got != 0 {
		t.Fatalf("%d concurrent OAuth request IDs were missing or crossed commands", got)
	}
}

func TestOAuthRequestIDPreservesExistingHeader(t *testing.T) {
	origin := mustParseURL(t, "https://mcp.example.test/mcp")
	ctx := oauthRequestIDContext(t.Context(), origin, "automatic", true)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	nonCanonicalName := strings.ToLower(forwardedRequestIDHeader)
	req.Header[nonCanonicalName] = []string{"caller-owned"}
	applyForwardedRequestID(req)
	if got := req.Header[nonCanonicalName]; len(got) != 1 || got[0] != "caller-owned" {
		t.Fatalf("existing request ID changed to %q", got)
	}
}
