package oauth

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/openai/tunnel-client/pkg/runtimeconfig"
	"github.com/openai/tunnel-client/pkg/tunnelctx"
)

const forwardedRequestIDHeader = "X-Request-Id"

type requestIDContextKey struct{}

type forwardedRequestID struct {
	value  string
	origin url.URL
}

// ContextWithForwardRequestID opts one queued OAuth discovery command into
// forwarding its original HTTP request ID. Only requests to the configured MCP
// origin receive it; advertised metadata and issuer URLs cannot expand this
// boundary. Startup discovery has no command ID and does not use this context.
func ContextWithForwardRequestID(ctx context.Context, mcpURL *url.URL) context.Context {
	if ctx == nil || !validDiscoveryURL(mcpURL) {
		return ctx
	}
	id, ok := tunnelctx.ControlPlaneCommandRequestIDFromContext(ctx)
	if !ok || id == "" || !runtimeconfig.ValidHTTPHeader(forwardedRequestIDHeader, id.String()) {
		return ctx
	}
	origin := url.URL{Scheme: mcpURL.Scheme, Host: mcpURL.Host}
	return context.WithValue(ctx, requestIDContextKey{}, forwardedRequestID{value: id.String(), origin: origin})
}

func applyForwardedRequestID(req *http.Request) {
	if req == nil || req.Context() == nil || req.Header == nil {
		return
	}
	forwarded, ok := req.Context().Value(requestIDContextKey{}).(forwardedRequestID)
	if !ok || !sameURLOrigin(req.URL, &forwarded.origin) {
		return
	}
	for name := range req.Header {
		if strings.EqualFold(name, forwardedRequestIDHeader) {
			return
		}
	}
	req.Header.Set(forwardedRequestIDHeader, forwarded.value)
}
