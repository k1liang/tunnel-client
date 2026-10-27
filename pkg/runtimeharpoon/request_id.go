package runtimeharpoon

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/openai/tunnel-client/pkg/runtimeconfig"
	"github.com/openai/tunnel-client/pkg/tunnelctx"
)

const forwardedRequestIDHeader = "X-Request-Id"

type forwardRequestIDKey struct{}
type outboundRequestIDKey struct{}
type autoRequestIDKey struct{}

type autoRequestID struct {
	value  string
	origin string
}

// ContextWithForwardRequestID opts one Harpoon command into forwarding the
// original HTTP X-Request-Id. The command's queue and JSON-RPC IDs are never
// candidates. Its in-memory transport attaches the value only to the request
// written on that connection, not to the server's setup or discovery traffic.
func ContextWithForwardRequestID(ctx context.Context) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, forwardRequestIDKey{}, true)
}

func requestIDForForwarding(ctx context.Context) string {
	if ctx == nil || ctx.Value(forwardRequestIDKey{}) != true {
		return ""
	}
	id, ok := tunnelctx.ControlPlaneCommandRequestIDFromContext(ctx)
	if !ok || !runtimeconfig.ValidHTTPHeader(forwardedRequestIDHeader, id.String()) {
		return ""
	}
	return id.String()
}

func contextWithOutboundRequestID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, outboundRequestIDKey{}, id)
}

// contextWithAutoRequestID records ownership before net/http starts following
// redirects. Explicit caller or template headers keep their existing policy.
func contextWithAutoRequestID(ctx context.Context, headers http.Header, target *url.URL) context.Context {
	if ctx == nil || hasRequestIDHeader(headers) {
		return ctx
	}
	id, _ := ctx.Value(outboundRequestIDKey{}).(string)
	origin := requestOrigin(target)
	if id == "" || origin == "" || !runtimeconfig.ValidHTTPHeader(forwardedRequestIDHeader, id) {
		return ctx
	}
	return context.WithValue(ctx, autoRequestIDKey{}, autoRequestID{value: id, origin: origin})
}

func hasRequestIDHeader(headers http.Header) bool {
	for name := range headers {
		if strings.EqualFold(name, forwardedRequestIDHeader) {
			return true
		}
	}
	return false
}

// applyAutoRequestID runs after the existing outbound policy. Exact targets
// may redirect to another registered origin; the automatically added ID stays
// with the original origin even when net/http copies its header to a redirect.
func applyAutoRequestID(req *http.Request, template bool) {
	if req == nil {
		return
	}
	auto, ok := req.Context().Value(autoRequestIDKey{}).(autoRequestID)
	if !ok || auto.value == "" {
		return
	}
	if requestOrigin(req.URL) != auto.origin {
		req.Header.Del(forwardedRequestIDHeader)
		return
	}
	if template {
		if !validTemplateHeaderValue(auto.value) {
			return
		}
		candidate := req.Header.Clone()
		candidate.Set(forwardedRequestIDHeader, auto.value)
		if validateTemplateHeaderSize(candidate) != nil {
			return
		}
	}
	req.Header.Set(forwardedRequestIDHeader, auto.value)
}

func requestOrigin(target *url.URL) string {
	if target == nil || target.Scheme == "" || target.Host == "" {
		return ""
	}
	scheme, host := strings.ToLower(target.Scheme), strings.ToLower(target.Host)
	if (scheme == "http" && target.Port() == "80") || (scheme == "https" && target.Port() == "443") {
		host = strings.TrimSuffix(host, ":"+target.Port())
	}
	return scheme + "://" + host
}
