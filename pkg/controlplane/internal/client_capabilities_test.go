package internal

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/openai/tunnel-client/pkg/clientcapabilities"
	"github.com/openai/tunnel-client/pkg/config"
	"github.com/openai/tunnel-client/pkg/controlplane/wiretypes"
	"github.com/openai/tunnel-client/pkg/runtimeconfig"
	"github.com/openai/tunnel-client/pkg/tracing"
	"github.com/openai/tunnel-client/pkg/tunnelctx"
	"github.com/openai/tunnel-client/pkg/types"
)

func TestPostResponseRetriesWithinOneUploadSpan(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "retry-trace.jsonl")
	runtime, err := tracing.New(runtimeconfig.TracingConfig{Enabled: true, File: path})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, runtime.Shutdown(context.Background())) })
	ctx, dispatch := runtime.StartCommand(t.Context(), "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	ctx, upload := runtime.Start(ctx, tracing.Upload)
	upload.SetAttributes(attribute.String("private_attribute", "sensitive-attribute"))
	upload.AddEvent("sensitive-event")
	ctx = responseContext(ctx, "sensitive-shard", "sensitive-caller-request")
	client := newResponseRetryTestClient(t)
	client.newResponseBackoff = deterministicResponseBackoff
	var attempts []capturedRequest
	var parents []trace.SpanContext
	authTransport, ok := client.client.Transport.(*controlPlaneRoundTripper)
	require.True(t, ok)
	authTransport.base = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		parents = append(parents, trace.SpanContextFromContext(request.Context()))
		attempts = append(attempts, captureRequest(t, request))
		if len(attempts) == 1 {
			return testHTTPResponse(request, http.StatusServiceUnavailable, nil), nil
		}
		return testHTTPResponse(request, http.StatusOK, nil), nil
	})
	var waits []time.Duration
	client.retrySleep = func(retryContext context.Context, delay time.Duration) bool {
		require.Equal(t, upload.SpanContext(), trace.SpanContextFromContext(retryContext))
		waits = append(waits, delay)
		return true
	}
	response := types.NewTunnelResponse(types.DefaultChannel,
		json.RawMessage(`{"jsonrpc":"2.0","id":1,"result":{"private":"sensitive-payload"}}`),
		http.StatusOK, http.Header{"X-Private": {"sensitive-header"}, "Mcp-Session-Id": {"sensitive-session"}})
	_, err = client.PostResponse(ctx, types.RequestID("sensitive-response-id"), response)
	require.NoError(t, err)
	upload.End()
	dispatch.End()
	require.NoError(t, runtime.Shutdown(context.Background()))
	require.Len(t, attempts, 2)
	require.Equal(t, []time.Duration{defaultBackoffMin}, waits)
	require.Equal(t, []trace.SpanContext{upload.SpanContext(), upload.SpanContext()}, parents)
	require.Equal(t, attempts[0].body, attempts[1].body)
	require.Equal(t, attempts[0].headers, attempts[1].headers)
	require.Equal(t, attempts[0].path, attempts[1].path)
	require.Contains(t, attempts[0].body, "sensitive-payload")
	require.NotContains(t, attempts[0].body, "sensitive-header")
	require.Contains(t, attempts[0].body, "sensitive-session")
	require.Equal(t, "sensitive-shard", attempts[0].headers.Get(wiretypes.ShardTokenHeader))
	require.Equal(t, "Bearer test-api-key", attempts[0].headers.Get("Authorization"))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	for _, forbidden := range []string{"sensitive", "private_attribute", "test-api-key", "Authorization", "attributes", "events"} {
		require.NotContains(t, string(data), forbidden)
	}
	records := make(map[string]tracing.Record)
	var attemptRecords []tracing.Record
	count := 0
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		var fields map[string]json.RawMessage
		require.NoError(t, json.Unmarshal([]byte(line), &fields))
		var record tracing.Record
		require.NoError(t, json.Unmarshal([]byte(line), &record))
		if record.Name == tracing.UploadAttempt {
			require.Len(t, fields, 11)
			attemptRecords = append(attemptRecords, record)
		} else {
			require.Len(t, fields, 7)
			records[record.Name] = record
		}
		count++
	}
	require.Equal(t, 4, count)
	require.Len(t, records, 2)
	require.Len(t, attemptRecords, 2)
	require.Equal(t, "00f067aa0ba902b7", records[tracing.Dispatch].ParentSpanID)
	require.Equal(t, dispatch.SpanContext().SpanID().String(), records[tracing.Upload].ParentSpanID)
	require.Equal(t, upload.SpanContext().SpanID().String(), records[tracing.Upload].SpanID)
	for index, record := range attemptRecords {
		require.Equal(t, int64(index+1), record.Attempt)
		require.Equal(t, upload.SpanContext().SpanID().String(), record.ParentSpanID)
		require.Equal(t, upload.SpanContext().TraceID().String(), record.TraceID)
		require.NotNil(t, record.ElapsedMS)
		require.GreaterOrEqual(t, *record.ElapsedMS, 0.0)
		require.False(t, record.EndTime.Before(record.StartTime))
	}
	require.Equal(t, int64(http.StatusServiceUnavailable), attemptRecords[0].HTTPStatus)
	require.Equal(t, "http_error", attemptRecords[0].Outcome)
	require.Equal(t, "Error", attemptRecords[0].Status)
	require.Equal(t, int64(http.StatusOK), attemptRecords[1].HTTPStatus)
	require.Equal(t, "accepted", attemptRecords[1].Outcome)
	require.Equal(t, "Unset", attemptRecords[1].Status)
	for _, record := range records {
		require.Equal(t, dispatch.SpanContext().TraceID().String(), record.TraceID)
	}
}

func TestPostResponseAttemptTraceClassifiesTransportFailureAndNotFound(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name         string
		firstFailure bool
		wantOutcome  []string
		wantStatus   []int64
	}{
		{name: "network retry", firstFailure: true, wantOutcome: []string{"network_error", "accepted"}, wantStatus: []int64{0, http.StatusOK}},
		{name: "not found", wantOutcome: []string{"already_fulfilled_or_unknown"}, wantStatus: []int64{http.StatusNotFound}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "trace.jsonl")
			runtime, err := tracing.New(runtimeconfig.TracingConfig{Enabled: true, File: path})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, runtime.Shutdown(context.Background())) })
			ctx, dispatch := runtime.StartCommand(t.Context(), "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
			ctx, upload := runtime.Start(ctx, tracing.Upload)
			ctx = responseContext(ctx, "private-shard", "private-caller")
			client := newResponseRetryTestClient(t)
			client.newResponseBackoff = deterministicResponseBackoff
			client.retrySleep = func(context.Context, time.Duration) bool { return true }
			calls := 0
			client.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				if test.firstFailure && calls == 1 {
					return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("private transport failure")}
				}
				status := http.StatusNotFound
				if test.firstFailure {
					status = http.StatusOK
				}
				return testHTTPResponse(request, status, nil), nil
			})
			_, err = client.PostResponse(ctx, types.RequestID("private-response"), testResponse())
			require.NoError(t, err)
			upload.End()
			dispatch.End()
			require.NoError(t, runtime.Shutdown(context.Background()))
			require.Equal(t, len(test.wantOutcome), calls)
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			require.NotContains(t, string(data), "private")
			var attemptRecords []tracing.Record
			for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
				var record tracing.Record
				require.NoError(t, json.Unmarshal([]byte(line), &record))
				if record.Name == tracing.UploadAttempt {
					attemptRecords = append(attemptRecords, record)
				}
			}
			require.Len(t, attemptRecords, len(test.wantOutcome))
			for index, record := range attemptRecords {
				require.Equal(t, int64(index+1), record.Attempt)
				require.Equal(t, test.wantOutcome[index], record.Outcome)
				require.Equal(t, test.wantStatus[index], record.HTTPStatus)
			}
		})
	}
}

func TestLocalTracingDoesNotInjectControlPlaneHeaders(t *testing.T) {
	previous := otel.GetTextMapPropagator()
	if len(previous.Fields()) == 0 {
		previous = propagation.NewCompositeTextMapPropagator()
	}
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	t.Cleanup(func() { otel.SetTextMapPropagator(previous) })
	runtime, err := tracing.New(runtimeconfig.TracingConfig{Enabled: true, File: filepath.Join(t.TempDir(), "trace.jsonl")})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, runtime.Shutdown(context.Background())) })
	member, err := baggage.NewMember("private", "never-export")
	require.NoError(t, err)
	bag, err := baggage.New(member)
	require.NoError(t, err)
	ctx, span := runtime.StartCommand(baggage.ContextWithBaggage(t.Context(), bag), "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	defer span.End()
	server := newHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		for _, name := range []string{"traceparent", "tracestate", "baggage"} {
			assert.Empty(t, request.Header.Values(name))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	client, err := NewTunnelServiceClient(t.Context(), &config.ControlPlaneConfig{
		BaseURL: mustParseURL(t, server.URL), TunnelID: "local", APIKey: "fixture",
		TraceContextEnabled: true,
	}, nil, newDiscardLogger(), &config.LoggingConfig{}, testMeterProvider)
	require.NoError(t, err)
	_, _, err = client.Poll(ctx, 1)
	require.NoError(t, err)
}

func TestClientCapabilitiesOnEveryControlPlaneOperation(t *testing.T) {
	t.Parallel()
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "tracing"}[enabled], func(t *testing.T) {
			t.Parallel()
			testClientCapabilitiesOnEveryControlPlaneOperation(t, enabled)
		})
	}
}

func testClientCapabilitiesOnEveryControlPlaneOperation(t *testing.T, enabled bool) {
	const commandToken = "legacy command,token"
	requests := make(chan string, 4)
	server := newHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := clientcapabilities.WrongClusterV1
		if enabled {
			want += "," + clientcapabilities.TraceContextV1
		}
		assert.Equal(t, []string{want}, r.Header.Values(clientcapabilities.HeaderName), "every control-plane request advertises implemented client capabilities")
		assert.Empty(t, r.Header.Values("X-Tunnel-Routing-Capability"))
		requests <- r.Method + " " + r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/tunnels/capabilities/poll":
			assert.Empty(t, r.Header.Values(wiretypes.ShardTokenHeader), "the first poll advertises capability before learning any token")
			w.WriteHeader(http.StatusNoContent)
		case "/v1/tunnels/capabilities":
			assert.Empty(t, r.Header.Values(wiretypes.ShardTokenHeader))
			_, _ = w.Write([]byte(`{"id":"capabilities","name":"Capabilities"}`))
		case "/v1/tunnels/capabilities/cloudflare/runtime":
			assert.Empty(t, r.Header.Values(wiretypes.ShardTokenHeader))
			_, _ = w.Write([]byte(`{"cloudflare_tunnel":{"tunnel_id":"provider","name":"managed","account_id":"account","created_at":"2026-07-31T00:00:00Z"},"runtime_token":"fixture-token"}`))
		case "/v1/tunnels/capabilities/response":
			assert.Equal(t, commandToken, r.Header.Get(wiretypes.ShardTokenHeader), "capability emission must preserve the command's response token")
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected control-plane operation: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	client, err := NewTunnelServiceClient(t.Context(), &config.ControlPlaneConfig{
		BaseURL:             mustParseURL(t, server.URL),
		TunnelID:            "capabilities",
		APIKey:              "fixture-api-key",
		TraceContextEnabled: enabled,
		ExtraHeaders: map[string]string{
			"x-tunnel-client-capabilities": "unimplemented-v1",
			"x-tunnel-shard-token":         "configuration-cannot-set-routing",
		},
	}, nil, newDiscardLogger(), &config.LoggingConfig{}, testMeterProvider)
	require.NoError(t, err)
	_, _, err = client.Poll(t.Context(), 1)
	require.NoError(t, err)
	_, err = client.FetchTunnelMetadata(t.Context())
	require.NoError(t, err)
	_, err = client.FetchManagedCloudflareTunnel(t.Context())
	require.NoError(t, err)
	ctx := tunnelctx.ContextWithShardToken(t.Context(), commandToken)
	ctx = tunnelctx.ContextWithChannel(ctx, types.DefaultChannel)
	_, err = client.PostResponse(ctx, "notification", types.NewNotificationAck(types.DefaultChannel, http.StatusOK, http.Header{}))
	require.NoError(t, err)
	require.Len(t, requests, 4)
	for _, want := range []string{
		"GET /v1/tunnels/capabilities/poll",
		"GET /v1/tunnels/capabilities",
		"GET /v1/tunnels/capabilities/cloudflare/runtime",
		"POST /v1/tunnels/capabilities/response",
	} {
		require.Equal(t, want, <-requests)
	}
}
