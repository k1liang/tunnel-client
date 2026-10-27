package internal

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openai/tunnel-client/pkg/config"
	"github.com/openai/tunnel-client/pkg/controlplane"
	tclog "github.com/openai/tunnel-client/pkg/log"
	"github.com/openai/tunnel-client/pkg/tunnelctx"
	"github.com/openai/tunnel-client/pkg/types"
)

// These complete exchanges are also protocol examples for service implementers.
//
//go:embed testdata/routing_sequences.json
var routingSequenceJSON []byte

const (
	routingTestCapabilityHeader = "X-Tunnel-Client-Capabilities"
	routingTestTokenHeader      = "X-Tunnel-Shard-Token"
)

type routingSequence struct {
	Name     string        `json:"name"`
	Endpoint string        `json:"endpoint"`
	TunnelID string        `json:"tunnel_id"`
	Steps    []routingStep `json:"steps"`
}

type routingStep struct {
	Request struct {
		Method        string      `json:"method"`
		Path          string      `json:"path"`
		Headers       http.Header `json:"headers"`
		AbsentHeaders []string    `json:"absent_headers"`
	} `json:"request"`
	Response struct {
		Status         int             `json:"status"`
		Headers        http.Header     `json:"headers"`
		Body           json.RawMessage `json:"body"`
		TransportError string          `json:"transport_error"`
	} `json:"response"`
	Expect struct {
		Error          bool     `json:"error"`
		ErrorStatus    int      `json:"error_status"`
		CachedToken    string   `json:"cached_token"`
		PolicyRevision *uint64  `json:"policy_revision"`
		CommandTokens  []string `json:"command_tokens"`
	} `json:"expect"`
	Note string `json:"note"`
}

func TestPollRoutingWireSequences(t *testing.T) {
	t.Parallel()
	var sequences []routingSequence
	require.NoError(t, json.Unmarshal(routingSequenceJSON, &sequences))
	require.NotEmpty(t, sequences)
	for _, sequence := range sequences {
		t.Run(sequence.Name, func(t *testing.T) {
			t.Parallel()
			attempts := 0
			client := newRoutingTestClient(t, sequence.Endpoint, sequence.TunnelID, func(req *http.Request) (*http.Response, error) {
				attempt := attempts
				attempts++
				if !assert.Less(t, attempt, len(sequence.Steps), "unexpected retry or non-poll request") {
					return nil, errors.New("unexpected extra request")
				}
				step := sequence.Steps[attempt]
				assert.Equal(t, step.Request.Method, req.Method)
				assert.Equal(t, step.Request.Path, req.URL.Path)
				assert.Equal(t, sequence.Endpoint, req.URL.Scheme+"://"+req.URL.Host, "routing must preserve the configured residency")
				for key, want := range step.Request.Headers {
					assert.Equal(t, want, req.Header.Values(key), "request %d header %s", attempt, key)
				}
				for _, key := range step.Request.AbsentHeaders {
					assert.Empty(t, req.Header.Values(key), "request %d header %s must be absent", attempt, key)
				}
				if step.Response.TransportError != "" {
					return nil, errors.New(step.Response.TransportError)
				}
				return routingTestResponse(req, step.Response.Status, step.Response.Headers, string(step.Response.Body)), nil
			})
			for i, step := range sequence.Steps {
				commands, _, err := client.Poll(context.Background(), 25)
				require.Equal(t, i+1, attempts, "every Poll must make exactly one attempt")
				if step.Expect.Error {
					require.Error(t, err, "step %d: %s", i, step.Note)
					if step.Expect.ErrorStatus != 0 {
						var statusErr *APIStatusError
						require.ErrorAs(t, err, &statusErr)
						assert.Equal(t, step.Expect.ErrorStatus, statusErr.StatusCode())
					}
				} else {
					require.NoError(t, err, "step %d: %s", i, step.Note)
				}
				assertRoutingState(t, client, step.Expect.CachedToken, step.Expect.PolicyRevision)
				tokens := make([]string, 0, len(commands))
				for _, command := range commands {
					tokens = append(tokens, command.ShardToken())
				}
				assert.Equal(t, step.Expect.CommandTokens, tokens)
			}
		})
	}
}

// Retain the constructor's authentication and redirect policy while replacing
// only its network transport, so requests still pass through the real client.
func newRoutingTestClient(t *testing.T, endpoint, tunnelID string, transport roundTripperFunc) *TunnelServiceClient {
	t.Helper()
	client, err := NewTunnelServiceClient(context.Background(), &config.ControlPlaneConfig{
		BaseURL:     mustParseURL(t, endpoint),
		TunnelID:    types.TunnelID(tunnelID),
		APIKey:      "fixture-api-key",
		PollTimeout: time.Second,
	}, nil, newDiscardLogger(), &config.LoggingConfig{}, testMeterProvider)
	require.NoError(t, err)
	wrapper, ok := client.client.Transport.(*controlPlaneRoundTripper)
	require.True(t, ok)
	wrapper.base = transport
	return client
}

func routingTestResponse(req *http.Request, status int, headers http.Header, body string) *http.Response {
	if headers == nil {
		headers = make(http.Header)
	}
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     headers,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

func routingTestCorrection(req *http.Request, token string, revision uint64) *http.Response {
	return routingTestResponse(req, http.StatusConflict, http.Header{routingTestTokenHeader: {token}},
		fmt.Sprintf(`{"error":{"code":"wrong_cluster","policy_revision":%d}}`, revision))
}

func assertRoutingState(t *testing.T, client *TunnelServiceClient, token string, revision *uint64) {
	t.Helper()
	client.routing.mu.Lock()
	defer client.routing.mu.Unlock()
	assert.Equal(t, token, client.routing.token)
	assert.Equal(t, revision != nil, client.routing.known)
	if revision != nil {
		assert.Equal(t, *revision, client.routing.revision)
	}
}

func TestPollRoutingAcceptsBoundaryValues(t *testing.T) {
	t.Parallel()
	const revision = 9007199254740991
	token := strings.Repeat("x", 4096)
	attempts := 0
	client := newRoutingTestClient(t, "https://eu.api.openai.com", "tunnel", func(req *http.Request) (*http.Response, error) {
		attempts++
		if attempts == 1 {
			return routingTestCorrection(req, token, revision), nil
		}
		assert.Equal(t, token, req.Header.Get(routingTestTokenHeader))
		return routingTestResponse(req, 204, nil, ""), nil
	})
	_, _, err := client.Poll(context.Background(), 1)
	require.Error(t, err)
	_, _, err = client.Poll(context.Background(), 1)
	require.NoError(t, err)
	assertRoutingState(t, client, token, new(uint64(revision)))
	assert.Equal(t, 2, attempts)
}

func TestPollRoutingLateCorrectionCannotReplaceNewerRoute(t *testing.T) {
	t.Parallel()
	entered, release := make(chan struct{}), make(chan struct{})
	var attempts atomic.Int32
	client := newRoutingTestClient(t, "https://eu.api.openai.com", "tunnel", func(req *http.Request) (*http.Response, error) {
		switch attempts.Add(1) {
		case 1:
			close(entered)
			<-release
			return routingTestCorrection(req, "older-route", 1), nil
		case 2:
			return routingTestCorrection(req, "newer-route", 2), nil
		default:
			assert.Equal(t, "newer-route", req.Header.Get(routingTestTokenHeader))
			return routingTestResponse(req, 204, nil, ""), nil
		}
	})
	done := make(chan error, 1)
	go func() { _, _, err := client.Poll(context.Background(), 1); done <- err }()
	<-entered
	_, _, err := client.Poll(context.Background(), 1)
	assert.Error(t, err)
	close(release)
	assert.Error(t, <-done)
	assertRoutingState(t, client, "newer-route", new(uint64(2)))
	_, _, err = client.Poll(context.Background(), 1)
	require.NoError(t, err)
	assert.EqualValues(t, 3, attempts.Load())
}

func TestPollRoutingLateFailureCannotCountAgainstNewerRoute(t *testing.T) {
	t.Parallel()
	for _, lateTransportError := range []bool{false, true} {
		t.Run(fmt.Sprintf("transport_error_%t", lateTransportError), func(t *testing.T) {
			t.Parallel()
			entered, release := make(chan struct{}), make(chan struct{})
			var attempts atomic.Int32
			client := newRoutingTestClient(t, "https://eu.api.openai.com", "tunnel", func(req *http.Request) (*http.Response, error) {
				switch attempts.Add(1) {
				case 1:
					return routingTestCorrection(req, "route-a", 1), nil
				case 2:
					close(entered)
					<-release
					if lateTransportError {
						return nil, errors.New("late connection reset")
					}
					return routingTestResponse(req, 503, nil, ""), nil
				case 3:
					return routingTestCorrection(req, "route-b", 2), nil
				default:
					assert.Equal(t, "route-b", req.Header.Get(routingTestTokenHeader))
					return routingTestResponse(req, 503, nil, ""), nil
				}
			})
			_, _, err := client.Poll(context.Background(), 1)
			require.Error(t, err)
			done := make(chan error, 1)
			go func() { _, _, err := client.Poll(context.Background(), 1); done <- err }()
			<-entered
			_, _, err = client.Poll(context.Background(), 1)
			assert.Error(t, err)
			close(release)
			assert.Error(t, <-done)
			for range 2 {
				_, _, err = client.Poll(context.Background(), 1)
				require.Error(t, err)
				assertRoutingState(t, client, "route-b", new(uint64(2)))
			}
			_, _, err = client.Poll(context.Background(), 1)
			require.Error(t, err)
			assertRoutingState(t, client, "", new(uint64(2)))
			assert.EqualValues(t, 6, attempts.Load())
		})
	}
}

func TestPollRoutingLateSuccessCannotResetNewerFailureStreak(t *testing.T) {
	t.Parallel()
	entered, release := make(chan struct{}), make(chan struct{})
	var attempts atomic.Int32
	client := newRoutingTestClient(t, "https://eu.api.openai.com", "tunnel", func(req *http.Request) (*http.Response, error) {
		switch attempts.Add(1) {
		case 1:
			return routingTestCorrection(req, "route-a", 1), nil
		case 2:
			close(entered)
			<-release
			return routingTestResponse(req, 204, nil, ""), nil
		default:
			assert.Equal(t, "route-a", req.Header.Get(routingTestTokenHeader))
			return routingTestResponse(req, 503, nil, ""), nil
		}
	})
	_, _, err := client.Poll(context.Background(), 1)
	require.Error(t, err)
	done := make(chan error, 1)
	go func() { _, _, err := client.Poll(context.Background(), 1); done <- err }()
	<-entered
	for range 2 {
		_, _, err = client.Poll(context.Background(), 1)
		assert.Error(t, err)
	}
	close(release)
	assert.NoError(t, <-done)
	_, _, err = client.Poll(context.Background(), 1)
	require.Error(t, err)
	assertRoutingState(t, client, "", new(uint64(1)))
}

func TestPollRoutingCancellationDoesNotEvictCachedRoute(t *testing.T) {
	t.Parallel()
	entered := make(chan struct{})
	var attempts atomic.Int32
	client := newRoutingTestClient(t, "https://eu.api.openai.com", "tunnel", func(req *http.Request) (*http.Response, error) {
		switch attempts.Add(1) {
		case 1:
			return routingTestCorrection(req, "route-a", 1), nil
		case 4:
			close(entered)
			<-req.Context().Done()
			return nil, req.Context().Err()
		default:
			assert.Equal(t, "route-a", req.Header.Get(routingTestTokenHeader))
			return routingTestResponse(req, 503, nil, ""), nil
		}
	})
	for range 3 {
		_, _, err := client.Poll(context.Background(), 1)
		require.Error(t, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, _, err := client.Poll(ctx, 1); done <- err }()
	<-entered
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	assertRoutingState(t, client, "route-a", new(uint64(1)))
	_, _, err := client.Poll(context.Background(), 1)
	require.Error(t, err)
	assertRoutingState(t, client, "", new(uint64(1)))
	assert.EqualValues(t, 5, attempts.Load())
}

func TestPollRoutingStateIsProcessLocalAndScopedToClient(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, endpoint, tunnel string }{
		{"restart", "https://eu.api.openai.com", "same-tunnel"},
		{"other_tunnel", "https://eu.api.openai.com", "other-tunnel"},
		{"other_environment", "https://test.example.com", "same-tunnel"},
		{"other_residency", "https://api.openai.com", "same-tunnel"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			first := newRoutingTestClient(t, "https://eu.api.openai.com", "same-tunnel", func(req *http.Request) (*http.Response, error) {
				return routingTestCorrection(req, "private-route", 17), nil
			})
			_, _, err := first.Poll(context.Background(), 1)
			require.Error(t, err)
			assertRoutingState(t, first, "private-route", new(uint64(17)))
			second := newRoutingTestClient(t, tc.endpoint, tc.tunnel, func(req *http.Request) (*http.Response, error) {
				assert.Empty(t, req.Header.Values(routingTestTokenHeader))
				assert.Equal(t, tc.endpoint, req.URL.Scheme+"://"+req.URL.Host)
				assert.Equal(t, "/v1/tunnels/"+tc.tunnel+"/poll", req.URL.Path)
				return routingTestResponse(req, 204, nil, ""), nil
			})
			_, _, err = second.Poll(context.Background(), 1)
			require.NoError(t, err)
			assertRoutingState(t, second, "", nil)
			assertRoutingState(t, first, "private-route", new(uint64(17)))
		})
	}
}

func TestPollRoutingRejectsRedirectsBeforeCredentialsCanLeaveEndpoint(t *testing.T) {
	t.Parallel()
	for _, location := range []string{
		"https://api.openai.com/v1/tunnels/tunnel/poll",
		"https://untrusted.example/poll",
		"https://eu.api.openai.com/other-poll",
		"/other-poll",
	} {
		for _, status := range []int{301, 302, 303, 307, 308} {
			t.Run(fmt.Sprintf("%d_%s", status, location), func(t *testing.T) {
				t.Parallel()
				attempts := 0
				client := newRoutingTestClient(t, "https://eu.api.openai.com", "tunnel", func(req *http.Request) (*http.Response, error) {
					attempts++
					assert.Equal(t, "eu.api.openai.com", req.URL.Host, "credentials must never reach a redirect target")
					assert.Equal(t, "/v1/tunnels/tunnel/poll", req.URL.Path)
					assert.Equal(t, "Bearer fixture-api-key", req.Header.Get("Authorization"))
					return routingTestResponse(req, status, http.Header{"Location": {location}}, ""), nil
				})
				_, _, err := client.Poll(context.Background(), 1)
				require.Error(t, err)
				assert.Equal(t, 1, attempts, "the auth transport must not replay onto a redirect")
				assertRoutingState(t, client, "", nil)
			})
		}
	}
}

func TestPollRoutingCorrectionUsesExistingBackoffAndRetryAfter(t *testing.T) {
	t.Parallel()
	for _, retryAfter := range []string{"", "600", "invalid"} {
		t.Run("retry_after_"+retryAfter, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			attempts := 0
			client := newRoutingTestClient(t, "https://eu.api.openai.com", "tunnel", func(req *http.Request) (*http.Response, error) {
				attempts++
				response := routingTestCorrection(req, "route-a", 1)
				response.Header.Set("Retry-After", retryAfter)
				return response, nil
			})
			q := &chanQueue{ch: make(chan controlplane.PolledCommand, 1)}
			p, err := NewPoller(q, client, newDiscardLogger(), testMeterProvider.Meter("routing-test"), time.Second, 0, 0, 0)
			require.NoError(t, err)
			loop := p.(*poller)
			assert.True(t, loop.backoff.Jitter, "production correction retries keep jitter enabled")
			loop.backoff.Jitter = false
			var delays []time.Duration
			loop.retrySleep = func(ctx context.Context, delay time.Duration) bool {
				delays = append(delays, delay)
				assert.Equal(t, len(delays), attempts, "one bounded attempt per backoff")
				if len(delays) == 8 {
					cancel()
					return sleepWithContext(ctx, delay)
				}
				return true
			}
			p.Run(ctx)
			want := []time.Duration{200 * time.Millisecond, 400 * time.Millisecond, 800 * time.Millisecond, 1600 * time.Millisecond, 3200 * time.Millisecond, 6400 * time.Millisecond, 10 * time.Second, 10 * time.Second}
			if retryAfter == "600" {
				for i := range want {
					want[i] = time.Minute
				}
			}
			assert.Equal(t, want, delays)
			assert.Equal(t, 8, attempts, "cancellation in backoff must prevent the next attempt")
		})
	}
}

func TestPollRoutingMismatchUsesBackoffWithoutChangingRoute(t *testing.T) {
	t.Parallel()
	const endpoint = "https://eu.api.openai.com"
	const tunnelID = "tunnel_extn_0123456789abcdef0123456789abcdef"
	const token = "existing-route"
	const revision = 17
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attempts := 0
	client := newRoutingTestClient(t, endpoint, tunnelID, func(req *http.Request) (*http.Response, error) {
		attempts++
		assert.Equal(t, http.MethodGet, req.Method)
		assert.Equal(t, endpoint, req.URL.Scheme+"://"+req.URL.Host)
		assert.Equal(t, "/v1/tunnels/"+tunnelID+"/poll", req.URL.Path)
		assert.Equal(t, "Bearer fixture-api-key", req.Header.Get("Authorization"))
		if attempts == 1 {
			assert.Empty(t, req.Header.Values(routingTestTokenHeader))
			return routingTestCorrection(req, token, revision), nil
		}
		assert.Equal(t, token, req.Header.Get(routingTestTokenHeader))
		return routingTestResponse(req, http.StatusMisdirectedRequest, http.Header{
			"Content-Type":  {"application/json"},
			"Cache-Control": {"no-store"},
			"Retry-After":   {"1"},
		}, `{"error":{"message":"This server does not serve this tunnel.","type":"invalid_request_error","param":"tunnel_id","code":"tunnel_routing_mismatch"}}`), nil
	})

	// Learn a token through the optional correction protocol before receiving a
	// generic misdirected-request rejection, which carries no routing correction.
	_, _, err := client.Poll(ctx, 1)
	require.Error(t, err)
	assertRoutingState(t, client, token, new(uint64(revision)))
	_, _, err = client.Poll(ctx, 1)
	var statusErr *APIStatusError
	require.ErrorAs(t, err, &statusErr)
	assert.Equal(t, http.StatusMisdirectedRequest, statusErr.StatusCode())
	assert.Equal(t, "tunnel_routing_mismatch", statusErr.Code())
	assert.Equal(t, "This server does not serve this tunnel.", statusErr.Message())
	retryAfter, hasRetryAfter := statusErr.RetryAfter()
	assert.True(t, hasRetryAfter)
	assert.Equal(t, time.Second, retryAfter)
	assert.Equal(t, 2, attempts, "each Poll must make only one HTTP attempt")

	q := &chanQueue{ch: make(chan controlplane.PolledCommand, 1)}
	p, err := NewPoller(q, client, newDiscardLogger(), testMeterProvider.Meter("routing-test"), time.Second, 0, 0, 0)
	require.NoError(t, err)
	loop := p.(*poller)
	assert.True(t, loop.backoff.Jitter)
	loop.backoff.Jitter = false
	var delays []time.Duration
	loop.retrySleep = func(ctx context.Context, delay time.Duration) bool {
		delays = append(delays, delay)
		assert.Equal(t, len(delays)+2, attempts, "one attempt per ordinary backoff")
		assertRoutingState(t, client, token, new(uint64(revision)))
		if len(delays) == 5 {
			cancel()
			return sleepWithContext(ctx, delay)
		}
		return true
	}
	p.Run(ctx)
	assert.Equal(t, []time.Duration{time.Second, time.Second, time.Second, 1600 * time.Millisecond, 3200 * time.Millisecond}, delays)
	assert.Equal(t, 7, attempts, "cancellation must prevent another attempt")
	assertRoutingState(t, client, token, new(uint64(revision)))
}

func TestPollRoutingErrorsNeverExposeCorrectionPayloads(t *testing.T) {
	t.Parallel()
	const secret = "private-routing-token-do-not-log"
	for name, body := range map[string]string{
		"valid":        `{"error":{"code":"wrong_cluster","policy_revision":1,"message":"` + secret + `"}}`,
		"invalid":      `{"error":{"code":"wrong_cluster","policy_revision":null,"message":"` + secret + `"}}`,
		"exponent":     `{"error":{"code":"wrong_cluster","policy_revision":1e2,"message":"` + secret + `"}}`,
		"malformed":    `{"error":{"code":"wrong_cluster","message":"` + secret,
		"oversized":    `{"error":{"code":"wrong_cluster","policy_revision":1,"message":"` + secret + strings.Repeat("x", maxControlPlaneErrorBodySize) + `"}}`,
		"other_fields": `{"error":{"code":"wrong_cluster","policy_revision":1,"message":"` + secret + `","mitigation":"` + secret + `","detail":"` + secret + `"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			attempts := 0
			client := newRoutingTestClient(t, "https://eu.api.openai.com", "tunnel", func(req *http.Request) (*http.Response, error) {
				attempts++
				return routingTestResponse(req, 409, http.Header{routingTestTokenHeader: {secret}}, body), nil
			})
			client.logger = logger
			_, _, err := client.Poll(ctx, 1)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), secret)
			var statusErr *APIStatusError
			require.ErrorAs(t, err, &statusErr)
			assert.NotContains(t, statusErr.Message(), secret)
			assert.NotContains(t, statusErr.Mitigation(), secret)
			q := &chanQueue{ch: make(chan controlplane.PolledCommand, 1)}
			p, err := NewPoller(q, client, logger, testMeterProvider.Meter("routing-test"), time.Second, 0, 0, 0)
			require.NoError(t, err)
			p.(*poller).retrySleep = func(context.Context, time.Duration) bool { cancel(); return false }
			p.Run(ctx)
			assert.Equal(t, 2, attempts)
			assert.NotContains(t, logs.String(), secret)
			assert.Contains(t, logs.String(), "poll failed; backing off", "diagnostics should retain the failure without payload data")
			if name != "valid" && name != "other_fields" {
				assertRoutingState(t, client, "", nil)
			}
		})
	}
}

func TestPollRoutingSuccessCannotLearnTokens(t *testing.T) {
	t.Parallel()
	attempts := 0
	client := newRoutingTestClient(t, "https://eu.api.openai.com", "tunnel", func(req *http.Request) (*http.Response, error) {
		attempts++
		assert.Empty(t, req.Header.Values(routingTestTokenHeader))
		return routingTestResponse(req, 200, http.Header{routingTestTokenHeader: {"not-a-correction"}},
			`{"commands":[{"command_type":"jsonrpc","request_id":"old-command","shard_token":"legacy-command-token","jsonrpc":{"jsonrpc":"2.0","id":1,"method":"tools/list"}}]}`), nil
	})
	for range 2 {
		commands, _, err := client.Poll(context.Background(), 1)
		require.NoError(t, err)
		require.Len(t, commands, 1)
		assert.Equal(t, "legacy-command-token", commands[0].ShardToken())
		assertRoutingState(t, client, "", nil)
	}
	assert.Equal(t, 2, attempts)
}

func TestRoutingCorrectionsDoNotRetryOrChangeNonPollRequests(t *testing.T) {
	t.Parallel()
	// Spaces and commas are invalid for newly learned polling tokens, but old
	// command tokens must keep their existing HTTP header semantics.
	const commandToken = "legacy command,token"
	attempts := 0
	client := newRoutingTestClient(t, "https://eu.api.openai.com", "tunnel", func(req *http.Request) (*http.Response, error) {
		attempts++
		if attempts == 1 {
			return routingTestCorrection(req, "poll-route", 1), nil
		}
		assert.Equal(t, []string{"wrong-cluster-v1"}, req.Header.Values(routingTestCapabilityHeader), "client capabilities describe every control-plane request")
		if req.Method == http.MethodPost {
			assert.Equal(t, "/v1/tunnels/tunnel/response", req.URL.Path)
			assert.Equal(t, commandToken, req.Header.Get(routingTestTokenHeader))
		} else {
			assert.Equal(t, "/v1/tunnels/tunnel", req.URL.Path)
			assert.Empty(t, req.Header.Values(routingTestTokenHeader))
		}
		return routingTestCorrection(req, "must-not-learn-this", 99), nil
	})
	_, _, err := client.Poll(context.Background(), 1)
	require.Error(t, err)
	ctx := tunnelctx.ContextWithShardToken(context.Background(), commandToken)
	ctx = tunnelctx.ContextWithChannel(ctx, types.DefaultChannel)
	_, err = client.PostResponse(ctx, "old-request", types.NewNotificationAck(types.DefaultChannel, http.StatusOK, http.Header{}))
	require.Error(t, err)
	assert.Equal(t, 2, attempts, "wrong_cluster must not add response replay")
	assertRoutingState(t, client, "poll-route", new(uint64(1)))
	_, err = client.FetchTunnelMetadata(context.Background())
	require.Error(t, err)
	assert.Equal(t, 3, attempts)
	assertRoutingState(t, client, "poll-route", new(uint64(1)))
}

func TestPollRoutingDisablesUnsafeRawDumpsForBothDirections(t *testing.T) {
	t.Parallel()
	const secret = "private-routing-token-do-not-dump"
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	attempts := 0
	client := newRoutingTestClient(t, "https://eu.api.openai.com", "tunnel", func(req *http.Request) (*http.Response, error) {
		attempts++
		if attempts == 1 {
			return routingTestCorrection(req, secret, 1), nil
		}
		assert.Equal(t, secret, req.Header.Get(routingTestTokenHeader))
		return routingTestResponse(req, 204, nil, ""), nil
	})
	wrapper := client.client.Transport.(*controlPlaneRoundTripper)
	wrapper.base = tclog.NewRoundTripper(wrapper.base, logger, &config.LoggingConfig{HTTPRawUnsafe: true}, tclog.ComponentControlPlane)
	_, _, err := client.Poll(context.Background(), 1)
	require.Error(t, err)
	_, _, err = client.Poll(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, 2, attempts)
	assert.NotContains(t, logs.String(), secret)
	assert.NotContains(t, logs.String(), "fixture-api-key")
	assert.NotContains(t, logs.String(), "/v1/tunnels/tunnel/poll")
	assert.NotContains(t, logs.String(), "raw http")
}

type routingReadSpy struct {
	reader *bytes.Reader
	read   int
	closed bool
}

func (r *routingReadSpy) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.read += n
	return n, err
}

func (r *routingReadSpy) Close() error { r.closed = true; return nil }

func TestPollRoutingOversizedErrorBodyIsClosedWithoutUnboundedDrain(t *testing.T) {
	t.Parallel()
	body := &routingReadSpy{reader: bytes.NewReader(bytes.Repeat([]byte("x"), 2*maxControlPlaneErrorBodySize))}
	client := newRoutingTestClient(t, "https://eu.api.openai.com", "tunnel", func(req *http.Request) (*http.Response, error) {
		response := routingTestCorrection(req, "private-token", 1)
		response.Body = body
		return response, nil
	})
	_, _, err := client.Poll(context.Background(), 1)
	require.Error(t, err)
	assert.Equal(t, maxControlPlaneErrorBodySize+1, body.read)
	assert.True(t, body.closed)
	assertRoutingState(t, client, "", nil)
}

type routingFailedBody struct{ err error }

func (r routingFailedBody) Read([]byte) (int, error) { return 0, r.err }
func (r routingFailedBody) Close() error             { return nil }

func TestPollRoutingBodyFailureCountsTowardDestinationRecovery(t *testing.T) {
	t.Parallel()
	for _, bodyErr := range []error{io.ErrUnexpectedEOF, context.DeadlineExceeded} {
		t.Run(bodyErr.Error(), func(t *testing.T) {
			t.Parallel()
			attempts := 0
			client := newRoutingTestClient(t, "https://eu.api.openai.com", "tunnel", func(req *http.Request) (*http.Response, error) {
				attempts++
				if attempts == 1 {
					return routingTestCorrection(req, "route-a", 1), nil
				}
				response := routingTestResponse(req, 200, nil, "")
				response.Body = routingFailedBody{err: bodyErr}
				return response, nil
			})
			for range 3 {
				_, _, err := client.Poll(context.Background(), 1)
				require.Error(t, err)
				assertRoutingState(t, client, "route-a", new(uint64(1)))
			}
			_, _, err := client.Poll(context.Background(), 1)
			require.ErrorIs(t, err, bodyErr)
			assertRoutingState(t, client, "", new(uint64(1)))
		})
	}
}

func TestPollRoutingMetadataOnWrongStatusIsPrivateAndNotAccepted(t *testing.T) {
	t.Parallel()
	const secret = "private-routing-token-do-not-log"
	for _, status := range []int{http.StatusUnauthorized, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			client := newRoutingTestClient(t, "https://eu.api.openai.com", "tunnel", func(req *http.Request) (*http.Response, error) {
				response := routingTestResponse(req, status, http.Header{routingTestTokenHeader: {secret}},
					`{"error":{"code":"wrong_cluster","policy_revision":1,"message":"`+secret+`","mitigation":"`+secret+`"}}`)
				response.Status = fmt.Sprintf("%d %s", status, secret)
				return response, nil
			})
			_, _, err := client.Poll(context.Background(), 1)
			require.Error(t, err)
			var statusErr *APIStatusError
			require.ErrorAs(t, err, &statusErr)
			assert.Equal(t, status, statusErr.StatusCode())
			for _, diagnostic := range []string{err.Error(), statusErr.Message(), statusErr.Mitigation(), statusErr.Status()} {
				assert.NotContains(t, diagnostic, secret)
			}
			assertRoutingState(t, client, "", nil)
		})
	}
}

type routingReaderFunc func([]byte) (int, error)

func (f routingReaderFunc) Read(p []byte) (int, error) { return f(p) }

func TestPollRoutingCancellationDuringErrorBodyDoesNotEvictRoute(t *testing.T) {
	t.Parallel()
	entered := make(chan struct{})
	var attempts atomic.Int32
	client := newRoutingTestClient(t, "https://eu.api.openai.com", "tunnel", func(req *http.Request) (*http.Response, error) {
		attempt := attempts.Add(1)
		if attempt == 1 {
			return routingTestCorrection(req, "route-a", 1), nil
		}
		response := routingTestResponse(req, 503, nil, "")
		if attempt == 4 {
			response.Body = io.NopCloser(routingReaderFunc(func([]byte) (int, error) {
				close(entered)
				<-req.Context().Done()
				return 0, req.Context().Err()
			}))
		}
		return response, nil
	})
	for range 3 {
		_, _, err := client.Poll(context.Background(), 1)
		require.Error(t, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, _, err := client.Poll(ctx, 1); done <- err }()
	<-entered
	cancel()
	require.Error(t, <-done)
	assertRoutingState(t, client, "route-a", new(uint64(1)))
	_, _, err := client.Poll(context.Background(), 1)
	require.Error(t, err)
	assertRoutingState(t, client, "", new(uint64(1)))
	assert.EqualValues(t, 5, attempts.Load())
}

func TestPollRoutingTransportDiagnosticsHidePrivateGateway(t *testing.T) {
	t.Parallel()
	const endpoint = "https://private-tunnel-gateway.example"
	const privateURL = "https://private-user:private-password@private-tunnel-gateway.example/private-tunnel-path?secret=private-query-token"
	for _, phase := range []string{"request", "successful_response_body"} {
		t.Run(phase, func(t *testing.T) {
			t.Parallel()
			cause := &url.Error{Op: "Get", URL: privateURL, Err: &net.DNSError{
				Err: "private-dns-error-token", Name: "private-tunnel-gateway.example", IsTimeout: true,
			}}
			client := newRoutingTestClient(t, endpoint, "private-tunnel-id", func(req *http.Request) (*http.Response, error) {
				if phase == "request" {
					return nil, cause
				}
				response := routingTestResponse(req, 200, nil, "")
				response.Body = routingFailedBody{err: cause}
				return response, nil
			})
			_, _, err := client.Poll(context.Background(), 1)
			require.Error(t, err)
			require.ErrorIs(t, err, cause)
			var networkErr net.Error
			require.ErrorAs(t, err, &networkErr)
			assert.True(t, networkErr.Timeout())
			var urlErr *url.Error
			require.ErrorAs(t, err, &urlErr)
			for _, diagnostic := range []string{err.Error(), tclog.ErrorForLog(err)} {
				for _, private := range []string{"private-tunnel-gateway", "private-tunnel-path", "private-query-token", "private-dns-error-token", "private-tunnel-id", "private-user", "private-password"} {
					assert.NotContains(t, diagnostic, private)
				}
				assert.Contains(t, diagnostic, "timeout", "diagnostics must retain the network failure category")
			}
		})
	}
}

func TestPollRoutingProxyLearningDiagnosticsHidePrivateGateway(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	client := &TunnelServiceClient{
		pollTimeout: 35 * time.Second, pollGuardrail: 5 * time.Second, usesProxy: true,
		logger: slog.New(slog.NewJSONHandler(&logs, nil)),
	}
	cause := &url.Error{Op: "Get", URL: "https://private-user:private-password@private-gateway.example/private-path?secret=private-query", Err: io.ErrUnexpectedEOF}
	ctx := context.Background()
	client.maybeLearnProxyPollTimeout(ctx, ctx, 35*time.Second, 30*time.Second, false, cause)
	assert.Equal(t, 25*time.Second, client.effectivePollTimeout(), "privacy must not disable proxy cutoff adaptation")
	var event map[string]any
	require.NoError(t, json.Unmarshal(logs.Bytes(), &event))
	assert.Equal(t, "control-plane proxy closed long poll; lowering future poll timeout", event["msg"])
	assert.Equal(t, float64(25000), event["learned_poll_timeout_ms"])
	assert.NotContains(t, logs.String(), "private-")
}

func TestPollRoutingErrorBodyFailuresTriggerBoundedBootstrap(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusConflict, http.StatusTooManyRequests} {
		for _, tc := range []struct {
			name    string
			body    string
			readErr error
			evicts  bool
		}{
			{"truncated_body", `{"error":{"code":"wrong_cluster"`, io.ErrUnexpectedEOF, true},
			{"timed_out_body", "", context.DeadlineExceeded, true},
			{"private_network_error", "", &net.DNSError{Err: "private-error-detail", Name: "private-gateway.example", IsTimeout: true}, true},
			{"arbitrary_reader_error", "", errors.New("private-non-network-error"), false},
			{"malformed_json", `{"error":{"code":"wrong_cluster"`, nil, false},
			{"oversized_body", strings.Repeat("x", maxControlPlaneErrorBodySize+1), nil, false},
		} {
			t.Run(fmt.Sprintf("%d_%s", status, tc.name), func(t *testing.T) {
				t.Parallel()
				attempts := 0
				client := newRoutingTestClient(t, "https://eu.api.openai.com", "tunnel", func(req *http.Request) (*http.Response, error) {
					attempts++
					if attempts == 1 {
						return routingTestCorrection(req, "route-a", 1), nil
					}
					if attempts == 5 {
						if tc.evicts {
							assert.Empty(t, req.Header.Values(routingTestTokenHeader))
						} else {
							assert.Equal(t, "route-a", req.Header.Get(routingTestTokenHeader))
						}
						return routingTestResponse(req, 204, nil, ""), nil
					}
					assert.Equal(t, "route-a", req.Header.Get(routingTestTokenHeader))
					response := routingTestResponse(req, status, http.Header{routingTestTokenHeader: {"route-b"}}, tc.body)
					if tc.readErr != nil {
						response.Body = io.NopCloser(io.MultiReader(strings.NewReader(tc.body), routingFailedBody{err: tc.readErr}))
					}
					return response, nil
				})
				_, _, err := client.Poll(context.Background(), 1)
				require.Error(t, err)
				for failure := range 3 {
					_, _, err = client.Poll(context.Background(), 1)
					require.Error(t, err)
					assert.NotContains(t, err.Error(), "private-")
					wantToken := "route-a"
					if failure == 2 && tc.evicts {
						wantToken = ""
					}
					assertRoutingState(t, client, wantToken, new(uint64(1)))
				}
				_, _, err = client.Poll(context.Background(), 1)
				require.NoError(t, err)
				assert.Equal(t, 5, attempts)
			})
		}
	}
}

func TestPollRoutingRejectsAmbiguousKnownJSONFields(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		body     string
		accepted bool
	}{
		{"duplicate_error", `{"error":{"code":"wrong_cluster","policy_revision":1},"error":{"code":"wrong_cluster","policy_revision":2}}`, false},
		{"split_error", `{"error":{"code":"wrong_cluster"},"error":{"policy_revision":2}}`, false},
		{"duplicate_code", `{"error":{"code":"unrelated","code":"wrong_cluster","policy_revision":2}}`, false},
		{"duplicate_revision", `{"error":{"code":"wrong_cluster","policy_revision":null,"policy_revision":2}}`, false},
		{"duplicate_identical_revision", `{"error":{"code":"wrong_cluster","policy_revision":2,"policy_revision":2}}`, false},
		{"conflicting_token_copies", `{"error":{"code":"wrong_cluster","policy_revision":2,"shard_token":"conflict","shard_token":"route-b"}}`, false},
		{"escaped_duplicate_revision", `{"error":{"code":"wrong_cluster","policy_revision":null,"policy\u005frevision":2}}`, false},
		{"wrong_case_envelope", `{"ERROR":{"code":"wrong_cluster","policy_revision":2}}`, false},
		{"wrong_case_code", `{"error":{"CODE":"wrong_cluster","policy_revision":2}}`, false},
		{"duplicate_unknown_metadata", `{"future":1,"future":2,"error":{"code":"wrong_cluster","policy_revision":2,"future":1,"future":2}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			attempts := 0
			wantToken, wantRevision := "route-a", uint64(1)
			if tc.accepted {
				wantToken, wantRevision = "route-b", 2
			}
			client := newRoutingTestClient(t, "https://eu.api.openai.com", "tunnel", func(req *http.Request) (*http.Response, error) {
				attempts++
				switch attempts {
				case 1:
					return routingTestCorrection(req, "route-a", 1), nil
				case 2:
					assert.Equal(t, "route-a", req.Header.Get(routingTestTokenHeader))
					return routingTestResponse(req, 409, http.Header{routingTestTokenHeader: {"route-b"}}, tc.body), nil
				default:
					assert.Equal(t, wantToken, req.Header.Get(routingTestTokenHeader))
					return routingTestResponse(req, 204, nil, ""), nil
				}
			})
			for range 2 {
				_, _, err := client.Poll(context.Background(), 1)
				require.Error(t, err)
			}
			assertRoutingState(t, client, wantToken, new(wantRevision))
			_, _, err := client.Poll(context.Background(), 1)
			require.NoError(t, err)
			assert.Equal(t, 3, attempts)
		})
	}
}

func TestPollRoutingCommandReceiptLogsOnlyBoundedDeliveryMetadata(t *testing.T) {
	t.Parallel()
	polledAt := time.Date(2026, time.September, 18, 12, 34, 56, 123456000, time.UTC)
	const (
		privateToken   = "private-command-routing-token"
		privateSession = "private-mcp-session"
		privateHeader  = "private-header-credential"
		privateRPCID   = "private-customer-rpc-id"
		privatePayload = "private-tool-argument"
		privateTimeout = "private-invalid-timeout"
	)
	for _, tc := range []struct {
		name        string
		commandType string
		requestID   string
		timeout     any
		wantTimeout string
	}{
		{"jsonrpc", "jsonrpc", "receipt-rpc", "4500ms", "4500ms"},
		{"oauth_discovery", "oauth_discovery", "receipt-oauth", "2s", "2s"},
		{"session_termination", "session_termination", "receipt-termination", "0ms", "0ms"},
		{"maximum_request_id", "jsonrpc", strings.Repeat("r", 128), "1s", "1s"},
		{"oversized_id_and_invalid_timeout", "jsonrpc", strings.Repeat("r", 129), privateTimeout, ""},
		{"wrong_timeout_type", "jsonrpc", "receipt-invalid-timing", map[string]string{"secret": privateTimeout}, ""},
		{"oversized_valid_timeout", "jsonrpc", "receipt-long-timing", strings.Repeat("0", 128) + "1ms", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			client := &TunnelServiceClient{logger: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
			payload, err := json.Marshal(map[string]any{"commands": []any{map[string]any{
				"command_type":     tc.commandType,
				"request_id":       tc.requestID,
				"response_timeout": tc.timeout,
				"shard_token":      privateToken,
				"headers": map[string][]string{
					"Mcp-Session-Id": {privateSession},
					"Authorization":  {"Bearer " + privateHeader},
				},
				"jsonrpc": map[string]any{
					"jsonrpc": "2.0",
					"id":      privateRPCID,
					"method":  "tools/call",
					"params":  map[string]any{"name": "private-tool-name", "arguments": map[string]string{"secret": privatePayload}},
				},
			}}})
			require.NoError(t, err)
			commands, err := client.decodeCommands(context.Background(), bytes.NewReader(payload), 1, polledAt)
			require.NoError(t, err)
			require.Len(t, commands, 1)
			assert.Equal(t, privateToken, commands[0].ShardToken(), "the log must omit metadata present on the accepted command")
			assert.Equal(t, polledAt, commands[0].PolledAt())
			if tc.name == "oversized_valid_timeout" {
				command, ok := commands[0].(*jsonRpcCommand)
				require.True(t, ok)
				require.NotNil(t, command.deadline, "logging bounds must not reject valid command timing")
				assert.Equal(t, polledAt.Add(time.Millisecond), *command.deadline)
			}

			var event map[string]any
			decoder := json.NewDecoder(&logs)
			require.NoError(t, decoder.Decode(&event))
			require.ErrorIs(t, decoder.Decode(new(map[string]any)), io.EOF, "exactly one receipt event per command")
			assert.Equal(t, "DEBUG", event["level"])
			assert.Equal(t, "control-plane command received", event["msg"])
			assert.Equal(t, tc.commandType, event["command_type"])
			loggedAt, ok := event["polled_at"].(string)
			require.True(t, ok)
			parsedAt, err := time.Parse(time.RFC3339Nano, loggedAt)
			require.NoError(t, err)
			assert.Equal(t, polledAt, parsedAt, "receipt timing must retain the actual poll timestamp")
			wantKeys := []string{"time", "level", "msg", "command_type", "polled_at"}
			if len(tc.requestID) <= 128 {
				assert.Equal(t, tc.requestID, event["request_id"])
				wantKeys = append(wantKeys, "request_id")
			}
			if tc.wantTimeout != "" {
				assert.Equal(t, tc.wantTimeout, event["response_timeout"])
				wantKeys = append(wantKeys, "response_timeout")
			}
			keys := make([]string, 0, len(event))
			for key := range event {
				keys = append(keys, key)
			}
			assert.ElementsMatch(t, wantKeys, keys, "receipt events must contain only bounded delivery metadata")
			encoded, err := json.Marshal(event)
			require.NoError(t, err)
			for _, private := range []string{privateToken, privateSession, privateHeader, privateRPCID, privatePayload, privateTimeout, "private-tool-name"} {
				assert.NotContains(t, string(encoded), private)
			}
		})
	}
}
