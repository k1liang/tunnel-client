package e2e_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/stretchr/testify/require"

	"github.com/openai/tunnel-client/pkg/controlplane/wiretypes"
	"github.com/openai/tunnel-client/testsupport/mockmcpserver"
	"github.com/openai/tunnel-client/testsupport/mocktunnelservice"
)

// Exercise serialized profile bytes and tool calls through an actual client
// process, including its poll/response transport and verified HTTPS callout.
func TestHarpoonTemplatesRuntimeE2E(t *testing.T) {
	t.Parallel()

	for _, subject := range runtimeSubjectsWithBinaries(t, runtimeFullSubject(), runtimeCustomerSubject()) {
		t.Run(subject.name, func(t *testing.T) {
			t.Parallel()
			runHarpoonTemplatesRuntime(t, subject)
		})
	}
}

func TestHarpoonLoopbackHTTPTemplateRuntimeE2E(t *testing.T) {
	t.Parallel()

	for _, subject := range runtimeSubjectsWithBinaries(t, runtimeFullSubject(), runtimeCustomerSubject()) {
		t.Run(subject.name, func(t *testing.T) {
			t.Parallel()
			runHarpoonLoopbackHTTPTemplateRuntime(t, subject)
		})
	}
}

func TestHarpoonRichTargetDiscoveryRuntimeE2E(t *testing.T) {
	t.Parallel()

	for _, subject := range runtimeSubjectsWithBinaries(t, runtimeFullSubject(), runtimeCustomerSubject()) {
		t.Run(subject.name, func(t *testing.T) {
			t.Parallel()
			runHarpoonRichTargetDiscoveryRuntime(t, subject)
		})
	}
}

func TestHarpoonHeaderRulesRuntimeE2E(t *testing.T) {
	t.Parallel()
	for _, subject := range runtimeSubjectsWithBinaries(t, runtimeFullSubject(), runtimeCustomerSubject()) {
		t.Run(subject.name, func(t *testing.T) {
			t.Parallel()
			runHarpoonHeaderRulesRuntime(t, subject)
		})
	}
}

func runHarpoonHeaderRulesRuntime(t *testing.T, subject runtimeSubject) {
	t.Helper()
	const (
		auth  = "Bearer header-e2e-private-token"
		trace = "trace_123"
	)
	recorder := &templateRuntimeRecorder{}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder.record(r)
		if strings.HasPrefix(r.URL.Path, "/rich/") && r.Header.Get("Authorization") != auth {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("header-rules-ok"))
	}))
	t.Cleanup(upstream.Close)
	caPath := filepath.Join(t.TempDir(), "upstream-ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})
	require.NoError(t, os.WriteFile(caPath, certPEM, 0o600))

	type callCase struct {
		name, headers string
		legacy, valid bool
		labelKind     string
	}
	validHeaders := fmt.Sprintf(`{"Authorization":%q,"X-Trace-Id":%q}`, auth, trace)
	cases := []callCase{
		{name: "valid", headers: validHeaders, valid: true},
		{name: "missing_auth", headers: fmt.Sprintf(`{"X-Trace-Id":%q}`, trace)},
		{name: "missing_trace", headers: fmt.Sprintf(`{"Authorization":%q}`, auth)},
		{name: "missing_headers"},
		{name: "auth_pattern", headers: fmt.Sprintf(`{"Authorization":"Basic private-invalid-token","X-Trace-Id":%q}`, trace)},
		{name: "trace_pattern", headers: fmt.Sprintf(`{"Authorization":%q,"X-Trace-Id":"bad trace"}`, auth)},
		{name: "trace_short", headers: fmt.Sprintf(`{"Authorization":%q,"X-Trace-Id":"x"}`, auth)},
		{name: "trace_long", headers: fmt.Sprintf(`{"Authorization":%q,"X-Trace-Id":%q}`, auth, strings.Repeat("x", 17))},
		{name: "auth_long", headers: fmt.Sprintf(`{"Authorization":%q,"X-Trace-Id":%q}`, "Bearer "+strings.Repeat("x", 128), trace)},
		{name: "unknown_header", headers: fmt.Sprintf(`{"Authorization":%q,"X-Trace-Id":%q,"X-Unknown":"private-unknown-value"}`, auth, trace)},
		{name: "renamed_destination", headers: fmt.Sprintf(`{"Authorization":%q,"X-Upstream-Trace":%q}`, auth, trace)},
		{name: "duplicate_header", headers: fmt.Sprintf(`{"Authorization":%q,"X-Trace-Id":%q,"X-Trace-Id":"second"}`, auth, trace)},
		{name: "duplicate_header_case", headers: fmt.Sprintf(`{"Authorization":%q,"X-Trace-Id":%q,"x-trace-id":"second"}`, auth, trace)},
		{name: "invalid_control", headers: fmt.Sprintf(`{"Authorization":%q,"X-Trace-Id":"bad\r\nvalue"}`, auth)},
		{name: "unbound", headers: validHeaders, labelKind: "unbound"},
		{name: "mismatched_revision", headers: validHeaders, labelKind: "mismatched"},
		{name: "legacy_optional", legacy: true, valid: true},
		{name: "legacy_empty", headers: `{"X-Request-Tag":""}`, legacy: true, valid: true},
		{name: "legacy_utf8", headers: `{"X-Request-Tag":"Grüße"}`, legacy: true, valid: true},
	}
	ready, invocationReady := make(chan struct{}), make(chan struct{})
	commands := []mocktunnelservice.CommandResponse{
		templateRuntimeCommand(t, "headers-tools-list", "tools/list", nil, ready),
		templateRuntimeCommand(t, "headers-list-targets", "tools/call", json.RawMessage(`{"name":"list_targets","arguments":{}}`), ready),
	}
	discoveredCommands := make(map[string]json.RawMessage, len(cases))
	for _, tc := range cases {
		command := templateRuntimeCommand(t, "headers-"+tc.name, "tools/call", nil, invocationReady)
		command.CommandMutator = func(_ json.RawMessage, _ mocktunnelservice.SharedStorage) json.RawMessage {
			// invocationReady publishes commands assembled from the live discovery.
			return discoveredCommands[tc.name]
		}
		commands = append(commands, command)
	}
	controlPlane := mocktunnelservice.NewMockTunnelService(
		mocktunnelservice.WithAPIKey(runtimeArtifactAPIKey),
		mocktunnelservice.WithTunnelID(runtimeArtifactTunnelID),
		mocktunnelservice.WithCommandResponses(commands...),
	)
	controlPlane.Start(t)
	healthURLFile := filepath.Join(t.TempDir(), "health.url")
	profilePath := filepath.Join(t.TempDir(), "header-rules.yaml")
	profile := fmt.Sprintf(`config_version: 2
ca_bundle: %s
control_plane:
  base_url: %s
  tunnel_id: %s
  api_key: env:CONTROL_PLANE_API_KEY
  poll_channels: [harpoon]
harpoon:
  targets:
    - label: header_auth
      description: Retrieve a resource using caller credentials
      template:
        version: 1
        origin: %s
        method: GET
        path_template: /rich/{id}
        parameters:
          id:
            type: string
            required: true
            pattern: '^[A-Za-z0-9_-]+$'
            max_length: 64
        header_rules:
          - name: Authorization
            description: Bearer token for the upstream API
            required: true
            credential: true
            validation:
              pattern: '^Bearer [A-Za-z0-9._-]+$'
              min_length: 8
              max_length: 128
          - name: X-Trace-Id
            description: Correlation identifier for this request
            required: true
            forward_as: X-Upstream-Trace
            validation:
              pattern: '^[A-Za-z0-9_-]+$'
              min_length: 3
              max_length: 16
        follow_redirects: false
    - label: legacy_headers
      template:
        version: 1
        origin: %s
        method: GET
        path_template: /legacy/{id}
        parameters:
          id:
            type: string
            required: true
            pattern: '^[A-Za-z0-9_-]+$'
            max_length: 64
        allowed_headers: [X-Request-Tag]
        follow_redirects: false
health:
  listen_addr: 127.0.0.1:0
  url_file: %s
admin_ui:
  open_browser: false
log:
  level: debug
  format: struct-text
  http_raw_unsafe: true
`, runtimeArtifactYAMLScalar(caPath), runtimeArtifactYAMLScalar(controlPlane.BaseURL().String()), runtimeArtifactTunnelID,
		runtimeArtifactYAMLScalar(upstream.URL), runtimeArtifactYAMLScalar(upstream.URL), runtimeArtifactYAMLScalar(healthURLFile))
	require.NoError(t, os.WriteFile(profilePath, []byte(profile), 0o600))
	proc := startRuntimeArtifactWithEnv(t, subject.binary, nil, "run", "--config", profilePath)
	_ = waitForRuntimeArtifactHealthURL(t, proc, healthURLFile)
	if len(subject.startupSignals) > 0 {
		waitForRuntimeArtifactOutput(t, proc, "completed startup", subject.startupSignals...)
	}
	close(ready)
	ctx, cancel := context.WithTimeout(context.Background(), runtimeArtifactSignalTimeout)
	t.Cleanup(cancel)
	require.NoError(t, controlPlane.WaitForResponses(ctx, 2), "discovery did not complete: %s", proc.output.String())
	discoveryResponses := controlPlane.ReceivedResponses(mocktunnelservice.ResponseMatchMatched)
	require.Len(t, discoveryResponses, 2)
	byID := make(map[string]mocktunnelservice.ReceivedResponse)
	for _, response := range discoveryResponses {
		byID[response.RequestID] = response
	}
	discovery := templateRuntimeResult(t, byID["headers-list-targets"])
	structured, ok := discovery["structuredContent"].(map[string]any)
	require.True(t, ok)
	targets, ok := structured["targets"].([]any)
	require.True(t, ok)
	invocations := make(map[string]map[string]any)
	for _, raw := range targets {
		target, ok := raw.(map[string]any)
		require.True(t, ok)
		label, ok := target["label"].(string)
		require.True(t, ok)
		invocation, ok := target["invocation"].(map[string]any)
		require.True(t, ok)
		invocations[label] = invocation
	}
	richInvocation := invocations["header_auth"]
	require.NotEmpty(t, richInvocation)
	richSchema, ok := richInvocation["input_schema"].(map[string]any)
	require.True(t, ok)
	richProperties, ok := richSchema["properties"].(map[string]any)
	require.True(t, ok)
	labelSchema, ok := richProperties["label"].(map[string]any)
	require.True(t, ok)
	boundLabel, ok := labelSchema["const"].(string)
	require.True(t, ok)
	require.True(t, strings.HasPrefix(boundLabel, "hr1:"), "structured policies require a bound invocation label")
	require.NotEqual(t, "header_auth", boundLabel)
	headerSchema, ok := richProperties["headers"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, false, headerSchema["additionalProperties"])
	require.ElementsMatch(t, []any{"Authorization", "X-Trace-Id"}, headerSchema["required"])
	headerProperties, ok := headerSchema["properties"].(map[string]any)
	require.True(t, ok)
	for _, want := range []struct {
		name, description, pattern string
		minLength, maxLength       float64
	}{
		{"Authorization", "Bearer token for the upstream API", "^Bearer [A-Za-z0-9._-]+$", 8, 128},
		{"X-Trace-Id", "Correlation identifier for this request", "^[A-Za-z0-9_-]+$", 3, 16},
	} {
		property, ok := headerProperties[want.name].(map[string]any)
		require.True(t, ok)
		require.Equal(t, want.description, property["description"])
		require.Equal(t, "^(?:"+want.pattern+")$", property["pattern"], "discovery must advertise whole-value matching")
		require.Equal(t, want.minLength, property["minLength"])
		require.Equal(t, want.maxLength, property["maxLength"])
	}
	tools := templateRuntimeResult(t, byID["headers-tools-list"])
	rawTools, ok := tools["tools"].([]any)
	require.True(t, ok)
	foundRichSchema := false
	for _, rawTool := range rawTools {
		tool, ok := rawTool.(map[string]any)
		require.True(t, ok)
		if tool["name"] != "call_target" {
			continue
		}
		input, ok := tool["inputSchema"].(map[string]any)
		require.True(t, ok)
		branches, ok := input["oneOf"].([]any)
		require.True(t, ok)
		for _, rawBranch := range branches {
			branch, ok := rawBranch.(map[string]any)
			require.True(t, ok)
			properties, ok := branch["properties"].(map[string]any)
			require.True(t, ok)
			label, ok := properties["label"].(map[string]any)
			if ok && label["const"] == boundLabel {
				require.Equal(t, richSchema, branch)
				foundRichSchema = true
			}
		}
	}
	require.True(t, foundRichSchema, "tools/list must advertise the same header constraints as list_targets")
	for _, public := range []map[string]any{discovery, tools} {
		encoded, err := json.Marshal(public)
		require.NoError(t, err)
		for _, private := range []string{"forward_as", "X-Upstream-Trace", upstream.URL, auth} {
			require.NotContains(t, string(encoded), private)
		}
	}

	for _, tc := range cases {
		invocation := richInvocation
		if tc.legacy {
			invocation = invocations["legacy_headers"]
		}
		schema, ok := invocation["input_schema"].(map[string]any)
		require.True(t, ok)
		properties, ok := schema["properties"].(map[string]any)
		require.True(t, ok)
		label, ok := properties["label"].(map[string]any)
		require.True(t, ok)
		callLabel, ok := label["const"].(string)
		require.True(t, ok)
		switch tc.labelKind {
		case "unbound":
			callLabel = "header_auth"
		case "mismatched":
			parts := strings.SplitN(callLabel, ":", 3)
			require.Len(t, parts, 3)
			require.NotEmpty(t, parts[1])
			last := "0"
			if strings.HasSuffix(parts[1], last) {
				last = "1"
			}
			parts[1] = parts[1][:len(parts[1])-1] + last
			callLabel = strings.Join(parts, ":")
		}
		arguments := fmt.Sprintf(`{"label":%q,"parameters":{"id":%q}`, callLabel, tc.name)
		if tc.headers != "" {
			arguments += `,"headers":` + tc.headers
		}
		arguments += "}"
		params := json.RawMessage(fmt.Sprintf(`{"name":%q,"arguments":%s}`, invocation["tool_name"], arguments))
		discoveredCommands[tc.name] = templateRuntimeCommand(t, "headers-"+tc.name, "tools/call", params, nil).Command
	}
	close(invocationReady)
	waitForRuntimeArtifactIdle(t, proc, controlPlane)
	require.NoErrorf(t, proc.stop(), "%s did not shut down cleanly; output:\n%s", subject.name, proc.output.String())
	responses := controlPlane.ReceivedResponses(mocktunnelservice.ResponseMatchMatched)
	require.Len(t, responses, len(commands))
	require.Empty(t, controlPlane.ReceivedResponses(mocktunnelservice.ResponseMatchUnexpected))
	for _, response := range responses {
		byID[response.RequestID] = response
	}
	for _, tc := range cases {
		response, found := byID["headers-"+tc.name]
		require.True(t, found)
		var envelope struct {
			Result map[string]any  `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		require.NoError(t, json.Unmarshal(response.JSONResponse, &envelope))
		failed := len(envelope.Error) > 0 || envelope.Result["isError"] == true
		require.Equal(t, !tc.valid, failed, "%s: %s", tc.name, response.JSONResponse)
		if tc.valid {
			result, ok := envelope.Result["structuredContent"].(map[string]any)
			require.True(t, ok)
			require.Equal(t, float64(http.StatusOK), result["status_code"])
		}
		for _, private := range []string{auth, "private-invalid-token", "private-unknown-value"} {
			require.NotContains(t, string(response.JSONResponse), private)
		}
	}
	// Every command has settled and the process has exited. This exact count
	// proves rejected input never reached HTTPS without waiting for absence.
	requests := recorder.snapshot()
	require.Len(t, requests, 4, "a rejected header invocation reached the upstream: %#v", requests)
	byPath := make(map[string]templateRuntimeRequest)
	for _, request := range requests {
		require.NotContains(t, byPath, request.escapedPath)
		byPath[request.escapedPath] = request
		require.Equal(t, http.MethodGet, request.method)
		require.Empty(t, request.body)
	}
	richRequest := byPath["/rich/valid"]
	require.Equal(t, auth, richRequest.headers.Get("Authorization"))
	require.Equal(t, trace, richRequest.headers.Get("X-Upstream-Trace"))
	require.NotContains(t, richRequest.headers, "X-Trace-Id")
	require.NotContains(t, byPath["/legacy/legacy_optional"].headers, "X-Request-Tag")
	require.Equal(t, []string{""}, byPath["/legacy/legacy_empty"].headers.Values("X-Request-Tag"))
	require.Equal(t, "Grüße", byPath["/legacy/legacy_utf8"].headers.Get("X-Request-Tag"))
	for _, name := range []string{"legacy_optional", "legacy_empty", "legacy_utf8"} {
		require.Empty(t, byPath["/legacy/"+name].headers.Get("Authorization"))
	}
	for _, private := range []string{auth, "private-invalid-token", "private-unknown-value"} {
		require.NotContains(t, proc.output.String(), private)
	}
	require.NotContains(t, proc.output.String(), "raw http response", "rich-header control-plane replies must bypass unsafe capture")
	require.NotContains(t, proc.output.String(), "raw http request", "rich-header control-plane requests must bypass unsafe capture")

	// A new process must derive the same binding from the same tunnel, key,
	// and policy. Changing only a private mapping must invalidate that binding.
	changedProfile := strings.Replace(profile, "forward_as: X-Upstream-Trace", "forward_as: X-Changed-Upstream-Trace", 1)
	require.NotEqual(t, profile, changedProfile)
	for index, phase := range []struct {
		name, profile string
		wantError     bool
	}{
		{name: "replica", profile: profile},
		{name: "stale_policy", profile: changedProfile, wantError: true},
	} {
		gate := make(chan struct{})
		requestID := "headers-" + phase.name
		params := json.RawMessage(fmt.Sprintf(`{"name":%q,"arguments":{"label":%q,"parameters":{"id":%q},"headers":%s}}`,
			richInvocation["tool_name"], boundLabel, phase.name, validHeaders))
		mocktunnelservice.WithCommandResponses(templateRuntimeCommand(t, requestID, "tools/call", params, gate))(controlPlane)
		require.NoError(t, os.WriteFile(profilePath, []byte(phase.profile), 0o600))
		if err := os.Remove(healthURLFile); err != nil {
			require.True(t, os.IsNotExist(err), "remove prior process health URL: %v", err)
		}
		restarted := startRuntimeArtifactWithEnv(t, subject.binary, nil, "run", "--config", profilePath)
		_ = waitForRuntimeArtifactHealthURL(t, restarted, healthURLFile)
		if len(subject.startupSignals) > 0 {
			waitForRuntimeArtifactOutput(t, restarted, "completed startup", subject.startupSignals...)
		}
		close(gate)
		waitForRuntimeArtifactIdle(t, restarted, controlPlane)
		require.NoErrorf(t, restarted.stop(), "%s %s restart did not shut down cleanly; output:\n%s", subject.name, phase.name, restarted.output.String())
		phaseResponses := controlPlane.ReceivedResponses(mocktunnelservice.ResponseMatchMatched)
		require.Len(t, phaseResponses, len(commands)+index+1)
		require.Empty(t, controlPlane.ReceivedResponses(mocktunnelservice.ResponseMatchUnexpected))
		var response mocktunnelservice.ReceivedResponse
		for _, candidate := range phaseResponses {
			if candidate.RequestID == requestID {
				response = candidate
				break
			}
		}
		require.Equal(t, requestID, response.RequestID)
		var envelope struct {
			Result map[string]any  `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		require.NoError(t, json.Unmarshal(response.JSONResponse, &envelope))
		failed := len(envelope.Error) > 0 || envelope.Result["isError"] == true
		require.Equal(t, phase.wantError, failed, "%s restart: %s", phase.name, response.JSONResponse)
		if !phase.wantError {
			result, ok := envelope.Result["structuredContent"].(map[string]any)
			require.True(t, ok)
			require.Equal(t, float64(http.StatusOK), result["status_code"])
		}
		phaseRequests := recorder.snapshot()
		require.Len(t, phaseRequests, 5, "same policy must permit exactly one request; changed policy must emit none")
		replica := phaseRequests[4]
		require.Equal(t, "/rich/replica", replica.escapedPath)
		require.Equal(t, auth, replica.headers.Get("Authorization"))
		require.Equal(t, trace, replica.headers.Get("X-Upstream-Trace"))
		require.NotContains(t, replica.headers, "X-Trace-Id")
		for _, private := range []string{auth, trace, "private-invalid-token", "private-unknown-value"} {
			require.NotContains(t, string(response.JSONResponse), private)
			require.NotContains(t, restarted.output.String(), private)
		}
		require.NotContains(t, restarted.output.String(), "raw http response", "rich-header replies must bypass unsafe capture after restart")
		require.NotContains(t, restarted.output.String(), "raw http request", "rich-header requests must bypass unsafe capture after restart")
	}
	t.Logf("%d initial header invocations produced four HTTPS requests; identical-policy restart added one and changed mapping rejected the original bound label", len(cases))
}

func runHarpoonRichTargetDiscoveryRuntime(t *testing.T, subject runtimeSubject) {
	t.Helper()
	const auth = "Bearer rich-discovery-private-credential"
	recorder := &templateRuntimeRecorder{}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder.record(r)
		if r.Header.Get("Authorization") != auth {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("rich-target-ok"))
	}))
	t.Cleanup(upstream.Close)
	caPath := filepath.Join(t.TempDir(), "upstream-ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})
	require.NoError(t, os.WriteFile(caPath, certPEM, 0o600))

	ready, invocationReady := make(chan struct{}), make(chan struct{})
	var discoveredCommand json.RawMessage
	invoke := templateRuntimeCommand(t, "rich-invoke", "tools/call", nil, invocationReady)
	invoke.CommandMutator = func(_ json.RawMessage, _ mocktunnelservice.SharedStorage) json.RawMessage {
		// Closing invocationReady publishes the command assembled from discovery.
		return discoveredCommand
	}
	controlPlane := mocktunnelservice.NewMockTunnelService(
		mocktunnelservice.WithAPIKey(runtimeArtifactAPIKey),
		mocktunnelservice.WithTunnelID(runtimeArtifactTunnelID),
		mocktunnelservice.WithCommandResponses(
			templateRuntimeCommand(t, "rich-list-targets", "tools/call", json.RawMessage(`{"name":"list_targets","arguments":{}}`), ready),
			invoke,
		),
	)
	controlPlane.Start(t)
	healthURLFile := filepath.Join(t.TempDir(), "health.url")
	profilePath := filepath.Join(t.TempDir(), "rich-discovery.yaml")
	profile := fmt.Sprintf(`config_version: 2
ca_bundle: %s
control_plane:
  base_url: %s
  tunnel_id: %s
  api_key: env:CONTROL_PLANE_API_KEY
  poll_channels: [harpoon]
harpoon:
  targets:
    - label: incomplete_example
      template:
        version: 1
        origin: %s
        method: GET
        path_template: /private-incomplete/{id}
        parameters:
          id:
            type: string
            required: true
            description: An identifier without a supplied example
            pattern: '^[A-Za-z0-9_-]+$'
            max_length: 64
        follow_redirects: false
    - label: complete_example
      description: Retrieve a case for an organization and query selection
      template:
        version: 1
        origin: %s
        method: GET
        path_template: /private-organizations/{organization}/private-cases/{case_id}
        query:
          privateQueryKey: '{query_id}'
          privateRegionKey: '{region}'
          privateFixedName: private-fixed-value
        parameters:
          organization:
            type: string
            required: true
            description: Organization identifier
            examples: [sample-org, another-org]
            pattern: '^[A-Za-z0-9_-]+$'
            max_length: 64
          case_id:
            type: string
            required: true
            description: Case identifier
            examples: [CASE-123, CASE-456]
            pattern: '^[A-Za-z0-9_-]+$'
            max_length: 64
          query_id:
            type: string
            required: true
            description: Query selection identifier
            examples: [sample-query]
            pattern: '^[A-Za-z0-9_-]+$'
            max_length: 64
          region:
            type: string
            required: true
            description: Region selection
            enum: [west, east]
            max_length: 16
        headers:
          Authorization: env:HP_RICH_AUTH
        allowed_headers: [X-Request-Tag]
        follow_redirects: false
health:
  listen_addr: 127.0.0.1:0
  url_file: %s
admin_ui:
  open_browser: false
log:
  level: info
  format: struct-text
`, runtimeArtifactYAMLScalar(caPath), runtimeArtifactYAMLScalar(controlPlane.BaseURL().String()),
		runtimeArtifactTunnelID, runtimeArtifactYAMLScalar(upstream.URL), runtimeArtifactYAMLScalar(upstream.URL),
		runtimeArtifactYAMLScalar(healthURLFile))
	require.NoError(t, os.WriteFile(profilePath, []byte(profile), 0o600))
	proc := startRuntimeArtifactWithEnv(t, subject.binary, map[string]string{"HP_RICH_AUTH": auth}, "run", "--config", profilePath)
	_ = waitForRuntimeArtifactHealthURL(t, proc, healthURLFile)
	// Health and polling start before the full client's remaining Fx hooks.
	// Finish startup before the scenario can complete and signal shutdown.
	if len(subject.startupSignals) > 0 {
		waitForRuntimeArtifactOutput(t, proc, "completed startup", subject.startupSignals...)
	}
	close(ready)
	ctx, cancel := context.WithTimeout(context.Background(), runtimeArtifactSignalTimeout)
	t.Cleanup(cancel)
	require.NoError(t, controlPlane.WaitForResponses(ctx, 1), "list_targets did not complete: %s", proc.output.String())
	discoveryResponses := controlPlane.ReceivedResponses(mocktunnelservice.ResponseMatchMatched)
	require.Len(t, discoveryResponses, 1)
	discovery := templateRuntimeResult(t, discoveryResponses[0])
	arguments := templateRuntimeInvocationFromDiscovery(t, discovery)
	discoveredCommand = templateRuntimeCommand(t, "rich-invoke", "tools/call", arguments, nil).Command
	close(invocationReady)
	waitForRuntimeArtifactIdle(t, proc, controlPlane)
	require.NoErrorf(t, proc.stop(), "%s did not shut down cleanly; output:\n%s", subject.name, proc.output.String())

	structured, ok := discovery["structuredContent"].(map[string]any)
	require.True(t, ok)
	targets, ok := structured["targets"].([]any)
	require.True(t, ok)
	targetByLabel := make(map[string]map[string]any)
	for _, raw := range targets {
		target, ok := raw.(map[string]any)
		require.True(t, ok)
		label, ok := target["label"].(string)
		require.True(t, ok)
		targetByLabel[label] = target
	}
	complete := targetByLabel["complete_example"]
	require.Equal(t, "Retrieve a case for an organization and query selection", complete["description"])
	require.Equal(t, float64(1), complete["template_version"])
	parameterSchema, ok := complete["parameters_schema"].(map[string]any)
	require.True(t, ok)
	properties, ok := parameterSchema["properties"].(map[string]any)
	require.True(t, ok)
	for _, parameter := range []struct {
		name, description string
		examples          []any
	}{
		{"organization", "Organization identifier", []any{"sample-org", "another-org"}},
		{"case_id", "Case identifier", []any{"CASE-123", "CASE-456"}},
		{"query_id", "Query selection identifier", []any{"sample-query"}},
		{"region", "Region selection", nil},
	} {
		property, ok := properties[parameter.name].(map[string]any)
		require.True(t, ok)
		require.Equal(t, parameter.description, property["description"])
		if parameter.examples != nil {
			require.Equal(t, parameter.examples, property["examples"])
		}
	}
	invocation, ok := complete["invocation"].(map[string]any)
	require.True(t, ok)
	inputSchema, ok := invocation["input_schema"].(map[string]any)
	require.True(t, ok)
	inputProperties, ok := inputSchema["properties"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, parameterSchema, inputProperties["parameters"])
	labelSchema, ok := inputProperties["label"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, complete["label"], labelSchema["const"])
	for _, field := range []string{"headers", "timeout_ms", "max_response_bytes"} {
		require.Contains(t, inputProperties, field)
	}
	incompleteInvocation, ok := targetByLabel["incomplete_example"]["invocation"].(map[string]any)
	require.True(t, ok)
	require.NotContains(t, incompleteInvocation, "examples", "partial examples must not become runnable invocations")

	encodedDiscovery, err := json.Marshal(discovery)
	require.NoError(t, err)
	for _, sensitive := range []string{upstream.URL, "/private-organizations/", "/private-cases/", "/private-incomplete/", "privateQueryKey", "privateRegionKey", "privateFixedName", "private-fixed-value", auth, "HP_RICH_AUTH", "Authorization"} {
		require.NotContains(t, string(encodedDiscovery), sensitive)
	}
	responses := controlPlane.ReceivedResponses(mocktunnelservice.ResponseMatchMatched)
	require.Len(t, responses, 2)
	require.Empty(t, controlPlane.ReceivedResponses(mocktunnelservice.ResponseMatchUnexpected))
	result := templateRuntimeResult(t, responses[1])
	response, ok := result["structuredContent"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, float64(http.StatusOK), response["status_code"])
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte("rich-target-ok")), response["body_base64"])
	requests := recorder.snapshot()
	require.Len(t, requests, 1)
	require.Equal(t, http.MethodGet, requests[0].method)
	require.Equal(t, "/private-organizations/sample-org/private-cases/CASE-123", requests[0].escapedPath)
	require.Equal(t, "privateFixedName=private-fixed-value&privateQueryKey=sample-query&privateRegionKey=east", requests[0].rawQuery)
	require.Empty(t, requests[0].body)
	require.Equal(t, auth, requests[0].headers.Get("Authorization"))
	for _, sensitive := range []string{auth, "/private-organizations/sample-org/private-cases/CASE-123", "private-fixed-value"} {
		require.NotContains(t, proc.output.String(), sensitive)
	}
	t.Log("list_targets alone supplied a schema-valid invocation; two control-plane commands produced exactly one HTTPS request")
}

// This caller knows only the discovery contract. It does not know a target label,
// tool name, parameter name, or parameter value until list_targets provides it.
func templateRuntimeInvocationFromDiscovery(t *testing.T, discovery map[string]any) json.RawMessage {
	t.Helper()
	structured, ok := discovery["structuredContent"].(map[string]any)
	require.True(t, ok)
	targets, ok := structured["targets"].([]any)
	require.True(t, ok)
	for _, raw := range targets {
		target, ok := raw.(map[string]any)
		require.True(t, ok)
		invocation, ok := target["invocation"].(map[string]any)
		if !ok {
			continue
		}
		examples, ok := invocation["examples"].([]any)
		if !ok || len(examples) == 0 {
			continue
		}
		tool, ok := invocation["tool_name"].(string)
		require.True(t, ok)
		require.NotEmpty(t, tool)
		schemaJSON, err := json.Marshal(invocation["input_schema"])
		require.NoError(t, err)
		var schema jsonschema.Schema
		require.NoError(t, json.Unmarshal(schemaJSON, &schema))
		resolved, err := schema.Resolve(nil)
		require.NoError(t, err)
		require.NoError(t, resolved.Validate(examples[0]), "discovered example must satisfy the complete invocation schema")
		arguments, err := json.Marshal(map[string]any{"name": tool, "arguments": examples[0]})
		require.NoError(t, err)
		return arguments
	}
	t.Fatal("list_targets did not expose a complete runnable example")
	return nil
}

type templateRuntimeRequest struct {
	method, escapedPath, rawQuery, body string
	headers                             http.Header
}

type templateRuntimeRecorder struct {
	mu       sync.Mutex
	requests []templateRuntimeRequest
}

func (r *templateRuntimeRecorder) record(req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, templateRuntimeRequest{
		method: req.Method, escapedPath: req.URL.EscapedPath(), rawQuery: req.URL.RawQuery,
		body: string(body), headers: req.Header.Clone(),
	})
}

func (r *templateRuntimeRecorder) snapshot() []templateRuntimeRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]templateRuntimeRequest(nil), r.requests...)
}

func runHarpoonLoopbackHTTPTemplateRuntime(t *testing.T, subject runtimeSubject) {
	t.Helper()
	const credential = "Bearer loopback-e2e-private-credential"
	upstreamRequests := &templateRuntimeRecorder{}
	redirectRequests := &templateRuntimeRecorder{}
	proxyRequests := &templateRuntimeRecorder{}
	redirectDestination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectRequests.record(r)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(redirectDestination.Close)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.record(r)
		if r.URL.Path == "/resource/redirect" {
			w.Header().Set("Location", redirectDestination.URL)
			w.WriteHeader(http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("local-ok"))
	}))
	t.Cleanup(upstream.Close)
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyRequests.record(r)
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(proxyServer.Close)

	ready := make(chan struct{})
	commands := []mocktunnelservice.CommandResponse{
		templateRuntimeCommand(t, "loopback-list-targets", "tools/call", json.RawMessage(`{"name":"list_targets","arguments":{}}`), ready),
		templateRuntimeCommand(t, "loopback-get", "tools/call", json.RawMessage(`{"name":"call_target","arguments":{"label":"local_resource","parameters":{"id":"one"}}}`), ready),
		templateRuntimeCommand(t, "loopback-redirect", "tools/call", json.RawMessage(`{"name":"call_target","arguments":{"label":"local_resource","parameters":{"id":"redirect"}}}`), ready),
	}
	controlPlane := mocktunnelservice.NewMockTunnelService(
		mocktunnelservice.WithAPIKey(runtimeArtifactAPIKey),
		mocktunnelservice.WithTunnelID(runtimeArtifactTunnelID),
		mocktunnelservice.WithCommandResponses(commands...),
	)
	controlPlane.Start(t)
	profilePath := filepath.Join(t.TempDir(), "loopback-template.yaml")
	healthURLFile := filepath.Join(t.TempDir(), "health.url")
	profile := fmt.Sprintf(`config_version: 2
control_plane:
  base_url: %s
  tunnel_id: %s
  api_key: env:CONTROL_PLANE_API_KEY
  poll_channels: [harpoon]
harpoon:
  targets:
    - label: local_resource
      template:
        version: 1
        origin: %s
        allow_loopback_http: true
        method: GET
        path_template: /resource/{id}
        parameters:
          id:
            type: string
            required: true
            pattern: '^[A-Za-z0-9_-]+$'
            max_length: 64
        headers:
          Authorization: env:LOCAL_HTTP_AUTH
        follow_redirects: false
health:
  listen_addr: 127.0.0.1:0
  url_file: %s
admin_ui:
  open_browser: false
`, runtimeArtifactYAMLScalar(controlPlane.BaseURL().String()), runtimeArtifactTunnelID,
		runtimeArtifactYAMLScalar(upstream.URL), runtimeArtifactYAMLScalar(healthURLFile))
	require.NoError(t, os.WriteFile(profilePath, []byte(profile), 0o600))
	proc := startRuntimeArtifactWithEnv(t, subject.binary, map[string]string{
		"LOCAL_HTTP_AUTH": credential, "HARPOON_HTTP_PROXY": proxyServer.URL,
		"HARPOON_ALLOW_PLAINTEXT_HTTP": "false",
	}, "run", "--config", profilePath)
	_ = waitForRuntimeArtifactHealthURL(t, proc, healthURLFile)
	if len(subject.startupSignals) > 0 {
		waitForRuntimeArtifactOutput(t, proc, "completed startup", subject.startupSignals...)
	}
	close(ready)
	waitForRuntimeArtifactIdle(t, proc, controlPlane)
	require.NoErrorf(t, proc.stop(), "%s did not shut down cleanly; output:\n%s", subject.name, proc.output.String())

	responses := controlPlane.ReceivedResponses(mocktunnelservice.ResponseMatchMatched)
	require.Len(t, responses, len(commands))
	require.Empty(t, controlPlane.ReceivedResponses(mocktunnelservice.ResponseMatchUnexpected))
	byID := make(map[string]mocktunnelservice.ReceivedResponse, len(responses))
	for _, response := range responses {
		byID[response.RequestID] = response
	}
	discovery := templateRuntimeResult(t, byID["loopback-list-targets"])
	discoveryJSON, err := json.Marshal(discovery)
	require.NoError(t, err)
	require.Contains(t, string(discoveryJSON), `"local_resource"`)
	require.NotContains(t, string(discoveryJSON), upstream.URL)
	require.NotContains(t, string(discoveryJSON), credential)
	for _, tc := range []struct {
		id         string
		statusCode int
	}{{"loopback-get", http.StatusOK}, {"loopback-redirect", http.StatusFound}} {
		result := templateRuntimeResult(t, byID[tc.id])
		structured, ok := result["structuredContent"].(map[string]any)
		require.True(t, ok, "missing structured result for %s", tc.id)
		require.Equal(t, float64(tc.statusCode), structured["status_code"])
	}

	requests := upstreamRequests.snapshot()
	require.Len(t, requests, 2, "the loopback API must receive both template calls")
	paths := make(map[string]bool, len(requests))
	for _, request := range requests {
		require.Equal(t, http.MethodGet, request.method)
		require.Equal(t, credential, request.headers.Get("Authorization"))
		paths[request.escapedPath] = true
	}
	require.True(t, paths["/resource/one"])
	require.True(t, paths["/resource/redirect"])
	if got := len(proxyRequests.snapshot()); got != 0 {
		t.Fatalf("configured proxy received %d loopback template request(s)", got)
	}
	if got := len(redirectRequests.snapshot()); got != 0 {
		t.Fatalf("redirect destination received %d request(s)", got)
	}
	require.NotContains(t, proc.output.String(), credential, "routine logs exposed the fixed credential")
}

func runHarpoonTemplatesRuntime(t *testing.T, subject runtimeSubject) {
	t.Helper()
	const (
		auth         = "Bearer template-e2e-private-credential"
		caseID       = "private-case-123"
		serialNumber = "private-serial-456"
		sessionID    = "private-session-789"
		deniedID     = "private-denied-object"
	)
	recorder := &templateRuntimeRecorder{}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder.record(r)
		if r.URL.Path == "/legacy" {
			_, _ = w.Write([]byte("legacy-ok"))
			return
		}
		if r.Header.Get("Authorization") != auth {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/resource/" + deniedID:
			// A syntactically valid identifier still requires upstream object
			// authorization. Harpoon must preserve that denial for the caller.
			http.Error(w, "forbidden", http.StatusForbidden)
		case "/redirect/" + caseID:
			// Even a same-origin, independently allowlisted exact target must
			// not grant a redirect permission to a template operation.
			http.Redirect(w, r, "/legacy", http.StatusFound)
		default:
			_, _ = w.Write([]byte("template-ok"))
		}
	}))
	t.Cleanup(upstream.Close)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})
	caPath := filepath.Join(t.TempDir(), "upstream-ca.pem")
	require.NoError(t, os.WriteFile(caPath, certPEM, 0o600))

	type callCase struct {
		name       string
		tool       string
		arguments  string
		statusCode int
		wantError  bool
		redirect   bool
	}
	validArgs := fmt.Sprintf(`{"label":"get_resource","parameters":{"id":%q}}`, caseID)
	cases := []callCase{
		{name: "resource", arguments: fmt.Sprintf(`{"label":"get_resource","parameters":{"id":%q},"headers":{"X-Request-Tag":"allowed-tag"}}`, caseID), statusCode: http.StatusOK},
		{name: "search", arguments: fmt.Sprintf(`{"label":"search_by_serial","parameters":{"serialNumber":%q}}`, serialNumber), statusCode: http.StatusOK},
		{name: "multiple_path_and_query_parameters", arguments: `{"label":"get_case","parameters":{"tenant":"private-tenant","case_id":"private-case","query_id":"private-query","region_id":"private-region"}}`, statusCode: http.StatusOK},
		{name: "profile_by_session", arguments: fmt.Sprintf(`{"label":"get_profile","parameters":{"session_id":%q}}`, sessionID), statusCode: http.StatusOK},
		{name: "case_orders", arguments: fmt.Sprintf(`{"label":"get_case_orders","parameters":{"case_id":%q}}`, caseID), statusCode: http.StatusOK},
		{name: "case_status_with_fixed_queries", arguments: fmt.Sprintf(`{"label":"get_case_status","parameters":{"case_id":%q}}`, caseID), statusCode: http.StatusOK},
		{name: "authorization_denied", arguments: fmt.Sprintf(`{"label":"get_resource","parameters":{"id":%q}}`, deniedID), statusCode: http.StatusForbidden},
		{name: "redirect", arguments: fmt.Sprintf(`{"label":"redirect_resource","parameters":{"id":%q}}`, caseID), redirect: true},
		{name: "legacy_exact", tool: "call_target", arguments: `{"label":"legacy","method":"GET"}`, statusCode: http.StatusOK},
		{name: "removed_template_tool", tool: "call_target_template", arguments: validArgs, wantError: true},
		{name: "missing", arguments: `{"label":"get_resource","parameters":{}}`, wantError: true},
		{name: "unknown_parameter", arguments: `{"label":"get_resource","parameters":{"id":"abc","extra":"abc"}}`, wantError: true},
		{name: "duplicate_parameter", arguments: `{"label":"get_resource","parameters":{"id":"first","id":"second"}}`, wantError: true},
		{name: "missing_parameters", arguments: `{"label":"get_resource"}`, wantError: true},
		{name: "unknown_target", arguments: `{"label":"not_configured","parameters":{"id":"abc"}}`, wantError: true},
		{name: "exact_target_with_template_arguments", arguments: `{"label":"legacy","parameters":{}}`, wantError: true},
		{name: "template_target_with_method", tool: "call_target", arguments: `{"label":"get_resource","method":"GET"}`, wantError: true},
		{name: "alternate_method", arguments: strings.TrimSuffix(validArgs, "}") + `,"method":"POST"}`, wantError: true},
		{name: "get_body", arguments: strings.TrimSuffix(validArgs, "}") + `,"body":"private-request-body"}`, wantError: true},
		{name: "redirect_override", arguments: strings.TrimSuffix(validArgs, "}") + `,"follow_redirects":true}`, wantError: true},
		{name: "query_override", arguments: strings.TrimSuffix(validArgs, "}") + `,"query":{"admin":"true"}}`, wantError: true},
		{name: "url_override", arguments: strings.TrimSuffix(validArgs, "}") + `,"url":"https://other.example/"}`, wantError: true},
		{name: "excessive_timeout", arguments: strings.TrimSuffix(validArgs, "}") + `,"timeout_ms":120001}`, wantError: true},
		{name: "excessive_response_limit", arguments: strings.TrimSuffix(validArgs, "}") + `,"max_response_bytes":2147483647}`, wantError: true},
	}
	multipleParameters := map[string]string{
		"tenant": "private-tenant", "case_id": "private-case", "query_id": "private-query", "region_id": "private-region",
	}
	for _, parameter := range []struct{ name, invalid string }{
		{"tenant", "private-tenant/escape"},
		{"case_id", "private-case%2fescape"},
		{"query_id", "private-query&admin=true"},
		{"region_id", "private-region?extra=1"},
	} {
		for _, failure := range []string{"missing", "invalid"} {
			values := maps.Clone(multipleParameters)
			if failure == "missing" {
				delete(values, parameter.name)
			} else {
				values[parameter.name] = parameter.invalid
			}
			arguments, err := json.Marshal(map[string]any{"label": "get_case", "parameters": values})
			require.NoError(t, err)
			cases = append(cases, callCase{
				name: "multiple_parameters_" + failure + "_" + parameter.name, arguments: string(arguments), wantError: true,
			})
		}
	}
	for _, value := range []struct{ name, raw string }{
		{"null", "null"}, {"number", "123"}, {"boolean", "true"}, {"array", `["abc"]`}, {"object", `{"id":"abc"}`},
	} {
		cases = append(cases, callCase{name: value.name, arguments: fmt.Sprintf(`{"label":"get_resource","parameters":{"id":%s}}`, value.raw), wantError: true})
	}
	for _, value := range []struct{ name, value string }{
		{"empty", ""}, {"overlength", strings.Repeat("x", 65)}, {"reserved", "admin"},
		{"dot", "."}, {"traversal", ".."}, {"slash", "x/y"}, {"backslash", `x\y`},
		{"encoded_separator", "%2f"}, {"double_encoded_separator", "%252f"},
		{"query_injection", "SN1&admin=true"}, {"query_delimiter", "x?admin=true"},
		{"fragment", "x#admin"}, {"control", "x\ny"}, {"format", "abc def"},
	} {
		cases = append(cases, callCase{name: value.name, arguments: fmt.Sprintf(`{"label":"get_resource","parameters":{"id":%q}}`, value.value), wantError: true})
	}
	for _, header := range []string{"Authorization", "Host", "X-Forwarded-Host", "X-OpenAI-Actor-Authorization", "X-HTTP-Method-Override", "X-Undeclared"} {
		cases = append(cases, callCase{
			name:      "header_" + header,
			arguments: strings.TrimSuffix(validArgs, "}") + fmt.Sprintf(`,"headers":{%q:"private-header-override"}}`, header),
			wantError: true,
		})
	}

	ready := make(chan struct{})
	initialize := runtimeArtifactChannelCommandResponse(t,
		"template-initialize", "harpoon", runtimeArtifactInitializePayload("template-initialize"),
		string(wiretypes.ResponsePayloadJSONRPC))
	initialize.DeliverAfter = ready
	commands := []mocktunnelservice.CommandResponse{
		initialize,
		templateRuntimeCommand(t, "template-tools-list", "tools/list", nil, ready),
		templateRuntimeCommand(t, "template-list-targets", "tools/call", json.RawMessage(`{"name":"list_targets","arguments":{}}`), ready),
	}
	for _, tc := range cases {
		tool := tc.tool
		if tool == "" {
			tool = "call_target"
		}
		params := json.RawMessage(fmt.Sprintf(`{"name":%q,"arguments":%s}`, tool, tc.arguments))
		commands = append(commands, templateRuntimeCommand(t, "template-"+tc.name, "tools/call", params, ready))
	}
	controlPlane := mocktunnelservice.NewMockTunnelService(
		mocktunnelservice.WithAPIKey(runtimeArtifactAPIKey),
		mocktunnelservice.WithTunnelID(runtimeArtifactTunnelID),
		mocktunnelservice.WithCommandResponses(commands...),
	)
	controlPlane.Start(t)
	mcpServer := mockmcpserver.NewMockMCPServer(mockmcpserver.WithOAuthDiscoveryResources())
	mcpServer.Start(t)

	profilePath := filepath.Join(t.TempDir(), "templates.yaml")
	healthURLFile := filepath.Join(t.TempDir(), "health.url")
	profile := fmt.Sprintf(`config_version: 2
ca_bundle: %s
control_plane:
  base_url: %s
  tunnel_id: %s
  api_key: env:CONTROL_PLANE_API_KEY
  poll_channels: [main, harpoon]
mcp:
  server_urls:
    - channel: main
      url: %s
harpoon:
  targets:
    - label: legacy
      url: %s
%s
health:
  listen_addr: 127.0.0.1:0
  url_file: %s
admin_ui:
  open_browser: false
log:
  level: info
  format: struct-text
`, runtimeArtifactYAMLScalar(caPath), runtimeArtifactYAMLScalar(controlPlane.BaseURL().String()),
		runtimeArtifactTunnelID, runtimeArtifactYAMLScalar(mcpServer.BaseURL().String()),
		runtimeArtifactYAMLScalar(upstream.URL+"/legacy"), templateRuntimeTargets(upstream.URL),
		runtimeArtifactYAMLScalar(healthURLFile))
	require.NoError(t, os.WriteFile(profilePath, []byte(profile), 0o600))
	proc := startRuntimeArtifactWithEnv(t, subject.binary, map[string]string{"HP_AUTH": auth}, "run", "--config", profilePath)
	_ = waitForRuntimeArtifactHealthURL(t, proc, healthURLFile)
	if len(subject.startupSignals) > 0 {
		waitForRuntimeArtifactOutput(t, proc, "completed startup", subject.startupSignals...)
	}
	close(ready)
	waitForRuntimeArtifactIdle(t, proc, controlPlane)
	require.NoErrorf(t, proc.stop(), "%s did not shut down cleanly; output:\n%s", subject.name, proc.output.String())

	responses := controlPlane.ReceivedResponses(mocktunnelservice.ResponseMatchMatched)
	require.Len(t, responses, len(commands))
	require.Empty(t, controlPlane.ReceivedResponses(mocktunnelservice.ResponseMatchUnexpected))
	byID := make(map[string]mocktunnelservice.ReceivedResponse, len(responses))
	for _, response := range responses {
		byID[response.RequestID] = response
	}
	initialized := templateRuntimeResult(t, byID["template-initialize"])
	instructions, ok := initialized["instructions"].(string)
	require.True(t, ok, "initialize must advertise Harpoon instructions")
	for _, guidance := range []string{"call_target", "template_version", "parameters_schema", "label", "all parameters"} {
		require.Contains(t, instructions, guidance, "initialize must explain how to call template targets")
	}
	tools := templateRuntimeResult(t, byID["template-tools-list"])
	encodedTools, err := json.Marshal(tools)
	require.NoError(t, err)
	require.NotContains(t, string(encodedTools), `"call_target_template"`)
	require.Contains(t, string(encodedTools), `"call_target"`)
	discovery := templateRuntimeResult(t, byID["template-list-targets"])
	structured, ok := discovery["structuredContent"].(map[string]any)
	require.True(t, ok, "list_targets must expose structured content")
	targets, ok := structured["targets"].([]any)
	require.True(t, ok)
	targetByLabel := make(map[string]map[string]any)
	for _, target := range targets {
		entry, ok := target.(map[string]any)
		require.True(t, ok)
		label, ok := entry["label"].(string)
		require.True(t, ok)
		targetByLabel[label] = entry
	}
	resource := targetByLabel["get_resource"]
	require.Equal(t, float64(1), resource["template_version"])
	require.Equal(t, []any{"GET"}, resource["allowed_methods"])
	schema, ok := resource["parameters_schema"].(map[string]any)
	require.True(t, ok, "template parameter schema missing")
	require.Equal(t, "object", schema["type"])
	require.Equal(t, false, schema["additionalProperties"])
	require.Equal(t, []any{"id"}, schema["required"])
	multipleSchema, ok := targetByLabel["get_case"]["parameters_schema"].(map[string]any)
	require.True(t, ok, "multiple-parameter discovery schema missing")
	require.Equal(t, []any{"case_id", "query_id", "region_id", "tenant"}, multipleSchema["required"])
	multipleProperties, ok := multipleSchema["properties"].(map[string]any)
	require.True(t, ok, "multiple-parameter discovery properties missing")
	require.Len(t, multipleProperties, 4)
	for _, name := range []string{"tenant", "case_id", "query_id", "region_id"} {
		require.Contains(t, multipleProperties, name)
	}
	for _, label := range []string{"get_profile", "get_case_orders", "get_case_status"} {
		require.Contains(t, targetByLabel, label)
	}
	require.NotContains(t, targetByLabel["legacy"], "template_version")
	require.NotContains(t, targetByLabel["legacy"], "parameters_schema")
	encodedDiscovery, err := json.Marshal(discovery)
	require.NoError(t, err)
	for _, sensitive := range []string{upstream.URL, "/resource/", "/search", "/tenants/", "/profiles", "/cases/orders", "/casestatus/", auth, "HP_AUTH"} {
		require.NotContains(t, instructions, sensitive)
		require.NotContains(t, string(encodedDiscovery), sensitive)
	}

	rejectedCalls := 0
	for _, tc := range cases {
		if tc.wantError {
			rejectedCalls++
		}
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			response, found := byID["template-"+tc.name]
			require.True(t, found)
			var envelope struct {
				Result map[string]any  `json:"result"`
				Error  json.RawMessage `json:"error"`
			}
			require.NoError(t, json.Unmarshal(response.JSONResponse, &envelope))
			failed := len(envelope.Error) > 0 || envelope.Result["isError"] == true
			if tc.wantError {
				require.True(t, failed, "invalid invocation accepted: %s", response.JSONResponse)
				for _, sensitive := range []string{upstream.URL, caseID, auth, "private-header-override", "private-request-body", "private-tenant", "private-case", "private-query", "private-region"} {
					require.NotContains(t, string(response.JSONResponse), sensitive)
				}
				return
			}
			require.False(t, failed, "valid invocation failed: %s", response.JSONResponse)
			structured, ok := envelope.Result["structuredContent"].(map[string]any)
			require.True(t, ok, "missing structured result: %s", response.JSONResponse)
			wantStatus := tc.statusCode
			if tc.redirect {
				wantStatus = http.StatusFound
			}
			require.Equal(t, float64(wantStatus), structured["status_code"])
		})
	}

	// All control-plane calls have settled and the process has exited. Exact
	// counts therefore prove rejected calls and redirects emitted no request,
	// without waiting an arbitrary time for a request that must never happen.
	requests := recorder.snapshot()
	require.Len(t, requests, 9, "invalid inputs or redirects reached the upstream: %#v", requests)
	byPath := make(map[string]templateRuntimeRequest)
	for _, request := range requests {
		require.Equal(t, http.MethodGet, request.method)
		require.Empty(t, request.body)
		require.NotContains(t, byPath, request.escapedPath, "unexpected duplicate upstream request")
		byPath[request.escapedPath] = request
		if request.escapedPath != "/legacy" {
			require.Equal(t, auth, request.headers.Get("Authorization"))
		}
	}
	require.Contains(t, byPath, "/resource/"+caseID)
	require.Empty(t, byPath["/resource/"+caseID].rawQuery)
	require.Equal(t, "allowed-tag", byPath["/resource/"+caseID].headers.Get("X-Request-Tag"))
	require.Equal(t, "serialNumber="+serialNumber, byPath["/search"].rawQuery)
	require.Equal(t, "archive=false&queryId=private-query&regionId=private-region", byPath["/tenants/private-tenant/cases/private-case"].rawQuery)
	require.Equal(t, "session-id="+sessionID, byPath["/profiles"].rawQuery)
	require.Equal(t, "CaseId="+caseID, byPath["/cases/orders"].rawQuery)
	require.Equal(t, "complaints=true&elevations=true", byPath["/casestatus/"+caseID].rawQuery)
	require.Contains(t, byPath, "/resource/"+deniedID)
	require.Contains(t, byPath, "/redirect/"+caseID)
	require.Contains(t, byPath, "/legacy")
	require.Empty(t, byPath["/legacy"].headers.Get("Authorization"), "template credential leaked into exact target")
	for _, sensitive := range []string{auth, caseID, serialNumber, sessionID, deniedID, "private-tenant", "private-query", "private-region", "private-header-override", "private-request-body", upstream.URL + "/resource/"} {
		require.NotContains(t, proc.output.String(), sensitive, "routine logs exposed private request material")
	}
	t.Logf("completed %d tool invocations (%d rejected), %d total control-plane commands, and exactly %d HTTPS requests", len(cases), rejectedCalls, len(commands), len(requests))
	t.Run("version_one_rejects_templates_at_startup", func(t *testing.T) {
		t.Parallel()
		// An operator cannot accidentally activate templates using the legacy
		// config version. The rejection must happen before any request is sent.
		legacyProfile := strings.Replace(profile, "config_version: 2", "config_version: 1", 1)
		legacyPath := filepath.Join(t.TempDir(), "legacy-config.yaml")
		require.NoError(t, os.WriteFile(legacyPath, []byte(legacyProfile), 0o600))
		rejected := startRuntimeArtifactWithEnv(t, subject.binary, map[string]string{"HP_AUTH": auth}, "run", "--config", legacyPath)
		err, exited := rejected.wait(runtimeArtifactSignalTimeout)
		require.True(t, exited, "legacy-version template config did not fail at startup")
		require.Error(t, err)
		require.Contains(t, rejected.output.String(), "config_version")
		require.NotContains(t, rejected.output.String(), auth)
		require.Len(t, recorder.snapshot(), len(requests), "invalid config caused an upstream request")
	})
}

func templateRuntimeTargets(origin string) string {
	type target struct {
		label, path, query string
		parameters         []string
	}
	var rendered strings.Builder
	for _, target := range []target{
		{"get_resource", "/resource/{id}", "", []string{"id"}},
		{"search_by_serial", "/search", "        query:\n          serialNumber: '{serialNumber}'\n", []string{"serialNumber"}},
		{"get_case", "/tenants/{tenant}/cases/{case_id}", "        query:\n          archive: 'false'\n          queryId: '{query_id}'\n          regionId: '{region_id}'\n", []string{"tenant", "case_id", "query_id", "region_id"}},
		{"get_profile", "/profiles", "        query:\n          session-id: '{session_id}'\n", []string{"session_id"}},
		{"get_case_orders", "/cases/orders", "        query:\n          CaseId: '{case_id}'\n", []string{"case_id"}},
		{"get_case_status", "/casestatus/{case_id}", "        query:\n          elevations: 'true'\n          complaints: 'true'\n", []string{"case_id"}},
		{"redirect_resource", "/redirect/{id}", "", []string{"id"}},
	} {
		fmt.Fprintf(&rendered, `    - label: %s
      description: A bounded inventory operation
      template:
        version: 1
        origin: %s
        method: GET
        path_template: %s
%s        parameters:
`, target.label, runtimeArtifactYAMLScalar(origin), runtimeArtifactYAMLScalar(target.path), target.query)
		for _, name := range target.parameters {
			fmt.Fprintf(&rendered, `          %s:
            type: string
            required: true
            pattern: '[A-Za-z0-9_-]+'
            max_length: 64
            reserved_values: [admin]
`, name)
		}
		rendered.WriteString(`        headers:
          Authorization: env:HP_AUTH
        allowed_headers: [X-Request-Tag]
        follow_redirects: false
`)
	}
	return strings.TrimSuffix(rendered.String(), "\n")
}

func templateRuntimeCommand(t *testing.T, id, method string, params json.RawMessage, ready <-chan struct{}) mocktunnelservice.CommandResponse {
	t.Helper()
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}
	// Preserve argument bytes, including duplicate keys, rather than letting
	// a map decode erase malformed caller input before it reaches the client.
	meta := `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"template-e2e","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}`
	paramsWithMeta := strings.TrimSuffix(string(params), "}")
	if paramsWithMeta != "{" {
		paramsWithMeta += ","
	}
	payload := json.RawMessage(fmt.Sprintf(`{"jsonrpc":"2.0","id":%q,"method":%q,"params":%s%s}}`, id, method, paramsWithMeta, meta))
	require.True(t, json.Valid(payload), "invalid fixture JSON: %s", payload)
	command := runtimeArtifactChannelCommandResponse(t, id, "harpoon", payload, string(wiretypes.ResponsePayloadJSONRPC))
	command.DeliverAfter = ready
	return command
}

func templateRuntimeResult(t *testing.T, response mocktunnelservice.ReceivedResponse) map[string]any {
	t.Helper()
	var envelope struct {
		Result map[string]any  `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	require.NoError(t, json.Unmarshal(response.JSONResponse, &envelope))
	require.Empty(t, envelope.Error, string(response.JSONResponse))
	require.NotEqual(t, true, envelope.Result["isError"], string(response.JSONResponse))
	return envelope.Result
}
