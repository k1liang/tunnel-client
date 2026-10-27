package runtimeharpoon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/invopop/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/openai/tunnel-client/pkg/runtimeconfig"
	"github.com/openai/tunnel-client/pkg/version"
)

const callTargetTool = "call_target"

type callTargetTemplateRequest struct {
	Label            string            `json:"label" jsonschema:"minLength=1,maxLength=64,pattern=^[a-z0-9][a-z0-9_-]{0\\,63}$"`
	Parameters       map[string]any    `json:"parameters" jsonschema:"minProperties=1,maxProperties=16,description=Required string values matching the target parameters_schema."`
	Operation        *string           `json:"operation,omitempty" jsonschema:"minLength=1,maxLength=73,description=Copy the required write operation constant from the discovered invocation schema; unavailable for GET."`
	Body             *string           `json:"body,omitempty" jsonschema:"maxLength=102400,description=Raw UTF-8 request body for a write template; must satisfy the discovered body policy."`
	ContentType      *string           `json:"content_type,omitempty" jsonschema:"minLength=1,maxLength=128,description=Exact allowed media type, required with body; unavailable for GET templates."`
	Headers          map[string]string `json:"headers,omitempty"`
	TimeoutMS        *int              `json:"timeout_ms,omitempty"`
	MaxResponseBytes *int              `json:"max_response_bytes,omitempty"`
}

// targetInvocation contains only public calling information. The input schema
// binds the label and parameter constraints to this target without revealing
// how the client maps them onto a private destination.
type targetInvocation struct {
	ToolName    string           `json:"tool_name" jsonschema:"description=MCP tool to call with arguments matching input_schema."`
	InputSchema map[string]any   `json:"input_schema" jsonschema:"description=Complete argument schema for this target, including optional call controls."`
	Examples    []map[string]any `json:"examples,omitempty" jsonschema:"description=Complete validated example argument objects; omit optional call controls to use their defaults."`
}

func (callTargetTemplateRequest) JSONSchemaExtend(schema *jsonschema.Schema) {
	(callTargetRequest{}).JSONSchemaExtend(schema)
	schema.Title = "Call Harpoon target template"
	schema.Description = "Call a configured GET, POST, or PUT operation with bounded string identifiers and an operator-controlled body policy."
}

// Keep exact requests in their original schema branch. Template calls omit the
// method and are authorized against the operator-selected policy at dispatch.
func (s *Server) callTargetInputSchema() *jsonschema.Schema {
	exact := buildCallTargetSchema(s.cfg)
	branches := []*jsonschema.Schema{exact}
	hasLegacyTemplate := false
	for _, target := range s.registry.Targets() {
		if target.template != nil {
			if !target.template.HasRichHeaderRules() {
				// Preserve the compact legacy discovery contract regardless of
				// catalog size. Its label pattern excludes the ':' in rich labels,
				// so this branch cannot overlap a policy-bound invocation.
				if !hasLegacyTemplate {
					branches = append(branches, s.templateCallInputSchema())
					hasLegacyTemplate = true
				}
				continue
			}
			// Both discovery surfaces use the identical target-specific public
			// rich-header projection. The exact branch requires method;
			// templates forbid it.
			branches = append(branches, &jsonschema.Schema{Extras: s.templateInvocation(target).InputSchema})
		}
	}
	if len(branches) > 1 {
		return &jsonschema.Schema{Version: exact.Version, Type: "object", OneOf: branches}
	}
	return exact
}

func (s *Server) templateCallInputSchema() *jsonschema.Schema {
	return buildTemplateCallInputSchema(s.cfg)
}

func buildTemplateCallInputSchema(cfg *runtimeconfig.HarpoonConfig) *jsonschema.Schema {
	reflector := &jsonschema.Reflector{DoNotReference: true}
	schema := reflector.Reflect(callTargetTemplateRequest{})
	applyCallTargetSchemaBounds(schema, cfg)
	return schema
}

func (s *Server) templateInvocation(target Target) *targetInvocation {
	return templateInvocationForLabel(target, s.templateInvocationLabel(target), s.templateCallInputSchema())
}

func templateInvocationForLabel(target Target, invocationLabel string, base *jsonschema.Schema) *targetInvocation {
	properties := make(map[string]any, base.Properties.Len())
	for pair := base.Properties.Oldest(); pair != nil; pair = pair.Next() {
		properties[pair.Key] = pair.Value
	}
	properties["label"] = map[string]any{"type": "string", "const": invocationLabel}
	properties["parameters"] = templateParametersSchema(target.template)
	required := append([]string(nil), base.Required...)
	bodyPolicy := target.template.bodyPolicy
	if bodyPolicy == nil {
		delete(properties, "operation")
		delete(properties, "body")
		delete(properties, "content_type")
	} else {
		properties["operation"] = map[string]any{"type": "string", "const": target.template.operationToken}
		required = append(required, "operation")
		policy := bodyPolicy.canonicalPolicy()
		bodySchema := map[string]any{
			"type": "string", "maxLength": policy.MaxBytes, "x-maxBytes": policy.MaxBytes,
			"description": "Raw UTF-8 body. x-maxBytes is an enforced byte limit; maxLength is a character limit. All configured JSON, full-string pattern, and exact raw-string enum checks must pass.",
		}
		if *policy.Required {
			bodySchema["minLength"] = 1
			required = append(required, "body", "content_type")
		}
		if policy.Validation.JSON {
			bodySchema["contentMediaType"] = "application/json"
		}
		if policy.Validation.Pattern != "" {
			bodySchema["pattern"] = "^(?:" + policy.Validation.Pattern + ")$"
			// Body patterns consume only printable ASCII. Advertise that
			// constraint explicitly: some schema regex engines allow $ before
			// a final newline, while the executor requires the entire string.
			bodySchema["not"] = map[string]any{"pattern": "[^ -~]"}
		}
		if len(policy.Validation.Enum) > 0 {
			bodySchema["enum"] = policy.Validation.Enum
		}
		properties["body"] = bodySchema
		properties["content_type"] = map[string]any{"type": "string", "enum": policy.ContentTypes}
	}
	headers, requiredHeaders := target.template.templateHeadersSchema()
	properties["headers"] = headers
	if requiredHeaders {
		required = append(required, "headers")
	}
	invocation := &targetInvocation{
		ToolName: callTargetTool,
		InputSchema: map[string]any{
			"$schema": base.Version, "type": "object", "properties": properties,
			"required": required, "additionalProperties": false,
			"description": "Arguments for this fixed-origin " + strings.ToUpper(target.template.origin.Scheme) + " " + target.template.method + " operation. Supply raw parameter values without URL encoding; the client renders them. The method, path structure, and query names are fixed. Redirects are disabled. GET rejects bodies; writes enforce the advertised body policy and are never automatically replayed.",
		},
	}
	if bodyPolicy != nil {
		invocation.InputSchema["dependentRequired"] = map[string][]string{"body": {"content_type"}, "content_type": {"body"}}
	}
	// Required header values, especially credentials, are supplied by the
	// caller. Do not synthesize or publish a credential-bearing example.
	if requiredHeaders {
		return invocation
	}
	values := make(map[string]any, len(target.template.parameters))
	for name, parameter := range target.template.PublicParameters() {
		switch {
		case len(parameter.Examples) > 0:
			values[name] = parameter.Examples[0]
		case len(parameter.Enum) > 0:
			// Enum order is not part of the policy digest. Keep the derived
			// example stable across equivalent configurations as well.
			sort.Strings(parameter.Enum)
			values[name] = parameter.Enum[0]
		default:
			return invocation
		}
	}
	// Revalidate the complete public example with the same renderer as calls.
	if _, err := target.template.Render(values); err == nil {
		example := map[string]any{"label": invocationLabel, "parameters": values}
		if bodyPolicy != nil {
			example["operation"] = target.template.operationToken
			policy := bodyPolicy.canonicalPolicy()
			if len(policy.Validation.Enum) > 0 {
				example["body"], example["content_type"] = policy.Validation.Enum[0], policy.ContentTypes[0]
			} else if *policy.Required {
				return invocation
			}
		}
		invocation.Examples = []map[string]any{example}
	}
	return invocation
}

func (s *Server) callTemplateHandler(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var params callTargetTemplateRequest
	if req == nil || req.Params == nil || decodeTemplateArguments(req.Params.Arguments, &params) != nil {
		return toolErrorResult("", "invalid template arguments"), nil
	}
	response, err := s.callTargetTemplate(ctx, params)
	if err != nil {
		if toolErr := asToolError(err); toolErr != nil {
			return toolErrorResult(toolErr.label, toolErr.msg), nil
		}
		return toolErrorResult("", "template request failed"), nil
	}
	payload, err := json.Marshal(response)
	if err != nil {
		return toolErrorResult(params.Label, "failed to encode response"), nil
	}
	return &mcp.CallToolResult{
		Content:           []mcp.Content{&mcp.TextContent{Text: string(payload)}},
		StructuredContent: response,
	}, nil
}

// Decode the original argument bytes before converting objects to maps, which
// would erase duplicate keys. Bound work independently of the MCP transport.
func decodeTemplateArguments(raw json.RawMessage, out *callTargetTemplateRequest) error {
	// Escaped JSON strings can occupy six bytes per body byte on the wire.
	if len(raw) > 32768+6*maxTemplateBodyBytes || !validTemplateJSONStrings(raw) {
		return errors.New("invalid template arguments")
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return errors.New("invalid template arguments")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := checkTemplateJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("invalid template arguments")
	}
	// encoding/json accepts case-insensitive struct field names. The tool's
	// published contract accepts only these exact keys, including their case.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return errors.New("invalid template arguments")
	}
	for name := range fields {
		if bytes.Equal(bytes.TrimSpace(fields[name]), []byte("null")) {
			return errors.New("null template argument")
		}
		switch name {
		case "label", "parameters", "headers", "operation", "body", "content_type", "timeout_ms", "max_response_bytes":
		default:
			return errors.New("unknown template argument")
		}
	}
	if rawHeaders, present := fields["headers"]; present {
		var headers map[string]json.RawMessage
		if err := json.Unmarshal(rawHeaders, &headers); err != nil {
			return errors.New("invalid template headers")
		}
		for _, value := range headers {
			if trimmed := bytes.TrimSpace(value); len(trimmed) == 0 || trimmed[0] != '"' {
				return errors.New("template header values must be strings")
			}
		}
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(out); err != nil {
		return errors.New("invalid template arguments")
	}
	if out.Parameters == nil || (!labelPattern.MatchString(out.Label) && !isPolicyBoundTemplateLabel(out.Label)) {
		return errors.New("invalid template arguments")
	}
	return nil
}

func checkTemplateJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 4 {
		return errors.New("invalid template arguments")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim != '{' && delim != '[' {
		return errors.New("invalid template arguments")
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		if delim == '{' {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("invalid template arguments")
			}
			if _, exists := seen[name]; exists {
				return errors.New("duplicate template argument")
			}
			seen[name] = struct{}{}
		}
		if err := checkTemplateJSONValue(decoder, depth+1); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

func (s *Server) callTargetTemplate(ctx context.Context, params callTargetTemplateRequest) (*callTargetResponse, error) {
	start := time.Now()
	label := defaultMetricsUnknownTargetLabel
	status, responseBytes, outcome := 0, 0, metricOutcomeInvalidInput
	defer func() {
		s.recordCallMetrics(ctx, label, status, outcome, responseBytes, start)
		// Template values and credentials must never enter routine logs or the
		// optional full-client payload observers.
		s.logger.InfoContext(ctx, "harpoon template request completed",
			slog.String("label", label), slog.String("outcome", outcome),
			slog.Int("status_code", status), slog.Int64("latency_ms", time.Since(start).Milliseconds()))
	}()
	target, ok := s.lookupTemplateInvocation(params.Label)
	if !ok || target.template == nil {
		return nil, newToolError("", "unknown template target")
	}
	label = target.Label
	if target.template.bodyPolicy != nil {
		if params.Operation == nil || *params.Operation != target.template.operationToken {
			return nil, newToolError(label, "write operation must match the discovered invocation schema")
		}
	} else if params.Operation != nil {
		return nil, newToolError(label, "GET templates do not accept a write operation")
	}
	if err := target.template.bodyPolicy.validate(params.Body, params.ContentType); err != nil {
		return nil, newToolError(label, err.Error())
	}
	parameters := maps.Clone(params.Parameters)
	resolved, err := target.template.Render(parameters)
	if err != nil {
		return nil, newToolError(label, err.Error())
	}
	headers, err := target.template.ValidateCallerHeaders(params.Headers)
	if err != nil {
		return nil, newToolError(label, err.Error())
	}
	maps.Copy(headers, target.template.FixedHeaders())
	headers.Set("User-Agent", version.UserAgent)
	if params.ContentType != nil {
		headers.Set("Content-Type", *params.ContentType)
	}
	timeout, err := normalizeTimeout(params.TimeoutMS)
	if err != nil {
		return nil, newToolError(label, err.Error())
	}
	limit, err := s.normalizeMaxResponseBytes(params.MaxResponseBytes)
	if err != nil {
		return nil, newToolError(label, err.Error())
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var requestBody io.Reader
	bodyText := ""
	if params.Body != nil {
		bodyText = *params.Body
	}
	if target.template.method != http.MethodGet {
		// Hide the replayable reader from net/http, even for an empty write.
		// An operator-pinned Idempotency-Key must not enable transport retries.
		requestBody = io.NopCloser(strings.NewReader(bodyText))
	}
	req, err := http.NewRequestWithContext(ctx, target.template.method, resolved.String(), requestBody)
	if err != nil {
		return nil, newToolError(label, "invalid template request")
	}
	req.Header = headers
	req = req.WithContext(contextWithAutoRequestID(req.Context(), req.Header, resolved))
	req.ContentLength = int64(len(bodyText))
	baseTransport := s.httpTransport
	if target.IsLoopbackHTTPTemplate() {
		baseTransport = s.loopbackTemplateTransport
	}
	client := &http.Client{
		Transport:     templateRoundTripper{policy: target.template, parameters: parameters, body: params.Body, contentType: params.ContentType, base: baseTransport},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	outcome = metricOutcomeRequestError
	resp, err := client.Do(req)
	if err != nil {
		return nil, newToolError(label, "template request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	status = resp.StatusCode
	body, tooLarge, err := readLimited(resp.Body, limit)
	responseBytes = len(body)
	if err != nil {
		outcome = metricOutcomeResponseReadError
		return nil, newToolError(label, "response read failed")
	}
	if tooLarge {
		outcome = metricOutcomeResponseTooLarge
		return nil, newToolError(label, "response exceeds size limit")
	}
	outcome = metricOutcomeSuccess
	return &callTargetResponse{StatusCode: status, Headers: resp.Header,
		BodyBase64: base64.StdEncoding.EncodeToString(body), BodySize: len(body)}, nil
}

type templateRoundTripper struct {
	policy      *TargetTemplate
	parameters  map[string]any
	body        *string
	contentType *string
	base        http.RoundTripper
}

func (t templateRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.policy.validateRequest(req, t.parameters, t.body, t.contentType); err != nil {
		return nil, err
	}
	applyAutoRequestID(req, true)
	return t.base.RoundTrip(req)
}

func templateParametersSchema(policy *TargetTemplate) map[string]any {
	properties := make(map[string]any)
	parameters := policy.PublicParameters()
	required := make([]string, 0, len(parameters))
	for name, parameter := range parameters {
		property := map[string]any{"type": "string", "minLength": parameter.MinLength, "maxLength": parameter.MaxLength,
			"allOf": []any{map[string]any{"not": map[string]any{"pattern": "[^A-Za-z0-9_.~-]"}}, map[string]any{"not": map[string]any{"enum": []string{".", ".."}}}},
		}
		if parameter.Description != "" {
			property["description"] = parameter.Description
		}
		if len(parameter.Examples) > 0 {
			property["examples"] = parameter.Examples
		}
		if parameter.Pattern != "" {
			property["pattern"] = "^(?:" + parameter.Pattern + ")$"
		}
		if len(parameter.Enum) > 0 {
			property["enum"] = parameter.Enum
		}
		if len(parameter.ReservedValues) > 0 {
			patterns := make([]string, 0, len(parameter.ReservedValues))
			for _, reserved := range parameter.ReservedValues {
				var pattern strings.Builder
				for _, char := range strings.ToLower(reserved) {
					if char >= 'a' && char <= 'z' {
						pattern.WriteString("[" + string(char) + strings.ToUpper(string(char)) + "]")
					} else {
						pattern.WriteString(regexp.QuoteMeta(string(char)))
					}
				}
				patterns = append(patterns, pattern.String())
			}
			property["not"] = map[string]any{"pattern": "^(?:" + strings.Join(patterns, "|") + ")$"}
		}
		properties[name] = property
		required = append(required, name)
	}
	sort.Strings(required)
	return map[string]any{"type": "object", "properties": properties, "required": required, "additionalProperties": false}
}
