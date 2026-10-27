package runtimeharpoon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/openai/tunnel-client/pkg/runtimeconfig"
	"github.com/openai/tunnel-client/pkg/version"
)

const (
	maxTemplateParameters  = 16
	maxTemplateValueBytes  = 256
	maxTemplateURLBytes    = 4096
	maxTemplateQueryKeys   = 32
	maxTemplateEnumValues  = 64
	maxTemplatePattern     = 512
	maxTemplateHeaders     = 32
	maxTemplateHeaderBytes = 8192
	maxTemplateDescription = 1024
	maxTemplateExamples    = 8
)

var templateNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
var templateHeaderNamePattern = regexp.MustCompile(headerNamePattern)

// TargetTemplate is an immutable, compiled HTTP operation. It never adds rendered
// URLs to the registry's exact-URL allowlist.
type TargetTemplate struct {
	method             string
	bodyPolicy         *compiledTemplateBodyPolicy
	origin             url.URL
	loopbackHTTP       bool
	path               []templatePart
	query              map[string]templatePart
	parameters         map[string]compiledTemplateParameter
	names              []string
	headers            http.Header
	headerRules        map[string]compiledTemplateHeaderRule
	headerDestinations map[string]compiledTemplateHeaderRule
	policyDigest       string
	operationToken     string
}

type templatePart struct {
	literal   string
	parameter string
}

type compiledTemplateParameter struct {
	schema  runtimeconfig.HarpoonTemplateParameter
	pattern *regexp.Regexp
}

// CompileTargetTemplate validates the complete operator policy and retains no
// mutable references to its input. Error messages exclude private destinations,
// header values, and identifier values.
func CompileTargetTemplate(cfg *runtimeconfig.HarpoonTargetTemplate) (*TargetTemplate, error) {
	if cfg == nil || cfg.Version != 1 {
		return nil, errors.New("template version must be 1")
	}
	if cfg.Method != http.MethodGet && cfg.Method != http.MethodPost && cfg.Method != http.MethodPut {
		return nil, errors.New("template method must be GET, POST, or PUT")
	}
	bodyPolicy, err := compileTemplateBodyPolicy(cfg.Method, cfg.BodyPolicy)
	if err != nil {
		return nil, err
	}
	if cfg.FollowRedirects {
		return nil, errors.New("template redirects must be disabled")
	}
	origin, err := compileTemplateOrigin(cfg.Origin, cfg.AllowLoopbackHTTP)
	if err != nil {
		return nil, err
	}
	if len(cfg.Parameters) == 0 || len(cfg.Parameters) > maxTemplateParameters {
		return nil, fmt.Errorf("template must declare 1 to %d parameters", maxTemplateParameters)
	}
	t := &TargetTemplate{
		method:       cfg.Method,
		bodyPolicy:   bodyPolicy,
		origin:       *origin,
		loopbackHTTP: cfg.AllowLoopbackHTTP,
		query:        make(map[string]templatePart, len(cfg.Query)),
		parameters:   make(map[string]compiledTemplateParameter, len(cfg.Parameters)),
		headers:      make(http.Header),
	}
	for name, schema := range cfg.Parameters {
		if !templateNamePattern.MatchString(name) {
			return nil, errors.New("invalid template parameter name")
		}
		parameter, err := compileTemplateParameter(schema)
		if err != nil {
			return nil, fmt.Errorf("parameter %s: %w", name, err)
		}
		t.parameters[name] = parameter
		t.names = append(t.names, name)
	}
	sort.Strings(t.names)
	if len(cfg.PathTemplate) == 0 || len(cfg.PathTemplate) > maxTemplateURLBytes || !strings.HasPrefix(cfg.PathTemplate, "/") {
		return nil, errors.New("template path must be absolute and bounded")
	}
	used := make(map[string]struct{}, len(t.parameters))
	segments := strings.SplitSeq(strings.TrimPrefix(cfg.PathTemplate, "/"), "/")
	for segment := range segments {
		part, err := compileTemplatePart(segment, t.parameters, used)
		if err != nil {
			return nil, err
		}
		if part.parameter == "" && (segment == "" && cfg.PathTemplate != "/" || segment != "" && !validTemplateIdentifier(segment)) {
			return nil, errors.New("template path contains an invalid literal segment")
		}
		t.path = append(t.path, part)
	}
	if len(cfg.Query) > maxTemplateQueryKeys {
		return nil, errors.New("template has too many query fields")
	}
	for key, value := range cfg.Query {
		if len(key) == 0 || len(key) > 64 || !validTemplateIdentifier(key) {
			return nil, errors.New("invalid template query field name")
		}
		part, err := compileTemplatePart(value, t.parameters, used)
		if err != nil {
			return nil, err
		}
		if part.parameter == "" && (len(value) > maxTemplateValueBytes || !validTemplateText(value)) {
			return nil, errors.New("invalid template query literal")
		}
		t.query[key] = part
	}
	for _, name := range t.names {
		if _, ok := used[name]; !ok {
			return nil, fmt.Errorf("parameter %s is unused", name)
		}
	}
	managedContentType := 0
	if bodyPolicy != nil {
		managedContentType = 1
	}
	rules, err := cfg.NormalizedHeaderRules()
	if err != nil {
		return nil, err
	}
	if len(cfg.Headers)+len(rules)+managedContentType > maxTemplateHeaders {
		return nil, errors.New("template has too many headers")
	}
	for key, value := range cfg.Headers {
		canonical, err := canonicalTemplateHeader(key)
		if err != nil {
			return nil, err
		}
		if bodyPolicy != nil && (canonical == "Content-Type" || canonical == "Content-Encoding") {
			return nil, errors.New("template writes require the body policy content type and unencoded body bytes")
		}
		if _, exists := t.headers[canonical]; exists {
			return nil, errors.New("duplicate template header name")
		}
		if !validTemplateHeaderValue(value) {
			return nil, errors.New("invalid template header value")
		}
		t.headers.Set(canonical, value)
	}
	if err := t.compileHeaderRules(rules); err != nil {
		return nil, err
	}
	if err := validateTemplateHeaderSize(t.headers); err != nil {
		return nil, err
	}
	// Reject a configured operation whose longest permitted identifiers could
	// exceed the URL bound, without relying on a later invocation to detect it.
	longest := make(map[string]string, len(t.parameters))
	for name, parameter := range t.parameters {
		longest[name] = strings.Repeat("x", parameter.schema.MaxLength)
	}
	if len(t.renderURL(longest).String()) > maxTemplateURLBytes {
		return nil, errors.New("template maximum rendered URL exceeds size limit")
	}
	t.policyDigest, err = t.computePolicyDigest()
	if err != nil {
		return nil, err
	}
	if bodyPolicy != nil {
		// This token deliberately hashes only metadata already exposed through
		// discovery. The private policy digest must remain inside the catalog HMAC.
		public, err := json.Marshal(struct {
			Method     string                                   `json:"method"`
			BodyPolicy *runtimeconfig.HarpoonTemplateBodyPolicy `json:"body_policy"`
			Parameters map[string]any                           `json:"parameters_schema"`
		}{t.method, bodyPolicy.canonicalPolicy(), templateParametersSchema(t)})
		if err != nil {
			return nil, errors.New("cannot fingerprint public template operation")
		}
		sum := sha256.Sum256(public)
		t.operationToken = "write-v1:" + hex.EncodeToString(sum[:])
	}
	return t, nil
}

// PolicyDigest fingerprints the complete compiled policy for inclusion in the
// keyed startup catalog digest. It must not be emitted independently: only the
// final HMAC protects private destinations and low-entropy credential values.
func (t *TargetTemplate) PolicyDigest() string {
	if t == nil {
		return ""
	}
	return t.policyDigest
}

func (t *TargetTemplate) computePolicyDigest() (string, error) {
	// This explicit private representation preserves the historical JSON field
	// order and string-allowlist digest. Config export has a different purpose:
	// it must retain alias spelling, which must never affect policy identity.
	policy := struct {
		Version           int                                               `json:"version"`
		Origin            string                                            `json:"origin"`
		AllowLoopbackHTTP bool                                              `json:"allow_loopback_http,omitempty"`
		Method            string                                            `json:"method"`
		BodyPolicy        *runtimeconfig.HarpoonTemplateBodyPolicy          `json:"body_policy,omitempty"`
		PathTemplate      string                                            `json:"path_template"`
		Query             map[string]string                                 `json:"query,omitempty"`
		Parameters        map[string]runtimeconfig.HarpoonTemplateParameter `json:"parameters"`
		Headers           map[string]string                                 `json:"headers,omitempty"`
		AllowedHeaders    []string                                          `json:"allowed_headers,omitempty"`
		FollowRedirects   bool                                              `json:"follow_redirects"`
		HeaderRules       []runtimeconfig.HarpoonHeaderRule                 `json:"header_rules,omitempty"`
	}{
		Version:           1,
		Origin:            t.origin.String(),
		AllowLoopbackHTTP: t.loopbackHTTP,
		Method:            t.method,
		BodyPolicy:        t.bodyPolicy.canonicalPolicy(),
		Query:             make(map[string]string, len(t.query)),
		Parameters:        t.PublicParameters(),
		Headers:           make(map[string]string, len(t.headers)),
	}
	parts := make([]string, len(t.path))
	for i, part := range t.path {
		parts[i] = part.policyValue()
	}
	policy.PathTemplate = "/" + strings.Join(parts, "/")
	for key, part := range t.query {
		policy.Query[key] = part.policyValue()
	}
	for name, parameter := range policy.Parameters {
		sort.Strings(parameter.Enum)
		for i, value := range parameter.ReservedValues {
			parameter.ReservedValues[i] = strings.ToLower(value)
		}
		sort.Strings(parameter.ReservedValues)
		policy.Parameters[name] = parameter
	}
	for key, values := range t.headers {
		policy.Headers[key] = values[0]
	}
	if t.HasRichHeaderRules() {
		policy.HeaderRules = t.canonicalHeaderRules()
	} else {
		for source := range t.headerRules {
			policy.AllowedHeaders = append(policy.AllowedHeaders, source)
		}
		sort.Strings(policy.AllowedHeaders)
	}
	encoded, err := json.Marshal(policy)
	if err != nil {
		return "", errors.New("cannot fingerprint template policy")
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func compileTemplateOrigin(raw string, allowLoopbackHTTP bool) (*url.URL, error) {
	if len(raw) == 0 || len(raw) > maxTemplateURLBytes || strings.ContainsAny(raw, "{}\\%#") || !validTemplateText(raw) {
		return nil, errors.New("invalid template origin")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.Path != "" && u.Path != "/" {
		return nil, errors.New("template origin must contain only a scheme, host, and optional port")
	}
	if allowLoopbackHTTP {
		addr, err := netip.ParseAddr(u.Hostname())
		if u.Scheme != "http" || err != nil || !addr.IsLoopback() || addr.Zone() != "" || u.Port() == "" {
			return nil, errors.New("allow_loopback_http requires an HTTP origin with a literal loopback IP and fixed port")
		}
	} else if u.Scheme != "https" {
		return nil, errors.New("template origin must use HTTPS unless allow_loopback_http is enabled")
	}
	if strings.HasSuffix(u.Host, ":") {
		return nil, errors.New("invalid template origin port")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, errors.New("invalid template origin port")
		}
	}
	u.Path, u.RawPath = "", ""
	return u, nil
}

func compileTemplateParameter(schema runtimeconfig.HarpoonTemplateParameter) (compiledTemplateParameter, error) {
	if schema.Type != "string" || !schema.Required {
		return compiledTemplateParameter{}, errors.New("only required string parameters are supported")
	}
	if len(schema.Description) > maxTemplateDescription || !utf8.ValidString(schema.Description) {
		return compiledTemplateParameter{}, errors.New("parameter description must be valid UTF-8 within 1024 bytes")
	}
	if len(schema.Examples) > maxTemplateExamples {
		return compiledTemplateParameter{}, errors.New("parameter examples exceed size limit")
	}
	if schema.MinLength == 0 {
		schema.MinLength = 1
	}
	if schema.MinLength < 1 || schema.MaxLength < schema.MinLength || schema.MaxLength > maxTemplateValueBytes {
		return compiledTemplateParameter{}, fmt.Errorf("length bounds must be within 1 to %d", maxTemplateValueBytes)
	}
	if schema.Pattern == "" && len(schema.Enum) == 0 {
		return compiledTemplateParameter{}, errors.New("a pattern or enum is required")
	}
	if len(schema.Pattern) > maxTemplatePattern || len(schema.Enum) > maxTemplateEnumValues || len(schema.ReservedValues) > maxTemplateEnumValues {
		return compiledTemplateParameter{}, errors.New("parameter constraints exceed size limits")
	}
	p := compiledTemplateParameter{schema: schema}
	if schema.Pattern != "" {
		if err := validateTemplatePattern(schema.Pattern); err != nil {
			return compiledTemplateParameter{}, err
		}
		pattern, err := regexp.Compile(`\A(?:` + schema.Pattern + `)\z`)
		if err != nil {
			return compiledTemplateParameter{}, errors.New("invalid parameter pattern")
		}
		p.pattern = pattern
	}
	p.schema.Enum = append([]string(nil), schema.Enum...)
	p.schema.ReservedValues = append([]string(nil), schema.ReservedValues...)
	p.schema.Examples = append([]string(nil), schema.Examples...)
	seen := make(map[string]struct{}, len(schema.ReservedValues))
	for _, value := range schema.ReservedValues {
		if len(value) > maxTemplateValueBytes || !validTemplateIdentifier(value) {
			return compiledTemplateParameter{}, errors.New("invalid reserved identifier")
		}
		key := strings.ToLower(value)
		if _, exists := seen[key]; exists {
			return compiledTemplateParameter{}, errors.New("duplicate reserved identifier")
		}
		seen[key] = struct{}{}
	}
	seen = make(map[string]struct{}, len(schema.Enum))
	for _, value := range schema.Enum {
		if err := p.validate(value); err != nil {
			return compiledTemplateParameter{}, errors.New("enum value violates parameter constraints")
		}
		if _, exists := seen[value]; exists {
			return compiledTemplateParameter{}, errors.New("duplicate enum identifier")
		}
		seen[value] = struct{}{}
	}
	seen = make(map[string]struct{}, len(schema.Examples))
	for _, value := range schema.Examples {
		if err := p.validate(value); err != nil {
			return compiledTemplateParameter{}, errors.New("example value violates parameter constraints")
		}
		if _, exists := seen[value]; exists {
			return compiledTemplateParameter{}, errors.New("duplicate example identifier")
		}
		seen[value] = struct{}{}
	}
	return p, nil
}

// Keep configured patterns in a common RE2/JSON Schema subset so discovery can
// publish the same full-string constraint enforced by the executor. In
// particular, Go-only anchors, inline flags, Unicode classes, and POSIX classes
// have different meanings or are invalid in JSON Schema consumers.
func validateTemplatePattern(pattern string) error {
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if c < 0x20 || c > 0x7e {
			return errors.New("parameter pattern must contain only printable ASCII")
		}
		if c == '\\' {
			i++
			if i >= len(pattern) || !strings.ContainsRune(`dDsSwW\\.^$|?*+()[]{}/-`, rune(pattern[i])) {
				return errors.New("parameter pattern uses an unsupported escape")
			}
			continue
		}
		if c == '(' && i+1 < len(pattern) && pattern[i+1] == '?' && (i+2 >= len(pattern) || pattern[i+2] != ':') {
			return errors.New("parameter pattern uses unsupported group syntax")
		}
		if strings.HasPrefix(pattern[i:], "[[:") {
			return errors.New("parameter pattern cannot use POSIX character classes")
		}
		if strings.HasPrefix(pattern[i:], "[]") || strings.HasPrefix(pattern[i:], "[^]") {
			return errors.New("parameter pattern must escape an initial closing bracket in a character class")
		}
	}
	return nil
}

func compileTemplatePart(value string, parameters map[string]compiledTemplateParameter, used map[string]struct{}) (templatePart, error) {
	if !strings.ContainsAny(value, "{}") {
		return templatePart{literal: value}, nil
	}
	if !strings.HasPrefix(value, "{") || !strings.HasSuffix(value, "}") {
		return templatePart{}, errors.New("placeholder must occupy an entire path segment or query value")
	}
	name := strings.TrimSuffix(strings.TrimPrefix(value, "{"), "}")
	if !templateNamePattern.MatchString(name) {
		return templatePart{}, errors.New("invalid template placeholder")
	}
	if _, exists := parameters[name]; !exists {
		return templatePart{}, errors.New("template uses an undeclared parameter")
	}
	used[name] = struct{}{}
	return templatePart{parameter: name}, nil
}

// Render validates raw logical identifiers before constructing a URL from
// separately encoded path segments and query values.
func (t *TargetTemplate) Render(parameters map[string]any) (*url.URL, error) {
	if t == nil {
		return nil, errors.New("template policy is missing")
	}
	if len(parameters) != len(t.parameters) {
		return nil, errors.New("template parameter keys must match the declared schema")
	}
	values := make(map[string]string, len(parameters))
	for _, name := range t.names {
		value, ok := parameters[name].(string)
		if !ok {
			return nil, fmt.Errorf("parameter %s must be a string", name)
		}
		if err := t.parameters[name].validate(value); err != nil {
			return nil, fmt.Errorf("parameter %s: %w", name, err)
		}
		values[name] = value
	}
	u := t.renderURL(values)
	if len(u.String()) > maxTemplateURLBytes {
		return nil, errors.New("rendered URL exceeds size limit")
	}
	return u, nil
}

func (p compiledTemplateParameter) validate(value string) error {
	if len(value) < p.schema.MinLength || len(value) > p.schema.MaxLength {
		return errors.New("identifier length is outside its bounds")
	}
	if !validTemplateIdentifier(value) {
		return errors.New("identifier contains forbidden characters or path segments")
	}
	for _, reserved := range p.schema.ReservedValues {
		if strings.EqualFold(value, reserved) {
			return errors.New("identifier is reserved")
		}
	}
	if p.pattern != nil && !p.pattern.MatchString(value) {
		return errors.New("identifier does not match its pattern")
	}
	if len(p.schema.Enum) > 0 {
		if slices.Contains(p.schema.Enum, value) {
			return nil
		}
		return errors.New("identifier is outside its enum")
	}
	return nil
}

func validTemplateIdentifier(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' && c != '.' && c != '~' {
			return false
		}
	}
	return true
}

func validTemplateText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, c := range value {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

func (t *TargetTemplate) renderURL(values map[string]string) *url.URL {
	segments := make([]string, len(t.path))
	escaped := make([]string, len(t.path))
	for i, part := range t.path {
		segments[i] = part.value(values)
		escaped[i] = url.PathEscape(segments[i])
	}
	u := t.origin
	u.Path = "/" + strings.Join(segments, "/")
	u.RawPath = "/" + strings.Join(escaped, "/")
	query := make(url.Values, len(t.query))
	for key, part := range t.query {
		query.Set(key, part.value(values))
	}
	u.RawQuery = query.Encode()
	return &u
}

func (p templatePart) value(values map[string]string) string {
	if p.parameter != "" {
		return values[p.parameter]
	}
	return p.literal
}

func (p templatePart) policyValue() string {
	if p.parameter != "" {
		return "{" + p.parameter + "}"
	}
	return p.literal
}

// PublicParameters returns a defensive copy suitable for discovery. It contains
// no destination, fixed query values, or authentication headers.
func (t *TargetTemplate) PublicParameters() map[string]runtimeconfig.HarpoonTemplateParameter {
	out := make(map[string]runtimeconfig.HarpoonTemplateParameter, len(t.parameters))
	for name, parameter := range t.parameters {
		schema := parameter.schema
		schema.Enum = append([]string(nil), schema.Enum...)
		schema.ReservedValues = append([]string(nil), schema.ReservedValues...)
		schema.Examples = append([]string(nil), schema.Examples...)
		out[name] = schema
	}
	return out
}

// FixedHeaders returns a copy of the operator's immutable header values.
func (t *TargetTemplate) FixedHeaders() http.Header { return t.headers.Clone() }

// ValidateCallerHeaders accepts only explicitly permitted application headers.
// It rejects a pinned-header override even when the supplied value is identical.
func (t *TargetTemplate) ValidateCallerHeaders(headers map[string]string) (http.Header, error) {
	if t == nil {
		return nil, errors.New("template policy is missing")
	}
	if len(headers) > maxTemplateHeaders {
		return nil, t.headerError("header_budget_exceeded", errors.New("too many template headers"))
	}
	out := make(http.Header, len(headers))
	sources := make(http.Header, len(headers))
	for key, value := range headers {
		canonical, err := canonicalTemplateHeader(key)
		if err != nil {
			return nil, t.headerError("header_invalid", err)
		}
		rule, allowed := t.headerRules[canonical]
		if !allowed {
			return nil, t.headerError("header_not_allowed", errors.New("caller header is not permitted by the target"))
		}
		if _, exists := sources[canonical]; exists {
			return nil, t.headerError("header_duplicate", errors.New("duplicate caller header name"))
		}
		if err := rule.validate(value); err != nil {
			return nil, t.headerError("header_invalid", err)
		}
		sources.Set(canonical, value)
		out.Set(rule.schema.ForwardAs, value)
	}
	for source, rule := range t.headerRules {
		if _, present := sources[source]; rule.schema.Required && !present {
			return nil, t.headerError("header_required", errors.New("required caller header is missing"))
		}
	}
	if err := t.validateCallerHeaderBudget(sources); err != nil {
		return nil, t.headerError("header_budget_exceeded", err)
	}
	if err := t.validateCallerHeaderBudget(out); err != nil {
		return nil, t.headerError("header_budget_exceeded", err)
	}
	return out, nil
}

// ValidateRequest reauthorizes a request at the outbound boundary against the
// selected operation and the original invocation values. Equivalent but
// differently encoded URLs and changes to another valid identifier are rejected.
func (t *TargetTemplate) ValidateRequest(req *http.Request, parameters map[string]any) error {
	return t.validateRequest(req, parameters, nil, nil)
}

func (t *TargetTemplate) validateRequest(req *http.Request, parameters map[string]any, body, contentType *string) error {
	expected, err := t.Render(parameters)
	if err != nil {
		return err
	}
	if req == nil || req.URL == nil || req.Method != t.method || req.URL.String() != expected.String() || req.URL.User != nil || req.URL.Opaque != "" || req.RequestURI != "" || req.Host != "" && req.Host != expected.Host {
		return errors.New("outbound request does not match the selected template")
	}
	if err := t.validateRequestBody(req, body, contentType); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(req.Header))
	for key, values := range req.Header {
		canonical := http.CanonicalHeaderKey(key)
		if key != canonical || len(values) != 1 || !validTemplateHeaderValue(values[0]) {
			return errors.New("invalid outbound template header")
		}
		seen[canonical] = struct{}{}
		if canonical == "User-Agent" && values[0] == version.UserAgent {
			continue
		}
		if t.bodyPolicy != nil && canonical == "Content-Type" && contentType != nil && values[0] == *contentType {
			continue
		}
		if _, err := canonicalTemplateHeader(key); err != nil {
			return err
		}
		if fixed, ok := t.headers[canonical]; ok {
			if values[0] != fixed[0] {
				return errors.New("fixed template header was modified")
			}
		} else {
			rule, allowed := t.headerDestinations[canonical]
			if !allowed {
				return errors.New("outbound header is not permitted by the target")
			}
			if err := rule.validate(values[0]); err != nil {
				return err
			}
		}
	}
	for key := range t.headers {
		if _, exists := seen[key]; !exists {
			return errors.New("fixed template header is missing")
		}
	}
	for destination, rule := range t.headerDestinations {
		if _, present := seen[destination]; rule.schema.Required && !present {
			return errors.New("required outbound template header is missing")
		}
	}
	return validateTemplateHeaderSize(req.Header)
}

func canonicalTemplateHeader(key string) (string, error) {
	if len(key) == 0 || len(key) > 128 || !templateHeaderNamePattern.MatchString(key) || isBlockedOutboundHeader(key) {
		return "", errors.New("invalid or forbidden template header name")
	}
	lower := strings.ToLower(key)
	if strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "x-envoy-") || strings.HasPrefix(lower, "x-original-") || strings.HasPrefix(lower, "x-rewrite-") || strings.HasPrefix(lower, "x-auth-request-") || lower == "remote-user" || lower == "x-remote-user" || lower == "x-authenticated-user" {
		return "", errors.New("routing and identity headers are forbidden for templates")
	}
	return http.CanonicalHeaderKey(key), nil
}

// Recognizable credential headers cannot be declared as caller application
// headers. Names frequently join credential words without a separator (ApiKey,
// AuthToken, ClientSecret), so token-only classification is insufficient here.
func isTemplateCredentialHeader(key string) bool {
	if isSensitiveHeaderName(key) {
		return true
	}
	normalized := strings.NewReplacer("-", "", "_", "", ".", "").Replace(strings.ToLower(key))
	for _, credential := range []string{
		"apikey", "apitoken", "apisecret", "authtoken", "accesstoken", "refreshtoken", "idtoken", "sessiontoken", "bearertoken",
		"clientsecret", "clientpassword", "clienttoken", "clientkey", "accesskey", "secretkey", "sessionkey", "privatekey", "authkey", "authsecret", "signingkey",
		"authorization", "authentication", "credential",
	} {
		if strings.Contains(normalized, credential) {
			return true
		}
	}
	return false
}

func validTemplateHeaderValue(value string) bool {
	return len(value) <= maxTemplateHeaderBytes && validTemplateText(value)
}

func validateTemplateHeaderSize(headers http.Header) error {
	if len(headers) > maxTemplateHeaders+1 { // The client adds its managed User-Agent.
		return errors.New("too many template headers")
	}
	size := 0
	if _, managed := headers["User-Agent"]; !managed {
		size = len("User-Agent") + len(version.UserAgent)
	}
	for key, values := range headers {
		size += len(key)
		for _, value := range values {
			size += len(value)
		}
	}
	if size > maxTemplateHeaderBytes {
		return errors.New("template headers exceed size limit")
	}
	return nil
}
