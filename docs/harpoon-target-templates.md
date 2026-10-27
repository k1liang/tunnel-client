# Harpoon target templates

A target template gives a caller access to one configured HTTP operation with
bounded identifier values. The operator fixes the origin, GET/POST/PUT method,
path structure, query names, and authentication headers. Harpoon validates the
arguments and constructs the request locally.

HTTPS is the default. To reach a local HTTP API, set `allow_loopback_http: true`
on that template and use a literal loopback IP with an explicit port, such as
`http://127.0.0.1:23373` or `http://[::1]:23373`. DNS names, including
`localhost`, and non-loopback IPs are rejected. This setting does not enable
plaintext exact-URL targets and does not require `harpoon.allow_plaintext_http`.
Loopback template calls always connect directly, ignoring configured and
environment HTTP proxies so fixed credentials stay on the local connection.

Templates require `config_version: 2` and `template.version: 1`. Existing
exact-URL targets can share the same file. A target must have either `url` or
`template`; templates cannot use `unix_socket`.

## Configure operations

The following complete configuration exposes three operations on an example
case-management API. Replace the tunnel ID and HTTPS origins with your own
values. The configured upstream must be reachable from the client and its TLS
certificate must be trusted; configure `ca_bundle` for a private CA when needed.

Provide `CONTROL_PLANE_API_KEY` and `CASE_API_AUTHORIZATION` through your process
environment or secret manager. `CASE_API_AUTHORIZATION` contains the complete
header value, such as `Bearer ...`. Keep the credential out of command-line
arguments and source control.

Save this as `templates.yaml`:

```yaml
config_version: 2
control_plane:
  tunnel_id: tunnel_0123456789abcdef0123456789abcdef
  api_key: env:CONTROL_PLANE_API_KEY
  poll_channels: [harpoon]
harpoon:
  targets:
    - label: get_profile
      description: Get a profile by session identifier
      template:
        version: 1
        origin: https://cases.example
        method: GET
        path_template: /profiles
        query:
          session-id: "{session_id}"
        parameters:
          session_id:
            type: string
            required: true
            description: Session identifier returned by the case application
            examples: [session-123]
            pattern: '^[A-Za-z0-9_-]+$'
            min_length: 1
            max_length: 64
        headers:
          Authorization: env:CASE_API_AUTHORIZATION
        allowed_headers: [Accept, X-Request-Tag]
        follow_redirects: false

    - label: get_case_orders
      description: Get orders for one case
      template:
        version: 1
        origin: https://cases.example
        method: GET
        path_template: /cases/orders
        query:
          CaseId: "{case_id}"
        parameters:
          case_id:
            type: string
            required: true
            description: Case identifier from the case application
            examples: [CASE-123]
            pattern: '^[A-Za-z0-9_-]+$'
            max_length: 64
        headers:
          Authorization: env:CASE_API_AUTHORIZATION
        follow_redirects: false

    - label: get_case_status
      description: Get the status of one case including elevations and complaints
      template:
        version: 1
        origin: https://cases.example
        method: GET
        path_template: /casestatus/{case_id}
        query:
          elevations: "true"
          complaints: "true"
        parameters:
          case_id:
            type: string
            required: true
            description: Case identifier whose status should be returned
            examples: [CASE-123]
            pattern: '^[A-Za-z0-9_-]+$'
            max_length: 64
            reserved_values: [all, search, admin]
        headers:
          Authorization: env:CASE_API_AUTHORIZATION
        follow_redirects: false
health:
  listen_addr: 127.0.0.1:8080
```

Start the client with the secrets already present in its environment:

```sh
tunnel-client run --config templates.yaml
```

This example subscribes only to the Harpoon channel. To serve your existing MCP
server as well, add its `mcp.server_urls` or `mcp.commands` binding and set
`control_plane.poll_channels: [main, harpoon]`.

For a mounted secret, replace the fixed header value with a file reference:

```yaml
headers:
  Authorization: file:/run/secrets/case-api-authorization
```

The file contains the complete header value. One final line ending is removed;
embedded line breaks and invalid HTTP header values are rejected. References
resolve at startup. Restart the process after changing configuration or rotating
the referenced credential; templates do not reload automatically.

## Caller header rules

Use `template.header_rules` to allow caller-supplied headers with public
descriptions, validation, and optional private renaming. `allowed_headers` is a
supported alias with the same behavior and no removal deadline. Either key
accepts a list mixing strings and rule objects. Use only one key per template;
both keys are rejected even when empty or identical. Omit the list or use `[]`
to allow no caller headers; explicit `null` is rejected. Profile round trips
preserve the chosen alias and structured rules.

This example adds runtime authentication and correlation to a GET template:

```yaml
template:
  version: 1
  origin: https://cases.example
  method: GET
  path_template: /cases/{case_id}
  parameters:
    case_id:
      type: string
      required: true
      pattern: '^[A-Za-z0-9_-]+$'
      max_length: 64
  headers:
    Accept: application/json
  header_rules:
    - X-Request-Tag
    - name: Authorization
      description: Complete bearer value issued by the case application
      credential: true
      required: true
      validation:
        pattern: '^Bearer [A-Za-z0-9._~+/-]+=*$'
        min_length: 8
        max_length: 4096
    - name: X-Trace-Id
      description: Correlation identifier for this request
      forward_as: X-Correlation-Id
      validation:
        pattern: '^[A-Za-z0-9_-]+$'
        min_length: 1
        max_length: 64
  follow_redirects: false
```

String entries preserve the existing allowlist behavior: optional, no renaming,
and empty or UTF-8 values allowed subject to the existing transport limits.
String-form `Authorization` remains prohibited. A structured rule requires
`name` and a nonempty public `description`; `required` and `credential` default
to false, and `forward_as` defaults to the source name. Required means present;
set `min_length: 1` to prohibit an empty value.

Validation combines every supplied constraint: full-string `pattern`, exact
`enum`, `min_length`, and `max_length`. Length bounds count Unicode code points;
the separate 8,192-byte aggregate header budget still applies. Patterns are
limited to 512 printable ASCII bytes and the same explicit ASCII subset as body
patterns: literals, positive character classes, grouping, alternation, anchors,
and quantifiers. Wildcards, shorthand or negated classes, lookarounds,
backreferences, and flags are rejected. Values subject to a pattern must
contain only printable ASCII. A description-only
noncredential rule is valid. Constraints may tighten the transport limits but
cannot relax them.

`Authorization`, `X-API-Key`, and `API-Key` require `credential: true` plus
positive minimum and maximum lengths and a nonempty format pattern. Credential
rules reject `enum`, even alongside a pattern: enumerating accepted credentials
would disclose their values through discovery. Noncredential headers may use
public enums. The rule
can use one of those names as its public name or private destination. Other
credential-like names and reserved transport or identity fields remain
prohibited. Both names are checked. Header names match case-insensitively;
duplicate sources, duplicate destinations, overlaps between separate source
and destination rules, and collisions with fixed or body-managed headers are
rejected. Only one outgoing field is sent after renaming; the public alias is
not also sent. Values are passed unchanged, without prefixes or interpolation.

For structured header rules, `tools/list` and
`list_targets.invocation.input_schema` expose the same target-specific schema,
including public names, descriptions, requiredness, and validation constraints.
Legacy templates retain a shared generic `tools/list` branch and expose their
target-specific constraints through `list_targets`. Neither surface exposes
`forward_as` or its destination.
Descriptions and validation constraints are public metadata: never put an
actual secret in an enum, pattern, or description. Required credentials are
never synthesized into discovery examples.

Copy the `label` constant from the discovered invocation schema. For structured
header rules it is an opaque policy-bound handle beginning with `hr1:`, while
the top-level target label remains the logical name. A call using the logical
name alone is rejected. The handle is bound to the complete private policy,
the tunnel ID, and the resolved runtime API key. Equivalent replicas using
the same key can accept it; a changed policy or runtime key requires fresh
discovery. Callers must not construct, trim, or rewrite the handle.

Only values supplied in the tool's `headers` argument are eligible for these
rules. HTTP ingress, MCP, tunnel, and actor credentials are never implicitly
forwarded. Each call supplies its own upstream credential; Harpoon does not
cache, refresh, or retry it. Tool arguments may be visible to the caller,
model, or conversation transcript. These rules do not provide a model-hidden
secret channel.

## Call and discover targets

Call `list_targets` to discover operations. A template entry contains enough
information to construct its tool arguments without reading the configuration
or calling MCP `tools/list`:

| Field | Meaning |
| --- | --- |
| `label`, `description` | The operation's public name and purpose. |
| `template_version` | `1` for the template contract described here. |
| `allowed_methods` | Exactly one operator-configured method: `["GET"]`, `["POST"]`, or `["PUT"]`. |
| `parameters_schema` | Required parameter names, string constraints, and any configured descriptions and examples. |
| `invocation.tool_name` | `call_target`. |
| `invocation.input_schema` | The complete argument schema: fixed `label`, required `parameters`, required write `operation` constant, write `body` and `content_type` policy, permitted caller headers, and bounded optional `timeout_ms` and `max_response_bytes`. |
| `invocation.examples` | One complete arguments object when every parameter has an example and a required body has a configured enum value; otherwise absent. |

To call an operation using only this discovery result:

1. Select the target entry and read its `invocation.input_schema`.
2. Construct the required arguments. An entry in `invocation.examples` can be a
   starting point, but replace sample identifiers with the intended identifiers.
3. Send MCP `tools/call` with `name` set to `invocation.tool_name` and
   `arguments` set to that object.

The per-target schema fixes `label` to that entry's label and rejects unknown
arguments and extra parameters. It describes only permitted caller header names;
it never publishes fixed authentication headers. Exact-URL entries retain their
existing discovery shape and use `call_target`. Use the caller header spelling
advertised by the per-target schema.

Template discovery excludes private origins, path and query templates, fixed
query values, and fixed header names and values. Descriptions, parameter names,
examples, enum values, reserved identifiers, and allowed caller header names are
public metadata available to tool callers. Operators must keep credentials,
private URLs, personal data, and other confidential values out of that metadata.

Send the following MCP tool call on the Harpoon channel:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "call_target",
    "arguments": {
      "label": "get_case_orders",
      "parameters": {"case_id": "CASE-123"}
    }
  }
}
```

Harpoon sends `GET https://cases.example/cases/orders?CaseId=CASE-123` with the
operator's fixed authorization header. These additional examples show the
arguments object and resulting operation:

| Arguments | Operation |
| --- | --- |
| `{"label":"get_profile","parameters":{"session_id":"session-123"}}` | `GET /profiles?session-id=session-123` |
| `{"label":"get_case_status","parameters":{"case_id":"CASE-123"}}` | `GET /casestatus/CASE-123?complaints=true&elevations=true` |

Query key order is canonicalized during encoding and has no semantic meaning.

The caller can supply `headers` only for names explicitly listed in that
target's `header_rules` or `allowed_headers`. For example, `get_profile` accepts:

```json
{
  "label": "get_profile",
  "parameters": {"session_id": "session-123"},
  "headers": {"Accept": "application/json", "X-Request-Tag": "support-check"},
  "timeout_ms": 10000,
  "max_response_bytes": 32768
}
```

`timeout_ms` and `max_response_bytes` are optional bounded execution limits.
Timeout defaults to 30 seconds and an explicit value must be from 100 through
120,000 milliseconds. The response limit defaults to the configured Harpoon
limit, which cannot exceed 102,400 bytes; an explicit per-call value must be
positive and cannot exceed that configured limit. Omit these fields to use
defaults; discovery reports the bounds for the running client.

Caller input cannot override the method, origin, URL, path, query, template,
fixed headers, or redirect policy. GET bodies, duplicate JSON keys, unknown
fields, missing or additional parameters, and non-string identifiers are
rejected. Both exact targets and templates use `call_target`. Exact targets
require `method`; template calls must omit it and follow their discovered
invocation schema. Template-shaped arguments never fall back to exact routing.

### Response contract

Template calls retain the exact-target response structure: the upstream
`status_code`, `headers` when present, `body_base64` when nonempty, and
`body_size_bytes`. For example, an upstream body of `{"ok":true}` produces this
result payload:

```json
{
  "status_code": 200,
  "headers": {"Content-Type": ["application/json"]},
  "body_base64": "eyJvayI6dHJ1ZX0=",
  "body_size_bytes": 11
}
```

Decode `body_base64` to obtain the upstream bytes; they are not necessarily JSON.
HTTP error statuses such as 403 or 404 are returned as upstream responses.
Redirect responses are also returned without following them. Invalid arguments,
transport failures, and responses that exceed the size limit are tool errors;
an oversized response is not returned as a successful partial body. Harpoon does
not accept a configured response schema or validate the upstream body's
application-specific structure. Parameter descriptions and examples describe
request arguments only.

### Parameter descriptions and examples

Parameter `description` and `examples` are optional. A description must be valid
UTF-8 and at most 1,024 bytes. Each parameter can have up to eight unique example
strings. Every example must pass the same type, identifier, length, pattern,
enum, and reserved-value rules as a real call.

Discovery builds one complete example by choosing the first explicit example
for each parameter, or its lexicographically first enum value (sorted as strings)
when no explicit example exists. Reordering an enum does not change this choice;
explicit example order is preserved.
`invocation.examples` is omitted if any parameter lacks both.
For a write, the example also includes the lexicographically first body enum
value and content type. A required body without an enum prevents example
generation. An optional body without an enum is omitted from the example.
Examples are suggestions, not defaults: callers must still provide every
required parameter. Validation does not confirm that an example identifies a
real upstream resource or grants access to it.

## Multiple parameters and enumerations

One template can contain multiple path arguments and multiple query parameters.
Each argument has its own required schema. This example combines two path
arguments, two dynamic query values, and one fixed query value:

```yaml
- label: get_tenant_case
  description: Get one tenant case with an approved view
  template:
    version: 1
    origin: https://cases.example
    method: GET
    path_template: /tenants/{tenant_id}/cases/{case_id}
    query:
      view: "{view}"
      requestId: "{request_id}"
      archive: "false"
    parameters:
      tenant_id:
        type: string
        required: true
        pattern: '^[A-Za-z0-9_-]+$'
        max_length: 64
      case_id:
        type: string
        required: true
        pattern: '^[A-Za-z0-9_-]+$'
        max_length: 64
      view:
        type: string
        required: true
        enum: [summary, details]
        max_length: 7
      request_id:
        type: string
        required: true
        pattern: '^[A-Za-z0-9_-]+$'
        max_length: 64
    headers:
      Authorization: env:CASE_API_AUTHORIZATION
    follow_redirects: false
```

Call arguments:

```json
{
  "label": "get_tenant_case",
  "parameters": {
    "tenant_id": "tenant-1",
    "case_id": "CASE-123",
    "view": "summary",
    "request_id": "req-456"
  }
}
```

The result is
`GET /tenants/tenant-1/cases/CASE-123?archive=false&requestId=req-456&view=summary`.
All four arguments must be present and valid. Missing or invalid values in any
position reject the entire call before an outbound request is sent.

## POST and PUT bodies

Add a separate operation for each write. The method remains part of operator
configuration; callers never supply a `method` argument. For example, add this
entry under `harpoon.targets` in the configuration above:

```yaml
- label: update_case
  description: Change one case status
  template:
    version: 1
    origin: https://cases.example
    method: PUT
    path_template: /tenants/{tenant_id}/cases/{case_id}
    query:
      view: "{view}"
      requestId: "{request_id}"
    parameters:
      tenant_id:
        type: string
        required: true
        enum: [tenant-1]
        max_length: 64
      case_id:
        type: string
        required: true
        examples: [CASE-123]
        pattern: '[A-Za-z0-9_-]+'
        max_length: 64
      view:
        type: string
        required: true
        enum: [summary, details]
        max_length: 7
      request_id:
        type: string
        required: true
        examples: [req-456]
        pattern: '[A-Za-z0-9_-]+'
        max_length: 64
    body_policy:
      content_types: [application/json]
      max_bytes: 4096
      required: true
      validation:
        json: true
        enum: ['{"status":"closed"}', '{"status":"open"}']
    headers:
      Authorization: env:CASE_API_AUTHORIZATION
    allowed_headers: [X-Request-Tag]
    follow_redirects: false
```

After discovering `update_case`, construct these arguments from its invocation
schema:

```json
{
  "label": "update_case",
  "operation": "COPY_THE_OPERATION_CONSTANT_FROM_DISCOVERY",
  "parameters": {
    "tenant_id": "tenant-1",
    "case_id": "CASE-123",
    "view": "summary",
    "request_id": "req-456"
  },
  "content_type": "application/json",
  "body": "{\"status\":\"closed\"}"
}
```

Replace the `operation` placeholder with
`invocation.input_schema.properties.operation.const` from discovery (a generated
`write-v1:...` token). Each generated invocation example already includes it.
Harpoon sends `PUT /tenants/tenant-1/cases/CASE-123?requestId=req-456&view=summary`
with `Content-Type: application/json`, the pinned authorization header, and the
exact UTF-8 body `{"status":"closed"}`. A separately configured `method: POST`
operation uses the same body contract. DELETE is unsupported.

Every POST/PUT policy must explicitly provide `content_types`, `max_bytes`,
`required` (either `true` or `false`), and `validation`. At least one of these
validators is required; all configured checks apply:

| Validator | Meaning |
| --- | --- |
| `json: true` | Require syntactically valid JSON, valid UTF-8, and paired Unicode surrogate escapes. This is a syntax check, not a JSON Schema or application authorization check. |
| `pattern` | Require the complete raw body to match a regular expression of at most 512 ASCII bytes, using the body-specific syntax below. |
| `enum` | Require an exact raw-string match, including whitespace. At most 64 unique values with at most 102,400 total UTF-8 bytes. Each value must satisfy the other checks. |

`content_types` lists 1–16 exact lowercase media types without wildcards or
parameters. `application/json` and media types ending in `+json` require
`json: true`. Other media types, such as `text/plain` or
`application/x-www-form-urlencoded`, can use a pattern or enum. Harpoon does not
serialize, reformat, or encode the body. The JSON-RPC `body` value must be a
string, including when its contents are JSON.

Body patterns support printable ASCII literals, positive character classes such
as `[A-Za-z0-9_-]`, ordinary and noncapturing groups, alternation, anchors, and
quantifiers. Escape literal regular-expression punctuation. Shorthand classes
such as `\s`, `\w`, and `\d`, wildcard `.`, nested or negated classes, and
non-ASCII literals are rejected. This limits pattern-matched bodies to printable
ASCII and avoids differences between Go and schema consumers in Unicode
whitespace, line terminators, and character counting. Use JSON validation or an
exact enum without a pattern for Unicode or multiline bodies. Parameter pattern
syntax is unchanged.

`max_bytes` must be from 1 through 102,400 and is independent of the response
limit. Discovery includes `x-maxBytes`; ordinary JSON Schema `maxLength` counts
characters, so the executor additionally checks the UTF-8 byte length. Both
discovery and runtime pattern validation reject nonprintable or non-ASCII body
characters, including a trailing newline.

When present, `body` and `content_type` must appear together. With
`required: true`, the body must be nonempty. With `required: false`, both may be
omitted; a supplied empty string still runs all configured validators. GET
rejects both arguments even when empty and cannot configure `body_policy`.
For writes, `Content-Type` is managed through `content_type`; it cannot appear
in fixed `headers` or `allowed_headers`.
Write templates also reject `Content-Encoding` in either header list; validation
and transmission operate on the same unencoded body bytes.

Every write requires the discovered `operation` constant, even when its body is
omitted. It identifies the public method, parameter schema, and body policy;
the executor rejects mismatches. It includes no private destination or credential
fingerprint. GET rejects this field. Older GET-only clients reject the unknown
field, so an optional body cannot silently turn a write into a GET on an older
executor.

Body enums and validation constraints are public discovery metadata. Keep
confidential values out of them. Payloads remain excluded from routine logs and
payload observers. Method and the complete body policy are included in the
policy digest.

### Write completion and retries

The shared `call_target` tool is advertised with read-only and idempotent
hints set to false. A PUT method alone does not promise that
every application's operation is safe to repeat.

The client sends each template invocation once. It disables redirects and
automatic HTTP body replay, including when an operator-pinned `Idempotency-Key` header
is present and when an optional write has an empty body. A transport error,
timeout, lost response, or response-size error can happen after the upstream
has applied the write. Treat that outcome as unknown and inspect upstream
state before deciding whether to make a new call. Do not automatically retry,
add or change the method, or substitute an exact-target call.

## Grammar and limits

The client compiles every selected template before serving requests. Unknown or
duplicate YAML fields are rejected. `config_version: 2` also rejects multiple YAML
documents, including a trailing `---`; version 1 and files without a version retain
their existing behavior of reading only the first document. Invalid policy fails
startup.

Catalogs containing structured header rules have a 512 KiB discovery budget,
including public schemas, descriptions, enums, examples, the escaped JSON text
copy returned by `list_targets`, and reserved space for response envelopes.
Registration rejects a target before it would exceed this budget, including
exact and legacy template targets in a mixed catalog. Reduce metadata or split
the catalog across clients if this happens. Catalogs without structured header
rules retain their existing limits and compact `tools/list` template schema.
For catalogs using structured rules, this keeps both `tools/list` and
`list_targets` comfortably below the tunnel response size limit; unrelated tools
registered by extensions are outside this catalog budget.

Profile add, edit, and init validate the same template policy before saving. They
check secret-reference syntax without reading environment variables or files.
Startup resolves those references and validates the actual header values and their
combined size; a profile can be saved before its credentials are available.

| Field or input | Version 1 rule |
| --- | --- |
| `origin` | Literal `https://host` with an optional port from 1 to 65,535 and optional trailing `/`. With `allow_loopback_http: true`, use `http://127.0.0.1:port` or `http://[::1]:port` (or another literal 127/8 address) with a required port. No credentials, variable host, query, fragment, or other path. |
| `allow_loopback_http` | Omit or set to `false` for HTTPS. Set to `true` only for a literal loopback HTTP origin with a fixed port. |
| `method` | Explicitly `GET`, `POST`, or `PUT`; POST/PUT require `body_policy`. DELETE and other methods are rejected. |
| `path_template` | Absolute path. A placeholder occupies one complete segment, such as `/cases/{case_id}`. Empty segments, traversal segments, and partial placeholders such as `case-{id}` are rejected. |
| `query` | At most 32 fixed, unique keys. Each key is 1–64 ASCII unreserved characters; its value is a fixed string or exactly one `{parameter}`. Fixed strings are valid UTF-8, contain no control characters, and are at most 256 bytes. Quote YAML booleans and numbers when using them as string literals. |
| Parameter names | 1–64 characters matching `[A-Za-z][A-Za-z0-9_]*`. Declare 1–16 parameters; every declared parameter must appear in the path or query. A parameter may appear more than once. |
| Parameter types | `type: string` and `required: true`. Optional parameters, arrays, objects, and repeated query keys are unsupported. |
| Identifier characters | ASCII letters, digits, `_`, `-`, `.`, and `~`; the complete values `.` and `..` are rejected. Percent signs, slash, backslash, whitespace, controls, query delimiters, fragments, and encoded separators are rejected before URL construction. |
| Identifier length | `max_length` is required, from 1 through 256 bytes. `min_length` defaults to 1 and cannot exceed the maximum. |
| `pattern` and `enum` | At least one is required. Patterns match the entire identifier, contain at most 512 ASCII bytes, and use the portable regular-expression subset described below. An enum contains at most 64 unique values. When both are present, every value must satisfy both. |
| `reserved_values` | At most 64 identifiers rejected case-insensitively, including enum values. Duplicate reserved values are rejected case-insensitively. |
| Parameter `description` | Optional public text, valid UTF-8 and at most 1,024 bytes. |
| Parameter `examples` | Optional list of at most eight unique strings, each valid under the parameter's complete policy. |
| URL length | At most 4,096 bytes after encoding. Policies whose longest permitted identifiers could exceed that limit are rejected at startup. |
| `headers` and `header_rules` (alias `allowed_headers`) | At most 32 names in total, including the managed write `Content-Type` slot. Names are at most 128 bytes and case-insensitive. Caller names cannot overlap fixed names. Total outbound header names and values, including the managed `User-Agent`, cannot exceed 8,192 bytes. Values must be valid UTF-8 without control characters. Renamed inputs and outputs both obey the byte limit. |
| `follow_redirects` | Omit or set to `false`. A redirect response is returned without following it, even for the same origin or an independently configured target. |

Literal path segments and query keys use the same ASCII unreserved character
set as identifiers, and cannot be `.` or `..`. Query values are encoded as query
values, while path identifiers are encoded as individual segments; the caller
does not provide pre-encoded input.

Patterns support literal ASCII characters, character classes, ordinary and
noncapturing groups (`(...)` and `(?:...)`), alternation, anchors, and
quantifiers. The supported escapes are `\d`, `\D`, `\s`, `\S`, `\w`, `\W`,
and escaped regular-expression punctuation. Inline flags, lookarounds,
backreferences, octal escapes, Unicode classes such as `\p`, Go-specific
anchors such as `\A` or `\z`, and POSIX classes are rejected. This common
subset keeps public JSON Schema validation consistent with runtime validation.
The separate identifier character and length restrictions apply to every
pattern, including permissive patterns such as `.*`.

Authentication headers belong in the operator's fixed `headers` map or an
explicit supported structured credential rule. String caller allowlists cannot
include names containing an `authorization`, `cookie`, `key`,
`secret`, `token`, or `password` component, or recognizable joined names such as
`ApiKey`, `X-AuthToken`, and `ClientSecret`. Transport, forwarding, trusted
identity, and method-override headers are prohibited even when explicitly
listed, including `Host`, `Cookie`, `User-Agent`, `Forwarded`, `X-Forwarded-*`,
`X-Envoy-*`, and `X-HTTP-Method-Override`.

## Proxy connectivity checks

When an HTTPS template uses an HTTP proxy, the full client's proxy health checker tests
CONNECT to the template's fixed origin host and port. It never supplies parameter
values, sends target authentication headers, or invokes the HTTP operation.
Successful CONNECT confirms proxy connectivity; it does not establish that a
specific resource exists or that the target will authorize a request. A rejected
CONNECT marks proxy health as degraded even when only template targets use that
proxy. Loopback HTTP templates are direct routes, regardless of proxy settings,
and do not initiate a proxy check.

## Authorization and privacy

Identifier validation limits request structure; the upstream API remains
responsible for deciding whether a caller may access a particular object.
Harpoon preserves upstream authorization failures such as HTTP 403.

A fixed service credential gives all callers of that target the authority of
that credential. Scope it to the intended operations and objects, and use a
separate upstream authorization layer when permissions must differ by end user.
Templates do not infer end-user identity from a case ID or propagate caller
identity headers. A syntactically valid ID alone is not evidence of permission
to read that object.

Template calls are excluded from payload observers and raw HTTP debug capture.
Routine call logs omit parameter values, rendered URLs, fixed headers, and
response bodies. Upstream response bodies still return to the authorized tool
caller and may contain sensitive information. The local admin UI and support
export are operator diagnostics; template discovery is the public metadata
surface. Fixed header values and environment variables referenced by those
headers are redacted in support exports, regardless of the header or variable's
name.

Invalid caller header values produce generic errors without reflecting the
submitted value. Validation and requiredness are checked again at the outbound
boundary. These protections do not redact secrets an upstream chooses to put
in its response to the caller.

When any structured header rule is configured, control-plane raw HTTP dumps
are disabled even if `log.http_raw_unsafe` is enabled. Poll envelopes can carry
runtime credentials, so this exclusion covers the connection's requests and
responses. Ordinary metadata logs remain available. Legacy string-only
configurations retain their existing logging behavior.

## Compatibility and upgrades

- Upgrade executors before using `header_rules` or structured entries. Older
  clients reject the new key and cannot decode objects in `allowed_headers`.
  Existing string lists keep their behavior under either key on new clients.
  Replace an explicit null list with `[]` or omit it before upgrading.
- Policy-bound invocations are incompatible with old or differently configured
  executors and fail without falling back to the logical label. They retain
  the existing `call_target` tool and tunnel envelopes. This is an invocation
  check, not a service-side poller admission fence. Old processes can still
  expose and execute their old configuration for stale, unbound callers.
  Retire all old configurations and pollers when tightening a policy; mixed
  incompatible replicas may reject calls. Rediscover after policy or runtime
  key changes, and never replay an ambiguous write automatically.
- Existing exact-URL configurations with no `config_version` or version 1 keep
  their existing behavior. Version 2 can contain exact targets alongside
  templates.
- Template configuration is an explicit opt-in. Older clients reject version 2
  or the unknown template fields; they cannot silently reinterpret the template
  as an exact URL.
- Rich discovery retains `config_version: 2` and `template.version: 1`. Clients
  that support templates but predate parameter `description` and `examples`
  reject those unknown YAML keys. Upgrade every eligible client before adding
  metadata to its configuration. Remove these keys before rolling back to such
  a client.
- Rich discovery adds metadata to template entries only; exact-only discovery
  and its output schema remain unchanged. The tunnel and MCP request/response
  envelopes remain unchanged.
- Templates and exact targets share `call_target`. Callers must use the tool
  name and argument schema returned by current discovery. The former
  `call_target_template` tool name is no longer registered. Existing GET
  template configuration remains valid; update callers to use discovery.
- Template calls omit `method`. Older exact-only executors require `method`
  and reject this shape; older GET-template executors reject template labels
  through `call_target`. Never retry by adding a method, changing the tool name,
  or passing a rendered URL.
- POST/PUT require an upgraded client. GET-only template clients reject the new
  body-policy configuration or body arguments before sending a request. Upgrade
  every executor eligible to poll this Harpoon channel before enabling writes.
  Remove write operations before rolling back to a GET-only client.
- Generic MCP carries the additional arguments in the existing JSON-RPC
  envelope. The gateway must reject duplicate JSON keys before converting
  unified `call_target` arguments to maps. An older gateway that applies this
  guard only to the former tool name can carry valid writes but does not meet
  the strict validation contract; deploy a compatible service revision before
  enabling unified template calls through that path.
- Python callers must upgrade the Harpoon helper to call `call_target` with
  `parameters`, the discovered write `operation`, `body`, and `content_type`.
  This source change does not publish a client release or roll out client
  configuration.
- The client uses the existing MCP JSON-RPC and tunnel poll/response envelopes.
  This client feature does not establish service-side routing guarantees for a
  mixture of old and new executors. Keep templates disabled for such a group
  until every eligible executor supports them or the service enforces compatible
  routing.
- Explicit `--harpoon.target` flags replace the **entire** YAML target list;
  otherwise an explicitly set `HARPOON_TARGETS` replaces that entire list.
  These legacy inputs accept exact targets only. They do not merge with YAML
  templates. An explicitly empty value clears the list. Remove stale overrides
  when activating templates from YAML.
- Changing templates or rotating a referenced credential requires a process
  restart. Preserve a version 1 exact-target configuration if you need to roll
  back to an older client.
