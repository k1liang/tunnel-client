# Continuation stability experiment

This fork contains an opt-in mitigation for ChatGPT hosted workflow stalls that can occur after a tool result has already been delivered.

## Behavior

When enabled, terminal JSON-RPC responses for `tools/call` are delayed briefly before final delivery. During that delay the client emits up to N non-terminal notifications on the same tunnel command:

- If the original MCP request contains `_meta.progressToken`, standard `notifications/progress` messages are used.
- If no progress token exists and fallback logging is enabled, `notifications/message` debug events from logger `tunnel-stability` are used instead.
- The original terminal response is still delivered last.
- Notification delivery is best-effort. A failed synthetic notification does not suppress the terminal response.
- Existing command deadlines remain authoritative; the delay stops when the context is canceled.

The feature is intentionally disabled by default so upstream-compatible behavior is preserved unless explicitly requested.

## Environment variables

```text
TUNNEL_STABILITY_PRE_FINAL_NOTIFY=1
TUNNEL_STABILITY_PRE_FINAL_DELAY_MS=500
TUNNEL_STABILITY_PRE_FINAL_NOTIFY_COUNT=2
TUNNEL_STABILITY_FALLBACK_LOG_NOTIFY=1
TUNNEL_STABILITY_FINAL_RESERVE_MS=3000
TUNNEL_STABILITY_NOTIFICATION_POST_TIMEOUT_MS=750
```

Recommended local stability-first settings are exactly the values above. They add roughly 500 ms to each terminal `tools/call` response in exchange for pre-final connector activity.

Set `TUNNEL_STABILITY_PRE_FINAL_NOTIFY=0` to disable the experiment immediately. Set `TUNNEL_STABILITY_FALLBACK_LOG_NOTIFY=0` to keep only standards-based progress notifications tied to an existing progress token.

## Rationale

The failure mode being investigated is not ordinary MCP execution latency: local MCP work and tunnel response delivery can complete successfully, while one hosted ChatGPT workflow waits tens of seconds before issuing the next command even though other workflows continue normally.

This experiment tries to reduce that post-tool continuation stall by keeping the connector stream active immediately before the terminal response. It is a mitigation experiment, not a guaranteed fix for hosted scheduling.

Use per-workflow gap logging on the DesktopCommander side to compare 30/60/120-second stall rates before and after enabling this mode.
