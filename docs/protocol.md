# Protocol

## Scope

This document defines the draft `agentcli` JSON-RPC protocol served over stdio.

The implementation lives in [src/jsonrpc.js](../src/jsonrpc.js).

## Transport

Transport is line-delimited JSON over stdin/stdout.

Rules:

- each request MUST be a single JSON object on one line
- each response MUST be a single JSON object on one line
- batch requests (JSON arrays) are not supported and return an error
- server startup notifications MAY be ignored by clients
- parse failures return JSON-RPC parse errors when possible

On startup, the server emits a readiness notification before processing requests:

```json
{"jsonrpc":"2.0","method":"agentcli.ready","params":{"ok":true,"manifest_version":"0.1"}}
```

Clients MAY ignore this notification, but it provides a clean synchronization point for process-spawn integrations.
Clients can discover the current method and notification surface programmatically with `agentcli.describe` and `target: "rpc"`.

## Envelope

Requests MUST follow JSON-RPC `2.0`.

Example request:

```json
{"jsonrpc":"2.0","id":"1","method":"agentcli.validate","params":{"manifest":{"version":"0.1","workflows":[{"id":"w1","name":"W","tasks":[{"id":"t1","name":"T","prompt":"hello","target":{"session_target":"isolated"},"schedule":{"cron":"0 9 * * *"}}]}]}}}
```

Example response:

```json
{"jsonrpc":"2.0","id":"1","result":{"ok":true,"errors":[],"warnings":[]}}
```

## Methods

### `agentcli.ping`

Purpose:

- health check

Result:

- `{ "ok": true, "pong": true }`

### `agentcli.version`

Purpose:

- version discovery for agent integrations

Result:

- `{ "ok": true, "package_version": "0.1.0", "manifest_version": "0.1" }`

### `agentcli.schema`

Params:

- `target` - defaults to `"manifest"` when omitted. Valid targets: `manifest`, `workflow`, `task`, `schedulerJob`, `standalonePlan`, `rpcRequest`, `rpcResponse`. Also accepts kebab-case aliases: `scheduler-job`, `standalone-plan`, `rpc-request`, `rpc-response`.

Result:

- `{ "ok": true, "schema": <schema-fragment> }`

### `agentcli.describe`

Params:

- `target` - defaults to `"commands"` when omitted. Valid targets: `manifest`, `workflow`, `task`, `targets`, `commands`, `rpc`.

Result:

- `{ "ok": true, "description": <metadata> }`
- for `target: "rpc"`, description contains separate `methods[]` and `notifications[]` arrays

### `agentcli.validate`

Params:

- `manifest`

Result:

- `{ "ok": <boolean>, "errors": [...], "warnings": [...] }`
- validation failures are returned in `result`, not as JSON-RPC errors

### `agentcli.compile`

Params:

- `manifest`
- `target`
- `explain`

Result:

- `{ "ok": true, "target": "<target-name>", "output": <compiled-artifact> }`
- `output` includes an `explain` array when the `explain` param is `true`

### `agentcli.apply`

Params:

- `manifest`
- `dbPath`
- `schedulerPrefix`
- `schedulerBin`
- `dryRun` - boolean, defaults to `false`. When `true`, no scheduler writes are executed (preview mode).
- `explain`
- `adoptBy` - `"id"` (default) or `"name"`. Use `"name"` for one-time migration of existing scheduler jobs to agentcli management. See README for the migration workflow.

Result:

- `{ "ok": true, "target": "openclaw-scheduler", "dry_run": <boolean>, "scheduler": { "command": "...", "db_path": "..." }, "job_count": <int>, "actions": [{ "action": "created|updated|adopted", "job_id": "...", "name": "...", "invocation_mode": "schedule|trigger" }], "explain": [...] }`
- `explain` is present only when the `explain` param is `true`
- intended for the `openclaw-scheduler` backend

### `agentcli.inspect`

Params:

- `dbPath`
- `entity`
- `limit`
- `fields` - array of field names, or a comma-delimited string for CLI-style parity
- `sanitize`

Result:

- `{ "ok": true, "target": "openclaw-scheduler", "entity": "...", "count": <int>, "items": [...] }`

## Notifications

### `agentcli.ready`

Purpose:

- announce that the server is ready to process requests
- surface the current manifest contract version for clients that want to gate behavior

Params:

- `ok`
- `manifest_version`

## Error Model

Current error classes:

- `-32700`: parse error
- `-32600`: invalid request
- `-32602`: invalid params
- `-32601`: method not found
- `-32000`: application error

Implementations SHOULD include machine-readable `data` for richer failures when available.
Caller-fixable request shape and argument issues SHOULD use `-32602`, including unknown schema targets, unknown description topics, unsupported compile targets, and invalid inspect arguments.

## Stability

The following are intended to be stable within manifest spec version `0.1`:

- method names
- request envelope shape
- response envelope shape
- top-level `result.ok` convention

Future protocol additions SHOULD be additive.
