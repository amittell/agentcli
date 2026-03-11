# Protocol

## Scope

This document defines the draft `agentcli` JSON-RPC protocol served over stdio.

The implementation lives in [src/jsonrpc.js](../src/jsonrpc.js).

## Transport

Transport is line-delimited JSON over stdin/stdout.

Rules:

- each request MUST be a single JSON object on one line
- each response MUST be a single JSON object on one line
- server startup notifications MAY be ignored by clients
- parse failures return JSON-RPC parse errors when possible

On startup, the server emits a readiness notification before processing requests:

```json
{"jsonrpc":"2.0","method":"agentcli.ready","params":{"ok":true,"manifest_version":"0.1"}}
```

Clients MAY ignore this notification, but it provides a clean synchronization point for process-spawn integrations.

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

### `agentcli.schema`

Params:

- `target`

Result:

- schema fragment for the requested target

### `agentcli.describe`

Params:

- `target`

Result:

- descriptive metadata for the requested topic

### `agentcli.validate`

Params:

- `manifest`

Result:

- the same validation payload returned by CLI validation

### `agentcli.compile`

Params:

- `manifest`
- `target`
- `explain`

Result:

- target-specific compiled artifact

### `agentcli.apply`

Params:

- `manifest`
- `dbPath`
- `schedulerPrefix`
- `schedulerBin`
- `dryRun`
- `explain`
- `adoptBy` - `"id"` (default) or `"name"`. Use `"name"` for one-time migration of existing scheduler jobs to agentcli management. See README for the migration workflow.

Result:

- scheduler apply payload with create, update, or adopted actions
- intended for the `openclaw-scheduler` backend

### `agentcli.inspect`

Params:

- `dbPath`
- `entity`
- `limit`
- `fields`
- `sanitize`

Result:

- runtime inspection payload for scheduler-backed entities

## Error Model

Current error classes:

- `-32700`: parse error
- `-32600`: invalid request
- `-32602`: invalid params
- `-32601`: method not found
- `-32000`: application error

Implementations SHOULD include machine-readable `data` for richer failures when available.

## Stability

The following are intended to be stable within manifest spec version `0.1`:

- method names
- request envelope shape
- response envelope shape
- top-level `result.ok` convention

Future protocol additions SHOULD be additive.
