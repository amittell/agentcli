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
{"jsonrpc":"2.0","method":"agentcli.ready","params":{"ok":true,"manifest_version":"0.2"}}
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

- `{ "ok": true, "package_version": "0.5.0", "manifest_version": "0.2" }`

### `agentcli.schema`

Params:

- `target` - defaults to `"manifest"` when omitted. Valid targets: `manifest`, `workflow`, `task`, `schedulerJob`, `standalonePlan`, `handoffV4`, `rpcRequest`, `rpcResponse`. Also accepts kebab-case aliases: `scheduler-job`, `standalone-plan`, `handoff-v4`, `rpc-request`, `rpc-response`.
- `legacy` - boolean, defaults to `false`. When false, returns JSON Schema Draft 2020-12. When true, returns the legacy agentcli descriptor.

Result:

- `{ "ok": true, "schema_format": "json-schema-draft-2020-12|agentcli-legacy", "schema": <schema-fragment> }`

### `agentcli.describe`

Params:

- `target` - defaults to `"commands"` when omitted. Valid targets: `manifest`, `workflow`, `task`, `targets`, `commands`, `rpc`.

Result:

- `{ "ok": true, "description": <metadata> }`
- for `target: "rpc"`, description contains separate `methods[]` and `notifications[]` arrays

### `agentcli.targets`

Purpose:

- discover compile targets and their declared static capabilities

Result:

- `{ "ok": true, "targets": [{ "name": "...", "description": "...", "capabilities": [...], "features": {...} }] }`

### `agentcli.paths`

Purpose:

- resolve local agentcli home, manifest, output, registry, state, audit, approval, and allowed-signers paths

Result:

- `{ "ok": true, "paths": {...} }`

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
- `allowProofCommand` - boolean, defaults to `false`. Explicitly permits `value_from.command` while locally verifying a proof for a runtime that cannot verify it. Keep false for untrusted manifests.

Result:

- `{ "ok": true, "target": "openclaw-scheduler", "dry_run": <boolean>, "scheduler": { "command": "...", "db_path": "..." }, "capabilities": { "source": "static|runtime", "negotiated": <boolean>, "handoff_version": "...", "schema_version": <integer|null>, "handoff_contract": <object|null> }, "handoff": { "field_version": "1|2|3|4", "projected_fields": <int>, "v02_fields_included": <boolean> }, "job_count": <int>, "actions": [{ "action": "created|updated|adopted", "job_id": "...", "adopted_from_job_id": "...", "name": "...", "invocation_mode": "schedule|trigger", "authorization_proof_verification": { ... } }], "authorization_proof_verifications": [{ ... }], "explain": [...] }`
- `adopted_from_job_id` is present only when `action` is `"adopted"`
- `capabilities` summarizes runtime capability negotiation for the selected scheduler
- `handoff` summarizes which scheduler field version was projected during apply
- `authorization_proof_verification` is present on an action when local proof verification was performed for that compiled execution unit
- `authorization_proof_verifications` is present only when `apply` performed local proof verification because the target backend does not advertise `authorization_proof_verification`
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

### `agentcli.audit`

Params:

- `limit` - optional positive integer

Result:

- `{ "ok": true, "count": <int>, "records": [...], "warnings": [{ "line_number": <int>, "message": "malformed audit record skipped" }] }`

Records are sanitized. Malformed JSONL lines are skipped and surfaced as warnings instead of aborting the read.

### `agentcli.approvals.list`

Params:

- `status` - optional `pending`, `consumed`, `expired`, `revoked`, or `all`
- `workflowId` - optional workflow filter
- `taskId` - optional task filter

Result:

- `{ "ok": true, "count": <int>, "records": [...] }`

### `agentcli.registry.list`

Result:

- `{ "ok": true, "entries": [...] }`

### `agentcli.registry.show`

Params:

- `name` - required registry entry name

Result:

- `{ "ok": true, "name": "...", "manifest": {...} }`

### `agentcli.convert`

*v0.2*

Purpose:

- convert a v0.1 manifest to v0.2 format

Params:

- `manifest` -- a valid v0.1 manifest object

Result:

- `{ "ok": true, "manifest": <converted-v0.2-manifest> }`

The converted manifest preserves all existing fields and adds v0.2 defaults where applicable. The `version` field is updated to `"0.2"`.

### `agentcli.identity.providers`

*v0.2*

Purpose:

- list registered identity providers

Params:

- none

Result:

- `{ "ok": true, "providers": [{ "name": "...", "capabilities": {...} }] }`

### `agentcli.identity.schema`

*v0.2*

Purpose:

- get identity provider metadata and capabilities

Params:

- `provider` -- provider name (string)

Result:

- `{ "ok": true, "provider": "...", "capabilities": {...} }`

### `agentcli.identity.resolve`

*v0.2*

Purpose:

- resolve the effective identity for a manifest and task, applying the three-stage merge (profile, workflow, task)

Params:

- `manifest` -- a valid manifest object
- `taskId` -- the task id to resolve identity for
- `workflowId` -- (optional) the workflow id; required when the manifest contains multiple workflows

Result:

- `{ "ok": true, "declared_identity": {...}, "resolved_identity": {...}, "principal_used": "..." }`

### `agentcli.identity.validateDelegation`

*v0.2*

Purpose:

- validate the delegation chain for a task's identity

Params:

- `manifest` -- a valid manifest object
- `taskId` -- the task id to validate
- `workflowId` -- (optional) the workflow id

Result:

- `{ "ok": true, "delegation": {...} }`

### `agentcli.authorizationProof.methods`

*v0.2*

Purpose:

- list available authorization proof verifier methods

Params:

- none

Result:

- `{ "ok": true, "methods": [{ "name": "...", "capabilities": {...} }] }`

### `agentcli.authorizationProof.schema`

*v0.2*

Purpose:

- get authorization proof verifier metadata

Params:

- `method` -- verifier method name (string)

Result:

- `{ "ok": true, "method": "...", "verifier": "..." }`

### `agentcli.authorizationProof.verify`

*v0.2*

Purpose:

- explicitly verify a task's resolved authorization proof without executing the target command

Params:

- `manifest` -- a valid manifest object
- `taskId` -- task id whose resolved proof is verified
- `workflowId` -- optional workflow id

Result:

- `{ "ok": true, "authorization_proof": {...} }`

This is a live governance inspection, not dry-run. It may resolve `value_from`, execute an explicitly declared proof command, or fetch configured JWKS trust material. It does not resolve identity, spawn the target command, generate evidence, or write an execution audit record.

### `agentcli.authorization.providers`

*v0.2*

Purpose:

- list registered authorization providers (e.g., OPA, Cedar, Topaz)

Params:

- none

Result:

- `{ "ok": true, "providers": [{ "name": "...", "capabilities": {...} }] }`

### `agentcli.authorization.schema`

*v0.2*

Purpose:

- get authorization provider metadata and capabilities

Params:

- `provider` -- provider name (string)

Result:

- `{ "ok": true, "provider": "...", "capabilities": {...} }`

### `agentcli.authorization.evaluate`

*v0.2*

Purpose:

- evaluate authorization for a task given its resolved identity and contract

Params:

- `manifest` -- a valid manifest object
- `taskId` -- the task id to evaluate
- `workflowId` -- (optional) the workflow id

Result:

- `{ "ok": true, "decision": { "allowed": <boolean>, "reason": "..." } }`

### `agentcli.evidence.providers`

*v0.2*

Purpose:

- list registered evidence providers

Params:

- none

Result:

- `{ "ok": true, "providers": [{ "name": "...", "capabilities": {...} }] }`

### `agentcli.evidence.schema`

*v0.2*

Purpose:

- get evidence provider metadata

Params:

- `provider` -- provider name (string)

Result:

- `{ "ok": true, "provider": "...", "methods": ["..."] }`

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

Error responses use this envelope:

```json
{"jsonrpc":"2.0","id":"1","error":{"code":-32602,"message":"...","data":{"code":"invalid_argument","error_type":"invalid_argument"}}}
```

Validation errors add `data.validation`. Internal failures use `-32603` and a generic public message. Application failures use `-32000` with their stable machine-readable code and one of the documented error types.

## Stability

The following are intended to be stable within manifest spec versions `0.1` and `0.2`:

- method names
- request envelope shape
- response envelope shape
- top-level `result.ok` convention

All v0.1 methods remain stable in v0.2. The v0.2 identity, authorization proof, authorization, and evidence methods are additive and do not alter existing method signatures.

Future protocol additions SHOULD be additive.
