# Changelog

## Unreleased

- `version` CLI command (`agentcli version`, `--version`, `-v`) returns package and manifest spec version as structured JSON
- `agentcli.version` JSON-RPC method for agent version discovery
- unknown-key warnings on workflows, tasks, and `on_failure` blocks to catch typos
- validation now rejects non-object values for optional blocks (`model_policy`, `intent`, `output`, `budgets`, `delivery`, `reliability`, `runtime`, `approval`, `context`, `session`)
- CLI `inspect --sanitize` validates the value before dispatching, matching the JSON-RPC path
- JSON-RPC batch requests (arrays) now return a clear error message instead of generic "Invalid Request"
- barrel export (`src/index.js`) now includes `inspectSchedulerState`, `listInspectableEntities`, `describeTarget`, `sanitizeForAgent`, `expandManifestShorthands`, `applyFieldMask`, `parseFieldMask`
- all Node.js built-in imports normalized to `node:` prefix
- eslint `no-unused-vars` tightened from `off` to error with underscore-prefix exceptions
- AGENTS.md includes a discovery flow section for first-time agent integrations
- SECURITY.md links to GitHub Security Advisories for private reporting
- protocol docs note batch request limitation and document `agentcli.version`
- `AGENTCLI_OUTPUT` env var now rejects unknown values instead of silently falling back to json
- CLI error output includes `error_type` field (`validation_error`, `unknown_command`, `invalid_argument`, `parse_error`, `internal_error`) for structured agent error handling
- `approvalPolicyForTask` returns null for `auto`, `timeout_s`, and `risk_level` when no approval block is present (previously defaulted to `reject`/`3600`/`medium`)
- `execution_read_only` and `delete_after_run` emit null instead of `0` when not explicitly set, matching the nullable schema declaration
- `loadJsonInput` wraps JSON parse errors with source context (file path or stdin)
- triggered-task sentinel cron extracted to named constants (`TRIGGERED_SENTINEL_CRON`, `TRIGGERED_SENTINEL_TZ`)
- JSON-RPC `agentcli.apply` `adoptBy` validation now uses the standard `InvalidParamsError` path
- `serveJsonRpc` handles output stream errors gracefully and checks writability before writes
- ndjson mode returns empty output for zero-item result sets (standard ndjson semantics)
- task schema now declares `required: ['cron']` on schedule and `required: ['parent', 'on']` on trigger
- task schema includes a `note` field documenting the schedule/trigger mutual exclusion constraint
- barrel export includes `resolveManifestCandidate` for library consumers
- capabilities doc clarifies the mapping between doc group names and code-level `capabilities`/`features` fields
- removed broken `"./compile"` export path pointing to non-existent `src/compile.js`
- removed undocumented `"./compile/shared"` export that exposed internal compiler infrastructure
- `resolveIntent` preserves `null` for `read_only` when intent block exists but `read_only` is absent (previously `Boolean(undefined)` produced `false`)
- `pickSchema`, `describeTarget`, and `getTarget` errors now carry `code: 'invalid_argument'` for consistent CLI error typing
- `inspectSchedulerState` errors carry `code: 'invalid_argument'` for database-not-found and missing-path cases
- trigger condition validation rejects whitespace-only suffixes after `contains:` and `regex:` prefixes
- non-object `schedule` or `trigger` values now produce a clear type error before the mutual exclusion check
- capabilities doc documents the `"model+thinking"` feature value
- JSON-RPC `agentcli.compile` result now includes `target` field matching CLI output shape
- `agentcli serve` forwards `AGENTCLI_SCHEDULER_PREFIX` and `AGENTCLI_SCHEDULER_BIN` to RPC defaults
- `delivery.mode` schema marked as `nullable: true` to match validation behavior
- `rpcRequest.id` schema accepts `['string', 'number']` per JSON-RPC 2.0 spec
- `standalonePlan` schema includes `capabilities` and `explain` fields matching compiled output
- `rpcResponse.id` schema accepts `['string', 'number']` matching `rpcRequest.id` per JSON-RPC 2.0 spec
- `parseFieldMask` rejects non-string `--fields` values with a clear error instead of crashing with TypeError
- validation now requires `trigger.on` (previously `checkEnum` silently skipped null/absent values)
- `approvalPolicyForTask` returns `null` for `auto` when approval block is present but has no explicit policy (previously defaulted to `'reject'`; `policy: 'manual'` still defaults `auto` to `'reject'`)
- `approvalPolicyForTask` uses `??` instead of `||` for `timeout_s` and `risk_level` to correctly handle falsy-but-valid values
- `loadJsonInput` removes redundant `existsSync(input)` fallback that ignored the caller-provided `cwd`
- JSON-RPC generic error handler uses fallback message when `err.message` is absent
- `standalonePlan` schema `version` field adds `const: '0.2'` matching compiled output
- barrel export includes `loadJsonInput`, `writeJsonOutput`, and `resolveSafeOutputPath` for library consumers
- AGENTS.md documents `--json` flag and `error_type` field in structured error output
- `normalizedTaskPlan` normalizes all `||` operators to `??` for nullable field defaults (`agent_id`, `schedule.tz`, `delivery.mode/channel/to`, `reliability.guarantee/overlap_policy`, `intent.mode`, `output.offload/retrieve`, `context.retrieval/limit`, `session.preferred_key`, `schedulerModel`, `approver_scope`)
- CLI `inspect --limit` validates the flag value before dispatching, matching the JSON-RPC `inspectLimit` path
- non-object `schedule` or `trigger` type errors no longer emit a redundant "must define exactly one" mutual exclusion error
- schema fields validated as tokens (`agent_id`, `model_policy.*`, `delivery.channel/to`, `session.preferred_key`, `approval.approver_scope`, `shell.program`) now carry `format: 'token'` annotation in the machine-readable schema
- capabilities doc documents `approvals` as a feature key and `true`/`false` as valid feature values alongside string levels
- `resolveManifestCandidate` resolves relative paths against the injected `cwd` instead of `process.cwd()`, fixing incorrect resolution for library consumers
- spec.md `on_failure` MAY-define list now includes `id`
- spec.md documents `trigger.delay_s` and `on_failure.delay_s` constraints (integer >= 0)
- protocol.md documents `agentcli.schema` and `agentcli.describe` result envelope shapes
- protocol.md documents `agentcli.apply` `dryRun` default (`false` = live execution)
- AGENTS.md clarifies `--json` scope (all commands except `serve`)
- `approvalPolicyForTask` with `policy: 'manual'` now always compiles `required` to `1` regardless of an explicit `required: false` (policy takes precedence per spec)
- `approvalPolicyForTask` uses `Number(Boolean(...))` for non-manual policies to safely coerce unexpected input types
- `safeLine` in JSON-RPC server wraps `stream.write` in try/catch to handle destroyed streams during mid-write
- protocol.md documents result envelope shapes for `agentcli.validate`, `agentcli.compile`, `agentcli.apply`, and `agentcli.inspect`
- conformance.md Profile C now requires `agentcli.version` and `agentcli.describe`
- spec.md documents synthesized `on_failure` id pattern (`<parent_id>.failure`) and name pattern (`<parent_name> Failure Handler`)
- added subpath exports for `./describe`, `./sanitize`, `./fields`, and `./io` in `package.json`
- protocol.md documents `explain` field in `agentcli.compile` and `agentcli.apply` result envelopes
- CLI usage string documents kebab-case schema name aliases (`scheduler-job`, `standalone-plan`, `rpc-request`, `rpc-response`)
- `parseArgs` in CLI uses `Object.create(null)` for flags to prevent prototype pollution
- `schedulerJob` schema documents SHA-256 derivation in `id` field note
- `standalonePlan` schema includes workflow sub-structure with `tasks` and `edges` fields
- spec.md documents `on_failure` target inference from `shell` presence
- protocol.md lists valid targets for `agentcli.schema` and `agentcli.describe` methods
- protocol.md clarifies `dryRun` semantics: "When `true`, no scheduler writes are executed (preview mode)"
- protocol.md corrects `explain` field location in `agentcli.compile` result (nested inside `output`, not top-level)
- `spawnSchedulerJson` errors in `apply.js` now carry structured `code` properties (`scheduler_error`, `parse_error`) for consistent agent error handling

## 0.1.0

Initial public draft release.

Includes:

- manifest schema and validation
- structured shell execution (`shell.program`, `shell.args`, `shell.env`, `shell.cwd`, `shell.stdin`) instead of raw `command` strings
- standalone compile target
- `openclaw-scheduler` compile target with POSIX shell rendering for `payload_message`
- scheduler inspection with field masks and sanitization
- stdio JSON-RPC
- publication docs for spec, protocol, conformance, capabilities, versioning, and adoption
- schema deduplication with shared field definitions
- `--adopt-by name` for one-time migration of existing scheduler jobs to agentcli management
- `--json` flag for structured JSON output from all commands including help
- TTY detection on stdin to prevent interactive terminal hangs
- `approval.auto` and `approval.approver_scope` documented in spec
- JSON-RPC `agentcli.apply` supports `adoptBy` parameter

Breaking changes from pre-release git snapshots:

- `command` field removed from tasks and `on_failure`; use `shell.program` and `shell.args` instead
- shell targets now reject `payload_kind` values other than `shellCommand`
- shell targets reject `prompt`; non-shell targets reject `shell`
