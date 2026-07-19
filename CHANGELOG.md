# Changelog

## 0.5.0 (2026-07-18)

- scheduler: added handoff v4 canonical artifacts with explicit artifact,
  canonicalization, execution-binding, and scheduler-binding versions
- discovery: added Draft 2020-12 schema access for the complete handoff v4
  artifact through CLI, JSON-RPC, and the public handoff module
- validation: handoff v4 artifacts now reject missing required identity fields,
  invalid nested types, and unknown properties before semantic verification
- negotiation: v4 now requires scheduler schema 29 or newer plus an exact live
  artifact, canonicalization, digest, and binding contract; partial or
  mismatched runtimes fall back to v3
- negotiation: every apply, including basic v0.1 manifests, probes the live
  runtime so v4 coverage is complete; static fallback enforcement features are
  disabled until explicitly advertised
- scheduler: complete non-lossy create, replace-style update, null clear, and
  adopt projections now carry the immutable artifact payload and digest
- scheduler: adoption rebinds the artifact after the final origin is selected,
  and apply hashes the same merged operational environment passed to the runner
- security: JWT, detached-signature, and certificate proofs bind the exact v4
  artifact, replay identifier, validity, key, and revocation result
- security: v4 proofs reject inverted validity intervals, bind asserted key IDs
  to the key or certificate that actually verified, and require an explicit
  not-revoked result from the runtime checker
- security: credential handoff compiles to exactly one runtime medium without
  persisting values, and delegation binds the exact source run and scope
- evidence: the complete AgentCLI evidence payload and verification envelope
  are available to the scheduler runtime for signed or provider-verified
  terminal evidence
- inspect: added immutable artifacts, runtime events, provider sessions, and
  credential presentations to the scheduler inspection surface
- conformance: added shared positive and negative v4 fixtures and exact digest
  parity tests with OpenClaw Scheduler
- examples: added a public scheduler manifest for exercising negotiated v4
  apply and schema discovery
- compatibility: handoff versions 1 through 3 and manifest versions 0.1 and 0.2
  retain their existing behavior

## 0.4.1 (2026-07-13)

- scheduler: post-success verification for shell tasks now runs from the task working directory while retaining the runtime-provided execution environment, and expanded verifier commands are checked against the scheduler's storage limit before apply
- tests: added quoted-path, runtime-environment, expanded-length, and cross-version integration regressions for scheduler handoff

## 0.4.0 (2026-07-11)

- security: manual approvals now bind the canonical manifest and complete effective execution configuration, enforce `approver_scope` and `timeout_s`, reject unexpected unsigned records, and fail without writing a grant when signing fails
- security: approval checks now run before proof commands, provider calls, sandbox probes, credential materialization, signing, and all other live side effects
- security: `exec --dry-run` is now a static preview that performs no proof, provider, network, sandbox, signing, evidence, verification, or audit side effects
- security: JWT, detached-signature, and certificate authorization proofs require cryptographic verification and canonical manifest binding; `verify.required: false` no longer permits presence-only or claims-only success
- security: evidence uses a complete versioned canonical payload, persists the verification envelope, binds manifest and effective execution metadata, and detects cross-execution transplantation
- security: sandbox, allowed-path, and network restrictions fail closed when unavailable; child processes inherit only a small operational allowlist and require every other ambient variable to be explicitly declared or provider-materialized
- security: identity providers validate configuration before network access, enforce delegation and handoff capabilities, use safer endpoint and file handling, and clean up materialized credentials across failure paths
- validation: v0.2 nested objects reject unknown fields, provider-specific structural validation runs during manifest validation, and the default schema output is JSON Schema Draft 2020-12 with `--legacy` opt-in
- CLI and JSON-RPC: strict flag parsing rejects unknown, duplicate, missing-value, and misplaced flags; RPC responses use stable result/error envelopes and add read-only targets, paths, audit, approvals, and registry discovery methods
- execution: disabled tasks and branches are skipped by `agentcli run`; audit identifiers are collision-resistant and malformed audit lines are skipped with warnings
- conversion and merge: v0.1 conversion maps unverifiable legacy attestations to `method: "none"`; merge preserves same-version semantics and v0.2 profile collections, rejects mixed manifest versions, and detects conflicting profile definitions
- scheduler: live capability values override static fallback values, handoff v3 preserves governed approval and output fields, auto-reject jobs compile disabled, and apply refuses inline `shell.env` or `shell.stdin`
- examples: repaired invalid runtime timeout placement and fail-closed proof and credential-cache declarations; all published JSON examples are validated in the test suite
- maintenance: minimum Node version is now 22.13.0 and CI also tests Node 24 with a pinned `openclaw-scheduler` integration checkout
- dependencies: pinned patched `brace-expansion` and `flatted` releases; `npm audit` reports no known vulnerabilities

## 0.3.2 (2026-04-21)

- fix: `verifyApprovalSignature` now performs a tamper check against the stored `signature.signed_payload`. Previously the canonical payload was rebuilt from the current grant but then discarded; post-sign edits to `approver`, `reason`, `expires_at`, or `task_hash` fields in `approvals.ndjson` would not be detected (the ssh provider only checks signature-against-signed_payload). The rebuilt payload is now compared to `signature.signed_payload` and divergence returns `verified: false` with reason "grant fields do not match signed payload (possible tampering)"
- tests: new tamper-detection test (ssh-signed grant, then mutate `approver`/`reason`/`expires_at` in the stored record and assert each edit fails verification) and new multi-workflow disambiguation tests (grantApproval throws without `--workflow` on multi-workflow manifests, throws on unknown workflow id, and correctly scopes grants per workflow with distinct task hashes)
- docs: clarify that `contract.max_cost_usd` is enforced by runtimes that track cost-attributed operations; declarative-only for shell-target `agentcli exec` (no cost signal to enforce against)
- docs: add recommendation that production-grade isolation on Linux / Windows should run `agentcli exec` inside a container until native OS sandbox adapters ship; manifest declaration remains valid metadata

## 0.3.1 (2026-04-21)

- fix: concurrent `agentcli exec` calls on the same gated task no longer double-consume a single approval. A new `claimApproval` primitive performs find-then-consume atomically under an fs-lockfile at `~/.agentcli/state/approvals.ndjson.lock` (openSync `wx` + `Atomics.wait` backoff); stale locks (older than 30s) are broken; `approval_lock_timeout` is raised after 5s of contention
- `enforceApprovalGate` in `src/exec.js` now calls `claimApproval` instead of the separate `findValidApproval` + `consumeApproval` pair; signature verification still runs after the atomic claim and a bad signature refuses execution (the grant is already consumed and its use is audited)
- `claimApproval` added to the barrel export (`src/index.js`)
- 4 new concurrency tests: worker-thread race (N=8 parallel claims, exactly 1 winner), distinct-grant parallelism, stale-lock recovery, lock-timeout behavior

## 0.3.0 (2026-04-21)

- local approval gate enforcement in `agentcli exec`: tasks with `approval.policy: "manual"` refuse to execute unless a matching, unconsumed, unrevoked, unexpired approval record is present (detailed `code: approval_required`; closed `error_type: validation_error`)
- `approval.policy: "auto-reject"` refuses execution even when an approval record exists (detailed `code: approval_auto_rejected`; closed `error_type: validation_error`)
- approval grants are bound to a canonical task hash over `{workflow_id, task_id, shell.program, shell.args, shell.cwd, identity.ref, approval.policy, approval.risk_level}`; drift in any of those fields invalidates prior approvals
- `--dry-run` bypasses the approval gate (no approval consumed, no gate enforced)
- successful gated executions include `approval_used: {approval_id, approver, reason, risk_level, granted_at, expires_at, signature_verified, signature: {method, key_fingerprint}}` in both the result payload and the audit record
- approvals are single-use, consumed before `spawnSync` (fail-closed: crashed executions still consume the grant)
- new `agentcli approve <manifest> <task-id>` command with `--workflow`, `--by`, `--reason`, `--ttl-s`, `--signer`, `--signing-key` flags; grants ssh-signed by default over canonical approval payload
- new `agentcli approvals list` command with `--status pending|consumed|expired|revoked|all`, `--workflow`, `--task` filters
- new `agentcli approvals revoke <approval-id>` command with `--by` and `--reason` flags
- new `--approval-id <id>` flag on `exec` to target a specific pending grant when more than one matches
- new append-only state file at `~/.agentcli/state/approvals.ndjson` (grant, consume, revoke events); path exposed by `agentcli paths`
- new module `src/approvals.js` exports `grantApproval`, `listApprovals`, `findValidApproval`, `consumeApproval`, `revokeApproval`, `computeTaskApprovalHash`, `approvalPolicyRequiresApproval`, `approvalPolicyAutoRejects`, `verifyApprovalSignature`
- approval signature verification reuses existing ssh allowed-signers chain (`~/.agentcli/state/allowed_signers`); tampered grants are refused with detailed `code: approval_signature_invalid` and closed `error_type: validation_error`
- scope: local single-machine enforcement only; durable multi-actor cron-triggered approvals remain owned by openclaw-scheduler

## 0.2.2 (2026-04-08)

- identity step-up verification for sensitive commands via signed JWT authorization proofs
- actor context module (`buildActorContext`, `buildStepUpContext`) for canonical actor chain metadata
- JWT verifier expanded: JWKS URI fetch with caching, key selection by `kid`/`alg`, issuer and audience validation, `verify.required` enforcement, audit-safe claim extraction
- OPA authorization request now supports `actor` and `step_up` include fields
- evidence payload and attestation now include `actor_context`
- `stripe-identity-step-up.json` example with matching OPA policy and testing guide
- pre-execution failure audit records now include `declared_identity` and `actor_context`
- `auth_profile` field on tasks for scheduler dispatch
- `sfdc-ops.json` example: Salesforce CLI with org status, SOQL queries, metadata, deployment validation, and deploy with approval
- `servicenow-ops.json` example: ServiceNow CLI with incidents, P1 monitoring, change requests, problems, CMDB, and incident creation

## 0.2.1 (2026-04-04)
- `agentcli run` command for local shell-only workflow DAG execution with trigger edges, contains:/regex: conditions, and on_failure handlers evaluated in-process
- `agentcli signing providers` command lists registered signing providers and their attestation methods
- delegation capability warnings surfaced in scheduler dispatch responses (previously silently swallowed)
- neon-ops.json example: neonctl with readonly/admin identity split, branch lifecycle pipeline, operations monitoring
- supabase-ops.json example: Supabase CLI with readonly/deploy split, db-push -> functions-deploy -> health-verify pipeline
- vercel-ops.json example: Vercel CLI with preview -> promote pipeline, approval gates, health verification
- stripe-projects.json expanded with full project lifecycle (init, add services, pull credentials, status check, migrations)
- publish-on-tag CI workflow for automated npm releases
- fix: vercel project rm uses pipe instead of unsupported --yes flag

## 0.2.0

- signing provider abstraction (`src/signing/`) with pluggable provider interface (resolve, sign, verify)
- `--signer` flag for `exec` command to select signing provider (`ssh`, `none`); `AGENTCLI_SIGNER` env var
- `ssh` signing provider extracted from monolithic attestation module into `src/signing/ssh.js`
- `none` signing provider for explicit opt-out (`--signer none`)
- `verify` command dispatches verification to the provider that produced the attestation (by `method` field)
- spec.md distinguishes manifest-time attestation (`identity.attestation`) from execution-time attestation (produced by `exec`)
- `signer` field in exec output and audit records identifies which signing provider was used
- `method` field in verify output identifies the attestation method that was verified
- barrel export includes `registerProvider`, `getProvider`, `listProviders`, `resolveProvider`, `resolveProviderForMethod`
- `registerTarget()` for library consumers to add custom compile targets without forking
- `init` command scaffolds a valid manifest in cwd; `--tool <program>` wraps a specific CLI; `--output` for custom path; warns if tool not on PATH
- `registry list|add|show|remove` commands for managing reusable manifest templates in `~/.agentcli/registry/`
- `import <directory>` discovers `agentcli.json` or `package.json` `"agentcli"` field and adds to registry
- `merge <manifest1> <manifest2>` combines workflows from multiple manifests; rejects duplicate workflow ids
- `output.format` field (`json`, `ndjson`, `text`) on tasks; when `json` or `ndjson`, `exec` parses stdout and includes `result.structured`
- structured parse failures are non-fatal (fall back to null, emit warning)
- audit records include `result.structured_present` boolean (not content) when output.format is active
- barrel export includes `createManifestScaffold`, `writeManifest`, `listRegistry`, `addToRegistry`, `showRegistryEntry`, `removeFromRegistry`, `importManifest`, `mergeManifests`, `registerTarget`
- `identity` block on workflows, tasks, and `on_failure` handlers for chain-of-trust execution (principal, run_as, attestation)
- `contract` block on workflows, tasks, and `on_failure` handlers for execution boundary declarations (sandbox, allowed_paths, network, max_cost_usd, audit)
- identity and contract inherit from workflow to task level, with task-level key-by-key override (same pattern as model_policy)
- `skill-path` CLI command prints the resolved path to the bundled SKILL.md for agent auto-discovery
- `--pretty` flag for colorized JSON output across all commands
- `registry` directory in agentcli home for reusable manifest templates
- `skill_path` and `registry` included in `agentcli paths` output
- standalone compile target declares `identity: true` and `contracts: true` capabilities
- openclaw-scheduler compile target emits `identity_principal`, `identity_run_as`, `identity_attestation`, `contract_sandbox`, `contract_allowed_paths`, `contract_network`, `contract_max_cost_usd`, `contract_audit` fields
- SKILL.md enhanced with discovery instructions, identity/contract guidance, and template registry documentation
- `exec` CLI command executes shell-target tasks directly from a manifest with identity verification, contract enforcement, and audit logging -- works with or without a scheduler runtime
- `audit` CLI command reads the local execution audit log with `--limit` support
- `exec` pre-flight contract enforcement rejects `shell.cwd` outside declared `allowed_paths`
- `exec` advisory warnings for sandbox and network contract constraints not yet enforced at OS level
- `exec` writes append-only NDJSON audit records to `~/.agentcli/state/audit.ndjson` governed by `contract.audit` policy (always, on-failure, none)
- `exec` output includes execution_id (SHA-256 derived), identity resolution, contract, timing, exit code, output hash, and audit status
- `exec` supports `--dry-run` for contract pre-flight without spawning, `--timeout` override, `--workflow` for multi-workflow manifests
- `exec` handles on_failure expanded tasks (e.g. `agentcli exec manifest.json root.failure`)
- `exec` cryptographically signs every execution with the user's SSH key (`ssh-keygen -Y sign`), producing an attestation that ties the execution to the key holder
- `exec` auto-discovers SSH signing keys from `~/.ssh/` (id_ed25519 > id_ecdsa > id_rsa) or explicit `AGENTCLI_SIGNING_KEY` / `--signing-key` path
- `exec --signer none` disables attestation signing when not needed
- `verify` CLI command cryptographically verifies an execution audit record against SSH key signatures using `ssh-keygen -Y verify`
- `verify` auto-generates `allowed_signers` file from `~/.ssh/*.pub` when not present
- attestation payload is canonical deterministic JSON covering execution_id, timestamp, source, command_hash, and principal
- attestation in audit records includes method, key_fingerprint, namespace, signed_payload, and full SSH signature
- `audit` and `allowed_signers` paths added to `agentcli paths` output
- `resolveIdentity` and `resolveContract` exported from compiler/shared.js for library consumers
- barrel export includes `executeTask`, `readAuditLog`, `writeAuditRecord`, `generateExecutionId`, `resolveIdentity`, `resolveContract`
- spec.md documents Identity and Contract sections with inheritance and enforcement semantics
- `identity-contract.json` example manifest demonstrating workflow/task-level identity and contract usage
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
