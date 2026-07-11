# Capabilities

## Purpose

`agentcli` separates the control-plane contract from backend execution details. Capabilities make that split explicit and machine-readable.

## Capability Groups

Control-plane capabilities:

- `schema`
- `describe`
- `validate`
- `compile`
- `apply`
- `json-rpc`

Inspection capabilities:

- `inspect`
- `field-mask`
- `sanitize-basic`
- `ndjson`

Execution-shape capabilities:

- `model-policy`
- `execution-intent`
- `output-hints`
- `timeout-support`
- `context-retrieval`

Runtime capabilities:

- `runtime-execution`
- `durability`
- `retry`
- `approval-gates`
- `delivery`
- `lineage`

## Programmatic Discovery

`agentcli targets` returns structured data for each target with two fields:

- `capabilities`: a string array of active capability identifiers (matching the control-plane and inspection groups above, using dash-delimited names like `field-mask`)
- `features`: a keyed object where each key corresponds to an execution-shape or runtime capability (using underscore-delimited names like `model_policy`, `execution_intent`) and each value describes the support level. Valid values: `"portable"`, `"runtime"`, `"model+thinking"`, `"intent-only"`, `true`, or `false`. The `"model+thinking"` value indicates the target compiles model policy into separate model and thinking fields for the backend. `true` indicates full runtime support; `false` indicates the feature is not supported.

Feature keys include `approvals`, `model_policy`, `execution_intent`, `output_hints`, `timeout_support`, `context_retrieval`, `runtime_execution`, `identity_declaration`, `runtime_identity_resolution`, `trust_evaluation`, `delegation_validation`, `credential_handoff`, `authorization_proof_verification`, `authorization_hook`, `evidence_generation`, `audit_export`, `root_approval_gate`, `approval_scope_enforcement`, and `structured_output_format`.

During scheduler apply, a live runtime value is authoritative for every known feature it reports, including `false`. Static target values are used only when the capability command is unavailable or omits a known key. This prevents a stale optimistic declaration from overriding the runtime's observed behavior.

## Current Target Matrix

### `standalone`

Provides:

- `schema`
- `describe`
- `validate`
- `compile`
- `json-rpc`
- portable `model-policy`
- portable `execution-intent`
- portable `output-hints`
- portable `timeout-support`
- portable `context-retrieval`

Does not provide:

- durable execution
- retries
- delivery
- lineage

Provides in `agentcli exec` (single-machine, non-durable):

- `approval-gates` (local enforcement): refuses execution of tasks whose `approval.policy` is `manual` without a matching, unconsumed, unrevoked, unexpired signed grant in `~/.agentcli/state/approvals.ndjson`; enforces the complete execution binding, approver scope, and timeout; refuses unconditionally when `policy` is `auto-reject`

Interpretation:

- approval fields declared at authoring time are both portable plan metadata AND enforced locally by `agentcli exec` (grants managed via `agentcli approve` and `agentcli approvals`)
- durable multi-actor and cron-triggered approval flows still require a runtime target such as `openclaw-scheduler`
- plan/read-only intent is preserved in the compiled plan
- output hints and budgets are preserved for another backend or consumer
- the standalone artifact hashes or removes raw shell environment, stdin, provider configuration, proof literals or commands, and other credential-bearing material
- `exec --dry-run` is static and marks every live phase skipped

### `openclaw-scheduler`

Provides through compile or inspection:

- `compile`
- `apply`
- `inspect`
- `field-mask`
- `sanitize-basic`
- `ndjson`
- `model-policy`
- `execution-intent`
- `output-hints`
- `timeout-support`
- `context-retrieval`

May be provided by the runtime itself and must be confirmed through capability negotiation:

- `runtime-execution`
- `durability`
- `retry`
- `approval-gates`
- `delivery`
- `lineage`

Interpretation:

- model policy compiles into scheduler model and thinking fields
- plan/read-only intent compiles into runtime execution-boundary fields
- output hints compile into scheduler output preview/offload budgets
- queue, approval, and fan-out budgets compile into runtime guardrails
- handoff version 3 is required to preserve approval risk, approver scope, and output format fields
- root manual approvals require `root_approval_gate`; approver scopes require `approval_scope_enforcement`; output formats require `structured_output_format`
- `auto-reject` jobs compile disabled so an older dispatcher cannot accidentally run them
- inline `shell.env` and `shell.stdin` are rejected because scheduler persistence is not a secret store
- proof, identity, authorization, trust, evidence, and credential-handoff requirements are checked against the effective runtime feature map before apply

## Why This Matters

Adopters should not assume every target is a full runtime, and they should not assume every backend enforces every field the same way.

The value of `agentcli` is that the manifest contract remains stable while target support varies in explicit ways.

That lets:

- lightweight tools implement authoring only
- protocol bridges implement validation and compilation
- runtimes implement execution without owning authoring UX
- operators inspect exactly which features are portable versus runtime-enforced
