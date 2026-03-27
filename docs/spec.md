# Manifest Spec

## Status

This document defines the `agentcli` manifest draft standard version `0.2`.

Version `0.2` is backward-compatible with `0.1`. All v0.1 manifests remain valid.
New features introduced in v0.2 are noted inline.

Normative language in this document uses:

- MUST
- MUST NOT
- SHOULD
- MAY

## Goals

The manifest format is designed to:

- be generated and consumed as raw JSON
- preserve workflow intent independently from a specific runtime
- support both human operators and agent integrations
- compile cleanly into backend-specific artifacts

## Top-Level Shape

A manifest MUST be a JSON object with:

- `version`
- `workflows`

A manifest MAY also contain:

- `identity_profiles` (v0.2)
- `authorization_proof_profiles` (v0.2)
- `authorization_profiles` (v0.2)
- `evidence_profiles` (v0.2)

`version` MUST equal `0.1` or `0.2`.

`workflows` MUST be a non-empty array.

`identity_profiles`, if present, MUST be an array (see Identity Profiles below).

`authorization_proof_profiles`, if present, MUST be an array (see Authorization Proof Profiles below).

`authorization_profiles`, if present, MUST be an array (see Authorization Profiles below).

`evidence_profiles`, if present, MUST be an array (see Evidence Profiles below).

## Workflow Object

Each workflow MUST contain:

- `id`
- `name`
- `tasks`

Each workflow MAY also define:

- `model_policy`
- `identity`
- `contract`
- `authorization_proof` (v0.2)
- `authorization` (v0.2)
- `evidence` (v0.2)

Rules:

- `id` MUST match `^[A-Za-z0-9][A-Za-z0-9._-]*$`
- `id` MUST be unique within the manifest
- `tasks` MUST be a non-empty array

## Task Object

Each task MUST contain:

- `id`
- `name`
- `target`

Rules:

- `id` MUST be unique within its workflow
- `id` MUST match `^[A-Za-z0-9][A-Za-z0-9._-]*$`
- a task MUST define exactly one of `schedule` or `trigger`

Each task MAY also define:

- `identity` (v0.2, see Identity below)
- `authorization_proof` (v0.2, see Authorization Proof Profiles below)
- `authorization` (v0.2, see Authorization Profiles below)
- `evidence` (v0.2, see Evidence Profiles below)

### Enabled State

`enabled`, if present, MUST be a boolean.

If omitted, implementations SHOULD treat the task as enabled by default.

This field expresses the desired active state when compiled into a runtime that supports dormant or disabled jobs.

### Target

`target.session_target` MUST be one of:

- `main`
- `isolated`
- `shell`

`target.payload_kind` MAY be one of:

- `systemEvent`
- `agentTurn`
- `shellCommand`

If omitted, implementations MAY infer `payload_kind` from `session_target`.

`target.agent_id`, if present, MUST be a restricted token and SHOULD avoid whitespace or shell-significant punctuation.

### Model Policy

`model_policy`, if present, MUST be an object.

It MAY define:

- `provider`
- `model`
- `thinking`

Workflow-level `model_policy` acts as a default for tasks in that workflow.

Task-level `model_policy` overrides workflow-level fields key by key.

### Intent

`intent`, if present, MUST be an object.

`intent.mode`, if present, MUST be one of:

- `execute`
- `plan`

`intent.read_only`, if present, MUST be a boolean.

This block expresses whether a task is allowed to act or should remain planning-only / read-only when compiled into a backend that supports execution boundaries.

### Output

`output`, if present, MUST be an object.

It MAY define:

- `preview_bytes`
- `offload`
- `retrieve`
- `format`

`output.preview_bytes`, if present, MUST be an integer greater than or equal to `64`.

`output.offload`, if present, MUST be one of:

- `auto`
- `always`
- `never`

`output.retrieve`, if present, MUST be one of:

- `inline`
- `on-demand`

`output.format`, if present, MUST be one of:

- `json`
- `ndjson`
- `text`

If omitted, implementations SHOULD treat the output as unstructured text.

When `json`, `exec` SHOULD parse stdout as JSON and include the parsed value in the result as `result.structured`. When `ndjson`, `exec` SHOULD parse each line of stdout as JSON. Parse failures are non-fatal; implementations SHOULD fall back to null and emit a warning.

This block expresses how large outputs should be previewed, whether backends should prefer offloading or inline retention, and the expected output format from the wrapped tool.

### Budgets

`budgets`, if present, MUST be an object.

It MAY define:

- `max_iterations`
- `max_fanout`
- `max_context_items`
- `max_pending_approvals`
- `max_queued_dispatches`

Each of these, if present, MUST be an integer greater than or equal to `1`.

### Prompt or Shell Execution

If `target.session_target` is `shell`, `shell` MUST be present.

`shell` MUST be an object with:

- `program`

It MAY also define:

- `args`
- `env`
- `cwd`
- `stdin`

`shell.program` MUST be a restricted token.

`shell.args`, if present, MUST be an array of non-empty strings.

`shell.env`, if present, MUST be an object whose keys match `^[A-Za-z_][A-Za-z0-9_]*$` and whose values are strings.

`shell.cwd`, if present, MUST be a non-empty string.

`shell.stdin`, if present, MUST be a string.

The legacy `command` string field is not supported. Implementations MUST reject manifests that include `command` and SHOULD direct users to `shell.program` and `shell.args`.

Backend targets that flatten shell execution into a single string (such as `payload_message` in `openclaw-scheduler`) SHOULD render it as a POSIX-safe shell command with single-quoted arguments. The rendered form is intended for machine consumption, not human display.

Otherwise, `prompt` MUST be present.

### Schedule

If present, `schedule` MUST contain:

- `cron`

It MAY also contain:

- `tz`

If `tz` is omitted, implementations SHOULD default to `UTC`.

`schedule` represents a root invocation.

### Trigger

If present, `trigger` MUST contain:

- `parent`
- `on`

It MAY also contain:

- `delay_s`
- `condition`

`trigger.on` MUST be one of:

- `success`
- `failure`
- `complete`

`trigger.delay_s`, if present, MUST be an integer greater than or equal to `0`.

`trigger.parent` MUST reference a different task id within the same workflow. Self-referential triggers are not permitted.

`trigger.condition`, if present, MUST start with exactly one of:

- `contains:`
- `regex:`

For `contains:` conditions, the suffix MUST be a non-empty string.

For `regex:` conditions, the suffix MUST be a valid regular expression.

### Failure Shortcut

`on_failure`, if present, MUST be an object.

It is a control-plane shorthand for synthesizing a triggered child task with:

- `trigger.parent` = the enclosing task id
- `trigger.on` = `failure`

`on_failure.id`, if present, MUST be unique within the workflow after shorthand expansion.

If `on_failure.id` is omitted, implementations SHOULD synthesize `<parent_task_id>.failure`.

If `on_failure.name` is omitted, implementations SHOULD synthesize `<parent_task_name> Failure Handler`.

`on_failure` MAY define:

- `id`
- `name`
- `enabled`
- `prompt` or `shell`
- `target`
- `delay_s`
- `condition`
- `delivery`
- `reliability`
- `runtime`
- `model_policy`
- `intent`
- `output`
- `budgets`
- `approval`
- `context`
- `session`
- `identity`
- `contract`
- `delete_after_run`

`on_failure.delay_s`, if present, MUST be an integer greater than or equal to `0`.

If `on_failure.target` is omitted, the session target is inferred: `shell` when `on_failure.shell` is present, `isolated` otherwise. The `agent_id` is inherited from the parent task's target when not explicitly set.

If the inferred or explicit `session_target` is `shell`, `on_failure.shell` MUST be present.

Otherwise, `on_failure.prompt` MUST be present.

## Delivery

`delivery.mode`, if present, MUST be one of:

- `announce`
- `announce-always`
- `none`

`delivery.channel` and `delivery.to`, if present, MUST be restricted tokens.

## Reliability

`reliability.guarantee`, if present, MUST be one of:

- `at-most-once`
- `at-least-once`

`reliability.overlap_policy`, if present, MUST be one of:

- `skip`
- `allow`
- `queue`

`reliability.max_retries`, if present, MUST be an integer greater than or equal to `0`.

## Runtime

`runtime.timeout_ms`, if present, MUST be an integer greater than or equal to `1`.

This field is intended for backend execution controls like per-task run timeouts. Control-plane implementations SHOULD preserve it across compile targets even when a given backend ignores it.

## Approval

`approval` is backend-portable intent, not a guarantee that every backend exposes the same gate semantics.

`approval.policy`, if present, MUST be one of:

- `manual`
- `auto-approve`
- `auto-reject`

`approval.risk_level`, if present, MUST be one of:

- `low`
- `medium`
- `high`

`approval.timeout_s`, if present, MUST be an integer greater than or equal to `1`.

`approval.auto`, if present, MUST be one of:

- `approve`
- `reject`

This field provides a direct override for the auto-resolution behavior when an approval gate times out. When `policy` is `auto-approve` or `auto-reject`, the corresponding `auto` value is implied. Explicit `auto` takes precedence over inference from `policy`.

`approval.approver_scope`, if present, MUST be a restricted token identifying the scope or group that may approve the gate.

`approval.required` is supported for compatibility, but `approval.policy` SHOULD be preferred in new manifests.

## Context

`context.retrieval`, if present, MUST be one of:

- `none`
- `recent`
- `hybrid`

`context.limit`, if present, MUST be an integer greater than or equal to `1`.

If both `context.limit` and `budgets.max_context_items` are present, implementations SHOULD prefer `context.limit`.

## Session

`session.preferred_key`, if present, MUST be a restricted token.

## Identity

`identity`, if present, MUST be an object.

It MAY define:

- `principal`
- `run_as`
- `attestation`

`identity.principal`, if present, MUST be a restricted token identifying the authorizing user or service.

`identity.run_as`, if present, MUST be a restricted token identifying the runtime identity the agent should assume.

`identity.attestation`, if present, MUST be a non-empty string carrying proof of authorization (such as a signed token or certificate reference). This is a **manifest-time attestation**: a pre-existing proof baked into the manifest declaring that the principal is authorized to define this workflow. Examples include a CI-issued JWT, a signed deployment token, or a certificate reference.

Manifest-time attestation is distinct from **execution-time attestation**, which is produced by `exec` at runtime (see Cryptographic Attestation below). The two serve complementary roles:

- Manifest-time: "this manifest was authorized by principal X" (static, embedded in the manifest)
- Execution-time: "this specific execution was performed by person Y at time T" (dynamic, recorded in the audit log)

Workflow-level `identity` acts as a default for tasks in that workflow.

Task-level `identity` overrides workflow-level fields key by key.

This block establishes the chain of trust: agents executing CLI tasks carry the declared principal's authorization, and backends MAY enforce that the `run_as` identity is permitted for the given principal.

### v0.2 Identity Fields

In v0.2, `identity` MAY additionally define:

- `ref` -- a reference to a named identity profile (see Identity Profiles below)
- `subject` -- an object describing the subject kind and attributes
- `auth` -- an object describing the authentication mode
- `trust` -- an object describing the trust level
- `presentation` -- an object describing credential presentation bindings

When `ref` is present, the identity is resolved by looking up the named profile from the top-level `identity_profiles` array. Inline fields (`subject`, `auth`, `trust`, `presentation`) override profile-level values key by key.

`identity.subject.kind`, if present, MUST be one of:

- `agent`
- `service`
- `workload`
- `user`
- `composite`
- `delegated-agent`
- `unknown`

`identity.auth.mode`, if present, MUST be one of:

- `none`
- `service`
- `delegated`
- `on-behalf-of`
- `impersonation`
- `exchange`

`identity.trust.level`, if present, MUST be one of:

- `untrusted`
- `restricted`
- `supervised`
- `autonomous`

`identity.presentation`, if present, MUST be an object. It MAY define:

- `bindings` -- an array of objects describing how credentials are presented to tools (e.g., environment variable injection, header injection)
- `handoff` -- how identity context is transferred across task boundaries; if present, MUST be one of `none`, `downscope`, `transaction-token`
- `cleanup` -- when credential cleanup runs; if present, MUST be one of `always`, `on-success`, `on-failure`, `never`
- `default_redaction` -- if present, MUST be a boolean indicating whether credential values are redacted by default in audit output

Workflow-level v0.2 identity fields act as defaults for tasks in that workflow. Task-level fields override workflow-level fields key by key.

## Identity Profiles

*v0.2*

`identity_profiles`, if present, MUST be a top-level array of identity profile objects.

Each identity profile MUST contain:

- `id` -- a unique identifier within the manifest

Each identity profile MAY contain:

- `provider` -- the identity provider name (e.g., `ssh`, `oidc-client-credentials`, `spiffe`)
- `subject` -- an object with `kind` and provider-specific attributes
- `auth` -- an object with `mode` and provider-specific configuration
- `trust` -- an object with `level`
- `presentation` -- an object with `bindings`, `handoff`, `cleanup`, and `default_redaction`

`subject.kind` MUST be one of: `agent`, `service`, `workload`, `user`, `composite`, `delegated-agent`, `unknown`.

`auth.mode` MUST be one of: `none`, `service`, `delegated`, `on-behalf-of`, `impersonation`, `exchange`.

`trust.level` MUST be one of: `untrusted`, `restricted`, `supervised`, `autonomous`.

Identity profiles are referenced from workflow-level or task-level `identity.ref` fields. Profiles provide reusable identity declarations that avoid repetition across workflows and tasks.

See [execution-identity.md](execution-identity.md) for full architectural details.

## Authorization Proof Profiles

*v0.2*

`authorization_proof`, if present on a workflow or task, MUST be an object.

It MAY define:

- `ref` -- a reference to a named authorization proof profile
- `claims` -- an object describing expected claims
- `verify` -- an object describing verification requirements

Authorization proof describes the method by which a task proves it is authorized to act. The proof is produced at manifest time or execution time and verified before execution proceeds.

### Methods

Authorization proof supports the following methods:

- `jwt` -- a JSON Web Token carrying signed claims
- `detached-signature` -- a cryptographic signature over the manifest or payload (e.g., SSH signature, PKCS#7)
- `certificate` -- an X.509 or SPIFFE certificate presented as proof of identity
- `none` -- no authorization proof is required

`authorization_proof.verify.method`, if present, MUST be one of the above values.

Implementations MUST verify the proof before executing a task when `verify` is present and `method` is not `none`. Verification failure MUST prevent execution.

See [execution-identity.md](execution-identity.md) for full architectural details.

## Authorization Profiles

*v0.2*

`authorization`, if present on a workflow or task, MUST be an object.

It MAY define:

- `ref` -- a reference to a named authorization provider
- `provider_config` -- provider-specific configuration (e.g., OPA endpoint, Cedar policy store)
- `on_error` -- behavior when the authorization provider is unreachable; MUST be one of `deny`, `warn`
- `request` -- an object describing the authorization request shape
- `decision` -- an object describing the normalized decision output

Authorization profiles integrate with external policy engines (such as OPA, Cedar, or Topaz) to evaluate whether a resolved identity is permitted to execute a given task.

Implementations MUST normalize the provider response into a decision object containing at minimum:

- `allowed` -- boolean
- `reason` -- human-readable explanation

When `on_error` is omitted, implementations MUST default to `deny`.

See [execution-identity.md](execution-identity.md) for full architectural details.

## Evidence Profiles

*v0.2*

`evidence`, if present on a workflow or task, MUST be an object.

It MAY define:

- `ref` -- a reference to a named evidence provider
- `payload` -- an object describing the evidence payload and its binding to the execution
- `verify` -- an object describing verification requirements

Evidence profiles describe how execution evidence is produced, bound to a specific execution, and made verifiable after the fact. Evidence is the execution-time counterpart to authorization proof.

`evidence.payload`, if present, MUST be an object. It MAY define:

- `binding` -- how the evidence is bound to the execution context (e.g., `execution_id`, `command_hash`)
- `context` -- additional context included in the evidence record

`evidence.verify`, if present, MUST be an object describing how the evidence can be independently verified.

Implementations SHOULD produce evidence for every execution when `evidence` is declared. Evidence records MUST be included in the audit trail.

See [execution-identity.md](execution-identity.md) for full architectural details.

## Contract Extensions

*v0.2*

In addition to the v0.1 contract fields, `contract` MAY define:

- `required_trust_level` -- the minimum trust level required for task execution; MUST be one of `untrusted`, `restricted`, `supervised`, `autonomous`
- `trust_enforcement` -- how trust level mismatches are handled; MUST be one of `none`, `advisory`, `strict`

When `required_trust_level` is present and `trust_enforcement` is `strict`, implementations MUST reject execution if the resolved identity's trust level is below the required level. The trust ordering from lowest to highest is: `untrusted` < `restricted` < `supervised` < `autonomous`.

When `trust_enforcement` is `advisory`, implementations MUST emit a warning but SHOULD proceed with execution.

When `trust_enforcement` is `none` (the default), the field is recorded for audit only and trust mismatches do not affect execution.

## Resolution Semantics

*v0.2*

Identity, authorization proof, authorization, and evidence are resolved through a three-stage merge:

1. **Profile resolution** -- if `ref` is present, the named profile is loaded from the top-level `identity_profiles` (or equivalent provider registry).
2. **Workflow-level defaults** -- workflow-level declarations act as defaults.
3. **Task-level overrides** -- task-level declarations override workflow-level fields key by key.

At each stage, explicit fields take precedence over inherited fields. The `ref` field is resolved first, then inline fields override the resolved profile values.

This merge order ensures that shared configuration is declared once at the profile or workflow level while individual tasks retain full control when needed.

## Contract

`contract`, if present, MUST be an object.

It MAY define:

- `sandbox`
- `allowed_paths`
- `network`
- `max_cost_usd`
- `audit`

`contract.sandbox`, if present, MUST be one of:

- `none`
- `permissive`
- `strict`

`contract.allowed_paths`, if present, MUST be an array of non-empty strings representing filesystem paths the execution may access.

`contract.network`, if present, MUST be one of:

- `unrestricted`
- `restricted`
- `none`

`contract.max_cost_usd`, if present, MUST be a number greater than or equal to `0`.

`contract.audit`, if present, MUST be one of:

- `none`
- `on-failure`
- `always`

Workflow-level `contract` acts as a default for tasks in that workflow.

Task-level `contract` overrides workflow-level fields key by key.

Contracts are intent declarations. Backends interpret and enforce them according to their own capabilities. A backend that does not support sandboxing MAY ignore `sandbox` but SHOULD log a warning.

## Delete After Run

`delete_after_run`, if present, MUST be a boolean.

When true, the compiled job is removed from the scheduler after its first successful execution. This field applies to both top-level tasks and `on_failure` handlers.

## Definitions

A **restricted token** is a string matching the pattern `^[A-Za-z0-9@:_./-]+$`. This covers file paths, model identifiers, agent IDs, delivery channels, and session keys without allowing shell metacharacters or control characters.

## Validation and Warnings

Implementations MUST reject invalid manifests.

Implementations MAY emit warnings for:

- approval settings that compile ambiguously for some backends
- approval gates on root scheduled tasks
- backend-specific behavior shims
- planning/read-only intent on targets that only support advisory enforcement
- conflicting context budgets

## Direct Execution

A conforming implementation MAY support direct task execution via an `exec` command. When supported:

- `exec` MUST only execute tasks with `target.session_target` equal to `shell`. Prompt-based tasks require an agent runtime and are not executable by agentcli directly.
- `exec` MUST resolve identity and contract by inheriting from the workflow level, with task-level fields overriding key by key.
- `exec` MUST perform pre-flight contract checks before spawning a process. If `contract.allowed_paths` is declared and the effective execution cwd (`shell.cwd` when set, otherwise the caller cwd) is not under any allowed path, `exec` MUST reject the execution with a contract violation error.
- `exec` SHOULD enforce `contract.sandbox` and `contract.network` when a supported local sandbox backend is available.
- `exec` SHOULD emit advisory warnings for contract constraints it cannot enforce on the current machine (for example, `sandbox: strict` or `network: none` on an unsupported OS).
- `exec` MUST respect `runtime.timeout_ms` as a process execution timeout.
- `exec` MUST record an audit trail governed by `contract.audit`:
  - `always`: write an audit record for every execution
  - `on-failure`: write an audit record only when the exit code is non-zero
  - `none`: do not write an audit record
  - If `contract.audit` is not set, `exec` SHOULD default to `always`
- The audit record MUST include: execution_id, timestamp, source (workflow_id, task_id), identity (principal, run_as, attestation presence), contract, command metadata (program, args, cwd, env key names, stdin presence), and result (exit code, duration, output size, output hash).
- The audit record MUST NOT include environment variable values or stdin content, as these may contain secrets.
- `exec` supports `--dry-run` to perform validation and contract checks without spawning a process.
- `exec` works independently of any scheduler runtime. It reads a manifest, resolves a task, and executes it directly.

### Execution-Time Attestation

`exec` SHOULD cryptographically sign each execution to produce an execution-time attestation. This is distinct from the manifest-time `identity.attestation` field (see Identity above).

#### Signing Provider Abstraction

`exec` uses a pluggable signing provider to produce attestations. The provider is resolved in order of precedence:

1. `--signer <name>` flag
2. `AGENTCLI_SIGNER` environment variable
3. Default: `ssh`

A conforming implementation MUST support at least:

- `ssh` -- signs with the user's SSH key via `ssh-keygen -Y sign`
- `none` -- explicitly disables signing

Implementations MAY support additional providers (e.g. `oidc`, `x509`, `kms`) that implement the same interface: resolve credentials, sign a canonical payload, and verify an attestation record.

#### Attestation Payload

The canonical attestation payload is deterministic JSON (sorted keys) containing: version, execution_id, timestamp, source, command_hash, and principal.

The `command_hash` is a SHA-256 hash of the program name, arguments, and working directory. It MUST NOT include environment variable values or stdin content.

#### SSH Provider

The built-in `ssh` provider:

1. Builds the canonical attestation payload.
2. Signs the payload with `ssh-keygen -Y sign -f <key> -n agentcli`.
3. Stores the signature, key fingerprint, namespace, and signed payload in the audit record.

The signing key is resolved in order of precedence:

1. `--signing-key <path>` flag
2. `AGENTCLI_SIGNING_KEY` environment variable
3. Auto-discovery from `~/.ssh/` (id_ed25519, then id_ecdsa, then id_rsa)

If no signing key is available or signing fails (e.g. passphrased key not loaded in ssh-agent), `exec` MUST proceed without attestation and record the reason.

Verification uses `ssh-keygen -Y verify` against an `allowed_signers` file mapping principals to public keys. The `verify` command auto-generates this file from `~/.ssh/*.pub` when not present.

#### Verification Dispatch

The `verify` command resolves the signing provider from the `method` field in the attestation record (e.g. `ssh-signature` dispatches to the `ssh` provider). This allows each provider to implement its own verification logic.

#### What Attestation Proves

- **Who**: the holder of the signing credential authorized this execution
- **What**: the exact command (via command_hash)
- **When**: the timestamp (included in signed payload)
- **Integrity**: the audit record has not been tampered with

This enables agents to inherit the user's identity with cryptographic proof, allowing downstream systems to verify that a specific human authorized a specific execution.

#### Chain of Custody

The `exec` command establishes the chain of custody: the audit log records who authorized the execution (identity), what constraints were declared (contract), what was executed (command), and what happened (result). The attestation makes this chain cryptographically verifiable.

The two attestation layers work together:
- Manifest-time (`identity.attestation`): proves the manifest was authorized
- Execution-time (audit record): proves each run was performed by a specific identity

## Compiler Targets

This spec does not require a single runtime.

A conforming control-plane implementation MUST support:

- schema access
- manifest validation
- at least one compile target

A target adapter MAY add backend-specific constraints, but MUST NOT silently reinterpret the meaning of `schedule`, `trigger`, or task ordering.

Custom compile targets MAY be registered via the library API using `registerTarget()`. A target MUST provide a `name` and a `compile(manifest, options)` function. The target registry rejects duplicate names.

## Tool Integration

### Manifest Scaffolding

`init` creates a valid manifest in the current directory. When `--tool <program>` is specified, the generated manifest wraps that program as a shell target. Implementations SHOULD check whether the tool exists on PATH and emit a warning if not found.

### Self-Description Convention

Tools MAY ship an `agentcli.json` manifest in their root directory. Alternatively, tools distributed as npm packages MAY declare an `"agentcli"` field in `package.json` pointing to the manifest path relative to the package root.

The `import` command discovers manifests from a directory using this convention, validates them, and adds them to the local registry.

### Registry

The registry (`~/.agentcli/registry/`) stores reusable manifest templates as named JSON files. The `registry` command supports:

- `list` -- enumerate templates with workflow summaries
- `add <path>` -- validate and store a manifest
- `show <name>` -- retrieve a stored manifest
- `remove <name>` -- delete a template

### Manifest Composition

The `merge` command combines workflows from multiple manifests into a single manifest. Workflow ids MUST be unique across all input manifests. The merged result MUST pass validation.
