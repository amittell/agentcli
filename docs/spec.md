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
- `child_credential_policy` (v0.2)

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
- `child_credential_policy` (v0.2)

### Enabled State

`enabled`, if present, MUST be a boolean.

If omitted, implementations SHOULD treat the task as enabled by default.

This field expresses the desired active state when compiled into a runtime that supports dormant or disabled jobs.

The local `run` command MUST NOT execute a task whose effective `enabled` value is `false`. A disabled root, triggered task, or failure handler is reported as skipped, and its dependent branch does not run.

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

A durable compiler or apply adapter MUST NOT persist raw `shell.env` values or `shell.stdin` into a scheduler job record. A backend that cannot resolve these values at dispatch through an explicit credential boundary MUST reject the manifest for that target.

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

Local approval scope accepts an exact principal or the prefixes `principal:`, `user:`, and `domain:`. `principal:` and `user:` require an exact principal match; `domain:` requires the approver's address domain to match case-insensitively.

`approval.required` is supported for compatibility, but `approval.policy` SHOULD be preferred in new manifests.

### Local enforcement in `agentcli exec`

`agentcli exec` enforces `approval.policy` directly, without a scheduler:

- When `approval.policy` is `manual` (or legacy `approval.required: true` with no `policy`), `exec` MUST refuse execution unless a matching, unconsumed, unrevoked, unexpired approval record exists in `~/.agentcli/state/approvals.ndjson`. The detailed code is `approval_required`; the closed error type is `validation_error`.
- When `approval.policy` is `auto-reject`, `exec` MUST refuse execution unconditionally. Approval records cannot override this policy. The detailed code is `approval_auto_rejected`; the closed error type is `validation_error`.
- When `approval.policy` is `auto-approve` or absent, `exec` proceeds without requiring an approval record.
- `exec --dry-run` MUST return a static preview without consuming or enforcing any approval record.

A matching approval record is one whose `task_hash` equals the canonical hash of the complete effective execution binding. The binding includes the canonical manifest digest, workflow and task ids, target and enabled state, hashes of command arguments, declared environment values and stdin, runtime timeout, approval fields, merged identity and provider configuration hashes, contract, authorization proof, authorization, evidence, child credential policy, postcondition, output contract, intent, and deletion policy. Raw credential values MUST NOT be stored in the grant or audit record. Any bound drift invalidates prior grants.

When `approval.approver_scope` is present, the approver MUST satisfy it at grant time and again at consumption. A grant lifetime MUST NOT exceed `approval.timeout_s`.

Approvals are single-use. The matching grant MUST be consumed (written as a `consume` event in `approvals.ndjson`) before the process is spawned; crashed or failed executions still consume the grant.

Successful gated executions MUST include an `approval_used` object in both the result payload and the audit record, carrying `approval_id`, `approver`, `reason`, `risk_level`, `approver_scope`, `granted_at`, `expires_at`, `signature_verified`, and `signature.{method, key_fingerprint}` when signed.

Grants SHOULD be signed. Signing failure MUST refuse grant creation without appending an unsigned record. If a grant carries a `signature` field, `exec` MUST verify it against the configured allowed-signers file. A failing signature MUST refuse execution with detailed code `approval_signature_invalid` and closed error type `validation_error`. A record without a signature MUST be rejected unless it explicitly records that signing was disabled by the caller.

This local mechanism is scoped to single-machine `exec` invocations. Durable multi-actor cron-triggered approvals remain the responsibility of the runtime target (e.g. `openclaw-scheduler`).

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
- `scope` -- a provider-defined scope selector used by scoped identity providers and child handoff flows
- `subject` -- an object describing the subject kind and attributes
- `auth` -- an object describing the authentication mode
- `trust` -- an object describing the trust level
- `presentation` -- an object describing credential presentation bindings

When `ref` is present, the identity is resolved by looking up the named profile from the top-level `identity_profiles` array. Inline fields (`subject`, `auth`, `trust`, `presentation`) override profile-level values key by key.

`identity.scope`, if present, MUST be a non-empty string.

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

## Child Credential Policy

*v0.2*

`child_credential_policy`, if present on a workflow or task, MUST be one of:

- `none`
- `inherit`
- `downscope`
- `independent`

Workflow-level `child_credential_policy` acts as a default for tasks in that workflow.

Task-level `child_credential_policy` overrides the workflow-level value.

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

It MUST define:

- `ref` -- a reference to a named authorization proof profile

It MAY additionally define:

- `claims` -- an object describing expected claims
- `verify` -- an object describing verification requirements

Authorization proof describes the method by which a task proves it is authorized to act. The proof is produced at manifest time or execution time and verified before execution proceeds.

### Methods

Authorization proof supports the following methods:

- `jwt` -- a JSON Web Token carrying signed claims
- `detached-signature` -- a cryptographic signature over the manifest or payload (e.g., SSH signature, PKCS#7)
- `certificate` -- an X.509 or SPIFFE certificate presented as proof of identity
- `none` -- no authorization proof is required

`authorization_proof_profiles[].method`, if present, MUST be one of the above values.

Workflow/task `authorization_proof` blocks are scoped overlays on reusable `authorization_proof_profiles[]` entries. Implementations MUST cryptographically verify every referenced proof whose resolved method is not `none`, regardless of `verify.required`. JWT verification MUST validate a signature with configured public-key or JWKS trust material and require a canonical manifest digest claim. Detached signatures and certificates MUST verify the signature or certificate chain and bind the same canonical manifest. Missing trust material, missing binding, or verification failure MUST prevent execution. `method: "none"` is the explicit representation for an informational or unverifiable declaration.

See [execution-identity.md](execution-identity.md) for full architectural details.

## Authorization Profiles

*v0.2*

`authorization`, if present on a workflow or task, MUST be an object.

It MUST define:

- `ref` -- a reference to a named authorization provider

It MAY additionally define:

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

Implementations SHOULD produce evidence for every execution when `evidence` is declared. The evidence envelope MUST retain a versioned canonical payload sufficient for later independent verification. It MUST bind the canonical manifest, effective task, execution id, audit-safe identity and command descriptors, result, and postcondition. Raw credentials, stdin, stdout, and stderr MUST NOT be embedded. Verification MUST reject an envelope whose payload or execution binding was changed or transplanted to another audit record. Evidence records MUST be included in the audit trail.

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

Contracts are portable intent declarations whose enforcement depends on the selected execution boundary. A backend MUST fail closed when a task requests restrictive sandbox, path, or network controls that the backend cannot enforce. `sandbox: none` and `network: unrestricted` explicitly opt out of those restrictions.

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
- `exec` MUST enforce restrictive `contract.sandbox`, `contract.allowed_paths`, and `contract.network` declarations or refuse execution when no supported local boundary is available.
- `exec` MUST respect `runtime.timeout_ms` as a process execution timeout.
- `exec` MUST record an audit trail governed by `contract.audit`:
  - `always`: write an audit record for every execution
  - `on-failure`: write an audit record only when the exit code is non-zero
  - `none`: do not write an audit record
  - If `contract.audit` is not set, `exec` SHOULD default to `always`
- The audit record MUST include: execution_id, timestamp, source (workflow_id, task_id), audit-safe identity, contract, effective task and manifest digests, command metadata (program, argument hashes, cwd, environment key names and value hashes, stdin presence and hash), and result (exit code, duration, output size, output hash).
- The audit record MUST NOT include raw environment variable values, command arguments, stdin, stdout, stderr, provider secrets, or credential material.
- `exec --dry-run` MUST be a static preview. It MUST NOT consume an approval, execute a proof command, resolve identity or authorization providers, contact network endpoints, probe a sandbox, materialize credentials, sign or verify evidence, run a postcondition, or write an audit record. Live phases MUST be reported as skipped.
- Before spawning, `exec` MUST construct child environments from a small operational allowlist such as PATH, HOME, temporary-directory, locale, shell, user, timezone, terminal, and Windows equivalents. Every other ambient variable MUST be omitted unless the task explicitly declares it or an identity provider materializes it.
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

## Scheduler Handoff Version 4

A scheduler target MAY advertise handoff version 4 only when it implements the
complete protocol below. Partial support MUST fall back to an earlier handoff
version or reject apply. It MUST NOT emit a partial v4 artifact.

### Artifact and canonicalization

The artifact schema is `openclaw.scheduler.handoff-artifact`, artifact schema
version 1, handoff version 4, and minimum scheduler schema 29. Canonicalization
is `json-sort-v1`, canonicalization version 1, using SHA-256. Object keys are
sorted recursively, array order is preserved, undefined values normalize to
JSON null, numbers must be finite, and the artifact digest is the SHA-256 digest
of the UTF-8 canonical JSON.

The artifact uses execution binding version 2 and scheduler job binding version
1. It MUST bind the canonical manifest digest, workflow and task IDs, stable job
ID, effective task hash, command and input hashes, complete persisted scheduler
execution projection, lifecycle, runtime, approval, output, identity, proof,
authorization, evidence, contract, verification, intent, delegation, and
credential-presentation policy.

The artifact MUST NOT contain a raw credential, proof value, stdin value,
environment value, private key, token, password, or provider session secret.
Credential and proof sources are represented by declarative locations and
hashes. A consumer MUST recompute and compare the artifact, scheduler binding,
and effective task digests before execution.

### Persistence and replacement

Artifacts are immutable and content-addressed. Create, update, adoption,
explicit null clearing, migration, inspection, restart, stale-claim recovery,
and crash recovery MUST preserve the exact payload and digest. A replacement
creates a new artifact and retains the old artifact for referenced runtime
history. Pending work bound to a superseded artifact MUST be cancelled or
executed from a complete immutable snapshot; it MUST NOT silently execute the
replacement configuration.

Every v4 dispatch, approval, run, runtime event, provider session, credential
presentation, and evidence record MUST carry the exact artifact digest. Chain
and retry work MUST also carry the exact source run ID and source artifact
digest.

### Runtime gates

The runtime MUST advertise all of these boolean features before AgentCLI emits
v4: `handoff_v4_artifact`, `artifact_bound_proofs`,
`signed_or_provider_verified_evidence`, `provider_session_cache`,
`credential_presentation`, `source_run_bound_delegation`, and
`immutable_runtime_events`. AgentCLI uses the live capability response as
authoritative for every key it reports.

JWT, detached-signature, and certificate proofs MUST cryptographically bind the
artifact digest, proof identity, validity interval, verification key, and a
single-use replay identifier. Required revocation checks MUST run before user
code. Missing, tampered, replayed, transplanted, expired, prematurely valid,
revoked, or unbound proofs fail closed.

Credential release MUST use exactly one negotiated medium: environment,
temporary file, stdin, or a Gateway capability-bound environment header.
Materialization state is recorded before release, values are never persisted,
cleanup is durable and restart-recoverable, and cleanup failure is visible to an
operator.

Delegation MUST bind the concrete source run, validate every grant and actor,
reject cycles, enforce maximum depth and scope, and prevent credential scope
escalation. Selecting a newer run from the same parent job is not equivalent.

Evidence MUST bind the artifact, runtime instance, lineage, identity, proof,
authorization, command result, structured output, postcondition, and terminal
status. A required evidence provider MUST sign or externally verify the
canonical payload. Verification failure MUST remain terminal and MUST NOT be
downgraded to checksum-only evidence.

### Compatibility and conformance

Handoff v4 is additive. Manifest versions 0.1 and 0.2 and scheduler handoff
versions 1 through 3 retain their existing behavior. Producers and consumers
SHOULD publish identical positive and negative conformance vectors. The
reference vectors are packaged under `fixtures/handoff-v4/` in AgentCLI and
OpenClaw Scheduler.

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
