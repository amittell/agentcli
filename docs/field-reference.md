# Manifest Field Reference

Complete reference for every field in an agentcli manifest (v0.2).

This document is derived from `src/schema.js` (ground truth) and `src/validate.js` (enforced
constraints). When in doubt, the source code is authoritative.

## Conventions

- **Required** means the validator rejects manifests missing this field.
- **Restricted token** means the value must match `/^[A-Za-z0-9@:_./-]+$/`.
- **Identifier** means the value must match `/^[A-Za-z0-9][A-Za-z0-9._-]*$/`.
- Fields marked **(v0.2)** were introduced in version 0.2. All v0.1 manifests remain valid.
- Nullable fields may be omitted entirely.

---

## Top-Level Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | Yes | Manifest spec version. Must be `"0.1"` or `"0.2"`. |
| `workflows` | array | Yes | Non-empty array of workflow objects. |
| `identity_profiles` | array | No | Reusable identity profile definitions (v0.2). |
| `authorization_proof_profiles` | array | No | Reusable authorization proof definitions (v0.2). |
| `authorization_profiles` | array | No | Reusable authorization provider definitions (v0.2). |
| `evidence_profiles` | array | No | Reusable evidence profile definitions (v0.2). |

---

## Workflow Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier within the manifest. Must be an identifier. |
| `name` | string | Yes | Human-readable workflow name. |
| `tasks` | array | Yes | Non-empty array of task objects. |
| `model_policy` | object | No | Default model policy for tasks in this workflow. See [Model Policy Fields](#model-policy-fields). |
| `identity` | object | No | Workflow-level identity declaration (v0.2 shape). See [Identity Fields (v0.2)](#identity-fields-v02). |
| `contract` | object | No | Workflow-level contract. See [Contract Fields](#contract-fields). |
| `authorization_proof` | object | No | Authorization proof reference (v0.2). See [Authorization Proof Reference Fields](#authorization-proof-reference-fields). |
| `authorization` | object | No | Authorization reference (v0.2). See [Authorization Reference Fields](#authorization-reference-fields). |
| `evidence` | object | No | Evidence reference (v0.2). See [Evidence Reference Fields](#evidence-reference-fields). |
| `child_credential_policy` | string | No | Child credential flow policy for triggered children. See [Child Credential Policy Fields](#child-credential-policy-fields). |
| `verify` | object | No | Post-success verification command. See [Task Verify Fields](#task-verify-fields). |

---

## Task Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique within the workflow. Must be an identifier. |
| `name` | string | Yes | Human-readable task name. |
| `target` | object | Yes | Execution target. See [Target Fields](#target-fields). |
| `enabled` | boolean | No | Whether the task is active. Default: `true`. |
| `prompt` | string | Conditional | Agent prompt text. Required when `target.session_target` is not `shell`. Must not be present for shell targets. |
| `shell` | object | Conditional | Shell execution block. Required when `target.session_target` is `shell`. Must not be present otherwise. See [Shell Fields](#shell-fields). |
| `command` | string | No | **Removed.** Rejected by the validator. Use `shell.program` and `shell.args` instead. |
| `schedule` | object | Conditional | Cron schedule. Exactly one of `schedule` or `trigger` must be present. See [Schedule Fields](#schedule-fields). |
| `trigger` | object | Conditional | Trigger from another task. Exactly one of `schedule` or `trigger` must be present. See [Trigger Fields](#trigger-fields). |
| `model_policy` | object | No | Task-level model policy (overrides workflow). See [Model Policy Fields](#model-policy-fields). |
| `intent` | object | No | Execution intent. See [Intent Fields](#intent-fields). |
| `output` | object | No | Output handling hints. See [Output Fields](#output-fields). |
| `budgets` | object | No | Resource budgets. See [Budgets Fields](#budgets-fields). |
| `delivery` | object | No | Notification delivery. See [Delivery Fields](#delivery-fields). |
| `reliability` | object | No | Reliability guarantees. See [Reliability Fields](#reliability-fields). |
| `runtime` | object | No | Runtime settings. See [Runtime Fields](#runtime-fields). |
| `approval` | object | No | Approval gate. See [Approval Fields](#approval-fields). |
| `context` | object | No | Context retrieval. See [Context Fields](#context-fields). |
| `session` | object | No | Session preferences. See [Session Fields](#session-fields). |
| `identity` | object | No | Task-level identity (v0.2 shape, overrides workflow). See [Identity Fields (v0.2)](#identity-fields-v02). |
| `contract` | object | No | Task-level contract (overrides workflow). See [Contract Fields](#contract-fields). |
| `authorization_proof` | object | No | Authorization proof reference (v0.2). See [Authorization Proof Reference Fields](#authorization-proof-reference-fields). |
| `authorization` | object | No | Authorization reference (v0.2). See [Authorization Reference Fields](#authorization-reference-fields). |
| `evidence` | object | No | Evidence reference (v0.2). See [Evidence Reference Fields](#evidence-reference-fields). |
| `child_credential_policy` | string | No | Child credential flow policy for triggered children. See [Child Credential Policy Fields](#child-credential-policy-fields). |
| `verify` | object | No | Post-success verification command. See [Task Verify Fields](#task-verify-fields). |
| `on_failure` | object | No | Failure handler shorthand. See [On-Failure Fields](#on-failure-fields). |
| `delete_after_run` | boolean | No | Remove the compiled job after first successful execution. |

---

## Target Fields

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `session_target` | string | Yes | `main`, `isolated`, `shell` | Where the task executes. |
| `agent_id` | string (token) | No | -- | Agent identifier. Restricted token. |
| `payload_kind` | string | No | `systemEvent`, `agentTurn`, `shellCommand` | Payload type hint. Inferred from `session_target` when omitted. Must be `shellCommand` when `session_target` is `shell`. |

---

## Shell Fields

Required when `target.session_target` is `shell`.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `program` | string (token) | Yes | Executable name or path. Must be a restricted token. |
| `args` | array of strings | No | Command-line arguments. Each element must be a non-empty string. |
| `env` | object | No | Environment variables. Keys must match `/^[A-Za-z_][A-Za-z0-9_]*$/`. Values must be strings. |
| `cwd` | string | No | Working directory for the process. |
| `stdin` | string | No | Standard input content. May be an empty string. |

---

## Schedule Fields

Mutually exclusive with `trigger`. Represents a root (cron-scheduled) invocation.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `cron` | string | Yes | Cron expression. |
| `tz` | string | No | IANA timezone. Defaults to `UTC` when omitted. |

---

## Trigger Fields

Mutually exclusive with `schedule`. Represents a task triggered by another task's outcome.

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `parent` | string | Yes | -- | Task id of the parent task within the same workflow. Must not reference itself. |
| `on` | string | Yes | `success`, `failure`, `complete` | Which parent outcome fires the trigger. |
| `delay_s` | integer | No | >= 0 | Delay in seconds before the triggered task starts. |
| `condition` | string | No | -- | Output-matching condition. Must start with `contains:` or `regex:`. Suffix must be non-empty (and valid regex for `regex:`). |

---

## Model Policy Fields

Workflow-level `model_policy` acts as a default for tasks. Task-level overrides key by key.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `provider` | string (token) | No | Model provider identifier. Restricted token. |
| `model` | string (token) | No | Model identifier. Restricted token. |
| `thinking` | string (token) | No | Thinking mode identifier. Restricted token. |

---

## Intent Fields

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `mode` | string | No | `execute`, `plan` | Whether the task should act or remain in planning mode. |
| `read_only` | boolean | No | -- | Whether the task is restricted to read-only operations. |

---

## Output Fields

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `preview_bytes` | integer | No | >= 64 | Maximum bytes for output preview. |
| `offload` | string | No | `auto`, `always`, `never` | Whether large outputs should be offloaded. |
| `retrieve` | string | No | `inline`, `on-demand` | How output is made available. |
| `format` | string | No | `json`, `ndjson`, `text` | Expected output format. When `json` or `ndjson`, exec parses stdout and includes structured result. |

---

## Budgets Fields

All budget fields, when present, must be integers >= 1.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `max_iterations` | integer | No | Maximum iteration count. |
| `max_fanout` | integer | No | Maximum trigger fan-out. |
| `max_context_items` | integer | No | Maximum context items. Superseded by `context.limit` when both are set. |
| `max_pending_approvals` | integer | No | Maximum pending approvals. |
| `max_queued_dispatches` | integer | No | Maximum queued dispatches. |

---

## Delivery Fields

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `mode` | string | No | `announce`, `announce-always`, `none` | Notification delivery mode. |
| `channel` | string (token) | No | -- | Delivery channel identifier. Restricted token. |
| `to` | string (token) | Conditional | -- | Delivery recipient. Restricted token. Required when `mode` is `announce` or `announce-always`. |

---

## Reliability Fields

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `guarantee` | string | No | `at-most-once`, `at-least-once` | Delivery guarantee. |
| `max_retries` | integer | No | >= 0 | Maximum retry count. |
| `overlap_policy` | string | No | `skip`, `allow`, `queue` | Behavior when a run overlaps with a previous invocation. |

---

## Runtime Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `timeout_ms` | integer | No | Process execution timeout in milliseconds. Must be >= 1. |

---

## Approval Fields

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `required` | boolean | No | -- | Whether approval is required. Superseded by `policy` when both are present. |
| `policy` | string | No | `manual`, `auto-approve`, `auto-reject` | Approval gate policy. Takes precedence over `required`. |
| `risk_level` | string | No | `low`, `medium`, `high` | Risk classification. |
| `approver_scope` | string (token) | No | -- | Scope or group that may approve. Restricted token. |
| `timeout_s` | integer | No | >= 1 | Approval timeout in seconds. |
| `auto` | string | No | `approve`, `reject` | Direct override for auto-resolution on timeout. Explicit value takes precedence over inference from `policy`. |

---

## Context Fields

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `retrieval` | string | No | `none`, `recent`, `hybrid` | Context retrieval strategy. |
| `limit` | integer | No | >= 1 | Maximum context items to retrieve. Takes precedence over `budgets.max_context_items`. |

---

## Session Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `preferred_key` | string (token) | No | Session key hint. Restricted token. |

---

## Identity Fields (v0.1)

The v0.1 identity shape uses flat fields. Used when none of `ref`, `subject`, `auth`, `trust`, or `presentation` are present.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `principal` | string (token) | No | Authorizing user or service. Restricted token. |
| `run_as` | string (token) | No | Runtime identity the agent should assume. Restricted token. |
| `attestation` | string | No | Manifest-time authorization proof (e.g., signed token or certificate reference). |

Workflow-level identity acts as a default for tasks. Task-level overrides key by key.

---

## Identity Fields (v0.2)

The v0.2 identity shape is used when any of `ref`, `scope`, `subject`, `auth`, `trust`, or `presentation` are present.

### Top-Level

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ref` | string | No | Reference to a named identity profile from `identity_profiles`. |
| `scope` | string | No | Provider-defined scope selector (for example `full`, `payments`, or `readonly`). |
| `subject` | object | No | Subject descriptor. See [subject](#identity-subject-fields). |
| `auth` | object | No | Authentication configuration. See [auth](#identity-auth-fields). |
| `trust` | object | No | Trust level declaration. See [trust](#identity-trust-fields). |
| `presentation` | object | No | Credential presentation bindings. See [presentation](#identity-presentation-fields). |

When `ref` is present, the referenced profile is loaded first, then inline fields override the profile values key by key.

`scope` resolves from workflow to task the same way as the other inline identity fields.

---

## Child Credential Policy Fields

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `child_credential_policy` | string | No | `none`, `inherit`, `downscope`, `independent` | Controls how a child task receives or derives credentials relative to its parent. Workflow-level values act as defaults for tasks. |

`child_credential_policy: "downscope"` is validated as a capability warning when a backend lacks `credential_handoff`: the scheduler can still persist the job, but child narrowing will not be enforceable at dispatch. This is intentionally softer than `identity.presentation.handoff != "none"`, which is a hard compatibility requirement because the active runtime/backend must advertise explicit handoff semantics up front.

---

## Task Verify Fields

Runs a shell command after the main task succeeds. Workflow-level `verify` acts as the default for tasks; a task-level `verify` replaces the workflow block and omitted optional fields fall back to built-in defaults.

In the v0.2 execution pipeline, `verify` runs after evidence generation. Evidence and attestation therefore describe the main command result; the `verify` outcome is recorded separately and can still flip the final task status according to `on_failure`. If operators need end-to-end proof that includes the verification step, model that requirement in the evidence payload rather than assuming `verify` is part of the attested result.

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `shell` | string | Yes | -- | Shell command to run after a successful task execution. |
| `timeout_seconds` | integer | No | `>= 1` | Timeout for the verify command. Default: `30`. |
| `on_failure` | string | No | `error`, `warn` | Whether a verify failure should fail the task or be surfaced as a warning. Default: `error`. |

### Identity Subject Fields

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `kind` | string | No | `agent`, `service`, `workload`, `user`, `composite`, `delegated-agent`, `unknown` | Nature of the identity. |
| `principal` | string | No | -- | Stable URI identifier (e.g., `agent://acme.com/deploy-bot`). |
| `display_name` | string | No | -- | Human-readable name. |
| `run_as` | string (token) | No | -- | Runtime account (e.g., UNIX user). Restricted token. |
| `issuer` | string | No | -- | Trust domain or token issuer. |
| `delegation_mode` | string | No | `none`, `on-behalf-of`, `impersonation` | How authority is exercised. |
| `attributes` | object | No | -- | Audit-safe metadata. Free-form key-value pairs. Common actor-context keys include `org_id`, `on_behalf_of_user_id`, `delegation_grant_id`, `run_id`, `agent_id`, `verification_ref`, `verification_level`, and `verification_verified_at`. |

### Identity Auth Fields

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `mode` | string | No | `none`, `service`, `delegated`, `on-behalf-of`, `impersonation`, `exchange` | Authentication mode. |
| `scopes` | array of strings | No | -- | Token scopes. |
| `audience` | string | No | -- | Token audience. |
| `resource` | string | No | -- | Token resource. |
| `cache` | string | No | `none`, `memory`, `state` | Session caching strategy. |
| `refresh` | string | No | `never`, `manual`, `auto` | Session refresh strategy. |
| `required` | boolean | No | -- | Whether auth is required. Default: `true`. |
| `delegation_policy` | object | No | -- | Delegation constraints. See [delegation_policy](#identity-auth-delegation-policy-fields). |
| `provider_config` | object | No | -- | Provider-specific configuration. Free-form. |
| `inputs` | object | No | -- | Named values using `value_from` indirection. Each value is a [value_from](#value_from-fields) object. |

### Identity Auth Delegation Policy Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `max_depth` | integer | No | Maximum delegation chain depth. Must be >= 1. |
| `allowed_delegators` | array of strings | No | Principal URIs allowed to delegate. |
| `require_grant_per_hop` | boolean | No | Whether to require an authorization grant at each hop. |

### Identity Trust Fields

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `level` | string | No | `untrusted`, `restricted`, `supervised`, `autonomous` | Trust level. Default: `supervised`. |
| `constraints` | object | No | -- | Trust constraints. See below. |

#### trust.constraints

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `escalation` | string | No | `fail`, `human-approval`, `log-and-proceed` | Behavior when trust is insufficient. |
| `max_autonomy` | string | No | `untrusted`, `restricted`, `supervised`, `autonomous` | Ceiling on trust level. Must not be lower than `contract.required_trust_level`. |
| `escalation_timeout` | string | No | -- | ISO 8601 duration for approval timeout. |
| `require_justification` | boolean | No | -- | Whether a reason string is required for escalation. |

### Identity Presentation Fields

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `bindings` | array | No | -- | Credential-to-tool binding rules. See [bindings](#identity-presentation-bindings). |
| `handoff` | string | No | `none`, `downscope`, `transaction-token` | Credential handoff mode at task boundaries. |
| `cleanup` | string | No | `always`, `on-success`, `on-failure`, `never` | When credential cleanup runs. |
| `default_redaction` | boolean | No | -- | Whether credential values are redacted by default in audit output. |

`identity.presentation.handoff` is stricter than `child_credential_policy`: any non-`none` handoff mode requires explicit `credential_handoff` support from the active runtime/backend during capability negotiation, because the handoff boundary itself must be modeled first-class.

### Identity Presentation Bindings

Each element in the `bindings` array is an object with these fields:

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `source` | string | Yes | -- | Dot-path into the credential session (e.g., `credentials.access_token.value`). |
| `target` | object | No | -- | How the credential is exposed. See below. |
| `required` | boolean | No | -- | Fail if the source path does not resolve. |
| `redact` | boolean | No | -- | Replace value with `[REDACTED]` in audit. |
| `format` | string | No | `raw`, `json`, `base64` | Serialization format. |

#### bindings[].target

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `kind` | string | No | `env`, `file`, `stdin`, `none` | Mechanism for exposing the credential. |
| `name` | string | No | -- | Environment variable name (for `env`) or file name (for `file`). |

---

## Identity Profile Fields

*v0.2.* Defined in the top-level `identity_profiles` array.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier within the manifest. Must be an identifier. |
| `provider` | string | Yes | Identity provider name. Free-form string. Known providers: `none`, `env-bearer`, `file-bearer`, `oidc-client-credentials`, `oidc-token-exchange`, `azure-managed-identity`, `aws-sts-assume-role`, `gcp-workload-identity`, `spiffe-jwt-svid`, `entra-agent-id`. |
| `subject` | object | No | Subject descriptor. Same fields as [Identity Subject Fields](#identity-subject-fields). |
| `auth` | object | No | Authentication configuration. Same fields as [Identity Auth Fields](#identity-auth-fields). |
| `trust` | object | No | Trust level declaration. Same fields as [Identity Trust Fields](#identity-trust-fields). |
| `presentation` | object | No | Credential presentation. Same fields as [Identity Presentation Fields](#identity-presentation-fields). |
| `provider_config` | object | No | Provider-specific configuration. Free-form. |

---

## Authorization Proof Profile Fields

*v0.2.* Defined in the top-level `authorization_proof_profiles` array.

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `id` | string | Yes | -- | Unique identifier. Must be an identifier. |
| `method` | string | Yes | `none`, `jwt`, `detached-signature`, `certificate` | Proof method. |
| `issuer` | string | No | -- | Token issuer. |
| `audience` | string | No | -- | Token audience. |
| `jwks_uri` | string | No | -- | URI for JSON Web Key Set (for `jwt` method). Used to resolve signing keys by `kid` when verifying a JWT proof. |
| `public_key` | string | No | -- | Public key material. For `jwt`, provide a PEM public key when you do not want to fetch JWKS. Also used by `detached-signature` and `certificate` verification flows. |
| `proof` | object | No | -- | Proof value container. See below. |
| `claims` | object | No | -- | Expected claims. Free-form key-value pairs. |
| `verify` | object | No | -- | Verification requirements. See below. |

### proof

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `value_from` | object | No | Indirection to resolve the proof value. See [value_from Fields](#value_from-fields). |

### verify (on proof profiles)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `required` | boolean | No | Whether verification must succeed before execution proceeds. |

For `jwt`, `verify.required: true` requires either `public_key` or `jwks_uri`.

---

## Authorization Proof Reference Fields

*v0.2.* Used on workflows and tasks to reference an authorization proof profile.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ref` | string | Yes | Reference to a named profile from `authorization_proof_profiles`. |
| `claims` | object | No | Claim overrides. Free-form key-value pairs. |
| `verify` | object | No | Verification overrides. See below. |

### verify (on proof references)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `required` | boolean | No | Whether verification is required for this scope. |

---

## Authorization Profile Fields

*v0.2.* Defined in the top-level `authorization_profiles` array.

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `id` | string | Yes | -- | Unique identifier. Must be an identifier. |
| `provider` | string | Yes | -- | Authorization provider name. Free-form string. Known providers: `none`, `opa`. |
| `provider_config` | object | No | -- | Provider-specific configuration. Free-form. |
| `on_error` | string | No | `deny`, `warn` | Behavior when the provider is unreachable. Default: `deny`. |
| `request` | object | No | -- | Authorization request shape. See below. |
| `decision` | object | No | -- | Decision output normalization. See below. |

### request

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `include` | array of strings | No | Fields to include in the authorization request. |

Current include values are:

- `identity`
- `contract`
- `command`
- `resource`
- `trust`
- `actor`
- `step_up`

`actor` contains the canonical actor context derived from `identity.subject.attributes`, task target metadata such as `agent_id`, and safe runtime identity details. `step_up` contains the safe verification summary and decoded audit-safe JWT claims from `authorization_proof`.

### decision

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `allow_values` | array of strings | No | Values that map to "allow" in the provider response. |
| `deny_values` | array of strings | No | Values that map to "deny" in the provider response. |
| `escalate_values` | array of strings | No | Values that map to "escalate" in the provider response. |

---

## Authorization Reference Fields

*v0.2.* Used on workflows and tasks to reference an authorization profile.

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `ref` | string | Yes | -- | Reference to a named profile from `authorization_profiles`. |
| `provider_config` | object | No | -- | Provider-specific overrides. Free-form. |
| `on_error` | string | No | `deny`, `warn` | Override for error behavior. |
| `request` | object | No | -- | Request overrides. Same fields as authorization profile [request](#request). |
| `decision` | object | No | -- | Decision overrides. Same fields as authorization profile [decision](#decision). |

---

## Evidence Profile Fields

*v0.2.* Defined in the top-level `evidence_profiles` array.

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `id` | string | Yes | -- | Unique identifier. Must be an identifier. |
| `provider` | string | Yes | -- | Evidence provider name. Free-form string. Known providers: `none`, `ssh`. |
| `methods` | array of strings | No | -- | Supported evidence methods. |
| `provider_config` | object | No | -- | Provider-specific configuration. Free-form. |
| `payload` | object | No | -- | Evidence payload configuration. See below. |
| `verify` | object | No | -- | Verification requirements. See below. |

### payload (on evidence profiles)

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `bind` | array of strings | No | -- | Execution context sections to bind into the evidence payload. |
| `context` | object | No | -- | Additional context included in the evidence record. Free-form. |
| `format` | string | No | `canonical-json`, `json` | Evidence payload serialization format. |

### verify (on evidence profiles)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `required` | boolean | No | Whether evidence verification is required. |

---

## Evidence Reference Fields

*v0.2.* Used on workflows and tasks to reference an evidence profile.

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `ref` | string | No | -- | Reference to a named profile from `evidence_profiles`. |
| `payload` | object | No | -- | Payload overrides. See below. |
| `verify` | object | No | -- | Verification overrides. See below. |

### payload (on evidence references)

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `bind` | array of strings | No | -- | Override for bound execution context sections. |
| `context` | object | No | -- | Override for additional context. Free-form. |
| `format` | string | No | `canonical-json`, `json` | Override for serialization format. |

### verify (on evidence references)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `required` | boolean | No | Whether evidence verification is required for this scope. |

---

## Contract Fields

Workflow-level `contract` acts as a default for tasks. Task-level overrides key by key.

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `sandbox` | string | No | `none`, `permissive`, `strict` | Sandbox enforcement level. |
| `allowed_paths` | array of strings | No | -- | Filesystem paths the execution may access. Each element must be a non-empty string. |
| `network` | string | No | `unrestricted`, `restricted`, `none` | Network access level. |
| `max_cost_usd` | number | No | >= 0 | Maximum cost in USD. |
| `audit` | string | No | `none`, `on-failure`, `always` | Audit trail strategy. Default: `always` for exec. |
| `required_trust_level` | string | No | `untrusted`, `restricted`, `supervised`, `autonomous` | Minimum trust level for execution (v0.2). Must not exceed the resolved identity's `trust.constraints.max_autonomy`. |
| `trust_enforcement` | string | No | `none`, `advisory`, `strict` | How trust level mismatches are handled (v0.2). Default: `none`. |

---

## On-Failure Fields

Shorthand for synthesizing a triggered child task with `trigger.on = "failure"`.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | No | Handler task id. Must be an identifier. Defaults to `<parent_task_id>.failure`. Must be unique within the workflow after shorthand expansion. |
| `name` | string | No | Handler task name. Defaults to `<parent_task_name> Failure Handler`. |
| `enabled` | boolean | No | Whether the failure handler is active. |
| `prompt` | string | Conditional | Handler prompt. Required when the inferred or explicit `session_target` is not `shell`. |
| `shell` | object | Conditional | Shell execution block. Required when `session_target` is `shell`. See [Shell Fields](#shell-fields). |
| `command` | string | No | **Removed.** Rejected by the validator. |
| `target` | object | No | Explicit target. See [Target Fields](#target-fields). When omitted, `session_target` is inferred: `shell` when `shell` is present, `isolated` otherwise. The `agent_id` is inherited from the parent task. |
| `delay_s` | integer | No | Delay before the handler fires. Must be >= 0. |
| `condition` | string | No | Output-matching condition. Same rules as [Trigger Fields](#trigger-fields) `condition`. |
| `model_policy` | object | No | See [Model Policy Fields](#model-policy-fields). |
| `intent` | object | No | See [Intent Fields](#intent-fields). |
| `output` | object | No | See [Output Fields](#output-fields). |
| `budgets` | object | No | See [Budgets Fields](#budgets-fields). |
| `delivery` | object | No | See [Delivery Fields](#delivery-fields). |
| `reliability` | object | No | See [Reliability Fields](#reliability-fields). |
| `runtime` | object | No | See [Runtime Fields](#runtime-fields). |
| `approval` | object | No | See [Approval Fields](#approval-fields). |
| `context` | object | No | See [Context Fields](#context-fields). |
| `session` | object | No | See [Session Fields](#session-fields). |
| `identity` | object | No | v0.2 identity shape. See [Identity Fields (v0.2)](#identity-fields-v02). |
| `contract` | object | No | See [Contract Fields](#contract-fields). |
| `authorization_proof` | object | No | See [Authorization Proof Reference Fields](#authorization-proof-reference-fields). |
| `authorization` | object | No | See [Authorization Reference Fields](#authorization-reference-fields). |
| `evidence` | object | No | See [Evidence Reference Fields](#evidence-reference-fields). |
| `delete_after_run` | boolean | No | Remove the compiled job after first successful execution. |

---

## value_from Fields

Used for credential and proof inputs that must not be hardcoded. At least one source must be provided.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `env` | string | No | Environment variable name. |
| `file` | string | No | File path. The file should have restrictive permissions. |
| `literal` | string | No | Inline value. Use sparingly. Not allowed in all contexts. |
| `command` | string | No | Shell command to run. stdout is captured. 30s timeout. |

---

## Validation Constraints

These additional constraints are enforced by `src/validate.js` and are not always visible from the schema alone.

### Cross-field rules

- A task must define exactly one of `schedule` or `trigger`.
- When `target.session_target` is `shell`, `shell` must be present and `prompt` must not be.
- When `target.session_target` is not `shell`, `prompt` must be present and `shell` must not be.
- When `target.session_target` is `shell`, `target.payload_kind` (if set) must be `shellCommand`.
- `trigger.parent` must reference another task id in the same workflow (not itself).
- `delivery.to` is required when `delivery.mode` is `announce` or `announce-always`.
- All `ref` fields are validated against their respective top-level profile arrays. Unknown refs produce errors.
- `contract.required_trust_level` must not exceed the resolved identity's `trust.constraints.max_autonomy`.
- Profile `id` fields must be unique within their respective profile array.
- Workflow `id` fields must be unique within the manifest.
- Task `id` fields must be unique within the workflow, including after `on_failure` shorthand expansion.

### Format constraints

- **Identifier**: `/^[A-Za-z0-9][A-Za-z0-9._-]*$/` -- used for `id` fields on workflows, tasks, and profiles.
- **Restricted token**: `/^[A-Za-z0-9@:_./-]+$/` -- used for `agent_id`, `principal`, `run_as`, `shell.program`, delivery tokens, session keys, and `approver_scope`.
- **Environment variable name**: `/^[A-Za-z_][A-Za-z0-9_]*$/` -- used for `shell.env` keys.
- **Control characters**: Strings must not contain ASCII control characters (0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F, 0x7F). Tabs (0x09), newlines (0x0A), and carriage returns (0x0D) are permitted.

### Warnings (non-fatal)

The validator emits warnings for these situations:

- Unknown keys at the manifest, workflow, task, or on_failure level.
- `approval.policy` and `approval.required` both present (policy takes precedence).
- `context.limit` and `budgets.max_context_items` both present with different values (limit takes precedence).
- `approval.required` set on a root scheduled task (approval is most useful on triggered tasks).
- `intent.mode = "plan"` or `intent.read_only` on shell targets (intent may be advisory only).
