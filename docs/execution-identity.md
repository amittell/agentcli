# Execution Identity Architecture

## Status

This document describes the execution identity architecture for `agentcli` manifest spec `0.2`.

Implementation status as of 2026-03-23:

- Phases 1-6 are complete
- All ten identity providers are shipped: none, env-bearer, file-bearer, oidc-client-credentials, oidc-token-exchange, azure-managed-identity, aws-sts-assume-role, gcp-workload-identity, spiffe-jwt-svid, entra-agent-id
- Authorization providers: none, opa
- Evidence providers: none, ssh
- Authorization proof verifiers: none, jwt, detached-signature, certificate
- All provider targets from the original spec are implemented, including `entra-agent-id`
- v0.1 backward compatibility is preserved: v0.1 manifests execute through the original code path unchanged

This spec is normative for `0.2` and backward-compatible with `0.1`.

## Problem

`agentcli` currently has the beginnings of an identity model:

- `identity` fields on workflows and tasks
- `contract` fields on workflows and tasks
- local `exec`
- attestation signing
- append-only audit records

That is directionally correct, but the current architecture is still incomplete.

Current limitations:

- `identity` is mostly declarative metadata, not a first-class runtime abstraction
- signing providers are treated as the main identity extension point, even though signing and authentication are different concerns
- manifest-time identity declaration and execution-time proof are partially conflated
- credential acquisition is not modeled generically
- credential presentation to tools is not modeled explicitly
- compile targets do not yet preserve enough structured identity intent for richer runtimes

This matters because agent workflows increasingly need:

- a distinct principal
- scoped runtime credentials
- delegated or exchanged authority
- explicit execution boundaries
- verifiable execution evidence
- audit-safe attribution
- runtime instance attribution for forensic traceability

The regulatory landscape reinforces this urgency. The EU AI Act applies in phases through 2026, and Colorado's AI Act takes effect on June 30, 2026. Those frameworks increase pressure for documentation, traceability, transparency, risk management, and attributable operation of AI systems. `agentcli` does not need to encode any one statute directly, but designs that cannot produce clear execution records, policy context, and attributable identity will be harder to justify in regulated environments.

The architecture must be flexible enough to support:

- local SSH-backed identity and attestation
- cloud workload identity
- managed identity
- token exchange systems
- enterprise agent identity systems such as Entra Agent ID
- SPIFFE-based workload identity and attestation
- future agent-native identity systems that do not exist yet

The IETF published `draft-klrc-aiagent-auth-00` in March 2026, defining the Agent Identity Management System (AIMS) framework. AIMS composes WIMSE, SPIFFE, and OAuth 2.0 into a layered reference architecture that treats agents as workloads rather than users. The architecture proposed in this document is independently aligned with AIMS and should remain compatible with it as that standard evolves.

## Goals

- Make execution identity a first-class control-plane concept in `agentcli`.
- Keep identity vendor-neutral at the manifest level.
- Separate identity declaration, credential acquisition, credential presentation, and execution evidence.
- Preserve backend portability.
- Allow provider-based extension without forking `agentcli`.
- Make credential handling safe by default.
- Ensure audit output is useful for operators and safe for agents.
- Support both local execution and backend runtimes.
- Keep compile-time and execution-time concerns separate.
- Align with emerging standards (AIMS, WIMSE, SPIFFE, OAuth 2.0) without coupling to any single specification.
- Support runtime instance attribution so that individual agent executions are distinguishable in audit and forensic contexts when the runtime can surface it.

## Non-Goals

- `agentcli` is not intended to become a general-purpose IdP.
- `agentcli` is not intended to replace cloud IAM systems, vaults, or corporate directory infrastructure.
- `agentcli` should not implement bespoke OAuth, token exchange, or certificate protocols manually when vendor SDKs are required.
- `agentcli` should not persist raw secrets or access tokens in manifests, compiled artifacts, or audit logs.
- `agentcli` should not move durable scheduler runtime responsibilities into this repo.
- `agentcli` does not implement agent discovery, fleet governance, or agent registry services. However, identity profiles SHOULD be structured so that they are exportable for consumption by external agent registries such as Microsoft Entra Agent Registry or organizational CMDB systems.
- `agentcli` does not implement per-action authorization policy engines. Contract enforcement provides execution boundaries, but fine-grained per-action policy evaluation is the responsibility of external policy engines (OPA, Cedar, Topaz) that may be invoked at runtime.

## Design Principles

- Separate concerns cleanly.
- Resolve credentials as late as possible.
- Keep manifests declarative.
- Do not bake vendor-specific concepts into the core schema when a provider abstraction will do.
- Prefer structured machine-readable data over prose.
- Never require raw secrets in manifests.
- Make audit and evidence first-class outputs, not side effects.
- Make dangerous fallbacks explicit.
- Compose existing standards rather than inventing new protocols. The IETF AIMS framework validates this: "No new authentication protocol is needed specifically for AI agents."
- Distinguish stable subject identity, runtime instance attribution, and per-run execution identifiers. `execution_id` is universal; instance attribution is additional runtime metadata when available.
- Model delegation chains explicitly so that authority provenance is traceable and auditable.
- Preserve a strict difference between:
  - who a task intends to act as
  - how credentials are acquired
  - how credentials are presented to the tool
  - whether derived credentials may be handed off across an explicit runtime boundary
  - how the execution is later proven

## Standards Alignment

This architecture is designed to compose with, not compete against, the following emerging standards and frameworks.

### IETF AIMS (draft-klrc-aiagent-auth-00)

The Agent Identity Management System defines a layered reference architecture: Identifier, Credentials, Attestation, Provisioning, Authentication, Authorization, and Monitoring. `agentcli`'s six-layer model maps to AIMS as follows:

| agentcli Layer | AIMS Layer(s) |
|---|---|
| Subject Declaration | Identifier |
| Manifest Authorization Proof | (not covered by AIMS; agentcli-specific) |
| Authentication and Credential Acquisition | Credentials, Attestation, Provisioning, Authentication |
| Credential Presentation | (not covered by AIMS; agentcli-specific) |
| Contract Enforcement | Authorization (partial; see Authorization section) |
| Evidence and Audit | Monitoring |

Manifest authorization proof and credential presentation are areas where `agentcli` extends beyond AIMS. AIMS does not model pre-execution manifest approval as a separate concern, and it does not prescribe how credentials are injected into wrapped tool processes.

### WIMSE and SPIFFE

AIMS uses WIMSE (Workload Identity in Multi-System Environments) URIs as agent identifiers, with SPIFFE as the operational implementation format:

```
spiffe://trust-domain.example/path/to/agent
```

`agentcli` identity profiles SHOULD use URI-formatted principals for interoperability. The recommended formats are:

- `agent://<domain>/<path>` for agentcli-native identifiers
- `spiffe://<trust-domain>/<path>` when integrating with SPIFFE infrastructure

The `subject.principal` field accepts any stable string, but URI format is strongly recommended for new profiles.

### OAuth 2.0 and Token Exchange

AIMS maps agent authentication to standard OAuth 2.0 grant types. `agentcli` auth modes correspond as follows:

| agentcli auth.mode | OAuth 2.0 Grant |
|---|---|
| `service` | Client Credentials Grant |
| `delegated` | Authorization Code Grant |
| `on-behalf-of` | JWT Authorization Grant (RFC 7523) |
| `exchange` | Token Exchange (RFC 8693) |

This mapping is intentional but not binding. Providers implement the actual protocol mechanics.

Human approval is intentionally not an `auth.mode`. Approval and step-up authorization are separate policy concerns that apply on top of an auth mode. When a deployment requires out-of-band approval, providers or authorization integrations MAY satisfy that via CIBA or an equivalent mechanism.

### Entra Agent ID

Microsoft Entra Agent ID provides enterprise-grade agent identity built on workload identity primitives (service principals, managed identities) with agent-specific extensions (Agent Registry, Conditional Access for agents, agent lifecycle governance). The `entra-agent-id` provider maps to this system directly.

Key Entra Agent ID properties that influenced this design:

- Agent identities do not use passwords or secrets; they authenticate only using access tokens issued to the platform where the agent runs
- Agent identities are distinct from application identities and human user identities
- Agent identities embrace dynamic, ephemeral lifecycles rather than long-lived static assignments
- Agent Registry provides centralized discovery and governance of deployed agents

### SPIFFE Instance Identity

Current SPIFFE implementations in Kubernetes (via Istio) anchor identity at the service account level, meaning all pod replicas receive identical identities. This is insufficient for agents because agents are non-deterministic and each instance may develop unique behavior through context, learning, and environmental factors.

`agentcli` addresses this by treating instance identity as runtime-resolved metadata associated with the credential session and audit record rather than a reusable declared subject field:

```
spiffe://acme.com/ns/trading/sa/trading-agent-sa/instance/001
```

When the underlying platform exposes a meaningful instance identifier, the runtime SHOULD preserve it in resolved identity metadata and audit output. When it does not, `execution_id` remains the universal run-level identifier.

## Terminology

### Subject

The logical principal the task intends to operate as.

Examples:

- a human delegate
- an autonomous service
- an enterprise agent principal
- a workload identity
- a composite multi-agent system

### Instance Identity

A runtime-resolved identifier for the specific actor instance that executed a task, as distinct from the stable subject principal and from `execution_id`. Instance identity is useful for forensic traceability when the runtime can surface a meaningful actor instance (for example, a workload instance, pod identity, or operator-supplied override). It is not part of the reusable manifest subject declaration.

### Identity Profile

A reusable manifest object that describes how a subject should authenticate and how credentials should be presented during execution.

### Identity Provider

A runtime plugin that can resolve credentials for a declared identity profile.

Examples:

- `none`
- `env-bearer`
- `azure-managed-identity`
- `entra-agent-id`
- `oidc-client-credentials`
- `aws-sts-assume-role`
- `spiffe-jwt-svid`

### Credential Session

An in-memory runtime object returned by an identity provider after successful resolution.

It contains:

- resolved subject metadata (including instance identity)
- credential material
- expiry and refresh metadata
- audit-safe provider metadata
- delegation chain with validation status

### Presentation

The structured rule set that determines how resolved credentials are exposed to the wrapped tool at execution time.

Examples:

- environment variables
- temporary files
- stdin materialization
- no direct materialization

### Credential Handoff

The rules governing whether `agentcli` or a compatible backend may prepare a derived credential for an explicit downstream handoff boundary. Handoff is narrower than arbitrary credential propagation: `agentcli` does not attempt to infer nested service calls inside opaque shell or prompt tasks.

### Authorization Proof

Manifest-time proof that a workflow or task declaration was authorized before execution. Authorization proof is distinct from both subject identity and execution evidence.

Examples:

- a CI-issued JWT asserting deployment authority
- a signed deployment token
- a certificate reference
- a detached signature over the manifest payload

### Evidence

Post-execution proof that an execution happened as described.

Examples:

- SSH signature
- KMS-backed signature
- Sigstore envelope
- cloud-issued receipt
- no evidence

### Evidence Provider

A runtime plugin that can attest and verify execution evidence.

This is the conceptual successor to the current signing provider abstraction.

### Contract

Execution boundary declarations such as sandbox level, allowed paths, network expectations, cost limits, minimum required trust level, and audit policy.

### Trust Level

A graduated classification of the autonomy granted to an agent identity. Trust levels enable earned autonomy models where agents start with restricted access and gain broader capabilities over time as they demonstrate reliable behavior.

### Escalation

A mechanism for pausing agent execution to request human approval before proceeding with a sensitive or high-impact operation. Escalation bridges autonomous execution with human-in-the-loop authorization.

### Delegation Policy

Constraints governing how authority flows through delegation chains, including maximum chain depth, allowed delegators, and required authorization grants at each hop.

## Architectural Model

The proposed model has six layers:

1. Subject declaration
2. Manifest authorization proof
3. Authentication and credential acquisition
4. Credential presentation
5. Execution contract enforcement
6. Evidence generation and audit

These layers are intentionally separate.

### Layer 1: Subject Declaration

This answers:

- what principal is this task intended to act as
- how should operators identify it
- what workflow-level defaults apply
- what trust level is assigned

This layer is declarative and portable.

### Layer 2: Manifest Authorization Proof

This answers:

- who authorized this manifest or workflow declaration
- what pre-existing proof was attached to that authorization
- how downstream systems can validate that the manifest itself was approved

This layer is static and travels with the manifest. It is not runtime credential acquisition and it is not execution evidence.

### Layer 3: Authentication and Credential Acquisition

This answers:

- which provider resolves credentials
- what auth mode is required
- what scopes or audiences are needed
- whether delegation or token exchange is involved
- what runtime instance attribution is available from the provider or operator input
- what delegation constraints apply

This layer is runtime-specific and provider-backed.

### Layer 4: Credential Presentation

This answers:

- how the tool receives credentials
- whether credentials are injected through env, files, or stdin
- what must be cleaned up afterward
- whether the runtime may prepare a derived credential for an explicit downstream handoff boundary

This layer must be explicit because authentication and tool execution are often decoupled.

### Layer 5: Contract Enforcement

This answers:

- what execution boundaries are required
- whether the task may run under the current conditions
- whether any declared limitations are advisory or enforceable
- what trust level is required and whether the current identity meets it
- whether per-action authorization checks are configured

This layer remains separate from identity but MAY consume identity metadata (such as trust level) as input to enforcement decisions.

Note: contract enforcement provides execution boundaries (what an agent is allowed to access). It does not provide per-action authorization (whether a specific action within those boundaries should proceed). Per-action authorization is a distinct concern that belongs to external policy engines. However, the execution lifecycle includes an authorization hook point where policy engines can be invoked. See the Execution Lifecycle section for details.

### Layer 6: Evidence and Audit

This answers:

- how the run is proven after execution
- what evidence is generated
- what gets written to the audit log
- what compliance-relevant context is captured (model version, policy version)

This layer must not own the identity model. It consumes it.

## Manifest Model

This proposal introduces reusable profile objects and a cleaner task-level structure.

### Top-Level Additions

A manifest MAY define:

- `identity_profiles`
- `authorization_proof_profiles`
- `authorization_profiles`
- `evidence_profiles`

These are reusable control-plane declarations. They do not contain raw credentials.

### Top-Level Shape

Proposed top-level manifest shape:

```json
{
  "version": "0.2",
  "identity_profiles": [],
  "authorization_proof_profiles": [],
  "authorization_profiles": [],
  "evidence_profiles": [],
  "workflows": []
}
```

## Identity Profiles

An identity profile defines subject intent, authentication requirements, and credential presentation defaults.

### Proposed Shape

```json
{
  "id": "corp-agent",
  "provider": "entra-agent-id",
  "subject": {
    "kind": "agent",
    "principal": "agent://corp/secops-bot",
    "display_name": "SecOps Bot",
    "issuer": "https://login.microsoftonline.com/<tenant>"
  },
  "auth": {
    "mode": "service",
    "scopes": [
      "https://graph.microsoft.com/.default"
    ],
    "audience": null,
    "resource": null,
    "cache": "memory",
    "refresh": "auto",
    "required": true,
    "delegation_policy": {
      "max_depth": 3,
      "allowed_delegators": [],
      "require_grant_per_hop": true
    },
    "provider_config": {
      "tenant_id": "11111111-2222-3333-4444-555555555555",
      "blueprint_app_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      "agent_identity_id": "ffffffff-1111-2222-3333-444444444444"
    }
  },
  "trust": {
    "level": "supervised",
    "constraints": {
      "escalation": "human-approval",
      "max_autonomy": "supervised"
    }
  },
  "presentation": {
    "bindings": [
      {
        "source": "credentials.access_token.value",
        "target": {
          "kind": "env",
          "name": "ACCESS_TOKEN"
        },
        "required": true,
        "redact": true
      }
    ],
    "handoff": "none",
    "cleanup": "always"
  }
}
```

### Identity Profile Fields

Each identity profile MUST contain:

- `id`
- `provider`

Each identity profile MAY contain:

- `subject`
- `auth`
- `trust`
- `presentation`
- `metadata`

### `subject`

`subject` describes identity intent and operator-facing metadata.

It MAY contain:

- `kind`
- `principal`
- `display_name`
- `run_as`
- `issuer`
- `delegation_mode`
- `attributes`

Proposed enums for `subject.kind`:

- `agent` -- an autonomous AI agent
- `service` -- a traditional backend service
- `workload` -- a cloud or container workload identity
- `user` -- a human user identity
- `composite` -- a multi-agent system acting as a single principal
- `delegated-agent` -- an agent whose primary purpose is to act on behalf of another identity; this describes what the agent IS, not how it authenticates for a specific task (use `delegation_mode` for that)
- `unknown` -- kind not specified or not determinable

`subject.kind` describes the nature of the identity. `subject.delegation_mode` describes how the identity exercises authority for a specific task. They are independent: an `agent` kind can use `delegation_mode: on-behalf-of` for a particular task without being a `delegated-agent`. A `delegated-agent` might use `delegation_mode: none` when performing internal housekeeping that doesn't require delegated authority.

Proposed enums for `subject.delegation_mode`:

- `none` -- this identity acts on its own authority only
- `on-behalf-of` -- this identity acts on behalf of an upstream principal
- `impersonation` -- this identity assumes the full authority of another principal

Rules:

- `principal` SHOULD be stable across executions and SHOULD use URI format (e.g., `agent://domain/path` or `spiffe://trust-domain/path`)
- `run_as` SHOULD represent the runtime account when known
- `issuer` SHOULD identify the trust domain when known
- `delegation_mode` defaults to `none` when not specified
- `attributes` MUST be audit-safe metadata only
- runtime instance attribution belongs in resolved session metadata, not in the reusable subject declaration

### `auth`

`auth` defines provider-backed runtime credential acquisition.

It MAY contain:

- `mode`
- `scopes`
- `audience`
- `resource`
- `cache`
- `refresh`
- `required`
- `delegation_policy`
- `provider_config`
- `inputs`

Proposed enums for `auth.mode`:

- `none` -- no authentication required
- `service` -- agent authenticates with its own credentials (maps to OAuth 2.0 Client Credentials Grant)
- `delegated` -- user delegates authority to the agent (maps to OAuth 2.0 Authorization Code Grant)
- `on-behalf-of` -- agent acts on behalf of an upstream principal (maps to JWT Authorization Grant, RFC 7523)
- `impersonation` -- agent assumes full authority of another principal
- `exchange` -- agent exchanges one credential for another (maps to Token Exchange, RFC 8693)

`auth.mode` defaults to `none` when not specified. When `auth.mode` is `none` and `auth.required` is `true` (the default), the runtime skips credential acquisition and proceeds with no credential session. This is valid for tasks that do not need authenticated access.

Proposed enums for `auth.cache`:

- `none` -- no caching; a fresh credential session is resolved for every task execution, even within the same workflow run
- `memory` -- the resolved session is held in process memory for the duration of the workflow run and reused across tasks that share the same resolved identity profile; the session is discarded when the process exits
- `state` -- the resolved session is persisted to the `agentcli` state directory (e.g., `~/.agentcli/state/sessions/`) and reused across workflow runs until it expires; persisted sessions MUST be stored with restrictive file permissions (0600) and MUST be invalidated when the credential expires or the manifest identity profile changes

Rules for `auth.cache`:

- `state` introduces credentials at rest; operators SHOULD prefer `memory` unless cross-run reuse is required
- cached sessions MUST still be validated against the current manifest profile before reuse; if the profile has changed, the cache entry MUST be invalidated
- `auth.cache` defaults to `none` when not specified

Proposed enums for `auth.refresh`:

- `never` -- the credential session is used as-is until it expires; no refresh is attempted even if the provider supports it
- `manual` -- refresh is available but only triggered by explicit operator action (e.g., `agentcli identity refresh`); the runtime does not refresh automatically
- `auto` -- the runtime refreshes the credential session automatically before expiry when the provider supports it; refresh occurs before execution begins (pre-execution refresh), not during execution (see Credential Lifetime and Execution Duration)

Rules for `auth.refresh`:

- `auth.refresh` defaults to `never` when not specified
- `auto` refresh only applies between tasks in a multi-task workflow or before execution begins; it does not interrupt a running tool (see Credential Lifetime section)
- if the provider does not declare `capabilities.refreshable`, `auth.refresh` values other than `never` MUST cause a validation error at `validateProfile` time

### `delegation_policy`

`delegation_policy` constrains how authority flows through delegation chains.

It MAY contain:

- `max_depth` -- maximum number of delegation hops allowed (default: 1)
- `allowed_delegators` -- array of principal URIs permitted to delegate to this identity (empty means unrestricted)
- `require_grant_per_hop` -- whether each hop in the delegation chain must have a recorded authorization grant (default: true)

### `inputs`

`inputs` defines named values that the identity provider needs but that MUST NOT be hardcoded in the manifest. Each input is a key-value pair where the value uses `value_from` indirection.

Example:

```json
{
  "inputs": {
    "client_certificate": {
      "value_from": { "env": "AGENTCLI_CLIENT_CERT" }
    }
  }
}
```

The set of valid input names is defined by each provider and validated during `validateProfile`.

### `value_from` Indirection

`value_from` is a reusable pattern for referencing sensitive values without embedding them in the manifest. It appears in `inputs`, `proof`, and `provider_config` fields throughout this document.

Proposed `value_from` sources:

- `env` -- read the value from the named environment variable at resolution time
- `file` -- read the value from the named file path at resolution time; the file MUST have restrictive permissions (0600 or equivalent)
- `command` -- run the specified shell command and use the trimmed stdout as the value; the command runs with a 30-second timeout and inherits the current environment

The `command` source runs the specified string through `sh -c` with a 30-second timeout and captures stdout. This enables integration with external credential managers such as HashiCorp Vault CLI, 1Password CLI, AWS SSM, Stripe Projects, and macOS Keychain.

Rules:

- `provider_config` is provider-specific and validated by the provider
- `inputs` MAY use `value_from` indirection and MUST NOT require inline raw secrets
- `required` defaults to `true`; when `false`, the runtime attempts credential acquisition but proceeds with no credential session if the provider returns an error (this is useful for tasks that can operate with or without authentication)
- delegation chains MUST be acyclic; a provider MUST reject circular delegation
- when `auth.mode` is `on-behalf-of`, the provider SHOULD validate that a valid upstream delegation grant exists, not just a declaration

### `trust`

`trust` defines the graduated trust level and autonomy constraints for this identity.

It MAY contain:

- `level`
- `constraints`

Proposed enums for `trust.level`:

- `untrusted` -- no autonomous operations permitted; all actions require explicit approval
- `restricted` -- read-only or low-impact operations only; writes and state changes require approval
- `supervised` -- autonomous operation permitted for routine actions; high-impact or irreversible actions require human approval
- `autonomous` -- full autonomous operation within contract boundaries

Canonical ordering for trust comparisons:

`untrusted` < `restricted` < `supervised` < `autonomous`

`trust.constraints` MAY contain:

- `max_autonomy` -- the highest trust level this identity may operate at, even if elevated by workflow or task overrides (defaults to `autonomous` when not specified, meaning no ceiling is imposed)
- `escalation` -- the escalation mechanism to use when an operation exceeds the current trust level
- `escalation_timeout` -- maximum time to wait for human approval before failing closed (ISO 8601 duration, e.g., `PT5M`; defaults to `PT5M` when `escalation` is `human-approval` and no timeout is specified)
- `require_justification` -- whether the agent must provide a reason string when requesting escalation (default: false)

Proposed enums for `trust.constraints.escalation`:

- `fail` -- fail the operation if trust level is insufficient (default when `escalation` is not specified)
- `human-approval` -- request out-of-band human approval (via CIBA or equivalent)
- `log-and-proceed` -- log the trust violation as a warning and proceed (advisory mode only; MUST NOT be used when `trust_enforcement` is `strict`)

Rules:

- `trust.level` defaults to `supervised` when not specified
- all comparisons involving trust levels and `max_autonomy` use the canonical ordering above
- `trust.constraints.max_autonomy` MUST NOT be lower than `trust.level` in the same profile (validation error)
- trust level evaluation occurs during contract enforcement (Layer 5)
- trust levels are advisory unless the contract explicitly marks them as enforceable via `trust_enforcement`
- `trust.constraints.escalation` is consulted only when the resolved trust level is below `contract.required_trust_level`
- when `trust_enforcement` is `none`, trust mismatches are recorded only; escalation is not entered
- when `trust_enforcement` is `advisory`, trust mismatches record warnings and execution proceeds; `log-and-proceed` is the explicit form of this behavior
- when `trust_enforcement` is `strict`, `fail` (or an omitted escalation value) fails closed and `human-approval` pauses execution pending approval
- when a strict mismatch is approved through `human-approval`, execution proceeds under an approved override but `trust.effective_level` does not change; the override decision is a separate audit event, not a self-elevation of trust

Proposed enums for `trust_enforcement` (on the contract block):

- `none` -- trust level metadata is recorded in audit but not evaluated during contract enforcement; the task runs regardless of trust level (default when `trust_enforcement` is absent)
- `advisory` -- trust level is evaluated against `contract.required_trust_level` and mismatches are recorded as warnings in audit output, but execution proceeds
- `strict` -- trust level is evaluated against `contract.required_trust_level` and mismatches fail closed; the task is not executed unless the resolved trust level meets or exceeds the required level

### `presentation`

`presentation` defines how resolved credentials are exposed to the tool.

It MAY contain:

- `bindings`
- `handoff`
- `cleanup`
- `default_redaction` -- the default value for `redact` on bindings that do not specify it explicitly (boolean, default: true)

Proposed enums for `cleanup`:

- `always`
- `on-success`
- `on-failure`
- `never`

Proposed enums for `handoff`:

- `none` -- `agentcli` does not prepare or forward credentials beyond the current tool invocation (default)
- `downscope` -- when the active runtime exposes an explicit handoff boundary and the provider supports it, the runtime MAY request a derivative credential with reduced scope and lifetime for the next hop
- `transaction-token` -- when the active runtime exposes an explicit handoff boundary and the provider supports it, the runtime MAY request a transaction-scoped credential or token format appropriate to that backend

`bindings` is an array of binding objects.

Each binding MUST contain:

- `source`
- `target`

Each binding MAY contain:

- `required` -- whether the source path must resolve to a non-null value; when true and the source is absent, materialization fails (default: false)
- `redact` -- whether this binding's value should be redacted from logs and audit output (default: value of `presentation.default_redaction`, which defaults to true)
- `format` -- the serialization format when the source resolves to a structured value

Proposed enums for `binding.format`:

- `raw` -- the value is used as-is (strings, tokens); this is the default for scalar sources
- `json` -- the value is serialized as JSON; this is the default for object or array sources
- `base64` -- the value is base64-encoded before materialization

### `binding.source` Path Syntax

The `source` field uses dot-delimited property access to navigate the credential session object. The path is evaluated against the session shape returned by `resolveSession`.

Examples:

- `credentials.access_token.value` -- resolves to the bearer token string
- `credentials.access_token.expires_at` -- resolves to the expiry timestamp
- `credentials` -- resolves to the entire credentials object (useful with `format: "json"` for file-based materialization)
- `subject.principal` -- resolves to the principal URI

Rules:

- paths are case-sensitive
- a path that resolves to `undefined` is treated as absent; if `required` is true, this is a materialization error
- array indexing is not supported; paths navigate object properties only
- paths MUST NOT reach into `provider_assertions` or `delegation_chain` for materialization; those are audit-only data

Proposed target kinds:

- `env`
- `file`
- `stdin`
- `none`

Examples:

```json
{
  "source": "credentials.access_token.value",
  "target": {
    "kind": "env",
    "name": "AZURE_ACCESS_TOKEN"
  },
  "required": true,
  "redact": true
}
```

```json
{
  "source": "credentials",
  "target": {
    "kind": "file",
    "name": "credentials.json",
    "expose_as": "GOOGLE_APPLICATION_CREDENTIALS"
  },
  "format": "json",
  "required": true,
  "redact": true
}
```

Rules:

- for opaque local shell or prompt execution, `handoff` MUST remain `none`
- when `handoff` is `downscope` or `transaction-token`, the executing runtime or backend MUST advertise explicit `credential_handoff` capability
- providers MAY refuse unsupported handoff modes even when a runtime requests them
- `agentcli` MUST NOT forward raw access tokens across a declared handoff boundary
- handoff mode MUST be recorded in audit output when used or requested

### `metadata`

`metadata` is optional provider-neutral operator metadata.

It is not used for runtime security decisions.

## Authorization Proof Profiles

Manifest authorization proof is deliberately separated from both subject identity and execution evidence.

An authorization proof profile defines how a manifest, workflow, or task declaration carries static proof that it was approved before execution.

### Proposed Shape

```json
{
  "id": "ci-approval",
  "method": "jwt",
  "issuer": "https://ci.example.com",
  "proof": {
    "value_from": {
      "env": "AGENTCLI_MANIFEST_ATTESTATION"
    }
  },
  "claims": {
    "subject": "deploy-bot",
    "audience": "agentcli",
    "workflow_scope": ["bot-health"]
  },
  "verify": {
    "required": true
  }
}
```

### Authorization Proof Profile Fields

Each authorization proof profile MUST contain:

- `id`
- `method`

Proposed enums for `method`:

- `jwt` -- the proof is a signed JWT; verification checks the signature against the declared `issuer`'s JWKS or a configured public key
- `detached-signature` -- the proof is a detached signature over the manifest payload (or a specified subset); verification checks the signature against a configured public key or allowed_signers file
- `certificate` -- the proof is a certificate chain; verification checks the chain against a configured trust anchor
- `none` -- no proof is attached; this is valid only when `verify.required` is `false` and exists for development or opt-out scenarios

Each authorization proof profile MAY contain:

- `issuer`
- `proof`
- `claims`
- `verify`

### `claims`

`claims` defines expected claim values that the verifier checks against the proof payload during verification.

The valid claim names depend on the `method`:

- for `jwt`: standard JWT claims (`sub`, `aud`, `iss`, `exp`) plus any custom claims the issuer includes; the verifier SHOULD validate all declared claims against the decoded token
- for `detached-signature`: claims are not applicable; if present, they are ignored
- for `certificate`: `subject` (DN or SAN), `issuer` (CA DN); the verifier SHOULD validate declared claims against the certificate fields

Custom claims (e.g., `workflow_scope`) are method-specific and validated by the verifier. Unknown claims that the verifier cannot validate SHOULD cause a warning, not a hard failure, unless `verify.required` is `true` and the verifier's policy treats unknown claims as errors.

Rules:

- authorization proof profiles describe manifest-time proof only; they MUST NOT be used for runtime credential acquisition
- authorization proof values MAY use `value_from` indirection and MUST NOT require inline raw secrets in the manifest
- `verify.required: true` means the execution stage responsible for verification MUST reject the execution unit if the proof cannot be verified; this is local `exec`, `apply` for backends that lack `authorization_proof_verification`, or a capable backend runtime
- authorization proof verification happens before execution-time identity resolution
- for local `exec`, authorization proof verification occurs during Phase 1
- for backend targets, verification occurs at execution time only when the target advertises `authorization_proof_verification`; otherwise `apply` MUST verify each resolved execution unit's proof before handoff and MUST persist only audit-safe verification summaries bound to the corresponding manifest digest and execution-unit scope
- compiled artifacts and persisted backend specs MUST NOT embed raw authorization proof values unless the target explicitly models secure proof retrieval and verification
- authorization proof metadata included in audit records MUST be audit-safe and MUST NOT expose raw tokens or detached signature payloads

## Authorization Proof Verification Architecture

Authorization proof methods are resolved through a dedicated verifier registry, separate from identity providers and evidence providers.

### Authorization Proof Verifier Interface

Each authorization proof verifier MUST implement:

```js
{
  name,
  validateProfile(profile, ctx),
  verifyProof(proof, profile, ctx),
  describeVerification(result, ctx)
}
```

### Required Behavior

- `validateProfile` MUST validate method-specific profile fields without resolving the proof value
- `verifyProof` MUST verify the proof against the declared method and return a machine-readable result
- `describeVerification` MUST return an audit-safe verification summary
- verifiers MUST bind successful verification to a manifest digest so the result cannot be replayed against a different manifest payload

### Verification Result Shape

Successful verification normalizes to an audit-safe summary:

```json
{
  "method": "jwt",
  "issuer": "https://ci.example.com",
  "verified": true,
  "verified_at": "2026-03-20T15:58:00Z",
  "manifest_digest": "sha256:...",
  "verifier": "jwt"
}
```

Rules:

- the verification summary MUST NOT include raw JWTs, detached signatures, certificate chains, or embedded proof payloads
- the verification summary MAY include selected verified claims when they are explicitly declared audit-safe
- when verification is performed during `apply` for a backend lacking `authorization_proof_verification`, the persisted backend artifact MUST contain only these summaries and not the original proof, with one summary for each resolved execution unit

## Authorization Profiles

Authorization is deliberately separate from both contract declaration and authorization proof. It describes how an optional external policy engine participates in Phase 4.5.

### Proposed Shape

```json
{
  "id": "prod-policy",
  "provider": "opa",
  "provider_config": {
    "endpoint": "https://opa.internal/v1/data/agentcli/allow"
  },
  "on_error": "deny",
  "request": {
    "include": ["identity", "contract", "command", "resource", "trust"]
  },
  "decision": {
    "allow_values": ["allow", "permit"],
    "deny_values": ["deny"],
    "escalate_values": ["require-escalation"]
  }
}
```

### Authorization Profile Fields

Each authorization profile MUST contain:

- `id`
- `provider`

Each authorization profile MAY contain:

- `provider_config`
- `on_error`
- `request`
- `decision`

Rules:

- authorization profiles describe an external authorization integration only; they MUST NOT be used for identity resolution or evidence generation
- `on_error` defines runtime behavior when the authorization provider errors before returning a normalized decision
- `request.include` controls which execution-context fields are sent to the authorization provider
- `decision` maps provider-specific responses into the normalized decision set: `permit`, `deny`, `require-escalation`
- if the authorization provider returns a response value that does not match any entry in `allow_values`, `deny_values`, or `escalate_values`, the runtime MUST treat it as `deny` and record the unmapped response in the audit warning

### `on_error`

`on_error` is the authorization failure policy.

Proposed enums:

- `deny` -- fail closed when the provider errors or is unavailable (default)
- `warn` -- record an audit warning and continue execution without a Phase 4.5 decision

## Evidence Profiles

Evidence is deliberately separated from identity.

An evidence profile defines how execution evidence is produced and verified.

### Proposed Shape

```json
{
  "id": "ssh-proof",
  "provider": "ssh",
  "provider_config": {
    "key_path": {
      "value_from": {
        "env": "AGENTCLI_SIGNING_KEY"
      }
    }
  },
  "payload": {
    "bind": [
      "execution_id",
      "declared_identity",
      "resolved_identity",
      "contract",
      "command",
      "result"
    ],
    "context": {
      "model_version": true,
      "policy_version": true,
      "tool_versions": true,
      "data_provenance": false
    },
    "format": "canonical-json"
  },
  "verify": {
    "required": false
  }
}
```

### Evidence Profile Fields

Each evidence profile MUST contain:

- `id`
- `provider`

Each evidence profile MAY contain:

- `provider_config`
- `payload`
- `verify`

### `payload.bind`

`payload.bind` is an array of named data sections that are included in the canonical evidence payload before attestation.

Proposed bind targets:

- `execution_id` -- the unique execution identifier for this run
- `declared_identity` -- the identity declaration after three-stage merge (subject, trust level, provider name); does not include resolved credentials
- `resolved_identity` -- the audit-safe session description (subject, instance, delegation chain, credential summary, provider assertions); does not include raw credentials
- `authorization_proof` -- the authorization proof verification summary (method, issuer, verified status, manifest digest)
- `contract` -- the contract block (sandbox, network, allowed_paths, trust_enforcement, required_trust_level, audit)
- `command` -- the resolved command (program, args, cwd); does not include environment variables or stdin
- `result` -- the execution result (exit_code, duration_ms, stdout_bytes, stderr_bytes, structured_present, output_hash)
- `authorization` -- the Phase 4.5 authorization decision (decision, provider, policy reference)

Rules:

- the evidence provider receives each bound section as a structured object, not a serialized string
- the evidence provider serializes the bound sections into a canonical payload according to `payload.format` before signing
- bind targets that were not present during execution (e.g., `authorization` when Phase 4.5 was skipped) are omitted from the payload rather than included as null

### `payload.context`

`payload.context` defines optional compliance-relevant metadata to include in the evidence payload.

It MAY contain:

- `model_version` -- whether to include the model identifier or version used by the agent (boolean, default: false)
- `policy_version` -- whether to include the version of the authorization or contract policy applied during execution (boolean, default: false)
- `tool_versions` -- whether to include versions of tools invoked during execution (boolean, default: false)
- `data_provenance` -- whether to include provenance metadata for data sources accessed during execution (boolean, default: false)

These fields are intended to support accountability, reproducibility, and compliance-oriented evidence collection in environments that need to explain which models, policies, and tools participated in an autonomous action. When enabled, the evidence provider collects the relevant metadata from the execution context and includes it in the attested payload.

### Context Metadata Collection

When a `payload.context` field is enabled, the evidence provider collects the value from the execution context (`ctx`) at attestation time. The runtime populates `ctx.compliance_context` with the following fields when available:

- `model_version`: populated from the task's `metadata.model_version` field, an environment variable (e.g., `AGENTCLI_MODEL_VERSION`), or provider-specific discovery
- `policy_version`: populated from the manifest version, the contract's `metadata.policy_version` field, or an environment variable (e.g., `AGENTCLI_POLICY_VERSION`)
- `tool_versions`: populated from the resolved tool binary version (e.g., `--version` output captured during execution) or the task's `metadata.tool_versions` field
- `data_provenance`: populated from the task's `metadata.data_provenance` field or provider-specific discovery

When a field is enabled but the runtime cannot determine its value, the evidence provider SHOULD include `null` for that field rather than omitting it, so that the absence is explicit and auditable.

Rules:

- context fields are opt-in; they add to the evidence payload but do not change the attestation mechanism
- the runtime populates `ctx.compliance_context` before calling `attest()`; providers SHOULD NOT perform their own discovery
- context metadata MUST be audit-safe and MUST NOT contain raw credentials or PII

## Workflow and Task Fields

Workflows and tasks MAY define:

- `identity`
- `authorization_proof`
- `authorization`
- `evidence`
- `contract`

`contract` remains a separate block.

### Proposed Task Shape

```json
{
  "id": "query-graph",
  "name": "Query Graph",
  "shell": {
    "program": "scripts/query_graph.sh"
  },
  "target": {
    "session_target": "shell"
  },
  "identity": {
    "ref": "corp-agent",
    "auth": {
      "scopes": [
        "https://graph.microsoft.com/.default"
      ]
    }
  },
  "authorization_proof": {
    "ref": "ci-approval"
  },
  "authorization": {
    "ref": "prod-policy"
  },
  "evidence": {
    "ref": "ssh-proof"
  },
  "contract": {
    "allowed_paths": [
      "/work/reports"
    ],
    "required_trust_level": "supervised",
    "trust_enforcement": "strict",
    "audit": "always"
  },
  "schedule": {
    "cron": "0 * * * *"
  }
}
```

### `authorization_proof`

The workflow/task `authorization_proof` block is a scoped overlay on an `authorization_proof_profiles[]` entry.

It MAY contain:

- `ref`
- `claims`
- `verify`

Rules:

- `ref` is REQUIRED when `authorization_proof` is present
- `method`, `issuer`, and `proof` are defined only in `authorization_proof_profiles[]` and MUST NOT be declared inline at workflow/task scope
- workflow/task scope may only override audit-safe `claims` overlays and `verify` behavior, subject to the merge rules below

### `authorization`

The workflow/task `authorization` block is a scoped overlay on an `authorization_profiles[]` entry.

It MAY contain:

- `ref`
- `provider_config`
- `on_error`
- `request`
- `decision`

Rules:

- `ref` is REQUIRED when `authorization` is present
- `provider` is defined only in `authorization_profiles[]` and MUST NOT be declared inline at workflow/task scope
- workflow/task scope may override `provider_config`, `on_error`, `request`, and `decision` only as allowed by the merge rules below

### `contract`

The contract block defines execution boundaries that are enforced independently of identity resolution.

Trust-related contract fields:

- `required_trust_level` -- the minimum resolved trust level required for this task or workflow to execute
- `trust_enforcement` -- how the runtime reacts when the resolved trust level is below `required_trust_level`

Rules:

- `required_trust_level` uses the same canonical ordering as `identity.trust.level`
- when `trust_enforcement` is `advisory` or `strict`, `required_trust_level` MUST be present
- when `trust_enforcement` is `none`, `required_trust_level` MAY be omitted
- if `required_trust_level` is omitted, the contract imposes no minimum trust threshold
- `required_trust_level` is a floor imposed by the contract; `identity.trust.constraints.max_autonomy` is a ceiling imposed by the identity, and both MUST be satisfiable at the same time
- after workflow/task merge and before execution begins, the runtime MUST validate that the resolved `required_trust_level` does not exceed the resolved `max_autonomy`; if it does, resolution fails in `trust_evaluation`

## Resolution Semantics

Identity resolution is a three-stage merge:

1. referenced profile
2. workflow-level overrides
3. task-level overrides

For `on_failure`, the same pattern applies after shorthand expansion.

Authorization proof resolution follows the same profile-ref plus workflow/task overlay pattern as other declarative blocks, but it is evaluated before runtime identity resolution because it governs whether the manifest itself is authorized to proceed.

Authorization proof scope is the resolved execution unit:

- a workflow-level `authorization_proof` applies to every task in that workflow that does not override it
- a task-level `authorization_proof` applies only to that task
- verification summaries MUST be emitted at the same scope as the resolved declaration they cover
- runtimes and backends MUST NOT collapse different task-scoped proofs into one manifest-global verification result

### Authorization Proof Merge Rules

- a task-level `authorization_proof.ref` replaces the workflow-level ref entirely; proofs are not composable across levels
- `claims` overlays merge key by key (task claims override workflow claims for the same key)
- `verify.required` MAY be tightened from `false` to `true`, but it MUST NOT be relaxed from `true` to `false` at a narrower scope
- when a narrower scope replaces `authorization_proof.ref`, the resolved replacement MUST preserve any broader-scope verification requirement; replacing a proof whose resolved `verify.required` is `true` with one whose resolved `verify.required` is `false` is invalid
- when a broader-scope resolved proof requires verification, a narrower-scope replacement MUST NOT resolve to `method: "none"`
- for local `exec`, the resolved proof is verified once per executed task invocation during Phase 1
- for compiled backends, verification summary production occurs once per compiled execution unit using the resolved proof for that unit

### Authorization Merge Rules

- a task-level `authorization.ref` replaces the workflow-level ref entirely
- `provider_config` overlays merge key by key
- `on_error` MAY be tightened from `warn` to `deny`, but it MUST NOT be relaxed from `deny` to `warn` at a narrower scope
- `request.include` replaces rather than appends so callers can make the authorization input narrower and more explicit
- task-level authorization MAY tighten decision handling but MUST NOT reinterpret a provider's deny decision as permit

### `on_failure` Identity and Authorization Handling

When a task fails and triggers an `on_failure` handler, the handler resolves its own identity through the standard three-stage merge. It does not inherit the failed task's credential session.

Rules:

- the `on_failure` handler MAY reference the same identity profile as the failed task, but it receives a fresh session
- if the `on_failure` handler does not declare its own `identity` block, it inherits the workflow-level identity declaration (not the failed task's resolved session)
- the failed task's credential session is cleaned up (Phase 8) before the `on_failure` handler begins its own Phase 2 resolution
- the `on_failure` handler's audit record is a separate record linked to the failed task's `execution_id` via the `source` field

The same rules apply to the `authorization` block: if the `on_failure` handler does not declare its own `authorization` block, it inherits the workflow-level authorization declaration. Authorization evaluation (Phase 4.5) runs independently for the handler.

This ensures that a failure in the primary task does not leave stale credentials accessible to the handler, and that the handler's identity posture is independently auditable.

### Session Scope

Credential sessions are resolved per-task. Each task in a workflow runs through the full Phase 2 resolution, even if multiple tasks reference the same identity profile. This guarantees that task-level overrides (e.g., different scopes per task) are always respected.

When `auth.cache` is `memory`, the runtime MAY reuse a previously resolved session for a subsequent task if all of the following are true:

- the resolved identity profile (after three-stage merge) is identical to the cached session's profile
- the cached session has not expired
- the cached session's delegation validation is still current

When `auth.cache` is `state`, the same reuse rules apply across workflow runs, with the additional requirement that the persisted session file has not been externally invalidated.

When `auth.cache` is `none`, a fresh session is always resolved. This is the safest default and SHOULD be used when tasks have different scopes or audiences even if they reference the same profile.

### Merge Rules

- scalar values replace parent values
- object values merge key by key
- arrays replace rather than append
- `bindings` replace rather than merge
- `provider` change resets provider-specific assumptions and triggers full provider revalidation
- `trust.level` at task level MUST NOT exceed `trust.constraints.max_autonomy` from the profile level; if it does, validation fails and no session is created
- `delegation_policy` merges key by key; task-level constraints can tighten but not relax profile-level constraints:
  - `max_depth`: task value MUST be less than or equal to profile value (lower depth is tighter)
  - `allowed_delegators`: task value MUST be a subset of profile value, or profile value is empty (unrestricted) and task value restricts it (adding restrictions is tighter; removing restrictions from a restricted list is not permitted)
  - `require_grant_per_hop`: task value MAY set `true` when profile is `false` (adding the requirement is tighter) but MUST NOT set `false` when profile is `true` (removing the requirement relaxes the constraint)
- `handoff` declarations MAY be narrowed at workflow or task level but MUST NOT request a mode unsupported by the executing runtime or backend

## Provider Architecture

The design introduces a new execution identity provider registry.

### Identity Provider Interface

Each identity provider MUST implement the following core methods:

```js
{
  name,
  capabilities,
  validateProfile(profile, ctx),
  resolveSession(request, ctx),
  describeSession(session, ctx),
  materialize(session, presentation, ctx),
  cleanup(materialization, ctx)
}
```

Each identity provider MAY implement the following optional methods, gated by declared capabilities:

```js
{
  refreshSession(session, ctx),       // when capabilities.refreshable is true
  prepareHandoff(session, handoff, ctx),  // when capabilities.handoff_modes includes non-"none" values
  validateDelegation(chain, policy, ctx)  // when capabilities.delegation is true
}
```

When a provider does not implement an optional method, the runtime MUST check capabilities before calling it. If a manifest requests a capability the provider does not declare, validation MUST fail at `validateProfile` time rather than at runtime.

### `capabilities`

Providers SHOULD expose machine-readable capabilities:

- supported auth modes
- supported credential types
- supported presentation kinds
- refresh support
- delegation support
- explicit handoff support
- trust level support
- approval mechanisms
- evidence compatibility hints

Example:

```json
{
  "auth_modes": ["service", "on-behalf-of", "exchange"],
  "credential_types": ["access_token"],
  "presentation_kinds": ["env", "file"],
  "handoff_modes": ["none", "downscope"],
  "refreshable": true,
  "delegation": true,
  "approval_mechanisms": ["ciba"],
  "trust_levels": ["restricted", "supervised", "autonomous"]
}
```

### `validateProfile(profile, ctx)`

This validates provider-specific configuration after core manifest validation.

It MUST NOT resolve credentials.

It SHOULD validate delegation_policy constraints against provider capabilities.

### `resolveSession(request, ctx)`

This resolves credentials and returns a credential session.

It MUST:

- avoid writing secrets to disk unless required for provider operation
- return enough data for presentation and audit-safe description
- fail closed when required credentials are unavailable
- derive runtime instance attribution when the provider can supply it, or accept an explicit operator override when one is provided
- validate delegation chains against the declared delegation policy before issuing credentials

### `refreshSession(session, ctx)`

This refreshes an existing credential session if supported.

If unsupported, the provider MUST signal that clearly.

### `describeSession(session, ctx)`

This returns an audit-safe summary of the session.

It MUST NOT include raw secrets.

It SHOULD include runtime instance attribution, delegation chain summary, and trust level.

### `materialize(session, presentation, ctx)`

This materializes credentials for the wrapped tool.

It MAY:

- set environment variables
- create temporary files
- generate stdin payloads
- return no direct materialization

It MUST return cleanup metadata.

### `prepareHandoff(session, handoff, ctx)`

This prepares a derived credential for an explicit runtime handoff boundary.

It is only called when the executing runtime or backend models a first-class next hop and advertises `credential_handoff` capability.

It MAY:

- return a downscoped derivative credential
- return a transaction-scoped credential or token
- decline the request if the provider cannot satisfy the requested handoff mode safely

It MUST NOT be used to infer arbitrary nested service calls inside an opaque wrapped command.

### `cleanup(materialization, ctx)`

This removes temporary files and provider-created state where applicable.

Cleanup failures SHOULD be recorded as warnings.

### `validateDelegation(chain, policy, ctx)`

This validates a delegation chain against a delegation policy.

It MUST:

- verify the chain is acyclic
- verify each hop has a valid authorization grant when `require_grant_per_hop` is true
- verify the chain depth does not exceed `max_depth`
- verify each delegator is in `allowed_delegators` when that list is non-empty
- return a machine-readable validation result with per-hop status

It SHOULD be called during `resolveSession` for any auth mode involving delegation.

## Credential Session Shape

The runtime should normalize provider output into a stable session model.

### Proposed Session Shape

```json
{
  "provider": "entra-agent-id",
  "subject": {
    "principal": "agent://corp/secops-bot",
    "issuer": "https://login.microsoftonline.com/<tenant>",
    "run_as": null
  },
  "instance": {
    "id": "secops-bot-instance-001",
    "source": "provider"
  },
  "trust": {
    "declared_level": "supervised",
    "effective_level": "supervised"
  },
  "delegation_chain": [
    {
      "kind": "service",
      "principal": "agent://corp/secops-bot",
      "grant": "client-credentials",
      "validated": true
    }
  ],
  "delegation_validation": {
    "valid": true,
    "depth": 1,
    "acyclic": true,
    "all_grants_present": true
  },
  "credentials": {
    "access_token": {
      "kind": "bearer",
      "value": "<secret>",
      "audience": "https://graph.microsoft.com",
      "scopes": [
        "https://graph.microsoft.com/.default"
      ],
      "expires_at": "2026-03-20T18:00:00Z"
    }
  },
  "provider_assertions": {
    "tenant_id": "11111111-2222-3333-4444-555555555555"
  },
  "refresh": {
    "supported": true,
    "expires_at": "2026-03-20T18:00:00Z"
  },
  "handoff": {
    "mode": "none",
    "prepared": false
  }
}
```

Rules:

- `credentials` MAY contain secret values
- audit output MUST NOT record those secret values
- `provider_assertions` MUST remain audit-safe
- `delegation_chain` entries SHOULD include `grant` (the authorization grant type) and `validated` (whether the grant was verified)
- `delegation_validation` MUST be computed during `resolveSession` and included in the session
- `instance.id` SHOULD be present when the runtime or provider can surface meaningful actor-instance attribution; it is optional for runtimes that only have per-run `execution_id`
- any derived handoff credential MUST remain outside audit output

### `trust.effective_level` Derivation

The session's `trust.effective_level` is the trust level actually used for contract enforcement. It is derived as follows:

1. Start with the identity profile's `trust.level` (default: `supervised`)
2. Apply any workflow-level `trust.level` override (replaces, per merge rules)
3. Apply any task-level `trust.level` override (replaces, per merge rules)
4. Validate that the declared level does not exceed `trust.constraints.max_autonomy`
5. When the contract declares `required_trust_level`, validate that it does not exceed `trust.constraints.max_autonomy`
6. If validation passes, the declared level becomes `effective_level`

`trust.declared_level` in the session records the level from step 3 (the declared intent after merge). `trust.effective_level` records the enforced level after step 6. In valid configurations they are equal; if they would differ, resolution fails instead of silently rewriting the level.

### `instance.source` Values

The `instance.source` field describes where the instance identifier came from:

- `provider` -- the identity provider supplied the instance identifier (e.g., from a workload attestation, pod identity, or managed identity metadata)
- `operator` -- the operator explicitly supplied the instance identifier via `--instance-id` CLI flag or equivalent
- `runtime` -- the runtime generated the instance identifier (e.g., derived from process ID, container ID, or hostname)

When `instance` is absent from the session, no meaningful instance attribution was available.

## Provider Families

The architecture should support provider families without changing the core manifest model.

### Initial Provider Targets

- `none`
- `env-bearer`
- `file-bearer`
- `oidc-client-credentials`
- `oidc-token-exchange`
- `azure-managed-identity`
- `entra-agent-id`
- `aws-sts-assume-role`
- `gcp-workload-identity`
- `spiffe-jwt-svid`

Not all of these need to ship in the first implementation wave.

## Authorization Provider Architecture

Phase 4.5 uses a dedicated authorization provider registry, separate from identity resolution and authorization proof verification.

### Authorization Provider Interface

Each authorization provider MUST implement:

```js
{
  name,
  capabilities,
  validateProfile(profile, ctx),
  authorize(request, profile, ctx),
  describeDecision(decision, ctx)
}
```

### `capabilities`

Authorization providers SHOULD expose machine-readable capabilities:

- supported decision kinds
- escalation support
- batch support
- dry-run support

Example:

```json
{
  "decision_kinds": ["permit", "deny", "require-escalation"],
  "escalation": true,
  "batch": false,
  "dry_run": true
}
```

### `authorize(request, profile, ctx)`

This evaluates a single authorization request and returns a normalized decision.

It MUST:

- accept normalized input derived from the manifest's `authorization` profile and the current execution context
- return one of `permit`, `deny`, or `require-escalation`
- include an audit-safe explanation or policy reference when available
- when returning `require-escalation`, include enough audit-safe escalation context for the runtime to request approval or explain why execution was blocked
- rely on the resolved `authorization.on_error` policy for provider-error handling: `deny` fails closed, `warn` records a warning and skips Phase 4.5 for that execution unit

### Request Shape

The runtime normalizes authorization input to a stable request model:

```json
{
  "source": {
    "workflow_id": "bot-health",
    "task_id": "query-graph"
  },
  "identity": {
    "principal": "agent://corp/secops-bot",
    "trust_level": "supervised"
  },
  "contract": {
    "required_trust_level": "supervised",
    "allowed_paths": ["/work/reports"]
  },
  "command": {
    "program": "scripts/query_graph.sh",
    "args": []
  },
  "resource": null
}
```

Rules:

- `request.include` in the authorization profile determines which top-level sections are present
- authorization providers MUST treat omitted sections as unavailable, not as empty grants
- authorization decisions are separate from contract enforcement; a provider cannot widen contract boundaries

## Evidence Architecture

The current signing provider system should evolve into an evidence provider system.

### Evidence Provider Interface

Each evidence provider MUST implement:

```js
{
  name,
  methods,
  resolve(config, ctx),
  attest(payload, config, ctx),
  verify(envelope, options, ctx),
  describe(envelope, ctx)
}
```

### Required Behavior

- `attest` MUST accept a canonical payload
- `attest` SHOULD include `payload.context` metadata when configured in the evidence profile
- `verify` MUST return a machine-readable verdict
- `describe` MUST produce audit-safe metadata

### Compatibility

The current `ssh` and `none` signing providers map cleanly to this model.

## Execution Lifecycle

`agentcli exec` should evolve into the following pipeline.

### Phase 1: Manifest Loading

- load manifest
- expand shorthands
- validate core schema
- validate provider references
- resolve and verify manifest authorization proof when declared

### Phase 2: Identity Resolution

- resolve profile references
- merge workflow and task overrides
- validate provider-specific config
- validate delegation chain against delegation policy
- resolve runtime credential session
- resolve runtime instance attribution when available
- evaluate trust level
- describe audit-safe session metadata

### Phase 3: Presentation Materialization

- materialize credentials according to declared bindings
- build effective process environment
- build temporary file set
- build stdin payload if requested

### Phase 3.5: Credential Handoff (Optional, Runtime-Scoped)

- only enter this phase when the executing runtime or backend exposes an explicit downstream handoff boundary
- request provider-prepared derived credentials according to declared `handoff` mode
- fail closed if handoff is required by policy but unsupported by the active runtime or provider
- record whether a derived handoff credential was prepared

### Phase 4: Contract Evaluation

- evaluate allowed paths
- evaluate network and sandbox expectations
- evaluate audit policy
- when `contract.required_trust_level` is present, evaluate the resolved trust level against it before execution
- when trust matches the contract floor, continue normally
- when trust is below the contract floor and `trust_enforcement` is `none`, record the mismatch for audit and continue
- when trust is below the contract floor and `trust_enforcement` is `advisory`, record a warning and continue
- when trust is below the contract floor and `trust_enforcement` is `strict` and `trust.constraints.escalation` is `human-approval`, pause for approval, require a justification when configured, fail closed on denial or timeout, and continue only on explicit approval
- when trust is below the contract floor and `trust_enforcement` is `strict` and escalation is `fail` or unset, fail closed before Phase 4.5
- emit trust-escalation decisions and warnings to audit

### Phase 4.5: Authorization (Optional)

This is an optional hook point for per-action authorization. It is not required for basic execution but provides an integration point for external policy engines.

When configured, the runtime resolves the task's `authorization` block to an `authorization_profiles[]` entry and dispatches the normalized request to the named authorization provider.

When configured:

- invoke external policy engine (OPA, Cedar, Topaz, or equivalent) via configured authorization provider
- pass action context including resolved identity, trust level, target resource, and operation type
- evaluate policy decision (`permit`, `deny`, `require-escalation`)
- if the decision is `permit`, continue to execution
- if the decision is `deny`, fail closed before execution
- if the decision is `require-escalation` and the resolved trust/authorization policy supports `human-approval`, initiate CIBA flow or equivalent out-of-band approval
- if the decision is `require-escalation` and no supported approval path is configured for the execution unit, fail closed and record that escalation could not be satisfied
- if escalation is denied or times out, fail closed
- if the authorization provider errors, apply the resolved `authorization.on_error` policy: `deny` fails closed, `warn` records an audit warning and continues without a Phase 4.5 decision
- record authorization decision in audit output

When not configured (no `authorization` block resolves for the current task after three-stage merge):

- this phase is skipped entirely
- contract enforcement (Phase 4) remains the sole access control mechanism

Phase 4 and Phase 4.5 ordering: if Phase 4 (contract enforcement) fails closed -- for example, because `trust_enforcement: "strict"` rejects the resolved trust level -- Phase 4.5 is never reached. Contract enforcement is a prerequisite gate.

This phase is intentionally optional. Many deployments will rely on contract enforcement alone. The hook point exists so that organizations with fine-grained authorization requirements can integrate their policy infrastructure without modifying `agentcli` internals.

### Credential Lifetime and Execution Duration

Credentials are resolved in Phase 2 and materialized in Phase 3. Once a tool begins executing in Phase 5, `agentcli` does not monitor or refresh the credential during execution. If the tool execution outlasts the credential lifetime, the tool itself determines the failure behavior (e.g., the downstream API rejects an expired token).

This is a known limitation for local exec with long-running tasks. Mitigations:

- operators SHOULD ensure credential lifetimes exceed expected task duration
- for tasks with unpredictable duration, providers SHOULD issue credentials with generous lifetimes or operators SHOULD use `auth.refresh: "auto"` so that pre-execution refresh extends the window
- `agentcli` records `credentials.expires_at` in the audit record so that operators can detect tasks that ran past credential expiry
- future runtime backends MAY implement mid-execution refresh when the backend models long-lived sessions natively

### Phase 5: Execution

- execute tool
- capture stdout, stderr, exit code, duration
- compute command and result hashes
- parse structured output when requested

### Phase 6: Evidence

- build canonical evidence payload
- collect compliance context metadata if configured (model version, policy version, tool versions)
- attest the execution if configured
- verify evidence if required by policy

Evidence verification occurs after execution (Phase 5) has already completed. A verification failure does not undo execution. Instead:

- `evidence.verified` is set to `false` in the audit record
- when `verify.required` is `true` in the evidence profile, a verification failure causes `agentcli exec` to return a non-zero exit code even if the tool itself succeeded; the audit record includes the tool's actual result alongside the verification failure
- when `verify.required` is `false`, a verification failure is recorded as a warning but does not affect the exit code
- the evidence envelope (including the failed verification status) is always written to the audit record so that operators can investigate

### Phase 7: Audit

- write append-only audit record
- redact secrets
- include declared and resolved identity summaries
- include authorization proof summary when present
- include delegation chain validation summary
- include trust level and authorization decision
- include runtime instance attribution when available
- include handoff mode

### Phase 8: Cleanup

- delete temporary files
- destroy ephemeral materialization
- destroy any derived handoff credentials
- emit cleanup warnings if needed

## Audit Model

The audit record should become more structured than the current `signer` plus command hash model.

### Proposed Audit Record Shape

```json
{
  "execution_id": "abc123",
  "timestamp": "2026-03-20T16:00:00Z",
  "source": {
    "workflow_id": "bot-health",
    "task_id": "query-graph"
  },
  "declared_identity": {
    "provider": "entra-agent-id",
    "subject": {
      "kind": "agent",
      "principal": "agent://corp/secops-bot",
      "delegation_mode": "none"
    },
    "trust": {
      "level": "supervised"
    }
  },
  "authorization_proof": {
    "method": "jwt",
    "issuer": "https://ci.example.com",
    "verified": true
  },
  "resolved_identity": {
    "provider": "entra-agent-id",
    "subject": {
      "principal": "agent://corp/secops-bot",
      "issuer": "https://login.microsoftonline.com/<tenant>"
    },
    "instance": {
      "id": "secops-bot-instance-001",
      "source": "provider"
    },
    "trust": {
      "declared_level": "supervised",
      "effective_level": "supervised"
    },
    "delegation_chain": [],
    "delegation_validation": {
      "valid": true,
      "depth": 0,
      "acyclic": true
    },
    "credential_summary": {
      "credential_types": ["access_token"],
      "expires_at": "2026-03-20T18:00:00Z"
    },
    "provider_assertions": {
      "tenant_id": "11111111-2222-3333-4444-555555555555"
    },
    "handoff": {
      "mode": "none"
    }
  },
  "authorization": {
    "decision": "permit",
    "engine": "opa",
    "escalation": null
  },
  "contract": {
    "sandbox": "permissive",
    "network": "restricted",
    "allowed_paths": ["/work/reports"],
    "required_trust_level": "supervised",
    "trust_enforcement": "strict",
    "audit": "always"
  },
  "command": {
    "program": "scripts/query_graph.sh",
    "args": [],
    "cwd": "/work/reports"
  },
  "hashes": {
    "command": "sha256:...",
    "result": "sha256:..."
  },
  "result": {
    "exit_code": 0,
    "duration_ms": 187,
    "stdout_bytes": 128,
    "stderr_bytes": 0,
    "structured_present": true
  },
  "evidence": {
    "provider": "ssh",
    "method": "ssh-signature",
    "verified": true,
    "key_fingerprint": "SHA256:...",
    "context": {
      "model_version": "gpt-5-mini-2026-02",
      "policy_version": "v1.3.0"
    }
  },
  "warnings": []
}
```

### Resolution Failure Records

When identity resolution (Phase 2) fails, the runtime MUST still write an audit record. The record SHOULD include:

- `declared_identity` as normal
- `resolved_identity` set to `null`
- a `resolution_error` field containing a machine-readable error summary

Example:

```json
{
  "execution_id": "def456",
  "timestamp": "2026-03-20T16:05:00Z",
  "source": {
    "workflow_id": "bot-health",
    "task_id": "query-graph"
  },
  "declared_identity": {
    "provider": "entra-agent-id",
    "subject": {
      "kind": "agent",
      "principal": "agent://corp/secops-bot",
      "delegation_mode": "none"
    },
    "trust": {
      "level": "supervised"
    }
  },
  "resolved_identity": null,
  "resolution_error": {
    "phase": "credential_acquisition",
    "provider": "entra-agent-id",
    "code": "token_request_failed",
    "message": "Failed to acquire access token: tenant not reachable",
    "retryable": true
  },
  "result": null,
  "warnings": []
}
```

Rules for resolution failures:

- `resolution_error.phase` identifies where resolution failed: `profile_validation`, `delegation_validation`, `credential_acquisition`, or `trust_evaluation`
- `resolution_error.code` is a machine-readable error code defined by the provider or the runtime
- `resolution_error.message` is a human-readable description that MUST NOT contain raw secrets
- `resolution_error.retryable` indicates whether the failure is transient
- when resolution fails, Phases 3-8 are skipped except for Phase 7 (Audit) and Phase 8 (Cleanup of any partial state)

### Authorization Proof Failure Records

When manifest authorization proof verification (Phase 1) fails and `verify.required` is `true`, the runtime MUST reject the manifest before identity resolution begins. A failure record SHOULD still be written to audit:

```json
{
  "execution_id": "ghi789",
  "timestamp": "2026-03-20T16:10:00Z",
  "source": {
    "workflow_id": "bot-health",
    "task_id": "query-graph"
  },
  "declared_identity": null,
  "authorization_proof": {
    "method": "jwt",
    "issuer": "https://ci.example.com",
    "verified": false,
    "error": "signature verification failed: key not found in issuer JWKS"
  },
  "resolved_identity": null,
  "result": null,
  "warnings": []
}
```

Rules:

- when authorization proof verification fails with `verify.required: true`, all subsequent phases (2-8) are skipped except audit (Phase 7)
- `declared_identity` is `null` because identity resolution never began
- the `authorization_proof.error` field contains a human-readable reason that MUST NOT expose raw proof values
- when `verify.required` is `false` and verification fails, the failure is recorded as a warning and execution proceeds normally

### Audit Rules

- raw credentials MUST NOT appear in audit records
- raw access tokens MUST NOT appear in audit records
- credential file contents MUST NOT appear in audit records
- derived handoff credentials MUST NOT appear in audit records
- provider summaries SHOULD include expiry and issuer when safe
- evidence metadata SHOULD include method and key fingerprint when safe
- runtime instance attribution MUST be included when present so that specific actor instances are traceable
- delegation chain validation summary MUST be included when delegation is involved
- trust level and authorization decisions MUST be included when trust enforcement is active
- handoff mode MUST be recorded when used or requested
- manifest authorization proof summary SHOULD be included when present
- raw authorization proof values (JWTs, signatures, certificate chains) MUST NOT appear in audit records; only method, issuer, and verification status are safe for audit

### Audit Compaction

For high-frequency task executions (e.g., tasks scheduled every minute), the full audit record may produce significant log volume. To manage this:

- audit writers SHOULD omit optional blocks that hold only default values; for example, when `delegation_chain` is empty, `delegation_validation.depth` is 0, `authorization.engine` is null, and `handoff.mode` is `none`, these blocks MAY be omitted from the record
- a reader MUST treat absent optional blocks as holding their default values
- the `audit` contract field controls whether records are written at all (`none`, `on-failure`, `always`); this remains the primary volume control
- implementations MAY offer an `audit: "compact"` mode that aggressively omits default-valued fields; this is an implementation choice, not a manifest-level specification

## Compiler Behavior

Compile targets must preserve identity intent, not resolve credentials.

Authorization proof is the main exception to "purely declarative" handoff semantics across backend boundaries:

- `compile` remains declarative and MUST NOT perform verifier I/O
- `apply` MUST either hand the manifest to a target that advertises `authorization_proof_verification` or verify proofs locally and persist only audit-safe verification summaries at the same scope as the compiled execution units
- backends that do not advertise `authorization_proof_verification` MUST NOT receive raw proof values
- if any compiled execution unit resolves an `authorization` block, `apply` MUST hand the manifest only to a target that advertises `authorization_hook`; unlike authorization proof, there is no local compile-time fallback because authorization decisions depend on runtime execution context
- for any backend that advertises `authorization_proof_verification` or `authorization_hook`, the handoff artifact for each compiled execution unit MUST contain either:
  - the fully resolved scoped declaration for the relevant block (`authorization_proof` and/or `authorization`), including all workflow/task overlays after merge, or
  - a backend-supported pointer to the original manifest plus a normative requirement that the backend re-resolve that block from the source manifest before execution
- bare profile refs plus provider names are insufficient on their own for capable backends, because runtime semantics depend on the resolved overlays for each execution unit

### `standalone`

The standalone target SHOULD preserve:

- identity profile definitions (including trust and delegation_policy)
- authorization proof profile definitions
- authorization profile definitions
- evidence profile definitions (including payload.context)
- resolved declaration overlays
- provider names
- execution requirements (including `required_trust_level` and `trust_enforcement`)

It MUST NOT:

- resolve credentials
- embed tokens
- perform provider I/O

### `openclaw-scheduler`

The scheduler target SHOULD compile:

- provider refs
- identity subject metadata
- when the target advertises `authorization_proof_verification`, the fully resolved scoped `authorization_proof` declaration per compiled execution unit (including resolved `ref`, merged `claims`, merged `verify`, and method metadata), or a source-manifest pointer that the backend is required to re-resolve before execution; otherwise verified authorization-proof summaries produced during `apply`, scoped per compiled execution unit
- when the target advertises `authorization_hook`, the fully resolved scoped `authorization` declaration per compiled execution unit (including resolved `ref`, merged `provider_config`, resolved `on_error`, resolved `request`, resolved `decision`, and provider metadata), or a source-manifest pointer that the backend is required to re-resolve before execution; otherwise `apply` MUST reject the handoff
- trust level and constraints
- contract metadata (including `required_trust_level` and `trust_enforcement`)
- evidence requirements (including context fields)
- delegation policy

It MUST NOT:

- embed secret material
- embed access tokens
- serialize provider session state into job specs

### Target Capability Model

Future target capabilities SHOULD distinguish:

- `identity_declaration`
- `runtime_identity_resolution`
- `evidence_generation`
- `audit_export`
- `trust_evaluation`
- `delegation_validation`
- `credential_handoff`
- `authorization_proof_verification`
- `authorization_hook`

## CLI Design

### Proposed Commands

- `agentcli authorization-proof methods`
- `agentcli authorization-proof schema <method>`
- `agentcli authorization-proof verify <manifest> <task-id> [--workflow id]`
- `agentcli identity providers`
- `agentcli identity schema <provider>`
- `agentcli identity resolve <manifest> <task-id> [--workflow id]`
- `agentcli identity validate-delegation <manifest> <task-id> [--workflow id]`
- `agentcli whoami <manifest> <task-id> [--workflow id]`
- `agentcli authorization providers`
- `agentcli authorization schema <provider>`
- `agentcli authorization evaluate <manifest> <task-id> [--workflow id]`
- `agentcli evidence providers`
- `agentcli evidence schema <provider>`

### Existing `exec`

`agentcli exec` SHOULD remain the main entry point for local task execution.

It SHOULD gain:

- `--identity-debug`
- `--evidence-provider`
- `--require-evidence`
- `--presentation-debug`
- `--require-authorization` (require that the selected execution unit resolve an authorization policy)
- `--instance-id` (explicitly set the runtime instance identifier for this execution)

`--signer` SHOULD eventually be replaced by `--evidence-provider`.

`--require-authorization` means the selected execution unit MUST resolve an `authorization` block after normal merge. If none resolves, `exec` fails before execution rather than inventing a provider or policy profile implicitly.

No CLI flag should elevate or directly override the resolved trust level for an execution. Trust changes must come from manifest declarations or explicit approval flows.

## JSON-RPC Design

### Proposed Methods

- `agentcli.authorizationProof.methods`
- `agentcli.authorizationProof.schema`
- `agentcli.authorizationProof.verify`
- `agentcli.identity.providers`
- `agentcli.identity.schema`
- `agentcli.identity.resolve`
- `agentcli.identity.validateDelegation`
- `agentcli.authorization.providers`
- `agentcli.authorization.schema`
- `agentcli.authorization.evaluate`
- `agentcli.evidence.providers`
- `agentcli.evidence.schema`
- `agentcli.exec`
- `agentcli.audit`

### Result Shapes

Identity resolution results SHOULD be safe by default:

- declared identity (including trust level)
- resolved subject
- runtime instance attribution when available
- provider metadata
- credential summary
- delegation chain validation summary
- no raw tokens

Authorization-proof verification results SHOULD return:

- method
- issuer
- verification status
- manifest digest
- audit-safe claim summary

Authorization evaluation results SHOULD return:

- normalized decision (`permit`, `deny`, `require-escalation`)
- provider name
- audit-safe policy reference or explanation

## Security Model

### Secret Handling

- manifests MUST NOT contain raw client secrets or bearer tokens
- `value_from` indirection SHOULD be used for sensitive inputs
- providers SHOULD prefer workload identities, managed identities, certificates, or external brokers over static shared secrets
- static API keys are an anti-pattern; short-lived credentials with explicit expiration are required

### Materialization Safety

- temp files MUST be created with restrictive permissions
- materialized credentials MUST be cleaned up after execution unless explicitly retained
- environment variable injection SHOULD be treated as sensitive and redacted from logs

### Delegation Safety

- delegation chains MUST be validated before credential issuance
- circular delegation MUST be rejected
- each delegation hop SHOULD have a recorded and verifiable authorization grant
- delegation depth MUST respect the configured `max_depth`
- delegation policy violations MUST fail closed and be recorded in audit

### Handoff Safety

- raw access tokens MUST NOT be forwarded by `agentcli` across an explicit credential handoff boundary
- non-`none` handoff modes are only valid when the active runtime or backend advertises `credential_handoff` capability
- derived handoff credentials MUST have shorter lifetimes or narrower scope than the source credential unless the provider's security model defines an equivalent transaction-bound mechanism
- handoff mode MUST be recorded in audit output so that credential flow is traceable when handoff is used

### Trust and Escalation Safety

- trust level evaluation MUST occur before execution, not after
- when `contract.required_trust_level` exceeds the resolved identity trust level, the runtime MUST apply the Phase 4 matrix exactly: `none` records only, `advisory` warns and proceeds, `strict` plus `human-approval` pauses for approval, and `strict` plus `fail` (or no escalation) fails closed
- when Phase 4.5 returns `require-escalation` and no supported approval path is configured, the runtime MUST fail closed rather than downgrade the decision to `permit`, `warn`, or contract-only handling
- human approval requests (via CIBA or equivalent) MUST have a timeout; indefinite waits are not permitted
- escalation decisions MUST be recorded in audit output
- an identity MUST NOT self-elevate its own trust level during execution

### Audit Safety

- audit writers MUST use structured allowlists, not ad hoc object dumping
- provider `describeSession` output MUST be audit-safe by construction
- runtime instance attribution MUST be included in audit records when available

### Verification

- evidence verification SHOULD be explicit and machine-readable
- verification failures MUST not silently downgrade to success

### Fallbacks

- providers MAY support fallback behavior
- fallback behavior MUST be explicit in the manifest or operator input
- fallback behavior MUST be written to audit output

## Migration from `0.1`

This design should be treated as a manifest spec `0.2` change.

### Breaking Conceptual Changes

- `identity` becomes a richer execution identity model with runtime instance attribution, trust levels, and delegation
- manifest authorization proof is separated from both subject identity and runtime evidence
- runtime evidence is separated from identity
- current signing provider registry becomes evidence provider registry
- trust and delegation are new first-class concepts

### Field Mapping

Current `0.1` fields map as follows:

- `identity.principal` -> `identity.subject.principal`
- `identity.run_as` -> `identity.subject.run_as`
- `identity.attestation` -> `authorization_proof.ref` plus an `authorization_proof_profiles[]` entry that preserves the manifest-time authorization proof separately from runtime evidence

New fields with no `0.1` equivalent:

- `identity.subject.kind` (new)
- `identity.subject.delegation_mode` (new)
- `identity.auth.delegation_policy` (new)
- `identity.trust` (new)
- `authorization_proof_profiles` (new)
- `authorization_profiles` (new)
- `workflow.authorization` / `task.authorization` (new)
- `contract.required_trust_level` (new)
- `identity.presentation.handoff` (new)
- `evidence.payload.context` (new)

### Runtime Migration

- current `ssh` signing provider becomes `ssh` evidence provider
- current `none` signing provider becomes `none` evidence provider
- current `exec --signer` flag becomes `exec --evidence-provider`

### Compatibility Strategy

The cleanest implementation is a spec-versioned change:

- `0.1` keeps the current identity block
- `0.2` adopts the new model
- implementation MAY provide a one-way conversion utility
- the conversion utility SHOULD set `trust.level` to `supervised`, `delegation_mode` to `none`, `handoff` to `none`, and omit `authorization_proof` and `authorization` blocks (no authorization proof or external authorization by default) as safe defaults

## Implementation Plan

### Implementation Status

Implementation began 2026-03-21. The following status annotations track progress.

Status key: [DONE] implemented, [PARTIAL] partially implemented, [PENDING] not started.

### Phase 1: Internal Refactor and Standards Alignment

- [DONE] introduce `src/identity/`
- [DONE] rename or conceptually replace `src/signing/` with `src/evidence/` (note: `src/signing/` preserved for v0.1 backward compat; `src/evidence/` created alongside it)
- [DONE] move runtime credential logic out of `src/exec.js` (credential resolution lives in identity provider `resolveSession`, evidence in evidence provider `attest`)
- [DONE] review identity provider interface against AIMS layers to ensure compatibility
- [DONE] define runtime instance attribution strategy (provider-supplied, operator override via --instance-id, execution-only fallback)
- [DONE] define URI format conventions for `principal` field (agent:// and spiffe:// in examples and docs)

### Phase 2: Core Schema

ALL items [DONE]:

- [DONE] add `identity_profiles` (including `subject.kind`, `subject.delegation_mode`)
- [DONE] add `authorization_proof_profiles`
- [DONE] add `authorization_profiles`
- [DONE] add `evidence_profiles` (including `payload.context`)
- [DONE] add richer workflow/task `identity`
- [DONE] add workflow/task `authorization_proof`
- [DONE] add workflow/task `authorization`
- [DONE] add workflow/task `evidence`
- [DONE] add `contract.required_trust_level`
- [DONE] add `trust` block to identity profiles
- [DONE] add `delegation_policy` to auth block
- [DONE] add `handoff` to presentation block

### Phase 3: Provider Registries

- [DONE] ship identity provider registry
- [DONE] ship authorization proof verifier registry
- [DONE] ship authorization provider registry
- [DONE] adapt current SSH signing provider to evidence provider API
- [DONE] ship `none`, `env-bearer` providers; [DONE] `oidc-client-credentials` provider; [DONE] `file-bearer` provider
- [DONE] ship `jwt` and `none` authorization-proof verifiers; [DONE] `detached-signature` and `certificate` verifiers
- [DONE] shipping at least one real credential acquisition provider (`oidc-client-credentials` validates the architecture end-to-end)

Implementation note: the `oidc-client-credentials` provider uses Node 22+ built-in `fetch()` for token endpoint calls, avoiding external HTTP dependencies.

### Phase 3.5: Explicit Credential Handoff

- [DONE] implement handoff mode handling in exec.js Phase 3.5
- [DONE] implement `prepareHandoff` in providers (`oidc-token-exchange` implements downscope handoff; other providers declare `handoff_modes: ['none']`)
- [DONE] support `downscope` first (declared in schema; actual downscoping deferred until a provider implements it)
- [DONE] ensure handoff metadata flows through to audit records
- [DONE] keep local opaque shell/prompt execution on `handoff: none`

Implementation note: Phase 3.5 checks for provider handoff capability and calls `prepareHandoff` when available. For initial providers (none, env-bearer, file-bearer, oidc-client-credentials), handoff is always `none`. Handoff mode and prepared status are recorded in audit records.

### Phase 4: Execution Integration

- [DONE] update `exec` pipeline with the full Phase 1-8 lifecycle
- [DONE] verify manifest authorization proof during Phase 1 for local execution
- [DONE] add runtime instance attribution to execution context and audit records when available
- [DONE] implement delegation chain validation via `validateDelegation` (structural validation in session; provider-level `validateDelegation` called when capability is declared)
- [DONE] implement trust level evaluation in contract enforcement
- [DONE] add authorization hook point (Phase 4.5 in lifecycle)
- [DONE] update audit format with delegation, trust, handoff, runtime-instance, and authorization fields
- [DONE] add provider discovery CLI and RPC
- [DONE] add `agentcli identity validate-delegation` command

Implementation note: exec.js detects v0.1 vs v0.2 manifests (`manifest.version === '0.2' || Boolean(manifest.identity_profiles)`) and dispatches to separate code paths. The v0.1 path is preserved exactly for backward compatibility.

### Phase 5: Backend Handoff

- [DONE] preserve declarations in standalone compile output (including trust, delegation_policy, handoff, context, authorization proof, and authorization profiles)
- [DONE] add identity/evidence metadata to scheduler-target compilation (flat fields)
- [DONE] add target capability flags for trust_evaluation, delegation_validation, credential_handoff, authorization_proof_verification, authorization_hook
- [DONE] make `apply` verify authorization proof locally when the target lacks `authorization_proof_verification`
- [DONE] make `apply` reject manifests whose compiled execution units resolve `authorization` when the target lacks `authorization_hook`
- [DONE] ensure capable backends receive per-execution-unit resolved authorization-proof and authorization declarations

Implementation note: `apply.js` was made async to support dynamic import of authorization proof verifiers during local verification. Target capability flags are defined in `src/targets.js` features.

### Phase 6: Real Providers

- [DONE] `oidc-client-credentials` as the initial cloud-neutral credential acquisition provider
- [DONE] `oidc-token-exchange` for RFC 8693 token exchange (supports delegation chains and downscope handoff)
- [DONE] add enterprise and cloud-specific providers: `azure-managed-identity` (IMDS), `aws-sts-assume-role` (STS with Signature V4), `gcp-workload-identity` (metadata server), `spiffe-jwt-svid` (Workload API + file-based SVID)
- [DONE] `entra-agent-id` provider -- authenticates via Entra token endpoint with JWT bearer client assertion, supports IMDS fallback, GUID validation, downscope handoff, and delegation
- [DONE] providers implement trust level capabilities from the start
- [DONE] ship at least one authorization provider: `opa` provider implements OPA REST API integration via fetch()

Implementation note: All ten identity providers are fully implemented and functional. Enterprise providers (`azure-managed-identity`, `aws-sts-assume-role`, `gcp-workload-identity`, `spiffe-jwt-svid`, `entra-agent-id`) use their platform's native metadata endpoints and fail with clear error messages when not running in the target environment. The `aws-sts-assume-role` provider includes a minimal AWS Signature V4 implementation using Node's built-in `crypto` module. The `spiffe-jwt-svid` provider supports both file-based SVID acquisition (for Kubernetes projected volumes) and HTTP-based Workload API access.

### Additional Implementation Items

- [DONE] v0.1 to v0.2 conversion utility (`src/convert.js`, CLI `agentcli convert`, RPC `agentcli.convert`)
- [DONE] v0.2 example manifest (`examples/identity-v2.json`)
- [DONE] v0.2 test coverage -- 365 total tests including 12 end-to-end integration tests (credential materialization, trust enforcement, authorization proof rejection, evidence generation, file-bearer e2e, validation of malformed profiles)
- [DONE] scheduler schema updated with v0.2 flat fields
- [DONE] comprehensive v0.2 profile validation in `validateManifest` (identity profiles, authorization proof profiles, authorization profiles, evidence profiles, cross-reference validation for dangling refs)
- [DONE] v0.1 to v0.2 converter produces proper profile refs (not inline identity blocks)

### Implementation Decisions

The following decisions were made during implementation and differ from or extend the original proposal.

#### v0.1/v0.2 Dual-Path Execution

`exec.js` detects the manifest version and dispatches to entirely separate code paths rather than using a single unified path with conditionals. Detection logic: `manifest.version === '0.2' || Boolean(manifest.identity_profiles)`. This guarantees zero behavioral change for v0.1 manifests and avoids accidental regressions from v0.2 logic affecting v0.1 execution.

#### `src/signing/` Preserved Alongside `src/evidence/`

The original plan called for renaming `src/signing/` to `src/evidence/`. Instead, `src/signing/` was preserved unchanged for v0.1 backward compatibility, and `src/evidence/` was created as a new parallel directory. The SSH evidence provider in `src/evidence/ssh.js` reimplements the signing logic cleanly rather than importing from `src/signing/ssh.js`. This avoids coupling the v0.2 evidence system to the v0.1 signing interface.

#### MANIFEST_VERSION Raised to '0.2'

The exported `MANIFEST_VERSION` constant is now `'0.2'`, which matches the public discovery surface exposed by `agentcli version`, `agentcli schema manifest`, and the JSON-RPC `agentcli.version` method. Backward compatibility for existing v0.1 manifests is preserved in validation: the validator accepts both `'0.1'` and `'0.2'`, while the schema and compile output use `'0.2'` as the canonical current spec version.

#### Async Identity Resolution

`executeTaskV2` is an `async` function because identity providers like `oidc-client-credentials` use `fetch()` for token endpoint calls. The v0.1 path (`executeTaskV1`) remains synchronous. The public `executeTask` export returns a Promise for v0.2 manifests and a plain object for v0.1 manifests. All callers in `cli.js` and `jsonrpc.js` use `await`, which is a no-op on non-Promise values.

#### Async `applyManifestToScheduler`

`applyManifestToScheduler` was changed from sync to async to support dynamic import of authorization proof verifier modules during local proof verification (when the target backend lacks `authorization_proof_verification` capability). All test call sites were updated to await the result.

#### Dynamic Imports for v0.2 Modules in CLI/RPC

New CLI commands and JSON-RPC methods use dynamic `await import()` for v0.2 modules (identity providers, evidence providers, authorization proof verifiers, authorization providers). This avoids loading v0.2 code when only v0.1 features are used, keeping startup time and memory usage unchanged for v0.1 workflows.

#### Provider Registration via Side-Effect Imports

Each provider file auto-registers with its registry on import (e.g., `import './identity/none.js'` registers the `none` identity provider). This follows the existing pattern from `src/signing/ssh.js` and avoids requiring callers to explicitly register providers.

#### JWT Verifier Signature Verification

The JWT authorization proof verifier performs structural validation, temporal checks (exp/nbf), and claims matching without external dependencies. Cryptographic signature verification (RS256, ES256) is supported when a `ctx.trustedKey` (PEM public key) is provided, using Node's built-in `crypto.createVerify`. When no trusted key is available, verification proceeds with `signature_verified: false` and a descriptive reason, allowing structural/claims validation to still provide value.

#### Certificate Verifier Uses `crypto.X509Certificate`

The certificate authorization proof verifier uses Node's built-in `crypto.X509Certificate` class (available since Node 15) for certificate parsing, validity checking, and chain verification. No external X.509 libraries are needed.

#### file-bearer Provider Permission Checking

The `file-bearer` identity provider checks file permissions via `statSync` and warns (but does not fail) if the token file is world-readable (mode bits include `0o004`). The warning is recorded in `provider_assertions.permission_warning` and flows through to audit output.

#### Conversion Utility Attestation Mapping

The v0.1 to v0.2 conversion utility maps legacy `identity.attestation` strings to `authorization_proof_profiles` entries by inferring the method from the attestation string content: strings containing "oidc" or "jwt" map to method `jwt`, strings containing "ssh" or "signature" map to `detached-signature`, strings containing "cert" or "x509" map to `certificate`, and all others map to `none`. Generated profile IDs use a `legacy-` prefix for traceability (e.g., `legacy-ssh-signature`).

#### Sync/Async Dual Dispatch in executeTask

`executeTask` remains a non-async function that internally routes to `executeV1()` (synchronous, returns plain object) or `executeV2()` (async, returns Promise). This preserves v0.1 test compatibility where tests call `executeTask` without `await` and use `assert.throws` for synchronous error testing. All production callers (cli.js, jsonrpc.js) use `await`, which is a no-op on non-Promise values.

#### Resolution Failure Audit Records

When Phase 2 (identity resolution) fails, the runtime writes an audit record with `resolved_identity: null` and a `resolution_error` field containing `{ phase, provider, code, message, retryable }` before rethrowing. This ensures audit trail completeness even for failed executions, as required by the spec.

#### Authorization Proof Failure Audit Records

When Phase 1 (authorization proof verification) fails with `verify.required: true`, the runtime writes an audit record with `declared_identity: null` and the proof verification summary before throwing. This captures pre-execution authorization failures in the audit trail.

#### OPA Authorization Provider

The OPA provider (`src/authorization/opa.js`) communicates via OPA's REST API (`POST /v1/data/<package>/<rule>`), normalizing OPA's flexible response formats (boolean, object with `.allow`, or string) into the standard decision set. Error handling respects the `on_error` policy: `deny` fails closed, `warn` records and continues.

#### Token Exchange Provider with Downscope Handoff

The `oidc-token-exchange` provider (`src/identity/oidc-token-exchange.js`) is the first provider to implement `prepareHandoff` with `downscope` mode. Downscoping works by performing a secondary token exchange using the current access token as the subject token with a reduced scope/audience. The provider also implements `validateDelegation` for delegation chain verification (acyclicity, depth limits, grant presence).

#### Scheduler Target Capability Defaults

The openclaw-scheduler target declares `authorization_proof_verification: false` and `authorization_hook: false` because the scheduler runtime itself does not yet implement these capabilities. When these are false, `apply.js` verifies authorization proofs locally during apply (for proofs marked `verify.required: true`) and rejects manifests that declare authorization blocks. These flags can be flipped to `true` when the scheduler runtime adds native support.

## Rejected Alternatives

### Add a single new enum under the current `identity` block

Rejected because it would bake vendor-specific runtime semantics into a metadata field that is too small for the problem.

### Treat authentication and attestation as one provider system

Rejected because credential acquisition and post-execution proof are different problems with different lifecycles.

### Resolve credentials at compile time

Rejected because it is unsafe and destroys backend portability.

### Store raw tokens in audit for forensic completeness

Rejected because it creates an unacceptable secret-handling risk.

### Model trust as a simple boolean (trusted/untrusted)

Rejected because real-world agent deployments require graduated autonomy. Agents earn trust over time, and binary models force a choice between no autonomy and full autonomy with no intermediate states. The graduated model (`untrusted`, `restricted`, `supervised`, `autonomous`) supports progressive trust building while keeping the default (`supervised`) safe.

### Make per-action authorization a required lifecycle phase

Rejected because it would force all deployments to integrate a policy engine even when contract enforcement is sufficient. The optional hook point preserves simplicity for basic use cases while enabling advanced authorization for organizations that need it.

### Implement agent registry and discovery in agentcli

Rejected because agent fleet governance is a platform concern, not a CLI tool concern. `agentcli` identity profiles are designed to be registry-compatible but registry services belong in external systems (Entra Agent Registry, organizational CMDBs, dedicated agent governance platforms).

## Open Design Constraints

The following constraints should guide review:

- the manifest must stay readable and generatable as raw JSON
- provider-specific complexity must remain inside provider plugins
- runtimes must be able to consume declarations without needing compile-time secrets
- audit output must remain safe for agent consumption
- the architecture must support enterprise agent identities without being designed around a single vendor
- runtime instance attribution must be cheap to produce when available and must not require external coordination for basic use cases
- delegation validation must fail closed; an invalid chain is never silently accepted
- trust level evaluation must be deterministic and auditable
- credential handoff safety must be the default; forwarding raw credentials is never implicit
- the architecture should remain compatible with IETF AIMS as that standard evolves

## Recommendation

Adopt this architecture direction for `agentcli` `0.2`.

The key decision is not whether to support one specific identity platform.

The key decision is that `agentcli` should formalize:

- execution identity with runtime instance attribution
- provider-backed credential acquisition with delegation validation
- explicit credential presentation with explicit handoff safety
- graduated trust and escalation for autonomous operations
- independent evidence generation with compliance context
- audit-safe execution records with full identity, delegation, and authorization provenance

That is the right abstraction boundary for a future where agent identities become normal infrastructure. The alignment with IETF AIMS, SPIFFE, and enterprise systems like Entra Agent ID validates that this direction is not speculative but reflects the consensus forming across the industry in 2025-2026.
