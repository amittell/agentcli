# Architecture

## Split

`openclaw-scheduler`

- runtime
- dispatcher loop
- SQLite state
- retries, approvals, delivery, recovery
- durable dispatch queue

`agentcli`

- manifest schema
- validation
- compile target adapters
- scheduler apply / upsert surface
- standalone planning surface
- scheduler inspection surface
- machine-readable CLI
- stdio JSON-RPC server
- non-durable local shell execution for `exec` and `run`
- local approval gate for direct `exec` (single-use ssh-signed grants; no queue, no cron coupling, no multi-actor routing)

The local gate and the scheduler's durable gate coexist: both honor the same `approval.policy` and `approval.risk_level` declarations in the manifest. `agentcli exec` enforces the gate for single-machine invocations using `~/.agentcli/state/approvals.ndjson`; `openclaw-scheduler` enforces the gate for cron-triggered durable execution using its own approval queue.

## Backend Model

`agentcli` has two backend stories:

- `standalone`: portable plan, validation, schema, describe, JSON-RPC
- `openclaw-scheduler`: compile target, apply/upsert path, and runtime inspection

This makes the standalone control plane useful on its own while also giving `openclaw-scheduler` a clean authoring and integration surface.

## Execution Identity Architecture

Manifest spec `0.2` introduces a full execution identity model. The detailed specification lives in `docs/execution-identity.md`; this section provides an architectural overview.

### Six-Layer Model

The identity architecture separates concerns into six distinct layers:

1. **Subject Declaration** -- the logical principal the task intends to act as (human delegate, autonomous service, enterprise agent, workload identity). Declarative and portable across backends.
2. **Manifest Authorization Proof** -- pre-execution proof that the workflow declaration was authorized (CI-issued JWT, signed deployment token, certificate reference, detached signature). Static, travels with the manifest, distinct from runtime credentials and execution evidence.
3. **Authentication and Credential Acquisition** -- runtime credential resolution through a provider plugin (auth mode, scopes, audiences, delegation chains, token exchange). Async and provider-backed.
4. **Credential Presentation** -- how the wrapped tool receives credentials at execution time (environment variables, temporary files, stdin). Explicit because authentication and tool execution are decoupled.
5. **Contract Enforcement** -- execution boundary evaluation (sandbox, allowed paths, network expectations, cost limits, required trust level). Consumes identity metadata but is architecturally separate from identity.
6. **Evidence and Audit** -- post-execution proof and structured audit records (SSH signatures, KMS-backed signatures, Sigstore envelopes). Consumes identity; does not own it.

### Provider Registry Pattern

Four separate provider registries serve distinct concerns:

- **Identity provider registry** -- resolves credentials for declared identity profiles (`none`, `env-bearer`, `oidc-client-credentials`, `oidc-token-exchange`, and future enterprise providers).
- **Authorization proof verifier registry** -- validates manifest-time authorization proof (`jwt`, `certificate`, `detached-signature`, `none`).
- **Evidence provider registry** -- generates and verifies post-execution attestation (`ssh`, `none`). Conceptual successor to the v0.1 signing provider.
- **Authorization provider registry** -- dispatches per-action authorization to external policy engines (`opa`).

Each provider file auto-registers with its registry on import (side-effect registration). Providers expose machine-readable `capabilities` objects for discovery, and the runtime checks capabilities before calling optional methods. This allows capability-based provider discovery without a central configuration file.

### Execution Lifecycle

`agentcli exec` runs the following pipeline for v0.2 manifests:

- **Phase 1: Static preparation**: load, expand, validate, resolve the selected task, and compute the canonical manifest digest and secret-safe effective execution binding.
- **Phase 2: Approval gate**: enforce `auto-reject` or atomically consume a matching manual grant before any live side effect. The grant binds the complete effective configuration, scope, and timeout.
- **Phase 3: Runtime boundary preparation**: resolve the signing provider and require the requested sandbox, allowed-path, and network enforcement. Missing enforcement fails closed.
- **Phase 4: Manifest authorization proof**: validate proof configuration, acquire the proof value, and cryptographically verify every non-`none` method against the canonical manifest.
- **Phase 5: Identity resolution and presentation**: validate the provider before network access, resolve the session and delegation chain, materialize declared bindings, and prepare any supported handoff. Required caching, refresh, or handoff capabilities fail closed when unavailable.
- **Phase 6: Trust and authorization**: enforce the trust floor and invoke the configured authorization provider. Deny, unknown, and unsupported escalation outcomes fail closed unless the manifest explicitly selects an advisory policy.
- **Phase 7: Execution**: run the tool with a sanitized child environment, capture the result, and calculate audit-safe hashes.
- **Phase 8: Postcondition and evidence**: run `workflow.verify` or `task.verify` after a successful command, then build and verify the complete versioned evidence envelope so the postcondition is part of the binding.
- **Phase 9: Audit and cleanup**: append an audit-safe record according to policy and clean up materialized and handoff credentials on success or failure.

`exec --dry-run` stops after static preparation and returns a plan whose live phases are marked `skipped`. It does not consume an approval, execute proof commands, resolve providers, contact a network endpoint, probe a sandbox, materialize credentials, sign or verify evidence, run postconditions, or write audit records.

### v0.1/v0.2 Dual Path

`exec.js` detects the manifest version (`manifest.version === '0.2' || Boolean(manifest.identity_profiles)`) and dispatches to separate execution paths. The v0.1 path remains synchronous and uses the signing-provider flow. The v0.2 path is asynchronous and adds proof, identity, authorization, and evidence providers. Both paths share the static dry-run contract, approval-before-side-effects ordering, canonical execution binding, child-environment sanitization, and safe audit metadata.

### Standards Alignment

The architecture composes with emerging standards rather than inventing new protocols:

- **IETF AIMS** (`draft-klrc-aiagent-auth-00`) -- the six-layer model maps to the AIMS reference layers (Identifier, Credentials, Attestation, Provisioning, Authentication, Authorization, Monitoring). Manifest authorization proof and credential presentation extend beyond AIMS scope.
- **SPIFFE/WIMSE** -- identity profiles use URI-formatted principals (`agent://`, `spiffe://`) for interoperability with workload identity infrastructure.
- **OAuth 2.0** -- auth modes map to standard grant types: `service` (Client Credentials), `delegated` (Authorization Code), `on-behalf-of` (JWT Authorization Grant, RFC 7523), `exchange` (Token Exchange, RFC 8693).

### Scheduler/Child Trust Boundary

The six-layer identity model enables a meaningful trust boundary between
the scheduler and its child tasks, but only when the child is configured
to be narrower than the parent.

The credential flow traces through four control surfaces:

1. **Operator provisions** -- credentials enter the system via env vars,
   Vault, managed identity, or files. The operator controls
   `SCHEDULER_PROVIDER_PATH` and the scheduler's execution environment.
2. **Scheduler resolves** -- when the selected runtime explicitly advertises the required capabilities, at dispatch time it calls the
   identity provider to resolve a credential session. Trust evaluation
   and authorization gates run before any credential is materialized.
3. **Provider narrows** -- when `child_credential_policy` is `downscope`,
   the provider mints a per-task restricted key via the credential
   issuer's API, scoped to exactly the permissions the child declared.
   Scope hierarchy validation ensures the child cannot escalate.
   The key is revoked in cleanup.
4. **Child receives scoped creds** -- the child task runs with only the
   narrowed credentials. For shell tasks, these are injected as env vars.
   For agent tasks, auth-profile forwarding directs the gateway to use
   the appropriate profile.

**Trust boundary definition:** the operator controls the scheduler binary, capability response, env
and provider directory. Everything downstream narrows only. A child
MUST NOT receive broader credentials than its parent. If the provider
directory or scheduler env is compromised, the trust model is broken --
these are root-of-trust assumptions, not runtime invariants.

**Credential strategies:** the current implementation supports both
precreated keys (operator creates restricted keys ahead of time, provider
resolves by scope name) and dynamic key minting (provider mints a
per-task restricted key via the credential issuer's API and revokes it on
cleanup). Both use the same manifest syntax; the provider's
`key_strategy` configuration determines which path runs.

For the full trust architecture with concrete guarantees and
non-guarantees, see `openclaw-scheduler/docs/trust-architecture.md`.

## Near-Term Roadmap

1. Stabilize manifest and target outputs.
2. Add an execution adapter boundary for optional local backends.
3. Expand JSON-RPC into MCP if that integration surface proves better.
4. Add more target adapters without weakening the manifest contract.
