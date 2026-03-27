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
- **Authorization proof verifier registry** -- validates manifest-time authorization proof (`jwt`, `certificate`, `signature`).
- **Evidence provider registry** -- generates and verifies post-execution attestation (`ssh`, `none`). Conceptual successor to the v0.1 signing provider.
- **Authorization provider registry** -- dispatches per-action authorization to external policy engines (`opa`).

Each provider file auto-registers with its registry on import (side-effect registration). Providers expose machine-readable `capabilities` objects for discovery, and the runtime checks capabilities before calling optional methods. This allows capability-based provider discovery without a central configuration file.

### Execution Lifecycle

`agentcli exec` runs the following pipeline for v0.2 manifests:

- **Phase 1: Manifest Loading + Authorization Proof Verification** -- load, expand shorthands, validate schema, verify manifest authorization proof when declared.
- **Phase 2: Identity Resolution** -- resolve profile references, merge workflow and task overrides (three-stage merge), validate delegation chains, resolve credential session, evaluate trust level. Async for providers that call external token endpoints.
- **Phase 3: Presentation Materialization** -- materialize credentials per declared bindings (env vars, temp files, stdin payload).
- **Phase 3.5: Credential Handoff** (optional) -- when the executing runtime exposes an explicit downstream handoff boundary, prepare a derived credential (downscoped or transaction-scoped). Fails closed if required but unsupported.
- **Phase 4: Contract Evaluation + Trust Enforcement** -- evaluate execution boundaries. When `required_trust_level` is declared, compare against the resolved trust level. Enforcement modes: `none` (log only), `advisory` (warn and continue), `strict` (escalate or fail closed).
- **Phase 4.5: Authorization** (optional) -- invoke external policy engine (OPA, Cedar, Topaz) when an authorization block is configured. Decisions: `permit`, `deny`, `require-escalation`. Skipped entirely when no authorization block resolves for the task.
- **Phase 5: Execution** -- run the tool, capture stdout/stderr/exit code/duration, compute hashes.
- **Phase 6: Evidence Generation** -- build canonical evidence payload, attest execution, verify evidence if required.
- **Phase 7: Audit** -- write structured append-only audit record with declared/resolved identity, authorization proof summary, delegation chain, trust level, authorization decision, and runtime instance attribution.
- **Phase 8: Cleanup** -- delete temporary files, destroy ephemeral materialization and derived handoff credentials.

### v0.1/v0.2 Dual Path

`exec.js` detects the manifest version (`manifest.version === '0.2' || Boolean(manifest.identity_profiles)`) and dispatches to entirely separate code paths. The v0.1 path (`executeTaskV1`) is preserved unchanged -- synchronous, no identity providers, original signing flow. The v0.2 path (`executeTaskV2`) is async and runs the full lifecycle above.

This dual-path design guarantees zero behavioral change for v0.1 manifests. `src/signing/` is preserved for v0.1; `src/evidence/` exists alongside it for v0.2 without cross-coupling.

### Standards Alignment

The architecture composes with emerging standards rather than inventing new protocols:

- **IETF AIMS** (`draft-klrc-aiagent-auth-00`) -- the six-layer model maps to the AIMS reference layers (Identifier, Credentials, Attestation, Provisioning, Authentication, Authorization, Monitoring). Manifest authorization proof and credential presentation extend beyond AIMS scope.
- **SPIFFE/WIMSE** -- identity profiles use URI-formatted principals (`agent://`, `spiffe://`) for interoperability with workload identity infrastructure.
- **OAuth 2.0** -- auth modes map to standard grant types: `service` (Client Credentials), `delegated` (Authorization Code), `on-behalf-of` (JWT Authorization Grant, RFC 7523), `exchange` (Token Exchange, RFC 8693).

## Near-Term Roadmap

1. Stabilize manifest and target outputs.
2. Add an execution adapter boundary for optional local backends.
3. Expand JSON-RPC into MCP if that integration surface proves better.
4. Add more target adapters without weakening the manifest contract.
