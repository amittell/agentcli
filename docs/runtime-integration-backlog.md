# Runtime Integration Backlog

Date: 2026-07-11

## Purpose

This document turns the current architectural assessment into an implementation backlog another agent can execute without re-deriving the repo boundaries.

## Decision

Keep a strict three-layer split:

- `agentcli` owns manifest authoring, validation, compilation, conversion, discovery, and thin execution adapters.
- `openclaw-scheduler` owns durable orchestration: queueing, retries, approvals, run state, chains, recovery, and runtime policy enforcement.
- OpenClaw owns agent/session execution primitives: isolated sessions, main-session injection, tool execution, and gateway APIs.

## Non-Goals

Do not:

- build a second durable runtime inside `agentcli`
- add scheduler-like queuing, retry, cron-triggered approval flows, or SQLite orchestration logic to `agentcli`
- reimplement isolated-session execution in `agentcli`
- move manifest authoring/schema concerns down into `openclaw-scheduler`

Allowed inside `agentcli` (non-durable, single-machine scope):

- local enforcement of `approval.policy` for direct `exec` via single-use, signed grants bound to the complete effective execution configuration in an append-only ndjson state file (`approvals.ndjson`). This is an authoring-time policy enforced at local execution time; it is not a queue, has no timeout resolver, no multi-actor routing, and no cron coupling.

## Current State

- `agentcli` is explicitly the control plane. Prompt tasks are not directly executable there; only `shell` tasks run locally.
- `openclaw-scheduler` is already a real runtime for `shell`, `isolated`, and `main` execution targets.
- `openclaw-scheduler` currently depends on OpenClaw gateway/session APIs for prompt-task execution.
- OpenClaw already exposes the gateway/session runtime surface the scheduler builds on: typed WebSocket control-plane APIs, device/auth handshakes, session lifecycle APIs, and built-in cron/heartbeat automation.

Current control-plane hardening:

- local approvals bind the complete effective execution configuration, enforce scope and timeout, and run before all live side effects
- scheduler apply queries live capabilities and treats reported values as authoritative, with conservative static fallback values only for unavailable keys
- scheduler handoff versions 1, 2, and 3 are explicit; version 3 carries approval risk, approver scope, and output format
- root approval gates, approver scope, structured output, proof, authorization, trust, evidence, and credential handoff fail capability negotiation when required support is absent
- scheduler compilation refuses raw `shell.env` and `shell.stdin` persistence and compiles `auto-reject` jobs disabled
- CI provisions a pinned scheduler checkout so missing cross-repository integration cannot silently skip the suite

## Scheduling Boundary

To avoid duplicating automation semantics across all three repos:

- OpenClaw heartbeat and native cron remain product-level assistant automation features.
- `openclaw-scheduler` remains the durable orchestration layer for manifest-native workflows that need queueing, retries, approvals, audit state, and recovery.
- `agentcli` should compile durable workflow intent toward `openclaw-scheduler`, not try to become a third scheduler.
- Cross-repo work must make the boundary explicit so users can tell when a task should live in OpenClaw cron versus `openclaw-scheduler`.

## Priority Order

1. Make runtime capability negotiation explicit.
2. Close the `agentcli v0.2` feature gap in `openclaw-scheduler`.
3. Add better one-off runtime UX in `agentcli` without creating a second runtime.
4. Stabilize the OpenClaw gateway/session contract the scheduler already relies on.
5. Document and enforce schedule ownership between OpenClaw automation and `openclaw-scheduler`.

## Workstream A: Runtime Capability Negotiation

Owner: `agentcli` + `openclaw-scheduler`

Status: implemented in the `agentcli` control plane. Each scheduler release remains responsible for accurately advertising its runtime surface.

Original problem:

- `agentcli` hardcodes target capability flags for `openclaw-scheduler`.
- `apply` currently compensates locally when runtime capabilities are missing.
- Capability drift will get worse as `openclaw-scheduler` adds more `v0.2` support.

Implemented contract:

1. Add a machine-readable scheduler capability endpoint/command.
2. Version the capability payload separately from human-facing docs.
3. Include runtime feature flags for:
   - `authorization_proof_verification`
   - `authorization_hook`
   - `trust_evaluation`
   - `delegation_validation`
   - `credential_handoff`
   - `evidence_generation`
   - `runtime_identity_resolution`
4. Make `agentcli apply` query the runtime before governed execution.
5. Fall back to conservative static flags only when the runtime is unreachable or too old.
6. Emit clear mismatch errors when the manifest requires a capability the runtime does not advertise.

Acceptance criteria:

- `agentcli` no longer relies only on hardcoded scheduler capability flags.
- A scheduler upgrade can enable new behavior without requiring matching hardcoded edits first.
- Capability mismatch errors identify the specific manifest feature and missing runtime capability.

## Workstream B: Make `openclaw-scheduler` the Real `agentcli v0.2` Runtime

Owner: `openclaw-scheduler`

Problem:

- `agentcli` manifests can express richer identity, trust, authorization, proof, evidence, and handoff semantics than the runtime currently executes natively.

Backlog:

1. Implement native authorization-proof verification in the scheduler runtime.
2. Implement runtime authorization hook support for resolved authorization blocks.
3. Implement trust evaluation and escalation handling at dispatch time.
4. Support human-approval escalation paths where trust/authorization requires it.
5. Implement runtime identity resolution/materialization for `v0.2` identity profiles.
6. Persist audit-safe identity/trust/evidence summaries in scheduler run state.
7. Implement evidence generation and required-evidence failure handling in the runtime.
8. Implement credential handoff only when the next-hop runtime boundary is explicit and supported.
9. Validate delegation chains/runtime constraints during execution, not only in control-plane tooling.

Acceptance criteria:

- `openclaw-scheduler` can consume a compiled `agentcli v0.2` task without `agentcli` needing to locally substitute core runtime behavior.
- `agentcli apply` no longer needs to reject authorization blocks when the scheduler advertises support.
- Runtime audit records include the fields required to explain trust, authorization, evidence, and approval outcomes.

## Workstream C: Harden the Handoff Boundary

Owner: `agentcli` + `openclaw-scheduler`

Status: shipped in AgentCLI 0.5.0 and OpenClaw Scheduler 0.5.0 as handoff v4. The canonical artifact, complete scheduler binding, shared fixtures, non-lossy apply/update/adopt path, immutable runtime bindings, and negative capability gates are executable release requirements.

Problem:

- The control plane and runtime need a cleaner contract than “flatten some fields and hope the semantics line up.”

Delivered:

1. Define a versioned compiled handoff artifact for `openclaw-scheduler`.
2. Preserve resolved per-task semantics needed by the runtime instead of requiring re-derivation from lossy fields.
3. Decide which fields are resolved in `agentcli` and which are intentionally runtime-resolved.
4. Add end-to-end tests from manifest -> compile -> apply -> runtime execution.
5. Add negative tests for capability mismatches and partial-support fallbacks.

Acceptance criteria:

- The scheduler input contract is explicit, versioned, and test-covered.
- The runtime does not depend on undocumented field flattening behavior.
- New manifest features can be added without fragile cross-repo guesswork.

## Workstream D: Thin One-Off Runtime UX in `agentcli`

Owner: `agentcli`

Problem:

- Users will reasonably expect prompt tasks in a manifest to be runnable without manually translating them into scheduler invocations.
- That does not justify building a second runtime in this repo.

Backlog:

1. Add an explicit runtime-adapter boundary in `agentcli` for non-shell task execution.
2. Support one-off execution by delegating to an external runtime rather than executing prompt tasks locally.
3. Keep this path stateless apart from transient request/response handling.
4. Reuse existing manifest validation and normalization before delegation.
5. Return runtime metadata that makes it obvious execution happened elsewhere.

Constraints:

- No local queue.
- No local retry engine.
- No local cron-triggered approval queue, timeout resolver, or multi-actor routing (local single-use approval records for direct `exec` are allowed -- see Workstream guardrails above).
- No local session manager for prompt tasks.

Acceptance criteria:

- A user can execute a prompt task from an `agentcli` manifest via a runtime adapter.
- The implementation delegates orchestration/session ownership outward instead of recreating it locally.

## Workstream E: OpenClaw Gateway / Session Contract

Owner: OpenClaw

Problem:

- `openclaw-scheduler` already depends on OpenClaw-specific behavior for isolated sessions, main-session events, session activity polling, auth-profile forwarding, and tool invocation.
- OpenClaw also has first-party cron and heartbeat features, so the runtime boundary must be explicit or users will face overlapping scheduling surfaces.
- Those runtime dependencies should be explicit and stable.

Backlog:

1. Publish a stable API contract for isolated session creation/execution.
2. Publish session lifecycle/status semantics used for activity-aware timeout handling.
3. Stabilize auth-profile override semantics for scheduler-dispatched runs.
4. Expose runtime/session metadata needed for scheduler attribution and audit.
5. Expose capability/version discovery for gateway features the scheduler depends on.
6. Define cancellation and interruption semantics for scheduled runs.
7. Define how scheduler-owned runs appear inside OpenClaw session/cron surfaces so operators can distinguish local automation from external orchestration.

Acceptance criteria:

- The scheduler no longer needs to infer important gateway semantics from ad hoc response shapes.
- Gateway/session behaviors used by the scheduler are documented and versioned.

## Workstream F: Schedule Ownership and Interop

Owner: `agentcli` + `openclaw-scheduler` + OpenClaw

Problem:

- OpenClaw already provides heartbeat and cron for personal assistant automation.
- `openclaw-scheduler` already provides durable orchestration.
- Without an explicit rule, new work will reintroduce the same feature in multiple places with slightly different semantics.

Backlog:

1. Write a short cross-repo decision record that states which scheduling problems belong to OpenClaw heartbeat/cron and which belong to `openclaw-scheduler`.
2. Define whether `agentcli` ever targets raw OpenClaw cron directly or only targets `openclaw-scheduler` for recurring prompt tasks.
3. Standardize operator-facing labels for scheduler-dispatched runs inside OpenClaw so they are visible but not confused with native cron jobs.
4. Decide whether OpenClaw native cron should remain intentionally non-durable compared with `openclaw-scheduler`, and document the tradeoff.
5. Add examples showing the same user intent implemented as:
   - personal assistant heartbeat/cron in OpenClaw
   - durable manifest workflow via `agentcli` -> `openclaw-scheduler`

Acceptance criteria:

- The repos no longer describe overlapping ownership for recurring prompt-task execution.
- Operators can explain, from docs alone, which layer to use for a given automation problem.

## Workstream G: Cross-Repo Testing

Owner: `agentcli` + `openclaw-scheduler` + OpenClaw (where available)

Status: shipped for the AgentCLI to scheduler boundary. CI uses exact cross-repository revisions and published-package black-box gates. The scheduler package includes a public fresh-database, restart-backed v4 E2E for identity, credentials, proof, authorization, approvals, structured output, postconditions, signed evidence, delivery, and all five durable dispatch kinds. Broader tests against upstream OpenClaw Gateway releases remain future cross-project work.

Delivered for the scheduler boundary:

1. Add an integration fixture that exercises `agentcli apply` against a real scheduler instance.
2. Add at least one end-to-end `v0.2` manifest for:
   - identity materialization
   - trust enforcement
   - authorization proof verification
   - authorization hook evaluation
   - evidence generation
   - approval escalation
3. Add compatibility tests for older scheduler versions against newer `agentcli`.
4. Add compatibility tests for newer scheduler versions against older `agentcli` static fallback behavior.

Acceptance criteria:

- The integration boundary is validated by tests, not just documentation.
- Capability drift is caught in CI instead of during manual wiring.

## Suggested Sequencing

### Phase 1

- Workstream A
- Workstream C (contract definition only)

### Phase 2

- Workstream B items for `authorization_proof_verification`
- Workstream B items for `authorization_hook`
- Workstream F initial end-to-end coverage

### Phase 3

- Workstream B items for trust evaluation and escalation
- Workstream E gateway contract publication
- Workstream F schedule ownership decision

### Phase 4

- Workstream B items for runtime identity resolution, evidence generation, delegation validation, and handoff
- Workstream D thin one-off runtime UX in `agentcli`
- Workstream G broader compatibility coverage

## Recommended Ticket Split

### `agentcli`

- Add runtime capability discovery client and fallback logic.
- Maintain the versioned scheduler handoff artifact and conformance fixtures.
- Improve `apply` error reporting around capability mismatches.
- Add stateless prompt-task runtime delegation path.
- Maintain exact-revision and published-package cross-repo integration tests.

### `openclaw-scheduler`

- Add machine-readable runtime capability output.
- Implement authorization-proof verification.
- Implement authorization hook support.
- Implement trust evaluation and escalation.
- Implement identity/evidence/handoff runtime support.
- Expose richer audit/run metadata.

### OpenClaw

- Stabilize isolated-session execution APIs.
- Stabilize main-session event injection contract.
- Stabilize auth-profile and capability discovery surfaces.
- Expose better session lifecycle/cancellation primitives.
- Document heartbeat/cron versus scheduler ownership and interoperability.

## Final Recommendation

If prompt-task execution beyond shell is the goal, do not build it as a second general-purpose runtime in `agentcli`.

The highest-leverage path is:

1. make `openclaw-scheduler` the canonical runtime for `agentcli` manifests
2. make the scheduler/OpenClaw execution contract explicit and versioned
3. let `agentcli` remain the control plane plus thin runtime delegation UX
