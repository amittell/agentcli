# Roadmap

The `v0.1` and `v0.2` headings below are manifest specification milestones, not npm package versions. Future work is intentionally unversioned until its compatibility boundary is defined.

## v0.1

- Manifest schema
- Validation
- Compile to standalone and scheduler targets
- JSON output for every command
- `describe`, `inspect`, and stdio JSON-RPC
- Example manifest

## v0.2

### Shipped

- Stable manifest versioning rules (v0.1 and v0.2 coexist, version field accepts both)
- Richer trigger-condition schema
- Local execution adapter for shell-only workflows
- Basic sanitization for inspect output and agent-facing text
- Identity profiles and provider system (`none`, `env-bearer`, `oidc-client-credentials`, `oidc-token-exchange`)
- Trust levels (`untrusted`, `restricted`, `supervised`, `autonomous`) and escalation (`fail`, `human-approval`, `log-and-proceed`)
- Authorization proof verification (`jwt`, `certificate`, `detached-signature` verifiers)
- External authorization via OPA provider (Phase 4.5 hook point)
- Evidence generation (`ssh`, `none` evidence providers, separate from v0.1 signing)
- Credential handoff (downscope and transaction modes)
- Audit enhancements (delegation chain, trust level, authorization decision, runtime instance attribution, handoff mode)
- v0.1 to v0.2 conversion utility (`agentcli convert`)
- v0.1/v0.2 dual-path execution with shared static dry-run, approval ordering, child-environment sanitization, and audit safety guarantees
- Provider discovery CLI and JSON-RPC (`agentcli identity providers`, `agentcli identity validate-delegation`)
- Delegation chain validation with policy enforcement
- Three-stage profile merge (profile, workflow, task) with tightening-only rules
- Backend compilation preserves v0.2 identity, evidence, authorization proof, and authorization metadata
- Enterprise identity providers: `azure-managed-identity`, `aws-sts-assume-role`, `gcp-workload-identity`, `spiffe-jwt-svid`
- Comprehensive v0.2 profile validation with cross-reference checks for dangling refs
- Converter produces proper identity profile refs (not inline blocks)
- Local approval gate enforcement in `agentcli exec` with single-use ssh-signed grants (`agentcli approve`, `agentcli approvals list|revoke`, `exec --approval-id`); approval records stored at `~/.agentcli/state/approvals.ndjson`; enforces `approval.policy: manual` and `approval.policy: auto-reject`
- Complete effective-execution approval binding with approver scope, timeout caps, unexpected-unsigned rejection, and approval-before-side-effects ordering
- Cryptographic, manifest-bound authorization proofs and versioned evidence envelopes with transplantation detection
- Fail-closed sandbox, network, provider capability, delegation, and credential cleanup behavior
- Draft 2020-12 JSON Schema output, strict nested validation, strict CLI flags, and read-only JSON-RPC discovery methods
- Scheduler handoff v3, authoritative live capabilities, governed feature gates, auto-reject disabling, and refusal to persist inline shell credentials

## Future identity and runtime expansion

- Additional Entra Agent ID governance features (Conditional Access policy integration, agent lifecycle hooks)
- Mid-execution credential refresh for long-running tasks (runtime-managed session renewal)
- Agent registry export compatibility (structured identity profiles exportable for Entra Agent Registry, organizational CMDBs)
- Multi-runtime credential handoff (cross-backend derived credential propagation)
- CIBA-based human approval for trust escalation (out-of-band approval flow for `require-escalation` decisions)
- Richer approval policy model building on the v0.2 local gate (approval quorum/multi-party, approver identity attribution beyond SSH principal, scheduler/local-gate unification)
- Streaming watch / tail surfaces for runtime state
- Scheduler lineage and causality queries

## Future integration surfaces

- MCP server
- Event streaming / NDJSON output
- Adapter/plugin boundary for non-scheduler runtimes
