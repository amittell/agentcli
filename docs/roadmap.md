# Roadmap

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
- Stronger sanitization policies beyond `basic`
- Identity profiles and provider system (`none`, `env-bearer`, `oidc-client-credentials`, `oidc-token-exchange`)
- Trust levels (`restricted`, `supervised`, `trusted`, `autonomous`) and escalation (`human-approval`, `fail`)
- Authorization proof verification (`jwt`, `certificate`, `signature` verifiers)
- External authorization via OPA provider (Phase 4.5 hook point)
- Evidence generation (`ssh`, `none` evidence providers, separate from v0.1 signing)
- Credential handoff (downscope and transaction modes)
- Audit enhancements (delegation chain, trust level, authorization decision, runtime instance attribution, handoff mode)
- v0.1 to v0.2 conversion utility (`agentcli convert`)
- v0.1/v0.2 dual-path execution (zero behavioral change for v0.1 manifests)
- Provider discovery CLI and JSON-RPC (`agentcli identity providers`, `agentcli identity validate-delegation`)
- Delegation chain validation with policy enforcement
- Three-stage profile merge (profile, workflow, task) with tightening-only rules
- Backend compilation preserves v0.2 identity, evidence, authorization proof, and authorization metadata
- 74 new tests (346 total)

## v0.3

- Enterprise identity providers: `entra-agent-id`, `aws-sts-assume-role`, `gcp-workload-identity`, `spiffe-jwt-svid`
- Mid-execution credential refresh for long-running tasks (runtime-managed session renewal)
- Agent registry export compatibility (structured identity profiles exportable for Entra Agent Registry, organizational CMDBs)
- Multi-runtime credential handoff (cross-backend derived credential propagation)
- CIBA-based human approval for trust escalation (out-of-band approval flow for `require-escalation` decisions)
- Approval policy model beyond scheduler boolean gates
- Streaming watch / tail surfaces for runtime state
- Scheduler lineage and causality queries

## v0.4

- MCP server
- Event streaming / NDJSON output
- Adapter/plugin boundary for non-scheduler runtimes
