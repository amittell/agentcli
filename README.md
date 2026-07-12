# agentcli

When an agent loop can touch GitHub, Kubernetes, Terraform, Stripe, or a production shell, the missing piece is usually not another runtime. It is control: who approved the action, what identity it ran as, which credentials it received, what boundaries applied, and what evidence remains afterward.

`agentcli` is a control plane for governed agent and CLI workflows. It gives agents and operators a portable manifest contract for execution identity, credential binding, trust boundaries, approval proofs, audit records, and signed evidence around existing tools and runtimes.

`agentcli` is not the durable runtime. Use it to author, validate, execute, inspect, and compile the governed workflow contract. Pair it with `openclaw-scheduler` when you need durable scheduling, queueing, retries, approvals, delivery, and persisted runtime state.

Use `agentcli` when you want to:

- put existing tools such as `gh`, `kubectl`, `terraform`, `flyctl`, `aws`, or internal CLIs behind approvals, identity, and audit
- keep workflows portable across local execution, CI, cron, and scheduler-backed runtimes
- give platform and security teams a control surface without forcing application teams onto one agent framework or one vendor runtime

| If you need... | Start here |
| --- | --- |
| Govern local or externally scheduled workflows | `agentcli` |
| Durable schedules, retries, approvals, and runtime state | `agentcli` + `openclaw-scheduler` |

## Quick Start

Start with one risky action you already understand.

The example below wraps `docker system prune -f` as a governed operation with supervised trust, manual approval, audit records, and optional signed evidence, while still calling plain old `docker`.

```bash
# Install
npm install -g @amittell/agentcli

# Validate the governed workflow manifest
agentcli validate examples/docker-ops.json

# Inspect the identity and trust level on the risky step
agentcli identity resolve examples/docker-ops.json prune-unused

# Preview the controlled action locally without executing it
agentcli exec examples/docker-ops.json prune-unused --dry-run --signer none

# Compile the same manifest for the durable scheduler runtime
agentcli compile examples/docker-ops.json --target openclaw-scheduler --explain
```

That is the core value of `agentcli`: keep the existing CLI, add identity, trust boundaries, approvals, audit, and evidence around it.

`agentcli validate examples/docker-ops.json` succeeds with advisory warnings because the example intentionally models manual approval on a scheduled destructive root.

Other good first examples:

- `examples/gh-ops.json` for GitHub read vs write operations and draft release approval
- `examples/kubectl-ops.json` for cluster inspection and controlled deploy actions
- `examples/terraform-ops.json` for init/plan/apply chains under policy
- `examples/stripe-ops.json` for API-key-backed finance and payments operations

If you just want the broader CLI surface, the sections below show the main local and scheduler-backed paths.

### `agentcli` on its own

```bash
# Install
npm install -g @amittell/agentcli

# Create a local home directory with a starter manifest
agentcli init

# Validate a governed workflow manifest
agentcli validate examples/docker-ops.json

# See the portable standalone plan
agentcli compile examples/docker-ops.json --target standalone --explain

# Preview a supervised task locally
agentcli exec examples/docker-ops.json prune-unused --dry-run --signer none

# Run a shell-only workflow DAG locally
agentcli run examples/trust-enforcement.json --root collect-data --signer none

# Inspect identity resolution
agentcli identity resolve examples/docker-ops.json prune-unused

# View recent audit records
agentcli audit --limit 10

# Verify execution evidence
agentcli verify <execution-id>
```

`npm install -g @amittell/agentcli` installs the `agentcli` command on your PATH so you can run `agentcli ...` from any directory. If you install the scoped package into a project instead, run the local binary with `npx agentcli ...`.

### `agentcli` with `openclaw-scheduler`

```bash
# Install and initialize the scheduler runtime
mkdir -p ~/.openclaw/scheduler
npm install --prefix ~/.openclaw/scheduler openclaw-scheduler@latest
npm exec --prefix ~/.openclaw/scheduler openclaw-scheduler -- setup

# Compile the same manifest for the durable runtime
agentcli compile examples/docker-ops.json --target openclaw-scheduler --explain

# Preview the jobs that would be created or updated
agentcli apply examples/docker-ops.json \
  --db ~/.openclaw/scheduler/scheduler.db \
  --scheduler-prefix ~/.openclaw/scheduler \
  --dry-run

# Ask the runtime which capability surface and handoff version it supports
agentcli apply examples/docker-ops.json \
  --db ~/.openclaw/scheduler/scheduler.db \
  --scheduler-prefix ~/.openclaw/scheduler \
  --check-capabilities

# Inspect the runtime state through agentcli
AGENTCLI_SCHEDULER_DB=~/.openclaw/scheduler/scheduler.db \
  agentcli inspect jobs --fields id,name,last_status
```

Node 22.13.0 or newer is required. The minimum is tested in CI alongside the current Node 24 line.

## Why Teams Use It

`agentcli` gives you a narrow, high-value layer on top of existing tools and agent loops:

- portable workflow manifests instead of runtime-specific job definitions
- explicit execution identity and credential presentation
- task contracts for trust level, sandboxing, network, and allowed paths
- approval and evidence surfaces that security and platform teams can inspect
- one path from local execution to durable scheduler-backed execution

If you are trying to add controls to an existing loop, start with `agentcli` alone. Add `openclaw-scheduler` when you need durable runtime behavior.

### Security and execution guarantees

- `exec --dry-run` is a static preview. It does not consume approvals, run proof commands, resolve providers, call token or policy endpoints, probe a sandbox, materialize credentials, sign evidence, execute postconditions, or write audit records.
- Manual approvals are single-use and bind the complete effective execution configuration, including the manifest digest, resolved profiles, command argument hashes, declared environment and stdin hashes, contract, verification, proof, evidence, and approval policy. `approver_scope` and `timeout_s` are enforced. Unexpected unsigned approval records are rejected; unsigned grants exist only when signing was explicitly disabled.
- Every non-`none` authorization proof is cryptographically verified and bound to the canonical manifest. JWT, detached-signature, and certificate declarations fail closed when their trust material or manifest binding is missing.
- Evidence uses a versioned canonical payload bound to the manifest, effective task, identity, command, result, and postcondition. Verification detects an envelope copied to another execution.
- Requested filesystem or network isolation fails closed when the host cannot enforce it. Use a container or a runtime with the needed isolation capabilities for production workloads.
- Child processes inherit only a small operational allowlist such as PATH, HOME, temporary-directory, locale, shell, user, timezone, terminal, and Windows equivalents. Every other ambient variable requires explicit `shell.env` declaration or identity-provider materialization.
- Never put credentials in `shell.args` or prompts. Arguments remain executable payload and may be visible in process listings; prompts may be persisted by a durable runtime. Use identity-provider env, file, or stdin materialization.
- `agentcli run` skips disabled roots, descendants, and failure handlers. It remains a local, non-durable shell DAG runner.
- Durable scheduler apply refuses `shell.env` and `shell.stdin` because persisting credential-bearing values in scheduler job records would cross the trust boundary. Use runtime identity materialization instead.

Dry-run and governance inspection are deliberately separate. Use `identity resolve`, `identity validate-delegation`, `authorization-proof verify`, or `authorization evaluate` when you intentionally want a live, read-only governance check without spawning the target command. Those commands may read declared proof or credential sources and contact configured identity, JWKS, or policy endpoints; they do not generate execution evidence or audit records.

## Better Together

`agentcli` and `openclaw-scheduler` are complementary:

- `agentcli` gives you the authoring contract: schema, validation, examples, discovery, identity binding, local execution, audit, and machine-readable CLI / JSON-RPC surfaces.
- `openclaw-scheduler` gives you the durable runtime: schedules, queueing, retries, approvals, delivery, and persistent state.
- The same manifest can start as a local, portable workflow in `agentcli` and then be compiled and applied into `openclaw-scheduler` without rewriting it into a runtime-specific format.

If you want to start simple, start with `agentcli` alone. If you want durable operation, pair it with `openclaw-scheduler`.

## Wrapping Existing CLI Tools

For most teams, this is the shortest path to value.

`agentcli` works well as a stable control layer around existing CLI tools such as `flyctl`, `kubectl`, `gh`, `terraform`, and the Stripe CLI. See [Wrapping CLI Tools](docs/guide-wrapping-tools.md) for the full guide, including a complete multi-tool deployment pipeline that chains Stripe Projects, Prisma, and Fly.io under agentcli governance.

The pattern is:

1. Put the exact tool invocation in `shell.program` and `shell.args[]`.
2. Bind credentials declaratively when the tool expects environment variables or temp files.
3. Validate and run the workflow locally with `agentcli exec`.
4. Compile and apply the same manifest into `openclaw-scheduler` when you want durable execution.

For example, [flyctl-ops.json](examples/flyctl-ops.json) wraps a simple `flyctl status --app my-app` check, binds `FLY_API_TOKEN` through an identity profile, and escalates failures into a read-only triage step.

```bash
agentcli validate examples/flyctl-ops.json
agentcli identity resolve examples/flyctl-ops.json check-app-status
agentcli compile examples/flyctl-ops.json --target openclaw-scheduler --explain
```

For shell-only manifests with trigger chains, use `agentcli run` to execute the local DAG from one or more scheduled roots:

```bash
agentcli run examples/trust-enforcement.json --root collect-data --signer none
agentcli run examples/trust-enforcement.json --all-roots --dry-run --signer none
```

[stripe-ops.json](examples/stripe-ops.json) wraps the Stripe CLI with three operations: list recent charges, check balance, and list failed payment intents. It binds `STRIPE_API_KEY` through an identity profile with strict trust enforcement, parses JSON output, generates SSH evidence, and escalates API failures into an agent-based triage step.

```bash
export STRIPE_API_KEY="sk_test_..."
agentcli validate examples/stripe-ops.json
agentcli exec examples/stripe-ops.json check-balance --signer none
agentcli exec examples/stripe-ops.json list-recent-charges --signer none
agentcli audit --limit 3
```

The same pattern works for any CLI tool that reads credentials from the environment: `kubectl` with `KUBECONFIG`, `gh` with `GH_TOKEN`, `terraform` with `TF_TOKEN_app_terraform_io`, `aws` with `AWS_ACCESS_KEY_ID`, and so on. Put the tool invocation in `shell`, bind the credential through an identity profile, and `agentcli` handles the rest.

If the tool only needs a direct wrapper, you can also scaffold the starting point with:

```bash
agentcli init --tool flyctl
```

### Dynamic credentials via `command`

When credentials are managed by an external tool, use `value_from: { command }` to
acquire them at execution time:

```json
"inputs": {
  "client_secret": {
    "value_from": {
      "command": "vault kv get -field=api_key secret/myapp"
    }
  }
}
```

This works with any CLI that prints a credential to stdout: Vault, 1Password, AWS SSM,
Stripe Projects, Doppler, macOS Keychain, and others. See
[stripe-projects.json](examples/stripe-projects.json) for a full example and
[docs/guide-identity.md](docs/guide-identity.md#dynamic-credential-acquisition) for the
complete reference. Command-based proof acquisition is disabled during scheduler apply unless the caller explicitly enables it; `exec` runs a declared proof command only after any manual approval gate succeeds.

## Core Model

A manifest is a declarative description of one or more workflows. Each workflow contains tasks that define what to execute, when, and under what identity and constraints.

```
manifest
  version: "0.2"
  identity_profiles[]         # reusable identity declarations
  authorization_proof_profiles[]  # manifest approval methods
  evidence_profiles[]         # post-execution attestation methods
  workflows[]
    identity                  # workflow-level identity binding
    contract                  # execution boundaries and trust requirements
    tasks[]
      shell / prompt          # what to execute
      schedule / trigger      # when to execute
      identity                # task-level identity override
      evidence                # attestation binding
      contract                # task-level execution boundaries
      model_policy            # LLM provider, model, thinking level
      intent                  # plan/read-only execution mode
      output                  # preview, offload, format hints
      budgets                 # fan-out, queue, context limits
      approval                # manual/auto approval policy
      delivery                # notification routing
      reliability             # retry, overlap, guarantee
      on_failure              # failure triage sub-task
```

Tasks use structured execution fields (`shell.program`, `shell.args[]`) instead of opaque command strings. Each task defines exactly one invocation mode: `schedule` (cron) or `trigger` (parent task dependency).

See the [manifest spec](docs/spec.md) for field-level detail.

## Execution Identity (v0.2)

Every `agentcli` execution answers five questions:

1. **Who** is running this? (identity profile with a stable principal URI)
2. **How** did they authenticate? (pluggable provider: env var, file, OIDC, cloud workload, or CLI command)
3. **What** are they allowed to do? (contract: trust level, sandbox, network, allowed paths)
4. **Can we prove it happened?** (evidence: SSH-signed attestation of command + result)
5. **Is there an audit trail?** (structured, append-only, secrets-redacted records)

```json
{
  "identity_profiles": [
    {
      "id": "deploy-agent",
      "provider": "oidc-client-credentials",
      "subject": { "kind": "service", "principal": "agent://acme.com/deploy-bot" },
      "auth": {
        "mode": "service",
        "scopes": ["deploy:staging"],
        "provider_config": { "token_endpoint": "https://auth.acme.com/oauth2/token", "client_id": "deploy-bot" },
        "inputs": { "client_secret": { "value_from": { "env": "DEPLOY_CLIENT_SECRET" } } }
      },
      "trust": { "level": "supervised" },
      "presentation": {
        "bindings": [{ "source": "credentials.access_token.value", "target": { "kind": "env", "name": "DEPLOY_TOKEN" }, "redact": true }],
        "cleanup": "always"
      }
    }
  ]
}
```

Trust levels (`untrusted`, `restricted`, `supervised`, `autonomous`) are enforced against the contract's `required_trust_level`. When a task's trust is below the floor and `trust_enforcement` is `strict`, execution is blocked.

For the full guide: [Identity Setup](docs/guide-identity.md) | [Wrapping CLI Tools](docs/guide-wrapping-tools.md) | [Spec Reference](docs/spec.md)

## Identity Providers

| Provider | Description |
|---|---|
| `none` | No credentials. Declares identity for audit and contract enforcement only. |
| `env-bearer` | Reads a bearer token from an environment variable at execution time. |
| `file-bearer` | Reads a bearer token from a file at execution time. |
| `oidc-client-credentials` | Acquires an access token using the OAuth 2.0 Client Credentials grant. |
| `oidc-token-exchange` | Exchanges an existing token for a new one using RFC 8693 Token Exchange. |
| `azure-managed-identity` | Acquires a token from the Azure Instance Metadata Service (IMDS). Works on Azure VMs, App Service, and Container Instances. |
| `aws-sts-assume-role` | Assumes an AWS IAM role via STS and returns temporary credentials. Includes AWS Signature V4 signing. |
| `gcp-workload-identity` | Acquires a token from the GCP metadata server. Works on Compute Engine, Cloud Run, and GKE. |
| `spiffe-jwt-svid` | Reads a file-mounted JWT-SVID and verifies its issuer, audience, lifetime, subject, and signature against exactly one local trust source. Workload API sockets are not accepted. |
| `entra-agent-id` | Acquires a token via Microsoft Entra Agent ID using JWT bearer client assertion. Supports Agent Registry, Conditional Access, and IMDS fallback. |
| `stripe-api-key` | Resolves Stripe API keys with scope-aware permissions. Supports precreated restricted keys by scope name and dynamic key minting via the Stripe API. |

Use `agentcli identity providers` to list registered providers and `agentcli identity schema <provider>` to inspect the current provider metadata surface, including capabilities.

## Authorization Proof Methods

Authorization proof verifies that the manifest itself was approved before execution.

| Method | Description |
|---|---|
| `none` | No proof required. |
| `jwt` | Manifest approval encoded as a signed JWT verified with a configured `public_key` or `jwks_uri`. |
| `detached-signature` | Manifest approval via a detached cryptographic signature. |
| `certificate` | Manifest approval via an X.509 certificate chain. |

Use `agentcli authorization-proof methods` to list available methods and `agentcli authorization-proof schema <method>` to inspect verifier metadata for a method.

`jwt`, `detached-signature`, and `certificate` are always cryptographic, manifest-bound checks. `verify.required: false` does not turn a non-`none` method into a claims-only or presence-only check. Use `method: "none"` when a declaration is intentionally informational and unverifiable.

## Authorization Providers

| Provider | Description |
|---|---|
| `none` | No external authorization. Contract enforcement still applies. |
| `opa` | Evaluates policy using Open Policy Agent. |

Use `agentcli authorization providers` to list registered providers and `agentcli authorization schema <provider>` to inspect provider metadata and capabilities.

## Evidence Providers

| Provider | Description |
|---|---|
| `none` | No evidence produced. Audit records are still written. |
| `ssh` | Signs evidence payloads using SSH keys. Verifiable with `agentcli verify`. |

Use `agentcli evidence providers` to list registered providers and `agentcli evidence schema <provider>` to inspect provider metadata.

Evidence envelopes retain the complete versioned payload needed for later verification. The payload contains hashes and audit-safe descriptors, not raw credential values, stdin, stdout, or stderr.

## Signing Providers

`agentcli exec` and `agentcli run` use signing providers for execution attestations.

Use `agentcli signing providers` to list the registered signing providers and the attestation methods they expose.

## CLI Reference

### General

| Command | Description |
|---|---|
| `version` | Show package and manifest spec version. |
| `init [--tool program] [--output path] [--workflow-id id] [--task-id id]` | Initialize agentcli home directory with starter manifests. |
| `paths` | Show resolved agentcli home, manifest, output, state, and audit paths. |
| `schema [target] [--legacy]` | Emit Draft 2020-12 JSON Schema for manifest, workflow, task, schedulerJob, standalonePlan, rpcRequest, or rpcResponse. `--legacy` opts into the older agentcli descriptor format. |
| `describe [target]` | Describe manifest, workflow, task, targets, commands, or rpc surfaces as structured JSON. |
| `targets` | List available compilation targets. |
| `skill-path` | Print the path to the agentcli skill manifest for MCP tool registration. |

### Manifest Operations

| Command | Description |
|---|---|
| `validate <path-or-json\|->` | Validate a manifest against the spec. Accepts file path, inline JSON, or stdin. |
| `compile <path> [--target t] [--write path] [--explain]` | Compile a manifest to a target format. Targets: `standalone`, `openclaw-scheduler`. |
| `convert <path-or-json\|-> [--output path]` | Convert a v0.1 manifest to v0.2 with safe defaults. |
| `merge <manifest1> <manifest2> [--output path]` | Merge two manifests into one. |
| `import <directory> [--name name]` | Import a manifest directory into the registry. |

### Execution

| Command | Description |
|---|---|
| `exec <path> <task-id> [--workflow id] [--dry-run] [--timeout ms] [--signer ssh\|none] [--signing-key path] [--approval-id id] [--db path] [--scheduler-prefix path\|--scheduler-bin path]` | Execute shell tasks locally with identity resolution, contract enforcement, attestation, and approval gate enforcement, or delegate non-shell tasks to the scheduler when configured. |
| `run <path> [--workflow id] [--root task-id\|--all-roots] [--dry-run] [--timeout ms] [--signer ssh\|none] [--signing-key path]` | Execute a shell-only workflow DAG locally. Trigger edges, `contains:` / `regex:` conditions, and `on_failure` handlers are evaluated in-process. |
| `apply <path> [--db path] [--scheduler-prefix path\|--scheduler-bin path] [--dry-run] [--explain] [--adopt-by id\|name] [--check-capabilities]` | Apply a manifest to the scheduler runtime, or inspect runtime capability negotiation without writing jobs. |

`agentcli run` is intentionally narrow:

- It only executes tasks with `target.session_target: "shell"`.
- It runs one workflow DAG locally from a selected scheduled root, or from every root when `--all-roots` is set.
- It skips every task whose effective `enabled` value is `false`, including roots, triggered descendants, and failure handlers.
- It does not add queueing, retries, or durable state. Approval gates declared on tasks are enforced through the same local mechanism that `exec` uses.
- Manifests that include `main` or `isolated` tasks still need a runtime adapter such as `openclaw-scheduler`.

### Approvals

| Command | Description |
|---|---|
| `approve <path> <task-id> [--workflow id] [--by principal] [--reason text] [--ttl-s seconds] [--signer ssh\|none] [--signing-key path]` | Grant a single-use local approval for a gated task. Writes a signed record bound to the complete effective execution hash to `~/.agentcli/state/approvals.ndjson`. |
| `approvals list [--status pending\|consumed\|expired\|revoked\|all] [--workflow id] [--task id]` | List approval records with current status, approver, reason, and signature metadata. |
| `approvals revoke <approval-id> [--by principal] [--reason text]` | Revoke a pending approval. |

`agentcli exec` enforces `approval.policy` at runtime:

- `manual`: exec refuses (`code: approval_required`, `error_type: validation_error`) unless a matching, unconsumed, unrevoked, unexpired approval record exists. The grant binds the canonical manifest and complete effective execution configuration, including profiles, command inputs, identity, contract, verify, proof, evidence, and approval settings. Any bound drift invalidates prior grants. The approver must satisfy `approver_scope`, and grant lifetime cannot exceed `timeout_s`.
- `auto-reject`: exec refuses unconditionally (`code: approval_auto_rejected`, `error_type: validation_error`). Grants cannot override.
- `auto-approve` or absent: exec proceeds without an approval record.

Approvals are single-use and consumed before `spawnSync` (fail-closed: a crashed execution still consumes the grant). Unexpected unsigned records fail verification; `--signer none` is the only explicit unsigned mode. `--dry-run` is a static preview and does not consume or enforce the gate. Successful gated executions include `approval_used` in both the result payload and the audit record. The local mechanism is single-machine; durable cron-triggered approvals remain owned by `openclaw-scheduler`.

### Identity and Authorization

| Command | Description |
|---|---|
| `identity providers` | List registered identity providers. |
| `identity schema <provider>` | Show provider metadata and capabilities for an identity provider. |
| `identity resolve <manifest> <task-id> [--workflow id]` | Resolve the effective identity for a task. |
| `identity validate-delegation <manifest> <task-id> [--workflow id]` | Validate delegation chain for a task. |
| `authorization-proof methods` | List available authorization proof methods. |
| `authorization-proof schema <method>` | Show verifier metadata for an authorization proof method. |
| `authorization-proof verify <manifest> <task-id> [--workflow id]` | Verify authorization proof for a task. |
| `authorization providers` | List registered authorization providers. |
| `authorization schema <provider>` | Show provider metadata and capabilities for an authorization provider. |
| `authorization evaluate <manifest> <task-id> [--workflow id]` | Evaluate authorization policy for a task. |
| `evidence providers` | List registered evidence providers. |
| `evidence schema <provider>` | Show provider metadata for an evidence provider. |
| `whoami <manifest> <task-id> [--workflow id]` | Show the fully resolved identity, trust, and contract for a task. |

### Inspection and Audit

| Command | Description |
|---|---|
| `inspect <jobs\|runs\|queue\|approvals> [--db path] [--fields a,b,c] [--limit n] [--sanitize basic] [--ndjson]` | Inspect scheduler runtime state with field masks and sanitization. |
| `audit [--limit n]` | Display recent audit records from the append-only log. |
| `verify <execution-id> [--allowed-signers path]` | Verify execution evidence for a completed run. |
| `signing providers` | List registered signing providers and their attestation methods. |

### Registry

| Command | Description |
|---|---|
| `registry list` | List all registered manifests. |
| `registry add <path> [--name name]` | Register a manifest by path. |
| `registry show <name>` | Show a registered manifest. |
| `registry remove <name>` | Remove a manifest from the registry. |

### JSON-RPC

| Command | Description |
|---|---|
| `serve [--db path]` | Start a stdio JSON-RPC server. |

### Global Flags

| Flag | Description |
|---|---|
| `--version`, `-v` | Show package and manifest spec version. |
| `--json` | Force JSON output. |
| `--pretty` | Colorize JSON output for human readability. |
| `--ndjson` | Emit item streams as newline-delimited JSON. |

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `AGENTCLI_HOME` | `~/.agentcli` | Home directory for manifests, output, state, and audit. |
| `AGENTCLI_OUTPUT` | `json` | Default output format: `json` or `ndjson`. |
| `AGENTCLI_TARGET` | `standalone` | Default compilation target. |
| `AGENTCLI_SIGNER` | `ssh` | Default signing provider for execution evidence. |
| `AGENTCLI_SIGNING_KEY` | (none) | Path to SSH private key for evidence signing. |
| `AGENTCLI_SCHEDULER_DB` | (none) | Path to scheduler SQLite database for inspection. |
| `AGENTCLI_SCHEDULER_PREFIX` | (none) | npm prefix path for the scheduler runtime. |
| `AGENTCLI_SCHEDULER_BIN` | (none) | Direct path to the scheduler binary. |

## JSON-RPC

`agentcli serve` exposes the full command surface over stdio JSON-RPC 2.0. This is the preferred integration point for agent systems that need programmatic access without shell parsing.

The server emits an `agentcli.ready` notification on startup. Use `agentcli describe rpc` to inspect the machine-readable method and notification surface. Read-only RPC methods include target and path discovery, sanitized audit reads, approval listing, and registry list/show. Successful replies use a JSON-RPC `result` envelope; failures use a JSON-RPC `error` envelope with machine-readable `data.code` and `data.error_type`.

See [docs/protocol.md](docs/protocol.md) for the full protocol specification.

## Compilation Targets

| Target | Description |
|---|---|
| `standalone` | Portable plan for authoring, validation, explanation, and protocol use. No durable runtime required. |
| `openclaw-scheduler` | Compiler target for the durable scheduler runtime. Apply uses live runtime capabilities when reported and conservative static fallback values otherwise. Governed root approvals, approver scopes, structured output, and v3 handoff fields require explicit runtime support. |

```bash
# Compile for standalone use
agentcli compile my-workflow.json --target standalone --explain

# Compile for the scheduler runtime
agentcli compile my-workflow.json --target openclaw-scheduler --explain

# Apply to the scheduler (creates or updates jobs)
agentcli apply my-workflow.json --dry-run
agentcli apply my-workflow.json
```

## Migration from v0.1

v0.1 manifests continue to work unchanged. The validator accepts both versions, and the execution path for v0.1 manifests is preserved.

To upgrade a v0.1 manifest to v0.2 and gain access to identity profiles, evidence, and authorization features:

```bash
# Preview the conversion
agentcli convert my-v1-workflow.json

# Write the converted manifest to a file
agentcli convert my-v1-workflow.json --output my-v2-workflow.json
```

The converter applies safe defaults:

- Subject kind is set to `unknown` (update to `agent`, `service`, `workload`, or `user` as appropriate)
- Trust level defaults to `supervised`
- Delegation mode defaults to `none`
- Cleanup policy defaults to `always`
- Legacy attestation strings are preserved as informational authorization proof profiles with `method: "none"`; conversion never invents missing cryptographic trust material

For scheduler migration (adopting existing jobs), use `--adopt-by name` during the initial apply:

```bash
agentcli apply my-v2-workflow.json --adopt-by name --dry-run
agentcli apply my-v2-workflow.json --adopt-by name
```

After adoption, subsequent applies use the default `--adopt-by id` with no flag needed.

## Examples

The `examples/` directory contains annotated manifests covering the full feature range:

| Manifest | Description |
|---|---|
| [hello-world.json](examples/hello-world.json) | Minimal workflow with a scheduled task and a triggered follow-up. |
| [shell-workflow.json](examples/shell-workflow.json) | Shell execution with delivery, reliability, and triggered escalation. |
| [public-shell-failure-triage.json](examples/public-shell-failure-triage.json) | Shell failure triage with model policy, plan intent, output offload, and budgets. |
| [public-report-publish.json](examples/public-report-publish.json) | Multi-step report pipeline: capture, analyze, publish with approval gates. |
| [public-bot-health.json](examples/public-bot-health.json) | Bot health monitoring with plan/read-only intent and context retrieval. |
| [flyctl-ops.json](examples/flyctl-ops.json) | Wrapping `flyctl` as a structured tool invocation with token binding and failure triage. |
| [identity-contract.json](examples/identity-contract.json) | v0.1 identity and contract fields with approval and attestation. |
| [identity-v2.json](examples/identity-v2.json) | Full v0.2 identity: profiles, trust levels, credential presentation, evidence, and authorization proof. |
| [oidc-service-auth.json](examples/oidc-service-auth.json) | OIDC client credentials authentication with token materialization into the process environment. |
| [trust-enforcement.json](examples/trust-enforcement.json) | Graduated trust levels with strict and advisory enforcement across multiple tasks. |
| [authorization-proof.json](examples/authorization-proof.json) | JWT-based manifest authorization proof with signature-backed verification via `jwks_uri`. |
| [stripe-identity-step-up.json](examples/stripe-identity-step-up.json) | Stripe Identity-style step-up for sensitive commands: normal service auth plus a short-lived signed JWT proof and actor-context audit metadata. |
| [stripe-identity-step-up.rego](examples/stripe-identity-step-up.rego) | Example OPA policy for the Stripe Identity step-up manifest. |
| [cloud-workload.json](examples/cloud-workload.json) | Azure managed identity for cloud workload authentication with evidence and compliance context. |
| [stripe-ops.json](examples/stripe-ops.json) | Wrapping the Stripe CLI with API key binding, JSON output parsing, evidence, and failure triage. |
| [stripe-projects.json](examples/stripe-projects.json) | Wrapping [Stripe Projects](https://projects.dev): credential sync, status checks, and database migrations with two identity profiles at different trust levels. |
| [full-stack-deploy.json](examples/full-stack-deploy.json) | Full deployment pipeline chaining Stripe, Prisma, and Fly.io with three identities, trust enforcement, evidence, and failure triage. |
| [aws-ops.json](examples/aws-ops.json) | AWS infrastructure monitoring: caller identity, S3 buckets, EC2 instances, CloudWatch alarms, and cost estimates with trust enforcement. |
| [kubectl-ops.json](examples/kubectl-ops.json) | Kubernetes operations: pods, deployments, nodes, warning events, and manifest apply with approval gates. |
| [terraform-ops.json](examples/terraform-ops.json) | Terraform pipeline: init, plan, apply, and state show chained via triggers with strict trust on apply. |
| [gh-ops.json](examples/gh-ops.json) | GitHub CLI: list PRs, check CI, list issues, and create releases with approval and trust enforcement. |
| [docker-ops.json](examples/docker-ops.json) | Docker operations: containers, images, disk usage, build, and prune with network isolation on destructive tasks. |
| [gcloud-ops.json](examples/gcloud-ops.json) | Google Cloud: identity check, compute instances, GKE clusters, and billing with evidence on all tasks. |
| [curl-api.json](examples/curl-api.json) | Generic REST API operations: health checks, authenticated data fetch, and webhook posts with token binding. |
| [psql-ops.json](examples/psql-ops.json) | PostgreSQL: connection check, table sizes, active queries, and migrations with strict trust and approval. |
| [npm-ops.json](examples/npm-ops.json) | Node.js lifecycle: trigger-chained install/test/build pipeline, security audit, and outdated checks. |
| [git-ops.json](examples/git-ops.json) | Git operations: status, log, diff, commit, and push with strict trust enforcement on push. |
| [ssh-remote.json](examples/ssh-remote.json) | SSH remote ops: uptime, disk, memory monitoring, service restart with approval, and log tailing. |
| [sfdc-ops.json](examples/sfdc-ops.json) | Salesforce CLI: org status, SOQL queries, metadata listing, deployment validation with triage, and deploy with approval gate. |
| [servicenow-ops.json](examples/servicenow-ops.json) | ServiceNow CLI: incidents, P1 monitoring with triage, change requests, problems, CMDB servers, and incident creation with approval. |
| [vercel-ops.json](examples/vercel-ops.json) | Vercel CLI: deployment listing, domain checks, preview→promote pipeline with approval gate, health verification, and env var audit. |

For a step-by-step local walkthrough of the Stripe Identity example, see [docs/guide-testing-stripe-identity-step-up.md](docs/guide-testing-stripe-identity-step-up.md).

### Putting it together: a v0.2 manifest

The following excerpt from `identity-v2.json` shows the key v0.2 concepts in one manifest. Identity profiles define who the task runs as and how credentials are acquired. Evidence profiles define how execution is proven after the fact. Workflows and tasks reference these profiles by ID.

```json
{
  "version": "0.2",
  "identity_profiles": [
    {
      "id": "env-token-agent",
      "provider": "env-bearer",
      "subject": {
        "kind": "service",
        "principal": "agent://local/env-service",
        "delegation_mode": "none"
      },
      "auth": {
        "mode": "service",
        "scopes": ["read"],
        "provider_config": {
          "token_env": "TEST_BEARER_TOKEN"
        }
      },
      "trust": { "level": "restricted" },
      "presentation": {
        "bindings": [
          {
            "source": "credentials.access_token.value",
            "target": { "kind": "env", "name": "API_TOKEN" },
            "redact": true
          }
        ],
        "cleanup": "always"
      }
    }
  ],
  "evidence_profiles": [
    {
      "id": "ssh-evidence",
      "provider": "ssh",
      "payload": {
        "bind": ["execution_id", "declared_identity", "contract", "command", "result"],
        "format": "canonical-json"
      }
    }
  ],
  "workflows": [
    {
      "id": "identity-demo",
      "name": "Identity Demo Workflow",
      "contract": {
        "sandbox": "permissive",
        "network": "unrestricted",
        "audit": "always",
        "required_trust_level": "restricted",
        "trust_enforcement": "advisory"
      },
      "tasks": [
        {
          "id": "env-token-task",
          "name": "Env Token Task",
          "shell": { "program": "echo", "args": ["token-test"] },
          "target": { "session_target": "shell" },
          "identity": { "ref": "env-token-agent" },
          "schedule": { "cron": "0 * * * *" }
        }
      ]
    }
  ]
}
```

The identity provider (`env-bearer`) resolves the bearer token from `$TEST_BEARER_TOKEN` at execution time, presents it as `$API_TOKEN` in the task environment, and ensures it is redacted in audit output. The evidence profile signs the execution payload with SSH keys for later verification. The contract requires at least `restricted` trust and enforces `always` audit.

## Standards Alignment

`agentcli`'s identity architecture is designed to compose with emerging agent identity standards rather than compete with them.

- **IETF AIMS** (`draft-klrc-aiagent-auth-00`): The Agent Identity Management System defines a layered reference architecture for agent identity. `agentcli`'s six-layer model (subject declaration, manifest authorization proof, credential acquisition, credential presentation, contract enforcement, evidence and audit) is independently aligned with AIMS.

- **SPIFFE/WIMSE**: Identity profiles support URI-formatted principals (`agent://`, `spiffe://`) for interoperability with workload identity infrastructure.

- **OAuth 2.0**: Auth modes map to standard OAuth grants. `service` maps to Client Credentials, `delegated` to Authorization Code, `on-behalf-of` to JWT Authorization Grant (RFC 7523), and `exchange` to Token Exchange (RFC 8693).

See [docs/execution-identity.md](docs/execution-identity.md) for the full architecture document, including standards mapping tables.

## Documentation

| Document | Description |
|---|---|
| [spec.md](docs/spec.md) | Manifest specification |
| [execution-identity.md](docs/execution-identity.md) | Execution identity architecture |
| [protocol.md](docs/protocol.md) | JSON-RPC protocol specification |
| [capabilities.md](docs/capabilities.md) | Capability surface documentation |
| [architecture.md](docs/architecture.md) | System architecture |
| [versioning.md](docs/versioning.md) | Version strategy |
| [conformance.md](docs/conformance.md) | Conformance requirements |
| [adoption.md](docs/adoption.md) | Adoption guide |
| [roadmap.md](docs/roadmap.md) | Roadmap |

## Installation

```bash
# From npm (after publication)
npm install -g @amittell/agentcli
agentcli init
agentcli paths

# Local development
npm install
npm test
```

`agentcli init` creates a local home directory (default `~/.agentcli`) with:

- `manifests/` -- manifest storage
- `output/` -- execution output
- `state/` -- runtime state
- A starter manifest at `~/.agentcli/manifests/bot-health.json`

Once initialized, you can refer to manifests by name instead of full path:

```bash
agentcli validate bot-health
agentcli compile bot-health --target openclaw-scheduler --explain
```

### Pairing with the scheduler runtime

```bash
mkdir -p ~/.openclaw/scheduler
npm install --prefix ~/.openclaw/scheduler openclaw-scheduler@latest
npm exec --prefix ~/.openclaw/scheduler openclaw-scheduler -- setup
```

Then point inspection commands at the runtime state:

```bash
AGENTCLI_SCHEDULER_DB=~/.openclaw/scheduler/scheduler.db agentcli inspect jobs --fields id,name,last_status
```
