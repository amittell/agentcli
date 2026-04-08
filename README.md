# agentcli

`agentcli` is an agent-native workflow manifest standard, execution identity framework, and reference CLI. It gives agents and operators a declarative way to describe workflows, bind execution identity, acquire credentials, produce verifiable evidence, and compile manifests into runtime-specific artifacts.

Use `agentcli` on its own when you want a clean authoring, validation, local execution, and audit surface.

Use `agentcli` with `openclaw-scheduler` when you want that same manifest contract backed by a durable runtime with scheduling, queueing, retries, approvals, delivery, and SQLite state.

Together, `agentcli` is the control plane and `openclaw-scheduler` is the runtime.

| If you need... | Start here |
| --- | --- |
| Fast local authoring, validation, and execution | `agentcli` |
| Durable schedules, retries, approvals, and runtime state | `agentcli` + `openclaw-scheduler` |

## Quick Start

If you just want to try the manifest model locally, start with the first path.

If you want to run the same workflows on a durable scheduler, use the second path.

### `agentcli` on its own

```bash
# Install
npm install -g @amittell/agentcli

# Create a local home directory with a starter manifest
agentcli init

# Validate a simple manifest
agentcli validate examples/hello-world.json

# See the portable standalone plan
agentcli compile examples/hello-world.json --target standalone --explain

# Run a task locally
agentcli exec examples/trust-enforcement.json collect-data --dry-run --signer none

# Run a shell-only workflow DAG locally
agentcli run examples/trust-enforcement.json --root collect-data --signer none

# Inspect identity resolution
agentcli identity resolve examples/identity-v2.json echo-identity

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
agentcli compile examples/hello-world.json --target openclaw-scheduler --explain

# Preview the jobs that would be created or updated
agentcli apply examples/hello-world.json \
  --db ~/.openclaw/scheduler/scheduler.db \
  --scheduler-prefix ~/.openclaw/scheduler \
  --dry-run

# Ask the runtime which capability surface and handoff version it supports
agentcli apply examples/hello-world.json \
  --db ~/.openclaw/scheduler/scheduler.db \
  --scheduler-prefix ~/.openclaw/scheduler \
  --check-capabilities

# Inspect the runtime state through agentcli
AGENTCLI_SCHEDULER_DB=~/.openclaw/scheduler/scheduler.db \
  agentcli inspect jobs --fields id,name,last_status
```

Node 22.5.0 or newer is required. Scheduler inspection uses `node:sqlite`, which became stable in Node 23.4.0.

## Better Together

`agentcli` and `openclaw-scheduler` are complementary:

- `agentcli` gives you the authoring contract: schema, validation, examples, discovery, identity binding, local execution, audit, and machine-readable CLI / JSON-RPC surfaces.
- `openclaw-scheduler` gives you the durable runtime: schedules, queueing, retries, approvals, delivery, and persistent state.
- The same manifest can start as a local, portable workflow in `agentcli` and then be compiled and applied into `openclaw-scheduler` without rewriting it into a runtime-specific format.

If you want to start simple, start with `agentcli` alone. If you want durable operation, pair it with `openclaw-scheduler`.

## Wrapping Existing CLI Tools

`agentcli` works well as a stable wrapper around existing CLI tools such as `flyctl`, `kubectl`, `gh`, `terraform`, and the Stripe CLI. See [Wrapping CLI Tools](docs/guide-wrapping-tools.md) for the full guide, including a complete multi-tool deployment pipeline that chains Stripe Projects, Prisma, and Fly.io under agentcli governance.

The pattern is:

1. Put the exact tool invocation in `shell.program` and `shell.args[]`.
2. Bind credentials declaratively when the tool expects environment variables or temp files.
3. Validate and run the workflow locally with `agentcli exec`.
4. Compile and apply the same manifest into `openclaw-scheduler` when you want durable execution.

For example, [flyctl-ops.json](examples/flyctl-ops.json) wraps a simple `flyctl status --app my-app` check, binds `FLY_API_TOKEN` through an identity profile, and escalates failures into a read-only triage step.

```bash
agentcli validate examples/flyctl-ops.json
agentcli exec examples/flyctl-ops.json check-app-status --dry-run --identity-debug
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
complete reference.

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
| `spiffe-jwt-svid` | Acquires a JWT-SVID from the SPIFFE Workload API or a projected volume file. Works in SPIFFE-enabled Kubernetes clusters. |
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
| `schema [target]` | Emit JSON schema for manifest, workflow, task, schedulerJob, standalonePlan, rpcRequest, or rpcResponse. |
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
| `exec <path> <task-id> [--workflow id] [--dry-run] [--timeout ms] [--signer ssh\|none] [--signing-key path] [--db path] [--scheduler-prefix path\|--scheduler-bin path]` | Execute shell tasks locally with identity resolution, contract enforcement, and attestation, or delegate non-shell tasks to the scheduler when configured. |
| `run <path> [--workflow id] [--root task-id\|--all-roots] [--dry-run] [--timeout ms] [--signer ssh\|none] [--signing-key path]` | Execute a shell-only workflow DAG locally. Trigger edges, `contains:` / `regex:` conditions, and `on_failure` handlers are evaluated in-process. |
| `apply <path> [--db path] [--scheduler-prefix path\|--scheduler-bin path] [--dry-run] [--explain] [--adopt-by id\|name] [--check-capabilities]` | Apply a manifest to the scheduler runtime, or inspect runtime capability negotiation without writing jobs. |

`agentcli run` is intentionally narrow:

- It only executes tasks with `target.session_target: "shell"`.
- It runs one workflow DAG locally from a selected scheduled root, or from every root when `--all-roots` is set.
- It does not add queueing, retries, approvals, or durable state.
- Manifests that include `main` or `isolated` tasks still need a runtime adapter such as `openclaw-scheduler`.

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

The server emits an `agentcli.ready` notification on startup. Use `agentcli describe rpc` to inspect the machine-readable method and notification surface.

See [docs/protocol.md](docs/protocol.md) for the full protocol specification.

## Compilation Targets

| Target | Description |
|---|---|
| `standalone` | Portable plan for authoring, validation, explanation, and protocol use. No durable runtime required. |
| `openclaw-scheduler` | Compiler target for the durable scheduler runtime. Supports runtime model policy, plan/read-only intent, output offload budgets, queue/approval/fan-out guardrails, and identity compilation. |

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
- Attestation strings are mapped to authorization proof profiles with method detection (OIDC to `jwt`, SSH to `detached-signature`, cert to `certificate`)

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
