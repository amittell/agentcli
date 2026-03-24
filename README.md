# agentcli

`agentcli` is an agent-native workflow manifest standard, execution identity framework, and reference CLI. It gives agents and operators a declarative way to describe workflows, bind execution identity, acquire credentials, produce verifiable evidence, and compile manifests into runtime-specific artifacts -- all without coupling authors to any single execution engine or identity provider.

If you are building or operating agent workflows that need to be safe, auditable, and portable, `agentcli` provides the control plane contract between authoring, identity, and execution.

## Quick Start

```bash
# Install
npm install -g agentcli

# Initialize local home directory
agentcli init

# Validate a manifest
agentcli validate examples/hello-world.json

# Compile to a standalone plan with explanation
agentcli compile examples/hello-world.json --target standalone --explain

# Execute a task locally with attestation
agentcli exec examples/identity-v2.json echo-identity --signer ssh

# View audit records
agentcli audit --limit 10

# Verify execution evidence
agentcli verify <execution-id>
```

Node 22.5.0 or newer is required. Scheduler inspection uses `node:sqlite`, which became stable in Node 23.4.0.

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

Execution identity is the headline feature of `agentcli` v0.2. It treats identity as a first-class control-plane concern rather than optional metadata.

### Why execution identity matters

Agent workflows increasingly operate as autonomous principals: they acquire credentials, call APIs, modify infrastructure, and produce artifacts. Without a structured identity model, there is no reliable answer to basic questions:

- Who authorized this execution?
- What credentials did the agent use, and how were they obtained?
- What trust level was the agent operating at?
- Can the execution be independently verified after the fact?
- Are audit records complete, tamper-evident, and free of leaked secrets?

Regulatory frameworks (EU AI Act, Colorado AI Act) add urgency: systems that cannot produce clear execution records, policy context, and attributable identity will be harder to justify in regulated environments.

### Identity profiles

Identity profiles are reusable, declarative descriptions of how a task should authenticate and present credentials. They are defined at the manifest top level and referenced by workflows and tasks.

```json
{
  "identity_profiles": [
    {
      "id": "deploy-agent",
      "provider": "oidc-client-credentials",
      "subject": {
        "kind": "service",
        "principal": "agent://acme.com/deploy-bot",
        "display_name": "Deploy Bot",
        "delegation_mode": "none"
      },
      "auth": {
        "mode": "service",
        "scopes": ["deploy:staging"],
        "provider_config": {
          "issuer": "https://auth.acme.com",
          "client_id_env": "DEPLOY_CLIENT_ID",
          "client_secret_env": "DEPLOY_CLIENT_SECRET"
        }
      },
      "trust": {
        "level": "supervised",
        "constraints": {
          "max_autonomy": "supervised",
          "escalation": "fail"
        }
      },
      "presentation": {
        "bindings": [
          {
            "source": "credentials.access_token.value",
            "target": { "kind": "env", "name": "DEPLOY_TOKEN" },
            "redact": true
          }
        ],
        "handoff": "none",
        "cleanup": "always"
      }
    }
  ]
}
```

Profiles never contain raw secrets. Credential references point to environment variables or files that are resolved at execution time.

### Provider system

Identity providers are pluggable modules that handle credential acquisition. Each provider implements a standard interface: validate the profile, resolve a credential session, materialize credentials for tool consumption, and clean up afterward.

Built-in providers are listed in the [Identity Providers](#identity-providers) section. Custom providers can be registered without forking agentcli.

### Trust levels

Trust levels express graduated autonomy. They control what an agent is allowed to do and how much oversight is required.

| Level | Meaning |
|---|---|
| `untrusted` | No autonomous capability. Every action requires external approval. |
| `restricted` | Limited capability. Scoped credentials, narrow allowed paths. |
| `supervised` | Broad capability with oversight. Actions are logged and may require approval for high-risk operations. |
| `autonomous` | Full capability within contract bounds. Suitable for well-established, well-tested workflows. |

Trust levels are declared in the identity profile and enforced against the contract's `required_trust_level`. When a task's effective trust level is below the contract requirement, execution fails or escalates depending on `trust_enforcement` policy.

### Credential presentation

Credentials are materialized into the task's execution environment through explicit bindings. Each binding maps a path in the credential session to an environment variable, file, or header that the wrapped tool consumes.

```json
"presentation": {
  "bindings": [
    {
      "source": "credentials.access_token.value",
      "target": { "kind": "env", "name": "API_TOKEN" },
      "required": false,
      "redact": true
    }
  ],
  "cleanup": "always"
}
```

Bindings support `raw`, `json`, and `base64` formats. The `redact` flag ensures the credential value is replaced with `[REDACTED]` in audit output. Cleanup runs unconditionally (`always`) or on failure only, depending on the policy.

### Evidence and attestation

After execution, evidence providers produce cryptographic proof binding the execution identity, command, and result into a verifiable record.

```json
"evidence_profiles": [
  {
    "id": "ssh-evidence",
    "provider": "ssh",
    "payload": {
      "bind": ["execution_id", "declared_identity", "contract", "command", "result"],
      "format": "canonical-json"
    }
  }
]
```

Evidence payloads are signed using the configured provider (e.g., SSH keys) and can be independently verified with `agentcli verify`.

### Authorization

Optional external authorization providers evaluate policy before execution. Authorization requests include structured context (identity, contract, command, trust level) that policy engines can evaluate.

Authorization decisions are normalized to three outcomes: `permit`, `deny`, or `require-escalation`. Unmapped provider responses default to `deny`.

### Audit records

Every execution produces a structured, append-only audit record. Records include the declared identity, resolved trust level, contract, command hash, execution result, and evidence reference. Raw secrets are never written to the audit log.

```bash
# View recent audit records
agentcli audit --limit 5

# Verify a specific execution
agentcli verify <execution-id> --allowed-signers ~/.ssh/allowed_signers
```

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

Use `agentcli identity providers` to list registered providers and `agentcli identity schema <provider>` to inspect provider-specific configuration fields.

## Authorization Proof Methods

Authorization proof verifies that the manifest itself was approved before execution.

| Method | Description |
|---|---|
| `none` | No proof required. |
| `jwt` | Manifest approval encoded as a signed JWT. |
| `detached-signature` | Manifest approval via a detached cryptographic signature. |
| `certificate` | Manifest approval via an X.509 certificate chain. |

Use `agentcli authorization-proof methods` to list available methods and `agentcli authorization-proof schema <method>` to inspect method-specific fields.

## Authorization Providers

| Provider | Description |
|---|---|
| `none` | No external authorization. Contract enforcement still applies. |
| `opa` | Evaluates policy using Open Policy Agent. |

Use `agentcli authorization providers` to list registered providers and `agentcli authorization schema <provider>` to inspect configuration.

## Evidence Providers

| Provider | Description |
|---|---|
| `none` | No evidence produced. Audit records are still written. |
| `ssh` | Signs evidence payloads using SSH keys. Verifiable with `agentcli verify`. |

Use `agentcli evidence providers` to list registered providers and `agentcli evidence schema <provider>` to inspect configuration.

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
| `exec <path> <task-id> [--workflow id] [--dry-run] [--timeout ms] [--signer ssh\|none] [--signing-key path]` | Execute a task locally with identity resolution, contract enforcement, and attestation. |
| `apply <path> [--db path] [--scheduler-prefix path\|--scheduler-bin path] [--dry-run] [--explain] [--adopt-by id\|name]` | Apply a manifest to the scheduler runtime. Creates or updates jobs. |

### Identity and Authorization

| Command | Description |
|---|---|
| `identity providers` | List registered identity providers. |
| `identity schema <provider>` | Show configuration schema for an identity provider. |
| `identity resolve <manifest> <task-id> [--workflow id]` | Resolve the effective identity for a task. |
| `identity validate-delegation <manifest> <task-id> [--workflow id]` | Validate delegation chain for a task. |
| `authorization-proof methods` | List available authorization proof methods. |
| `authorization-proof schema <method>` | Show schema for an authorization proof method. |
| `authorization-proof verify <manifest> <task-id> [--workflow id]` | Verify authorization proof for a task. |
| `authorization providers` | List registered authorization providers. |
| `authorization schema <provider>` | Show schema for an authorization provider. |
| `authorization evaluate <manifest> <task-id> [--workflow id]` | Evaluate authorization policy for a task. |
| `evidence providers` | List registered evidence providers. |
| `evidence schema <provider>` | Show schema for an evidence provider. |
| `whoami <manifest> <task-id> [--workflow id]` | Show the fully resolved identity, trust, and contract for a task. |

### Inspection and Audit

| Command | Description |
|---|---|
| `inspect <jobs\|runs\|queue\|approvals> [--db path] [--fields a,b,c] [--limit n] [--sanitize basic] [--ndjson]` | Inspect scheduler runtime state with field masks and sanitization. |
| `audit [--limit n]` | Display recent audit records from the append-only log. |
| `verify <execution-id> [--allowed-signers path]` | Verify execution evidence for a completed run. |

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
| [identity-contract.json](examples/identity-contract.json) | v0.1 identity and contract fields with approval and attestation. |
| [identity-v2.json](examples/identity-v2.json) | Full v0.2 identity: profiles, trust levels, credential presentation, evidence, and authorization proof. |

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
npm install -g agentcli
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
