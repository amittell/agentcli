# Manifest Authoring

Use this skill when working on `agentcli` manifests, compile targets, or protocol behavior.

## Discovery

Run `agentcli skill-path` to get the resolved path to this file programmatically.

Run `agentcli schema <target>` to get machine-readable field definitions. Targets: manifest, workflow, task, schedulerJob, standalonePlan, rpcRequest, rpcResponse.

Run `agentcli describe <topic>` for narrative metadata. Topics: manifest, workflow, task, targets, commands, rpc.

Run `agentcli paths` to resolve the home directory, manifests, output, state, and registry locations.

## Workflow

1. Start from `examples/hello-world.json` or another raw JSON manifest.
2. Validate first with `agentcli validate`.
3. If the task is backend-neutral, compile to `standalone`.
4. If the task explicitly targets the scheduler runtime, compile to `openclaw-scheduler`.
5. Use `agentcli describe` and `agentcli schema` instead of relying on prose docs alone.
6. When reading scheduler state, use `agentcli inspect` with `--fields` and `--sanitize basic` when agent reuse is likely.
7. Use `--pretty` for colorized JSON output during interactive sessions.
8. Use `--explain` with `compile` or `apply` to see how fields were resolved.

## Identity and Chain of Trust

Agents executing CLI tasks assume the user's identity. Manifests declare this via `identity` blocks:

```json
{
  "identity": {
    "principal": "user@example.com",
    "run_as": "ci-service",
    "attestation": "signed-jwt-token"
  }
}
```

- `principal`: who authorized the execution
- `run_as`: the runtime identity the agent should assume
- `attestation`: optional proof of authorization (token, signature)

Identity flows from workflow to task. Task-level identity overrides workflow-level fields key by key.

## Execution Contracts

Contracts define the boundaries an agent must respect during execution:

```json
{
  "contract": {
    "sandbox": "strict",
    "allowed_paths": ["/data/output", "/tmp"],
    "network": "restricted",
    "max_cost_usd": 5.00,
    "audit": "always"
  }
}
```

- `sandbox`: none, permissive, or strict
- `allowed_paths`: filesystem paths the agent may access
- `network`: unrestricted, restricted, or none
- `max_cost_usd`: cost ceiling for the execution
- `audit`: none, on-failure, or always

Contracts inherit from workflow to task, same as identity and model_policy.

## Direct Execution

`agentcli exec` runs shell-target tasks directly from a manifest, without a scheduler:

```
agentcli exec manifest.json check-space
agentcli exec manifest.json build --workflow secure-deploy --dry-run
agentcli exec manifest.json deploy --timeout 30000
```

Exec enforces contracts before spawning:
- Rejects `shell.cwd` outside `allowed_paths`
- Warns about sandbox/network constraints not yet enforced at OS level
- Respects `runtime.timeout_ms`

The audit log (`~/.agentcli/state/audit.ndjson`) records every execution with identity, contract, timing, and output hash. Read it with `agentcli audit` or `agentcli audit --limit 10`.

The audit record never includes environment variable values or stdin content (these may contain secrets). It records env key names and a boolean for stdin presence.

## Execution-Time Attestation

Every `agentcli exec` run can be cryptographically signed using a pluggable signing provider. This is separate from the manifest-time `identity.attestation` field (which carries pre-existing authorization proof like a CI-issued JWT).

### Signing Providers

```
agentcli exec manifest.json deploy                        # ssh (default)
agentcli exec manifest.json deploy --signer none           # skip signing
agentcli exec manifest.json deploy --signing-key ~/.ssh/id_ed25519  # explicit SSH key
AGENTCLI_SIGNER=none agentcli exec manifest.json deploy    # env-configured
```

Provider resolution order:
1. `--signer <name>` flag
2. `AGENTCLI_SIGNER` environment variable
3. Default: `ssh`

Built-in providers:
- `ssh` -- signs with the user's SSH key via `ssh-keygen -Y sign`
- `none` -- explicitly disables signing

The `ssh` provider resolves keys in order: `--signing-key` flag, `AGENTCLI_SIGNING_KEY` env, then auto-discovery from `~/.ssh/` (id_ed25519, then id_ecdsa, then id_rsa).

The attestation payload is canonical deterministic JSON containing: version, execution_id, timestamp, source (workflow_id + task_id), command_hash, and principal. The command_hash is SHA-256 of program + args + cwd. Environment variable values and stdin content are never included.

If signing fails (e.g. passphrased key not loaded in ssh-agent), the execution proceeds without attestation and the audit record notes the reason.

### Verifying Executions

```
agentcli verify <execution_id>              # verify from audit log
agentcli verify <execution_id> --allowed-signers path/to/file
```

The `verify` command dispatches to the provider that produced the attestation (determined by the `method` field in the audit record). For SSH attestations, it uses `ssh-keygen -Y verify` against an `allowed_signers` file. If no allowed_signers file exists, it auto-generates one from `~/.ssh/*.pub`.

The attestation proves:
- Who held the signing credential that authorized the execution
- What command was executed (via command_hash)
- When the execution occurred (timestamp in signed payload)
- That the audit record has not been tampered with

### Two Layers of Attestation

- **Manifest-time** (`identity.attestation`): static proof baked into the manifest that the principal is authorized (e.g. a signed JWT or certificate reference)
- **Execution-time** (audit record): dynamic proof that a specific person ran a specific command at a specific time

Both layers work together: the manifest declares who is authorized, and the execution attestation proves who actually ran it.

## Integrating a Tool

### Scaffolding

```
agentcli init                          # create agentcli.json with echo hello
agentcli init --tool kubectl           # wrap kubectl
agentcli init --tool my-cli --workflow-id deploy --task-id run
agentcli init --output deploy.json     # write to specific file
```

The generated manifest passes `agentcli validate` immediately.

### Self-Description Convention

Tools can ship an `agentcli.json` in their root directory:

```
my-tool/
  agentcli.json        <-- agentcli discovers this
  package.json         <-- or reads "agentcli": "path/to/manifest.json"
  src/
```

Import a tool's manifest into the local registry:

```
agentcli import ./my-tool              # discovers agentcli.json or package.json field
agentcli import ./my-tool --name deploy-tool
```

### Registry

```
agentcli registry list                 # list templates with workflow summaries
agentcli registry add manifest.json    # validate and store
agentcli registry add manifest.json --name custom-name
agentcli registry show my-template     # retrieve
agentcli registry remove my-template   # delete
```

Templates are stored in `~/.agentcli/registry/` and can be referenced by name in `agentcli validate <name>` or `agentcli compile <name>`.

### Manifest Composition

Combine workflows from multiple manifests:

```
agentcli merge monitoring.json deploy.json
agentcli merge monitoring.json deploy.json --output combined.json
```

Workflow ids must be unique across inputs. The merged result is validated before output.

### Structured Output

Set `output.format` on a task to have `exec` parse the tool's stdout:

```json
{
  "output": { "format": "json" }
}
```

Supported formats: `json`, `ndjson`, `text` (default). When `json` or `ndjson`, the parsed result is available in `result.structured`. Parse failures are non-fatal and produce a warning.

### Library Extension

To add custom compile targets or signing providers, use agentcli as a library:

```js
import { registerTarget, registerProvider } from 'agentcli';

registerTarget({
  name: 'my-scheduler',
  compile: (manifest, options) => { /* ... */ },
  capabilities: ['compile'],
});
```

## Constraints

- Do not add durable scheduler behavior here.
- Keep new manifest features mappable either to the standalone plan or to explicit backend capability gaps.
- Prefer protocol- and schema-level affordances over custom one-off CLI flags.
- Identity and contract blocks are intent declarations. Backends interpret and enforce them.
