# Wrapping CLI Tools with agentcli

## The problem

Modern deployment involves multiple CLI tools, each with its own credentials, its own failure modes, and no shared governance. A typical deploy might look like this:

```bash
stripe projects env --pull
npx prisma migrate deploy
flyctl deploy --remote-only
flyctl checks list
stripe charges list --limit 1
```

Five commands, three credential sets, no audit trail, no trust enforcement, no evidence of who ran what or whether they were authorized to. If the migration fails at 2am, there is no record of which identity triggered it, what trust level it ran under, or what the contract boundaries were.

## What agentcli adds

agentcli wraps these same CLI tools with a declarative manifest that binds:

- **Identity** -- who is running the command (a named principal with a trust level, not just "whoever has the env var")
- **Credentials** -- how the tool gets its secrets (bound through the identity profile, redacted from logs, cleaned up after execution)
- **Contract** -- what boundaries the task must respect (sandbox mode, network posture, trust floor, audit policy)
- **Evidence** -- cryptographic proof that the execution happened as described (signed payload with execution ID, identity, command, and result)
- **Audit** -- append-only structured records with identity provenance, trust evaluation, and execution metadata

The CLI tools themselves are unchanged. agentcli is the governance layer around them.

## Full-stack deployment example

[full-stack-deploy.json](../examples/full-stack-deploy.json) demonstrates a complete deployment pipeline that chains five tools together under agentcli governance:

```
sync-credentials (stripe projects env --pull)
    |
    v  [on success]
run-migrations (npx prisma migrate deploy)
    |
    v  [on success]
deploy-app (flyctl deploy --remote-only --strategy rolling)
    |
    +---> [on success, 30s delay] verify-health (flyctl checks list)
    +---> [on success, 30s delay] verify-payments (stripe charges list)
```

Each step has:
- A distinct identity profile with its own trust level
- Credential bindings that inject the right secret into the right env var
- Contract enforcement (the migration step requires `restricted` trust; the deploy step requires `supervised`)
- Evidence generation (SSH-signed attestation of what ran and what it returned)
- Failure triage (agent-based read-only analysis with delivery to the operator)

### Three identities, three trust levels

```json
"identity_profiles": [
  {
    "id": "stripe-credentials",
    "provider": "env-bearer",
    "subject": { "principal": "agent://deploy/stripe" },
    "auth": { "provider_config": { "token_env": "STRIPE_API_KEY" } },
    "trust": { "level": "supervised" }
  },
  {
    "id": "fly-credentials",
    "provider": "env-bearer",
    "subject": { "principal": "agent://deploy/flyctl" },
    "auth": { "provider_config": { "token_env": "FLY_API_TOKEN" } },
    "trust": { "level": "supervised" }
  },
  {
    "id": "database-credentials",
    "provider": "env-bearer",
    "subject": { "principal": "agent://deploy/database" },
    "auth": { "provider_config": { "token_env": "DATABASE_URL" } },
    "trust": { "level": "restricted" }
  }
]
```

The database migration agent is `restricted` -- it can read and write the database but nothing else. The deploy agent is `supervised` -- it has broader access but is still bounded by its contract. These are not just labels; the contract's `trust_enforcement: "strict"` means execution is blocked if the identity's trust level is below the required floor.

### What the contract enforces

Each task declares what it needs:

```json
{
  "id": "deploy-app",
  "contract": {
    "required_trust_level": "supervised",
    "trust_enforcement": "strict"
  }
}
```

If someone swaps in a `restricted` identity profile for the deploy task, agentcli refuses to run it. This is not advisory -- it is a hard gate. The contract is the boundary; the identity must satisfy it.

### What the audit record captures

Every execution writes a structured record:

```json
{
  "execution_id": "a1b2c3...",
  "timestamp": "2026-03-27T02:00:00Z",
  "source": { "workflow_id": "full-stack-deploy", "task_id": "deploy-app" },
  "declared_identity": {
    "provider": "env-bearer",
    "subject": { "principal": "agent://deploy/flyctl", "kind": "service" },
    "trust_level": "supervised"
  },
  "trust": { "declared_level": "supervised", "effective_level": "supervised" },
  "contract": {
    "required_trust_level": "supervised",
    "trust_enforcement": "strict",
    "audit": "always"
  },
  "hashes": { "command": "sha256:...", "result": "sha256:..." },
  "evidence": { "provider": "ssh", "method": "ssh-signature", "attested": true },
  "result": { "exit_code": 0, "duration_ms": 45200 }
}
```

No raw credentials appear in the record. The identity is traced by principal URI and trust level. The command and result are hashed. The evidence is a signed attestation that can be independently verified with `agentcli verify`.

## The Stripe Projects connection

[Stripe Projects](https://projects.dev) provisions infrastructure from multiple providers (Vercel, Neon, Clerk, PostHog, etc.) and centralizes credential management. `stripe projects env --pull` syncs all provider credentials to your local environment.

agentcli complements this by adding the governance layer that Stripe Projects does not cover:

| Concern | Stripe Projects | agentcli |
|---------|----------------|----------|
| Infrastructure provisioning | Yes (multi-provider catalog) | No |
| Credential acquisition | Yes (`stripe projects env --pull`) | Yes (identity providers, `command` value_from) |
| Credential binding to tools | Manual (paste into .env) | Declarative (presentation bindings) |
| Who ran what | Not tracked | Identity profiles with principal URIs |
| Trust boundaries | Not modeled | Trust levels with strict enforcement |
| Execution evidence | Not generated | SSH-signed attestation |
| Audit trail | Not maintained | Append-only structured records |
| Failure triage | Not handled | Agent-based read-only analysis |

The two tools sit at different layers. Stripe Projects handles provisioning and credential sourcing. agentcli handles governance, execution, and accountability. Together they give you infrastructure that provisions itself and a deployment pipeline that audits itself.

### Dynamic credential acquisition

agentcli can pull credentials directly from Stripe Projects at execution time using the `command` value_from source:

```json
"auth": {
  "inputs": {
    "credential_sync": {
      "value_from": {
        "command": "stripe projects env --pull --format env 2>/dev/null | grep STRIPE_API_KEY | cut -d= -f2"
      }
    }
  }
}
```

This means the manifest does not contain secrets and does not depend on the local `.env` file being up to date. agentcli resolves the credential at execution time by running the Stripe Projects CLI.

The same pattern works for any credential manager:

```json
"value_from": { "command": "vault kv get -field=token secret/myapp" }
"value_from": { "command": "op item get 'API Key' --fields credential" }
"value_from": { "command": "aws ssm get-parameter --name /app/key --with-decryption --query Parameter.Value --output text" }
```

## Wrapping other tools

The pattern generalizes to any CLI tool that reads credentials from the environment.

### kubectl

```json
{
  "id": "k8s-deploy",
  "provider": "env-bearer",
  "auth": { "provider_config": { "token_env": "KUBECONFIG" } },
  "presentation": {
    "bindings": [{
      "source": "credentials.access_token.value",
      "target": { "kind": "env", "name": "KUBECONFIG" }
    }]
  }
}
```

```json
"shell": { "program": "kubectl", "args": ["apply", "-f", "k8s/deployment.yaml"] }
```

### terraform

```json
{
  "id": "tf-credentials",
  "provider": "env-bearer",
  "auth": { "provider_config": { "token_env": "TF_TOKEN_app_terraform_io" } },
  "presentation": {
    "bindings": [{
      "source": "credentials.access_token.value",
      "target": { "kind": "env", "name": "TF_TOKEN_app_terraform_io" }
    }]
  }
}
```

```json
"shell": { "program": "terraform", "args": ["apply", "-auto-approve"] }
```

### gh (GitHub CLI)

```json
{
  "id": "github-token",
  "provider": "env-bearer",
  "auth": { "provider_config": { "token_env": "GH_TOKEN" } },
  "presentation": {
    "bindings": [{
      "source": "credentials.access_token.value",
      "target": { "kind": "env", "name": "GH_TOKEN" }
    }]
  }
}
```

```json
"shell": { "program": "gh", "args": ["pr", "create", "--fill"] }
```

## Why the manifest matters

Without a manifest, a deployment is a shell script. Shell scripts work, but they have no intrinsic concept of identity, trust, or evidence. When something goes wrong at 2am, you are left searching shell history and log files to reconstruct what happened.

With a manifest:

- **Identity is declared, not inferred.** The principal URI (`agent://deploy/flyctl`) is stable across executions and attributable in audit records.
- **Trust is enforced, not assumed.** A `restricted` agent cannot run a `supervised` task, even if the shell script would let it.
- **Credentials are bound, not scattered.** The manifest declares which credential goes where; the runtime materializes it, the audit redacts it, the cleanup removes it.
- **Evidence is generated, not reconstructed.** Every execution produces a signed attestation that can be verified months later.
- **Failure is triaged, not ignored.** On-failure handlers delegate to an agent that can read the context and recommend recovery without making changes.

The manifest is the contract between the operator and the system. It says: this is who runs, this is what they can do, this is how we prove it happened, and this is what we do when it fails.

## Running the example

```bash
# Set credentials (or use stripe projects env --pull)
export STRIPE_API_KEY="sk_test_..."
export FLY_API_TOKEN="fo1_..."
export DATABASE_URL="postgres://..."

# Validate the manifest
agentcli validate examples/full-stack-deploy.json

# Inspect identity resolution for any task
agentcli whoami examples/full-stack-deploy.json deploy-app

# Dry-run the deploy step
agentcli exec examples/full-stack-deploy.json deploy-app --dry-run --signer none

# Run for real (with SSH evidence)
agentcli exec examples/full-stack-deploy.json sync-credentials

# Inspect the audit trail
agentcli audit --limit 5

# Verify a specific execution
agentcli verify <execution-id>

# Compile for durable scheduling
agentcli compile examples/full-stack-deploy.json --target openclaw-scheduler --explain
```
