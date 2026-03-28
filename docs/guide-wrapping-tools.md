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

## agentcli + Stripe Projects

[Stripe Projects](https://projects.dev) provisions infrastructure from multiple providers
(Vercel, Neon, Clerk, PostHog, Railway, Supabase, and others) and centralizes credential
management through a single CLI. `stripe projects add neon/postgres` provisions a database.
`stripe projects env --pull` syncs all provider credentials to your local `.env`.

agentcli sits on top of this. It does not provision infrastructure -- Stripe Projects
handles that. What agentcli adds is the governance layer: who ran what, with what
authority, within what boundaries, and how do you prove it.

| Layer | Stripe Projects | agentcli |
|-------|----------------|----------|
| Provision infrastructure | `stripe projects add neon/postgres` | -- |
| Acquire credentials | `stripe projects env --pull` | Identity providers, `command` value_from |
| Bind credentials to tools | Manual (.env copy) | Declarative presentation bindings |
| Track who ran what | -- | Identity profiles with principal URIs |
| Enforce trust boundaries | -- | Trust levels with strict/advisory enforcement |
| Prove execution happened | -- | SSH-signed evidence attestation |
| Maintain audit trail | -- | Append-only structured records, secrets redacted |
| Triage failures | -- | Agent-based read-only analysis |

Together: Stripe Projects gives you the infrastructure, agentcli gives you the
accountability.

### How it works in practice

**Step 1: Provision with Stripe Projects**

```bash
stripe projects init my-app
stripe projects add neon/postgres
stripe projects add clerk/auth
stripe projects env --pull
```

After this, your `.env` has `NEON_CONNECTION_STRING`, `CLERK_SECRET_KEY`, and other
credentials from all provisioned services.

**Step 2: Wrap operations with agentcli**

The [stripe-projects.json](../examples/stripe-projects.json) example shows three tasks
that operate on a Stripe Projects-managed stack:

- **sync-credentials** -- runs `stripe projects env --pull` to refresh credentials
- **check-project-status** -- runs `stripe projects status` to verify all services are healthy
- **run-migrations** -- runs `npx prisma migrate deploy` with the database URL bound through an identity profile

The project management tasks (sync, status) use the `none` identity provider because
Stripe Projects authenticates through its own browser-based session, not through an
API key. The migration task uses `env-bearer` to bind `DATABASE_URL` from the
environment into the spawned process.

```bash
# Validate the manifest
agentcli validate examples/stripe-projects.json

# Check project status through agentcli (audited, identity-tracked)
agentcli exec examples/stripe-projects.json check-project-status --signer none

# Sync credentials through agentcli
agentcli exec examples/stripe-projects.json sync-credentials --signer none

# Inspect the audit trail
agentcli audit --limit 3
```

**Step 3: See the difference**

Without agentcli, `stripe projects status` is a shell command with no record of who ran
it or when. With agentcli, the same command produces an audit record:

```json
{
  "execution_id": "a1b2c3...",
  "source": { "workflow_id": "project-ops", "task_id": "check-project-status" },
  "declared_identity": {
    "provider": "none",
    "subject": { "principal": "agent://ops/stripe-project", "kind": "service" }
  },
  "trust": { "declared_level": "supervised", "effective_level": "supervised" },
  "result": { "exit_code": 0 }
}
```

The principal URI is stable across executions. The trust level is enforced. The
audit record is machine-readable and secrets-free. If the migration fails at 3am,
you know exactly which identity ran it, what trust level it operated at, and
whether the contract was satisfied.

### Why two identity profiles

The example uses two identity profiles at different trust levels:

- **project-agent** (`none` provider, `supervised` trust) -- for Stripe Projects
  CLI commands that use browser-session auth. These are read-only operations
  (status checks, credential syncs) that don't need injected credentials.

- **database-credentials** (`env-bearer` provider, `restricted` trust) -- for the
  migration task that needs `DATABASE_URL` injected. This identity is `restricted`
  because database writes are high-impact. The migration contract requires
  `supervised` trust with `strict` enforcement, which means a `restricted` identity
  is intentionally blocked from running it unless the operator upgrades the
  profile's trust level. This is graduated autonomy in action.

### Dynamic credential acquisition

For environments where credentials should be pulled fresh at execution time rather
than read from a static `.env`, use the `command` value_from source:

```json
"provider_config": {
  "token_env": "DATABASE_URL"
},
"inputs": {
  "db_url": {
    "value_from": {
      "command": "grep NEON_CONNECTION_STRING .env | cut -d= -f2-"
    }
  }
}
```

The `command` source runs any shell command and captures stdout. This works with
Stripe Projects, HashiCorp Vault, 1Password CLI, AWS SSM, or any tool that prints
a credential value:

| Tool | Command |
|------|---------|
| Stripe Projects | `stripe projects env --pull && grep NEON_CONNECTION_STRING .env \| cut -d= -f2-` |
| HashiCorp Vault | `vault kv get -field=token secret/myapp` |
| 1Password CLI | `op item get "API Key" --fields credential` |
| AWS SSM | `aws ssm get-parameter --name /app/key --with-decryption --query Parameter.Value --output text` |
| Doppler | `doppler secrets get DATABASE_URL --plain` |
| macOS Keychain | `security find-generic-password -a account -s service -w` |

### The full-stack picture

[full-stack-deploy.json](../examples/full-stack-deploy.json) takes this further by
chaining Stripe Projects, Prisma, Fly.io, and post-deploy verification into a single
pipeline with three separate identities, trust enforcement, evidence, and failure
triage at each stage. See [the full pipeline walkthrough](#full-stack-deployment-example)
at the top of this guide.

## agentcli + AWS CLI

[aws-ops.json](../examples/aws-ops.json) wraps the AWS CLI for infrastructure
monitoring: caller identity checks, S3 bucket listing, EC2 instance inventory,
CloudWatch alarm monitoring, and cost estimates.

AWS credentials flow through the standard `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
environment variables. The AWS CLI reads these automatically, so agentcli does not need
to inject them via presentation bindings -- they are already in the environment. The
example uses the `none` identity provider for read-only operations because the
credentials are pre-configured in `~/.aws/credentials` or the environment.

```bash
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."

agentcli exec examples/aws-ops.json check-identity --signer none
agentcli exec examples/aws-ops.json list-s3-buckets --signer none
agentcli audit --limit 3
```

What agentcli adds on top of the AWS CLI:

- **Audit trail for every AWS API call**: each `aws` invocation produces an audit record
  with the identity principal, trust level, command hash, and result. When an IAM
  permission denial happens (exit code 254), the failure is recorded with the same
  provenance as a success.
- **Trust enforcement**: the cost estimate task requires `restricted` trust with `strict`
  enforcement, so only agents with at least `restricted` trust can check billing data.
- **Failure triage**: the CloudWatch alarm check has an on-failure handler that delegates
  to an agent for read-only diagnosis.
- **Evidence**: SSH-signed attestation binds the AWS CLI command and its output to a
  verifiable execution record.

For environments where AWS credentials should be acquired dynamically (e.g., from
a role or SSM), use `value_from: { command }`:

```json
"value_from": {
  "command": "aws ssm get-parameter --name /app/secret --with-decryption --query Parameter.Value --output text"
}
```

Or use the built-in `aws-sts-assume-role` identity provider for role-based access:

```json
{
  "id": "aws-role",
  "provider": "aws-sts-assume-role",
  "auth": {
    "provider_config": {
      "role_arn": "arn:aws:iam::123456789012:role/deploy-role",
      "region": "us-east-1"
    }
  }
}
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
