# Manifest Quick Reference

Copy-paste patterns for common agentcli manifests.

## Shell task with schedule

```json
{
  "version": "0.1",
  "workflows": [{
    "id": "my-workflow",
    "name": "My Workflow",
    "tasks": [{
      "id": "my-task",
      "name": "My Task",
      "shell": { "program": "bash", "args": ["/path/to/script.sh"] },
      "target": { "session_target": "shell" },
      "schedule": { "cron": "0 9 * * *", "tz": "America/New_York" },
      "delivery": { "mode": "announce-always", "channel": "telegram", "to": "CHAT_ID" },
      "reliability": { "overlap_policy": "skip" }
    }]
  }]
}
```

## Agent task (isolated session)

```json
{
  "id": "email-check",
  "name": "Check Email",
  "prompt": "Check inbox for important messages. Summarize anything urgent.",
  "target": { "session_target": "isolated" },
  "schedule": { "cron": "0 9 * * *", "tz": "America/New_York" },
  "delivery": { "mode": "announce-always", "channel": "telegram", "to": "CHAT_ID" },
  "reliability": { "overlap_policy": "skip" }
}
```

## Chained tasks (parent triggers child)

```json
{
  "tasks": [
    {
      "id": "collect-data",
      "name": "Collect Data",
      "shell": { "program": "python3", "args": ["collect.py"] },
      "target": { "session_target": "shell" },
      "schedule": { "cron": "0 6 * * *", "tz": "America/New_York" }
    },
    {
      "id": "process-data",
      "name": "Process Data",
      "shell": { "program": "python3", "args": ["process.py"] },
      "target": { "session_target": "shell" },
      "trigger": { "parent": "collect-data", "on": "success" },
      "delivery": { "mode": "announce-always", "channel": "telegram", "to": "CHAT_ID" }
    }
  ]
}
```

## Key fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Unique task identifier (alphanumeric + hyphens) |
| `name` | yes | Human-readable name |
| `shell.program` | for shell tasks | Executable to run |
| `shell.args` | for shell tasks | Arguments array |
| `prompt` | for agent tasks | Natural language instruction |
| `target.session_target` | yes | `shell`, `isolated`, or `main` |
| `schedule.cron` | for roots | Cron expression |
| `schedule.tz` | optional | IANA timezone (default: UTC) |
| `trigger.parent` | for children | Parent task id |
| `trigger.on` | for children | `success`, `failure`, or `complete` |
| `delivery.mode` | optional | `announce-always`, `announce` (error-only), `none` |
| `delivery.channel` | optional | `telegram`, etc. |
| `delivery.to` | optional | Channel-specific target (chat ID) |
| `reliability.overlap_policy` | optional | `skip`, `queue`, `allow` |
| `verify.shell` | optional | Post-completion verification command |
| `verify.required` | optional | When `true`, requires `public_key` or `jwks_uri` for jwt proofs |
| `authorization.request.include` | optional | Array of include fields for OPA request (`actor`, `step_up`) |
| `subject.attributes` | optional | Actor metadata object (`org_id`, `on_behalf_of_user_id`, `delegation_grant_id`, `run_id`, `agent_id`, `verification_ref`, `verification_level`) |
| `authorization_proof_profiles[].jwks_uri` | optional | JWKS endpoint URI for JWT key discovery and caching |
| `authorization_proof_profiles[].public_key` | optional | Inline public key for JWT verification |

## Session targets

- **shell**: Runs a command. Fast, predictable. Use for scripts and pipelines.
- **isolated**: Fresh agent session per run. Waits for response. Use for agent tasks needing output capture.
- **main**: Persistent agent session. Sync by default (waits for response). Use for quick tasks that benefit from conversation context.

## Delivery modes

- **announce-always**: Deliver on success and error.
- **announce**: Deliver on error only.
- **none**: Silent.

## Examples

### v0.1 -- no auth, good starting points

| Manifest | Tasks | Description |
|----------|-------|-------------|
| [hello-world.json](examples/hello-world.json) | 2 | Minimal: scheduled task + triggered follow-up |
| [shell-workflow.json](examples/shell-workflow.json) | 2 | Shell command with agent escalation on failure |
| [public-bot-health.json](examples/public-bot-health.json) | 2 | Health check with delivery |
| [public-report-publish.json](examples/public-report-publish.json) | 3 | Approval-gated publish flow |
| [public-shell-failure-triage.json](examples/public-shell-failure-triage.json) | 1 | Failure triage with on_failure handler |
| [identity-contract.json](examples/identity-contract.json) | 2 | Contract enforcement without identity profiles |

### v0.2 -- with identity, credentials, and trust

| Manifest | Tasks | Description |
|----------|-------|-------------|
| [stripe-ops.json](examples/stripe-ops.json) | 3 | Stripe CLI: scoped API keys with downscope hierarchy |
| [stripe-projects.json](examples/stripe-projects.json) | 3 | Stripe Projects: two identity profiles, different trust levels |
| [full-stack-deploy.json](examples/full-stack-deploy.json) | 5 | Deploy pipeline: Stripe + Prisma + Fly.io with three identities |
| [ansible-ops.json](examples/ansible-ops.json) | 5 | Ansible: inventory check, fact gathering, dry run, approval-gated apply, agent drift report |
| [kubectl-ops.json](examples/kubectl-ops.json) | 5 | Kubernetes: RBAC-scoped kubeconfig with strict trust |
| [terraform-ops.json](examples/terraform-ops.json) | 4 | Terraform: plan/apply with approval gate |
| [gh-ops.json](examples/gh-ops.json) | 4 | GitHub CLI: PR, issue, and release workflows |
| [docker-ops.json](examples/docker-ops.json) | 5 | Docker: build, push, deploy with registry credentials |
| [aws-ops.json](examples/aws-ops.json) | 5 | AWS: STS assume-role with S3/Lambda/CloudWatch |
| [gcloud-ops.json](examples/gcloud-ops.json) | 4 | GCP: workload identity with GKE/Cloud Run |
| [ssh-remote.json](examples/ssh-remote.json) | 5 | SSH: remote execution with key-based identity |
| [vercel-ops.json](examples/vercel-ops.json) | 7 | Vercel: deployments, domains, preview→promote pipeline with approval, health verify |
| [neon-ops.json](examples/neon-ops.json) | 7 | Neon: branch management, connection strings, operations monitoring with admin/readonly split |
| [supabase-ops.json](examples/supabase-ops.json) | 7 | Supabase: migrations, edge functions, secrets audit with deploy pipeline |
| [psql-ops.json](examples/psql-ops.json) | 4 | PostgreSQL: queries, migrations with strict trust and approval |
| [npm-ops.json](examples/npm-ops.json) | 5 | npm: publish, audit, update workflows |
| [git-ops.json](examples/git-ops.json) | 5 | Git: commit, push, tag with signing identity |
| [curl-api.json](examples/curl-api.json) | 3 | Generic API calls with bearer auth |
| [flyctl-ops.json](examples/flyctl-ops.json) | 1 | Fly.io deploy with env-bearer |
| [cloud-workload.json](examples/cloud-workload.json) | 1 | Cloud workload identity patterns |
| [oidc-service-auth.json](examples/oidc-service-auth.json) | 1 | OIDC client credentials flow |
| [identity-v2.json](examples/identity-v2.json) | 2 | Minimal v0.2 identity with env-bearer |
| [trust-enforcement.json](examples/trust-enforcement.json) | 3 | Trust level enforcement with contract boundaries |
| [authorization-proof.json](examples/authorization-proof.json) | 1 | JWT-based authorization proof verification |
| [stripe-identity-step-up.json](examples/stripe-identity-step-up.json) | - | Identity step-up verification with OPA policy and testing guide |

## Commands

```bash
agentcli validate manifest.json          # Check for errors
agentcli compile manifest.json --target openclaw-scheduler --explain
agentcli apply manifest.json --db scheduler.db --scheduler-prefix ./scheduler --dry-run
agentcli apply manifest.json --db scheduler.db --scheduler-prefix ./scheduler --adopt-by name
agentcli exec manifest.json task-id      # Run a task locally
agentcli schema manifest                 # Machine-readable schema
agentcli describe commands --json        # All CLI commands
```
