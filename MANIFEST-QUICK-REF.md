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

## Session targets

- **shell**: Runs a command. Fast, predictable. Use for scripts and pipelines.
- **isolated**: Fresh agent session per run. Waits for response. Use for agent tasks needing output capture.
- **main**: Persistent agent session. Sync by default (waits for response). Use for quick tasks that benefit from conversation context.

## Delivery modes

- **announce-always**: Deliver on success and error.
- **announce**: Deliver on error only.
- **none**: Silent.

## Examples with identity and credentials (v0.2)

For tasks that need API keys or scoped credentials:

- **[stripe-ops.json](examples/stripe-ops.json)** -- Stripe CLI wrapping: charge listing, refunds, balance checks with scoped API keys (full, payments, readonly) and scope-hierarchy downscoping for child tasks.
- **[stripe-projects.json](examples/stripe-projects.json)** -- Stripe Projects: credential sync, status checks, and database migrations with two identity profiles at different trust levels.
- **[identity-v2.json](examples/identity-v2.json)** -- Minimal v0.2 identity profile with env-bearer provider.
- **[trust-enforcement.json](examples/trust-enforcement.json)** -- Trust level enforcement with contract boundaries.
- **[authorization-proof.json](examples/authorization-proof.json)** -- JWT-based authorization proof verification.

These use v0.2 features: `identity_profiles`, `trust`, `contract`, `child_credential_policy`, and `presentation` bindings.

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
