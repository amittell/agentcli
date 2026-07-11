# Adoption Guide

## Why Adopt It

Adopt `agentcli` if you want:

- a stable workflow manifest for agents
- a cleaner separation between workflow authoring and execution
- machine-readable CLI and RPC interfaces
- a path to support multiple runtimes over time

## Better Together with `openclaw-scheduler`

If you own both products, the clean story is:

- `agentcli` is the control plane for workflow authoring, identity, validation, local execution, local approval gates for direct `exec`, and discovery
- `openclaw-scheduler` is the durable runtime for schedule execution, retries, cron-triggered approval queues, delivery, and persistent state
- the same manifest can be authored and tested in `agentcli`, then compiled and applied into `openclaw-scheduler`; local approval declarations are enforced by `exec`, while durable enforcement is accepted only when the scheduler explicitly advertises the required gate, scope, and handoff capabilities

That means users do not have to choose between them.

- Start with `agentcli` when you want to design and test workflows quickly.
- Add `openclaw-scheduler` when you want those workflows to run durably in production.
- Keep the same manifest contract across both stages instead of rewriting jobs for a different runtime surface.

## Who Can Adopt It

Three common adopters:

- runtime maintainers
- editor or IDE integrations
- agent platforms and automation services

## Practical Integration Paths

### Path 1: `agentcli` on its own

Use `agentcli` to:

- validate manifests
- compile standalone plans
- expose schema and describe to agents
- run governed shell tasks and shell-only DAGs locally without adding a durable runtime

This is the lowest-friction entry point.

### Path 2: `agentcli` paired with `openclaw-scheduler`

This is the default “better together” path.

Use `agentcli` to:

- author manifests
- validate them
- compile them for the scheduler
- inspect scheduler state through one consistent CLI / JSON-RPC surface

Use `openclaw-scheduler` to:

- run the durable schedule loop
- manage retries, approvals, delivery, and queue state
- store runtime state in SQLite

`agentcli apply` treats live scheduler capability values as authoritative and falls back to conservative static declarations only when a value is unavailable. It rejects jobs that require unsupported root approval gates, approver scopes, structured output formats, trust, authorization, proof, evidence, or credential handoff. It also rejects inline `shell.env` and `shell.stdin`; durable secrets must be resolved at dispatch through an identity provider.

Current reference example:

```bash
mkdir -p ~/.openclaw/scheduler
npm install --prefix ~/.openclaw/scheduler openclaw-scheduler@latest
npm exec --prefix ~/.openclaw/scheduler openclaw-scheduler -- setup
agentcli compile examples/hello-world.json --target openclaw-scheduler
agentcli apply examples/hello-world.json --db ~/.openclaw/scheduler/scheduler.db --scheduler-prefix ~/.openclaw/scheduler --dry-run
```

### Path 3: Existing Runtime Adapter

If you already have scheduler jobs running outside agentcli, use `--adopt-by name` to migrate them without creating duplicates. The CLI and JSON-RPC `agentcli.apply` method both support this. See the [migration guide](../README.md#migrating-existing-scheduler-jobs-to-agentcli) in the README.

Keep your current runtime and add a compiler target.

You only need to map:

- task execution
- schedule roots
- trigger edges
- delivery policy
- approval intent

This lets your runtime adopt the manifest without replacing its engine.

### Path 4: Full Tooling Surface

Add:

- CLI support
- JSON-RPC
- inspection
- field masks

This is the best path if your users interact through agents.

## Manifest Structure: One Concern Per Manifest

The recommended pattern is one manifest per operational concern:

```
manifests/
  betting-pipeline.json     # scores, settle, CLV, card, lines, edges, ratings
  fitness.json              # withings, peloton, tonal, apple health, reminders
  infra-health.json         # gateway check, telegram check, stuck run detector
  backups.json              # workspace backup, minio snapshot + rollup
```

Each manifest is applied independently. Changes to the betting pipeline don't touch fitness jobs. You can version, review, and roll back each concern separately.

This is the same principle as terraform modules or kubernetes manifests per service: small, focused units of configuration that compose through convention, not through a single monolithic file.

### Why not multi-workflow manifests?

Multi-workflow manifests (multiple `workflows` entries in one file) are supported but not recommended. The problems:

- **Blast radius**: `agentcli apply mega-manifest.json` touches every job on the host. A typo in the betting section can disable fitness jobs.
- **Review friction**: PRs that touch the mega-manifest require reviewers to understand all workflows, not just the one that changed.
- **Rollback granularity**: you cannot roll back one workflow without rolling back all of them.

### Sharing configuration across manifests

If multiple manifests need the same identity profiles or delivery targets, prefer convention over coupling:

- Use the same profile id across manifests (e.g., `"stripe-service"` in both `betting-pipeline.json` and `stripe-ops.json`). The profiles are resolved at compile time from the manifest that declares them.
- Use delivery aliases (`"@owner_dm"`) that the scheduler resolves at runtime, so manifests don't hardcode chat IDs.
- If you need shared profiles across many manifests, extract them into a base file and merge at apply time with a simple script or CI step.

### Name handling for adoption

Single-workflow manifests compile task names without a workflow prefix (e.g., `"Nightly Score Capture"` not `"Betting Pipeline: Nightly Score Capture"`). This makes `--adopt-by name` work seamlessly with existing scheduler jobs.

Multi-workflow manifests include the prefix to avoid name collisions between workflows.

### Choosing session targets

Each task declares a `session_target` that controls how it executes:

| Target | Behavior | Best for |
|--------|----------|----------|
| `shell` | Runs a shell command directly. Fastest, most predictable. | Scripts, pipelines, CLI tools, data syncs |
| `isolated` | Creates a fresh agent session per run. Waits for response. | Agent tasks that need response capture and delivery |
| `main` | Runs in the persistent main agent session (conversation context preserved). | Tasks that benefit from ongoing context (email checks, pending reviews) |

**Main session guidance:**

Main session tasks wait for a response. `agentcli` does not currently expose a separate manifest flag for non-blocking "fire-and-forget" dispatch, so reserve `session_target: "main"` for short tasks that need the persistent conversation context. For longer-running agent work, prefer `session_target: "isolated"`:

```json
{
  "tasks": [
    {
      "id": "quick-acks-check",
      "name": "Pending Acks Check",
      "prompt": "Check for any pending acknowledgment requests.",
      "target": { "session_target": "main" },
      "schedule": { "cron": "*/30 * * * *" }
    },
    {
      "id": "deep-email-scan",
      "name": "Deep Email Analysis",
      "prompt": "Scan inbox for important messages and summarize.",
      "target": { "session_target": "isolated" },
      "delivery": { "mode": "announce-always", "channel": "telegram", "to": "484946046" },
      "schedule": { "cron": "0 9 * * *" }
    }
  ]
}
```

- **`main`:** Best for quick tasks that benefit from the existing conversation context.
- **`isolated`:** Best for longer-running analysis, summaries, and other work that should not depend on the persistent main session.

### Delivery modes

| Mode | Delivers on | Use when |
|------|------------|----------|
| `announce` | Error only | You only want to know when things break |
| `announce-always` | Success and error | You want results from every run (betting card, fitness summary) |
| `none` | Never | Silent background tasks (backups, health checks) |

## Adoption Risks

The main current risks are:

- the standard is still draft
- only one production-grade runtime adapter exists today
- runtime compatibility depends on explicit capability negotiation, especially for root approvals, approver scope, structured output, and handoff v3

### Avoiding heavy single-prompt jobs

A common antipattern: one isolated agent task that asks the model to do many things in sequence ("check all 6 k8s environments, review deployments, summarize findings"). The agent makes many tool calls, each taking seconds, and eventually the model provider times out.

**Break heavy agent work into shell pre-checks and a final agent summary:**

```
k8s-health-prod (shell) ─┐
k8s-health-staging (shell)├─→ morning-summary (isolated, trigger: all complete)
deploy-check (shell)     ─┘
```

The shell tasks run fast (1-2s each), collect the raw data, and the agent's only job is to read the outputs and write a concise summary. This avoids model provider timeouts, makes each step independently retriable, and gives the operator visibility into which step fails.

Rules of thumb:
- If a task requires more than 2-3 tool calls, break it into shell pre-checks
- Shell tasks are 10-100x faster than agent tasks and never time out on model providers
- Use agent tasks for synthesis and judgment, not data collection
- Sync main session tasks should complete in under 10 seconds to avoid blocking interactive DMs

## Why It Still Has Value Before Broad Adoption

Even with one runtime adapter, `agentcli` already gives a useful internal standard:

- better workflow authoring
- cleaner agent integration
- less coupling to one runtime schema
- easier future migration

The standard becomes more valuable with adoption, but it is not dependent on external adoption to be useful internally.
