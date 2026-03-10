# agentcli

`agentcli` is an agent-native workflow manifest standard and reference CLI.

It gives agents and operators a stable way to describe workflows, validate them, inspect them, and compile them into runtime-specific artifacts without coupling authors directly to one execution engine.

Standard status:

- `0.1` draft standard
- reference implementation in this repo
- production runtime adapter available for `openclaw-scheduler`

## Why This Exists

Most CLIs are designed for humans:

- prose output
- bespoke flags
- weak input validation
- poor schema discovery

Agents do better with:

- raw JSON input
- stable JSON output
- schema and describe surfaces
- field masks and sanitization
- protocol access instead of screen scraping

`agentcli` packages those ideas into one control plane.

For shell work, manifests use structured execution fields instead of opaque command strings. Complex shell logic should live in scripts that tasks invoke with explicit arguments and environment.

## What You Get

- a portable workflow manifest
- a standalone planning target
- a scheduler-backed compilation target
- a machine-readable CLI
- a stdio JSON-RPC surface
- workflow-level model policy
- explicit plan/read-only execution intent
- output preview and offload hints
- portable resource budgets for fan-out, approvals, queue depth, and context
- stricter validation than a typical CLI

## Why Someone Would Care

If you are building or operating agent workflows, `agentcli` gives you a cleaner contract between authoring and execution.

That matters because:

- workflow authors should describe intent, not runtime table layouts
- agent systems should consume schemas and JSON, not terminal prose
- runtimes should be replaceable without rewriting every workflow definition
- multi-tool automation gets easier when CLI and RPC share the same contract

## Core Model

A manifest contains:

- `version`
- `workflows[]`
- `workflows[].tasks[]`

Each task can define:

- execution target
- prompt or `shell.program` plus `shell.args[]`
- exactly one invocation mode: `schedule` or `trigger`
- optional `on_failure` shorthand for failure triage or remediation
- model policy
- plan/read-only intent
- output handling hints
- resource budgets
- delivery settings
- reliability settings
- runtime settings like execution timeout
- approval policy
- context settings

See [examples/hello-world.json](examples/hello-world.json) and [examples/shell-workflow.json](examples/shell-workflow.json).
For public-safe examples that use the newer contract features, see [examples/public-shell-failure-triage.json](examples/public-shell-failure-triage.json), [examples/public-report-publish.json](examples/public-report-publish.json), and [examples/public-bot-health.json](examples/public-bot-health.json).
Normal users do not need a second repo checkout. Install `agentcli`, run `agentcli init`, and keep your manifests under `~/.agentcli/manifests` by default.

## Targets

`agentcli` currently exposes two targets:

- `standalone`
  - portable plan for authoring, validation, explain output, and protocol use
  - no durable runtime required
- `openclaw-scheduler`
  - compiler target and inspection surface for the durable scheduler runtime
  - supports runtime model policy, plan/read-only intent, output offload budgets, and queue / approval / fan-out guardrails

The target model is defined in [src/targets.js](src/targets.js).

## Commands

```bash
agentcli schema [manifest|workflow|task|schedulerJob|standalonePlan|rpcRequest|rpcResponse]
agentcli describe [manifest|workflow|task|targets|commands|rpc]
agentcli targets
agentcli paths
agentcli init [--home path] [--force]
agentcli validate <path-or-json|->
agentcli compile <path-or-json|-> [--target standalone|openclaw-scheduler] [--write path] [--explain]
agentcli apply <path-or-json|-> [--db path] [--scheduler-prefix path|--scheduler-bin path] [--dry-run] [--explain] [--adopt-by id|name]
agentcli inspect <jobs|runs|queue|approvals> [--db path] [--fields a,b,c] [--limit n] [--sanitize basic] [--ndjson]
agentcli serve [--db path]
```

## Migrating existing scheduler jobs to agentcli

When you start using `agentcli apply` on top of an already-running scheduler, there is a stable ID gap:
`agentcli` assigns each job a deterministic ID — `sha256(workflowId:taskId).slice(0, 32)` — but jobs
that were created outside agentcli carry random UUIDs. A plain `agentcli apply` will not find those
jobs by ID and will create duplicates instead of updating the existing ones.

Use `--adopt-by name` for a one-time migration. It matches existing jobs by their `name` field,
updates them with the compiled spec (including the new stable ID), and re-keys them in the scheduler.
After migration, future applies use the default `--adopt-by id` — no flag needed.

**Migration workflow:**

1. Write manifests whose workflow and task names produce a composite name matching your existing scheduler job names exactly. agentcli compiles job names as `"Workflow Name: Task Name"`. For example, if a scheduler job is named `"Disk Health: Check Disk Space"`, set the workflow name to `"Disk Health"` and the task name to `"Check Disk Space"`.
2. Validate the manifest:
   ```bash
   agentcli validate my-workflow.json
   ```
3. Preview what would be adopted:
   ```bash
   agentcli apply my-workflow.json --adopt-by name --dry-run
   ```
   Jobs with a matching name show `"action": "adopted"`. Unmatched jobs show `"action": "created"`.
4. Execute the migration:
   ```bash
   agentcli apply my-workflow.json --adopt-by name
   ```
   Each matched job is updated with its stable ID. From this point on, the job is managed by agentcli.
5. Verify, then switch to normal applies — no flag needed going forward:
   ```bash
   agentcli apply my-workflow.json
   ```

**Notes:**

- Job name matching is case-sensitive and exact.
- If a job name is not found, it is created (same as default behavior).
- If a job ID already matches (e.g. already migrated), it is updated as normal regardless of `--adopt-by`.
- Run `--dry-run` first whenever you are unsure — it is always safe.

## Installation

Local development:

```bash
npm install
npm test
```

Node 22.5.0 or newer is required. Scheduler inspection uses `node:sqlite`; that API was still experimental in Node 22.x and only became stable in Node 23.4.0.

After publication:

```bash
npm install -g agentcli
agentcli init
agentcli paths
```

That creates a local home like `~/.agentcli` with:

- `manifests/`
- `output/`
- `state/`
- a starter manifest at `~/.agentcli/manifests/bot-health.json`

Once initialized, you can refer to a manifest by name instead of a full path:

```bash
agentcli validate bot-health
agentcli compile bot-health --target openclaw-scheduler --explain
```

To pair `agentcli` with the current production runtime adapter:

```bash
mkdir -p ~/.openclaw/scheduler
npm install --prefix ~/.openclaw/scheduler openclaw-scheduler@latest
npm exec --prefix ~/.openclaw/scheduler openclaw-scheduler -- setup
```

Then point inspection commands at the runtime state:

```bash
AGENTCLI_SCHEDULER_DB=~/.openclaw/scheduler/scheduler.db agentcli inspect jobs --fields id,name,last_status
```

Defaults:

- output is JSON unless `AGENTCLI_OUTPUT=ndjson`
- compile target defaults to `standalone` unless `AGENTCLI_TARGET` is set
- scheduler inspection reads `AGENTCLI_SCHEDULER_DB` when present
- scheduler apply uses `AGENTCLI_SCHEDULER_PREFIX` or `AGENTCLI_SCHEDULER_BIN` when present

## End-To-End Examples

Validate and compile a portable standalone plan:

```bash
agentcli validate examples/hello-world.json
agentcli compile examples/hello-world.json --target standalone --explain
```

Compile the same manifest for the scheduler runtime:

```bash
agentcli compile examples/hello-world.json --target openclaw-scheduler --explain
```

Compile a public-safe shell-failure triage workflow with model policy, plan intent, output hints, and budgets:

```bash
agentcli validate examples/public-shell-failure-triage.json
agentcli compile examples/public-shell-failure-triage.json --target openclaw-scheduler --explain
```

Compile a public-safe bot health workflow:

```bash
agentcli validate examples/public-bot-health.json
agentcli compile examples/public-bot-health.json --target openclaw-scheduler --explain
```

Draft installs can stay dormant by setting `"enabled": false` on tasks in the manifest. The scheduler target compiles that directly into disabled jobs.

For real deployments, you can keep manifests anywhere:

- under `~/.agentcli/manifests` like a normal installed tool user
- in a project repo
- in a separate private ops repo if you want version control for private automation

Install the scheduler runtime from npm, then inspect its state:

```bash
mkdir -p ~/.openclaw/scheduler
npm install --prefix ~/.openclaw/scheduler openclaw-scheduler@latest
AGENTCLI_SCHEDULER_DB=~/.openclaw/scheduler/scheduler.db agentcli inspect runs --fields id,job_id,status --ndjson
```

Inspect scheduler runtime state with a narrow field mask:

```bash
agentcli inspect runs --db /path/to/scheduler.sqlite --fields id,job_id,status,started_at --ndjson
```

Serve JSON-RPC over stdio:

```bash
agentcli serve
```

## Publication Docs

- spec: [docs/spec.md](docs/spec.md)
- protocol: [docs/protocol.md](docs/protocol.md)
- capabilities: [docs/capabilities.md](docs/capabilities.md)
- versioning and conformance: [docs/versioning.md](docs/versioning.md) and [docs/conformance.md](docs/conformance.md)
- adoption guide: [docs/adoption.md](docs/adoption.md)
- architecture: [docs/architecture.md](docs/architecture.md)
- roadmap: [docs/roadmap.md](docs/roadmap.md)

## Project Status

This repo is ready to publish as a draft standard and reference implementation.

What is already solid:

- manifest validation
- standalone compile target
- scheduler compile target
- scheduler apply / upsert flow
- scheduler inspection surface
- stdio JSON-RPC
- test coverage for the core contract

What is intentionally still future work:

- additional backend adapters
- MCP surface
- richer approval and capability negotiation
- local execution adapter for selected standalone cases
