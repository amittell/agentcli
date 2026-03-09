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
- prompt or shell command
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

See [examples/hello-world.json](/Users/alex/git/agentcli/examples/hello-world.json) and [examples/shell-workflow.json](/Users/alex/git/agentcli/examples/shell-workflow.json).
For public-safe examples that use the newer contract features, see [examples/public-shell-failure-triage.json](/Users/alex/git/agentcli/examples/public-shell-failure-triage.json), [examples/public-report-publish.json](/Users/alex/git/agentcli/examples/public-report-publish.json), and [examples/public-bot-health.json](/Users/alex/git/agentcli/examples/public-bot-health.json).
Normal users do not need a second repo checkout. Install `agentcli`, run `agentcli init`, and keep your manifests under `~/.agentcli/manifests` by default.

## Targets

`agentcli` currently exposes two targets:

- `standalone`
  - portable plan for authoring, validation, explain output, and protocol use
  - no durable runtime required
- `openclaw-scheduler`
  - compiler target and inspection surface for the durable scheduler runtime
  - supports runtime model policy, plan/read-only intent, output offload budgets, and queue / approval / fan-out guardrails

The target model is defined in [src/targets.js](/Users/alex/git/agentcli/src/targets.js#L1).

## Commands

```bash
agentcli schema [manifest|workflow|task|schedulerJob|standalonePlan|rpcRequest|rpcResponse]
agentcli describe [manifest|workflow|task|targets|commands|rpc]
agentcli targets
agentcli paths
agentcli init [--home path] [--force]
agentcli validate <path-or-json|->
agentcli compile <path-or-json|-> [--target standalone|openclaw-scheduler] [--write path] [--explain]
agentcli apply <path-or-json|-> [--db path] [--scheduler-prefix path|--scheduler-bin path] [--dry-run] [--explain]
agentcli inspect <jobs|runs|queue|approvals> [--db path] [--fields a,b,c] [--limit n] [--sanitize basic] [--ndjson]
agentcli serve [--stdio] [--db path]
```

## Installation

Local development:

```bash
npm install
npm test
```

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

- spec: [docs/spec.md](/Users/alex/git/agentcli/docs/spec.md)
- protocol: [docs/protocol.md](/Users/alex/git/agentcli/docs/protocol.md)
- capabilities: [docs/capabilities.md](/Users/alex/git/agentcli/docs/capabilities.md)
- versioning and conformance: [docs/versioning.md](/Users/alex/git/agentcli/docs/versioning.md) and [docs/conformance.md](/Users/alex/git/agentcli/docs/conformance.md)
- adoption guide: [docs/adoption.md](/Users/alex/git/agentcli/docs/adoption.md)
- architecture: [docs/architecture.md](/Users/alex/git/agentcli/docs/architecture.md)

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
