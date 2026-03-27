# Adoption Guide

## Why Adopt It

Adopt `agentcli` if you want:

- a stable workflow manifest for agents
- a cleaner separation between workflow authoring and execution
- machine-readable CLI and RPC interfaces
- a path to support multiple runtimes over time

## Better Together with `openclaw-scheduler`

If you own both products, the clean story is:

- `agentcli` is the control plane for workflow authoring, identity, validation, local execution, and discovery
- `openclaw-scheduler` is the durable runtime for schedule execution, retries, approvals, delivery, and persistent state
- the same manifest can be authored and tested in `agentcli`, then compiled and applied into `openclaw-scheduler`

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

## Adoption Risks

The main current risks are:

- the standard is still draft
- only one production-grade runtime adapter exists today
- some backend-specific areas, especially approvals, still need richer negotiation

## Why It Still Has Value Before Broad Adoption

Even with one runtime adapter, `agentcli` already gives a useful internal standard:

- better workflow authoring
- cleaner agent integration
- less coupling to one runtime schema
- easier future migration

The standard becomes more valuable with adoption, but it is not dependent on external adoption to be useful internally.
