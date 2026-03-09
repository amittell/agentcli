# Manifest Authoring

Use this skill when working on `agentcli` manifests, compile targets, or protocol behavior.

## Workflow

1. Start from `examples/hello-world.json` or another raw JSON manifest.
2. Validate first with `agentcli validate`.
3. If the task is backend-neutral, compile to `standalone`.
4. If the task explicitly targets the scheduler runtime, compile to `openclaw-scheduler`.
5. Use `agentcli describe` and `agentcli schema` instead of relying on prose docs alone.
6. When reading scheduler state, use `agentcli inspect` with `--fields` and `--sanitize basic` when agent reuse is likely.

## Constraints

- Do not add durable scheduler behavior here.
- Keep new manifest features mappable either to the standalone plan or to explicit backend capability gaps.
- Prefer protocol- and schema-level affordances over custom one-off CLI flags.
