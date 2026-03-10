# AGENTS

## Purpose

`agentcli` is the agent-native control plane for workflow manifests. It is not the durable runtime.

Use this repo when the task is about:

- manifest authoring
- validation
- compile target behavior
- scheduler inspection surfaces
- JSON-RPC / MCP style integration

Do not reimplement scheduler durability here. Runtime concerns belong in `openclaw-scheduler`.

## Working Rules

- Prefer machine-readable output and raw JSON payloads.
- Keep manifests backend-portable unless the task explicitly targets `openclaw-scheduler`.
- Default compile target is `standalone`.
- Treat `openclaw-scheduler` as an adapter/backend, not as the core abstraction.
- Preserve agent-safe behavior: safe output paths, strict validation, field masks, and sanitization.

## Useful Commands

- `agentcli init` -- bootstrap a local home directory with a starter manifest
- `agentcli targets` -- list available compilation targets
- `agentcli paths` -- show resolved home directory layout
- `agentcli schema manifest` -- emit machine-readable schema for the manifest format
- `agentcli describe commands` -- list all CLI commands with summaries
- `agentcli validate examples/hello-world.json`
- `agentcli compile examples/hello-world.json --target standalone --explain`
- `agentcli compile examples/hello-world.json --target openclaw-scheduler`
- `agentcli apply <manifest> --adopt-by name --dry-run` -- preview migration of existing scheduler jobs
- `agentcli inspect jobs --db /path/to/scheduler.sqlite --fields id,status`
- `agentcli serve`
