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

- `agentcli validate examples/hello-world.json`
- `agentcli compile examples/hello-world.json --target standalone --explain`
- `agentcli compile examples/hello-world.json --target openclaw-scheduler`
- `agentcli inspect jobs --db /path/to/scheduler.sqlite --fields id,status`
- `agentcli serve`
