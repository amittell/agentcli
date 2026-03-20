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
- Pass `--json` to force structured JSON output from any command (including `help`), except `serve` which runs the JSON-RPC server on stdio.
- Keep manifests backend-portable unless the task explicitly targets `openclaw-scheduler`.
- Default compile target is `standalone`.
- Treat `openclaw-scheduler` as an adapter/backend, not as the core abstraction.
- Preserve agent-safe behavior: safe output paths, strict validation, field masks, and sanitization.

## Error Handling

All CLI errors are written to stderr as JSON with the following shape:

```json
{
  "ok": false,
  "error": "Human-readable error message",
  "error_type": "validation_error | unknown_command | invalid_argument | parse_error | internal_error"
}
```

Use `error_type` for structured dispatch rather than parsing the `error` string. Validation errors include an additional `validation` field with the full error and warning arrays.

## Discovery Flow

When first interacting with `agentcli`, use this sequence:

1. `agentcli version` -- confirm the package and manifest spec version
2. `agentcli describe commands` -- enumerate all available CLI commands
3. `agentcli describe rpc` -- enumerate JSON-RPC methods and notifications
4. `agentcli targets` -- list available compile targets with capabilities
5. `agentcli schema manifest` -- get the machine-readable manifest schema

For JSON-RPC integrations, use `agentcli.version` and `agentcli.describe` with `target: "rpc"` to discover the method surface programmatically.

## Useful Commands

- `agentcli version` -- show package and manifest spec version
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
