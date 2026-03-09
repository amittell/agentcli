# Architecture

## Split

`openclaw-scheduler`

- runtime
- dispatcher loop
- SQLite state
- retries, approvals, delivery, recovery
- durable dispatch queue

`agentcli`

- manifest schema
- validation
- compile target adapters
- scheduler apply / upsert surface
- standalone planning surface
- scheduler inspection surface
- machine-readable CLI
- stdio JSON-RPC server

## Backend Model

`agentcli` has two backend stories:

- `standalone`: portable plan, validation, schema, describe, JSON-RPC
- `openclaw-scheduler`: compile target, apply/upsert path, and runtime inspection

This keeps the control plane useful by itself without forcing a second durable runtime into the repo.

## Near-Term Roadmap

1. Stabilize manifest and target outputs.
2. Add an execution adapter boundary for optional local backends.
3. Expand JSON-RPC into MCP if that integration surface proves better.
4. Add more target adapters without weakening the manifest contract.
