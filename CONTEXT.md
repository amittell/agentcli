# Context

## Problem

Schedulers and workflow engines often expose human-oriented CLIs with flags and prose output. Agents work better with:

- raw JSON input
- schema discovery
- narrow field selection
- stable machine-readable output
- protocol surfaces instead of screen scraping

## Repo Position

`agentcli` sits above execution runtimes.

- It can work standalone for authoring, validation, planning, and JSON-RPC.
- It can target `openclaw-scheduler` for durable execution and inspection.

## Design Bias

- keep the manifest portable
- keep output structured
- prefer explicit schemas over docs-only conventions
- avoid duplicating runtime durability in this repo
