# Versioning

## Current Versions

- package version: `0.3.2`
- manifest spec version: `0.2`
- protocol status: draft, aligned to manifest spec `0.2`

## Compatibility Rules

Within manifest spec `0.2`:

- existing required fields MUST keep their meaning
- validation MAY become stricter only when rejecting clearly invalid or unsafe input
- new optional fields MAY be added
- existing optional fields MUST NOT change meaning incompatibly

Backward compatibility for `0.1` remains part of the current release surface:

- validators accept both `0.1` and `0.2`
- `0.2` is the canonical discovery and schema version reported by `agentcli version`, `agentcli schema manifest`, and JSON-RPC `agentcli.version`
- schema discovery emits JSON Schema Draft 2020-12 by default; the legacy descriptor requires an explicit `--legacy` flag or RPC `legacy: true`
- existing `0.1` manifests remain executable through the preserved legacy execution path

## Breaking Changes

A change requires a new manifest spec version when it:

- changes the meaning of `schedule` or `trigger`
- changes required fields
- removes existing enum values
- changes JSON-RPC method names or result envelope semantics

## Package vs Spec

The npm package version and the manifest spec version are related but distinct.

- package version tracks the implementation release
- manifest version tracks the portable workflow contract

This allows:

- implementation fixes without spec churn
- experimental additions behind new package releases while keeping spec stability clear
