# Versioning

## Current Versions

- package version: `0.1.0`
- manifest spec version: `0.1`
- protocol status: draft, aligned to manifest spec `0.1`

## Compatibility Rules

Within manifest spec `0.1`:

- existing required fields MUST keep their meaning
- validation MAY become stricter only when rejecting clearly invalid or unsafe input
- new optional fields MAY be added
- existing optional fields MUST NOT change meaning incompatibly

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
