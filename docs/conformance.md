# Conformance

## Purpose

This document defines what it means to be compatible with the `agentcli` draft standard.

## Profiles

### Profile A: Manifest Consumer

Must:

- parse manifest version `0.1`
- validate required structure
- reject invalid task invocation modes

Should:

- surface machine-readable validation errors

### Profile B: Control Plane

Must implement everything in Profile A and also:

- expose schema access
- expose validation
- support at least one compile target

Should:

- expose machine-readable describe metadata
- support raw JSON input and JSON output

### Profile C: Protocol Surface

Must implement everything in Profile B and also:

- expose JSON-RPC `2.0`
- implement `agentcli.ping`
- implement `agentcli.version`
- implement `agentcli.schema`
- implement `agentcli.describe`
- implement `agentcli.validate`
- implement `agentcli.compile`

### Profile D: Runtime Adapter

Must:

- accept a valid manifest-derived compile output
- document backend-specific constraints
- preserve task ordering and trigger semantics

Should:

- expose a manifest apply or upsert path
- expose runtime inspection
- document delivery, retry, and approval behavior separately from the core manifest

## Reference Implementation

This repo is the reference implementation for Profiles A, B, and C.

`openclaw-scheduler` is the current reference runtime adapter for Profile D.
