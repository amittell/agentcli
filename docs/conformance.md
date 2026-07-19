# Conformance

## Purpose

This document defines what it means to be compatible with the `agentcli` draft standard.

## Profiles

### Profile A: Manifest Consumer

Must:

- parse manifest version `0.1`
- parse manifest version `0.2`
- validate required structure
- reject invalid task invocation modes
- reject unknown nested v0.2 fields and structurally invalid provider profiles

Should:

- surface machine-readable validation errors

### Profile B: Control Plane

Must implement everything in Profile A and also:

- expose schema access
- expose validation
- support at least one compile target
- emit JSON Schema Draft 2020-12 by default when advertising JSON Schema conformance

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
- use JSON-RPC result envelopes for success and error envelopes with machine-readable `data.code` and `data.error_type` for failure

### Profile D: Runtime Adapter

Must:

- accept a valid manifest-derived compile output
- document backend-specific constraints
- preserve task ordering and trigger semantics
- expose or document an explicit capability map for security-relevant runtime behavior
- advertise the exact artifact, canonicalization, digest, and binding contract
  before accepting handoff v4

Should:

- expose a manifest apply or upsert path
- expose runtime inspection
- document delivery, retry, and approval behavior separately from the core manifest
- fail closed when a compiled contract requires an enforcement capability the runtime does not advertise
- reject missing required fields and unknown properties in handoff v4 artifacts

## Reference Implementation

This repo is the reference implementation for Profiles A, B, and C.

`openclaw-scheduler` is the current reference runtime adapter for Profile D.
