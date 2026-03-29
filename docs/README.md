# Documentation

## Start here

| Question | Document | Time |
|----------|----------|------|
| What is agentcli and what problem does it solve? | [Project README](../README.md) (Quick Start section) | 3 min |
| How do I wrap a CLI tool with identity and audit? | [Wrapping CLI Tools](guide-wrapping-tools.md) | 5 min |
| How do I set up identity providers and trust? | [Identity Setup Guide](guide-identity.md) | 10 min |

## Reference

| Document | Audience | Purpose |
|----------|----------|---------|
| [Field Reference](field-reference.md) | Everyone | Complete reference for every JSON field, type, enum value, and default |
| [Manifest Spec](spec.md) | Implementers | Normative schema definition with MUST/SHOULD/MAY language |
| [JSON-RPC Protocol](protocol.md) | Integration developers | RPC method signatures, params, results, error model |
| [Execution Identity Architecture](execution-identity.md) | System designers | Full architectural proposal, six-layer model, standards alignment |

## Project

| Document | Purpose |
|----------|---------|
| [Architecture](architecture.md) | High-level system picture, agentcli vs openclaw-scheduler split |
| [Capabilities](capabilities.md) | Machine-readable feature matrix by target |
| [Conformance](conformance.md) | Conformance profiles for implementers (A-D) |
| [Adoption](adoption.md) | Integration paths, risks, and value proposition |
| [Runtime Integration Backlog](runtime-integration-backlog.md) | Cross-repo implementation plan for agentcli, openclaw-scheduler, and OpenClaw |
| [Roadmap](roadmap.md) | What shipped, what's next |
| [Versioning](versioning.md) | Package version vs spec version rules |

## Reading order for different roles

**Operator** (wrapping tools, running workflows):
1. README Quick Start
2. guide-wrapping-tools.md
3. guide-identity.md (Choosing a Provider + Quick Setup sections)

**Platform engineer** (integrating agentcli into a system):
1. README Quick Start
2. architecture.md
3. spec.md
4. protocol.md
5. conformance.md

**Contributor** (extending agentcli):
1. README Quick Start
2. execution-identity.md
3. spec.md
4. guide-identity.md (full document)
