# Capabilities

## Purpose

`agentcli` separates the control-plane contract from backend execution details. Capabilities make that split explicit and machine-readable.

## Capability Groups

Control-plane capabilities:

- `schema`
- `describe`
- `validate`
- `compile`
- `apply`
- `json-rpc`

Inspection capabilities:

- `inspect`
- `field-mask`
- `sanitize-basic`
- `ndjson`

Execution-shape capabilities:

- `model-policy`
- `execution-intent`
- `output-hints`
- `timeout-support`
- `context-retrieval`

Runtime capabilities:

- `runtime-execution`
- `durability`
- `retry`
- `approval-gates`
- `delivery`
- `lineage`

## Current Target Matrix

### `standalone`

Provides:

- `schema`
- `describe`
- `validate`
- `compile`
- `json-rpc`
- portable `model-policy`
- portable `execution-intent`
- portable `output-hints`
- portable `timeout-support`
- portable `context-retrieval`

Does not provide:

- durable execution
- retries
- delivery
- approvals
- lineage

Interpretation:

- approval fields are intent only
- plan/read-only intent is preserved in the compiled plan
- output hints and budgets are preserved for another backend or consumer

### `openclaw-scheduler`

Provides through compile or inspection:

- `compile`
- `apply`
- `inspect`
- `field-mask`
- `sanitize-basic`
- `ndjson`
- `model-policy`
- `execution-intent`
- `output-hints`
- `timeout-support`
- `context-retrieval`

Provides in the runtime itself:

- `runtime-execution`
- `durability`
- `retry`
- `approval-gates`
- `delivery`
- `lineage`

Interpretation:

- model policy compiles into scheduler model and thinking fields
- plan/read-only intent compiles into runtime execution-boundary fields
- output hints compile into scheduler output preview/offload budgets
- queue, approval, and fan-out budgets compile into runtime guardrails

## Why This Matters

Adopters should not assume every target is a full runtime, and they should not assume every backend enforces every field the same way.

The value of `agentcli` is that the manifest contract remains stable while target support varies in explicit ways.

That lets:

- lightweight tools implement authoring only
- protocol bridges implement validation and compilation
- runtimes implement execution without owning authoring UX
- operators inspect exactly which features are portable versus runtime-enforced
