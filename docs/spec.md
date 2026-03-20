# Manifest Spec

## Status

This document defines the `agentcli` manifest draft standard version `0.1`.

Normative language in this document uses:

- MUST
- MUST NOT
- SHOULD
- MAY

## Goals

The manifest format is designed to:

- be generated and consumed as raw JSON
- preserve workflow intent independently from a specific runtime
- support both human operators and agent integrations
- compile cleanly into backend-specific artifacts

## Top-Level Shape

A manifest MUST be a JSON object with:

- `version`
- `workflows`

`version` MUST equal `0.1`.

`workflows` MUST be a non-empty array.

## Workflow Object

Each workflow MUST contain:

- `id`
- `name`
- `tasks`

Each workflow MAY also define:

- `model_policy`

Rules:

- `id` MUST match `^[A-Za-z0-9][A-Za-z0-9._-]*$`
- `id` MUST be unique within the manifest
- `tasks` MUST be a non-empty array

## Task Object

Each task MUST contain:

- `id`
- `name`
- `target`

Rules:

- `id` MUST be unique within its workflow
- `id` MUST match `^[A-Za-z0-9][A-Za-z0-9._-]*$`
- a task MUST define exactly one of `schedule` or `trigger`

### Enabled State

`enabled`, if present, MUST be a boolean.

If omitted, implementations SHOULD treat the task as enabled by default.

This field expresses the desired active state when compiled into a runtime that supports dormant or disabled jobs.

### Target

`target.session_target` MUST be one of:

- `main`
- `isolated`
- `shell`

`target.payload_kind` MAY be one of:

- `systemEvent`
- `agentTurn`
- `shellCommand`

If omitted, implementations MAY infer `payload_kind` from `session_target`.

`target.agent_id`, if present, MUST be a restricted token and SHOULD avoid whitespace or shell-significant punctuation.

### Model Policy

`model_policy`, if present, MUST be an object.

It MAY define:

- `provider`
- `model`
- `thinking`

Workflow-level `model_policy` acts as a default for tasks in that workflow.

Task-level `model_policy` overrides workflow-level fields key by key.

### Intent

`intent`, if present, MUST be an object.

`intent.mode`, if present, MUST be one of:

- `execute`
- `plan`

`intent.read_only`, if present, MUST be a boolean.

This block expresses whether a task is allowed to act or should remain planning-only / read-only when compiled into a backend that supports execution boundaries.

### Output

`output`, if present, MUST be an object.

It MAY define:

- `preview_bytes`
- `offload`
- `retrieve`

`output.preview_bytes`, if present, MUST be an integer greater than or equal to `64`.

`output.offload`, if present, MUST be one of:

- `auto`
- `always`
- `never`

`output.retrieve`, if present, MUST be one of:

- `inline`
- `on-demand`

This block expresses how large outputs should be previewed and whether backends should prefer offloading or inline retention.

### Budgets

`budgets`, if present, MUST be an object.

It MAY define:

- `max_iterations`
- `max_fanout`
- `max_context_items`
- `max_pending_approvals`
- `max_queued_dispatches`

Each of these, if present, MUST be an integer greater than or equal to `1`.

### Prompt or Shell Execution

If `target.session_target` is `shell`, `shell` MUST be present.

`shell` MUST be an object with:

- `program`

It MAY also define:

- `args`
- `env`
- `cwd`
- `stdin`

`shell.program` MUST be a restricted token.

`shell.args`, if present, MUST be an array of non-empty strings.

`shell.env`, if present, MUST be an object whose keys match `^[A-Za-z_][A-Za-z0-9_]*$` and whose values are strings.

`shell.cwd`, if present, MUST be a non-empty string.

`shell.stdin`, if present, MUST be a string.

The legacy `command` string field is not supported. Implementations MUST reject manifests that include `command` and SHOULD direct users to `shell.program` and `shell.args`.

Backend targets that flatten shell execution into a single string (such as `payload_message` in `openclaw-scheduler`) SHOULD render it as a POSIX-safe shell command with single-quoted arguments. The rendered form is intended for machine consumption, not human display.

Otherwise, `prompt` MUST be present.

### Schedule

If present, `schedule` MUST contain:

- `cron`

It MAY also contain:

- `tz`

If `tz` is omitted, implementations SHOULD default to `UTC`.

`schedule` represents a root invocation.

### Trigger

If present, `trigger` MUST contain:

- `parent`
- `on`

It MAY also contain:

- `delay_s`
- `condition`

`trigger.on` MUST be one of:

- `success`
- `failure`
- `complete`

`trigger.delay_s`, if present, MUST be an integer greater than or equal to `0`.

`trigger.parent` MUST reference a different task id within the same workflow. Self-referential triggers are not permitted.

`trigger.condition`, if present, MUST start with exactly one of:

- `contains:`
- `regex:`

For `contains:` conditions, the suffix MUST be a non-empty string.

For `regex:` conditions, the suffix MUST be a valid regular expression.

### Failure Shortcut

`on_failure`, if present, MUST be an object.

It is a control-plane shorthand for synthesizing a triggered child task with:

- `trigger.parent` = the enclosing task id
- `trigger.on` = `failure`

`on_failure.id`, if present, MUST be unique within the workflow after shorthand expansion.

If `on_failure.id` is omitted, implementations SHOULD synthesize `<parent_task_id>.failure`.

If `on_failure.name` is omitted, implementations SHOULD synthesize `<parent_task_name> Failure Handler`.

`on_failure` MAY define:

- `id`
- `name`
- `enabled`
- `prompt` or `shell`
- `target`
- `delay_s`
- `condition`
- `delivery`
- `reliability`
- `runtime`
- `model_policy`
- `intent`
- `output`
- `budgets`
- `approval`
- `context`
- `session`
- `delete_after_run`

`on_failure.delay_s`, if present, MUST be an integer greater than or equal to `0`.

If `on_failure.target` is omitted, the session target is inferred: `shell` when `on_failure.shell` is present, `isolated` otherwise. The `agent_id` is inherited from the parent task's target when not explicitly set.

If the inferred or explicit `session_target` is `shell`, `on_failure.shell` MUST be present.

Otherwise, `on_failure.prompt` MUST be present.

## Delivery

`delivery.mode`, if present, MUST be one of:

- `announce`
- `announce-always`
- `none`

`delivery.channel` and `delivery.to`, if present, MUST be restricted tokens.

## Reliability

`reliability.guarantee`, if present, MUST be one of:

- `at-most-once`
- `at-least-once`

`reliability.overlap_policy`, if present, MUST be one of:

- `skip`
- `allow`
- `queue`

`reliability.max_retries`, if present, MUST be an integer greater than or equal to `0`.

## Runtime

`runtime.timeout_ms`, if present, MUST be an integer greater than or equal to `1`.

This field is intended for backend execution controls like per-task run timeouts. Control-plane implementations SHOULD preserve it across compile targets even when a given backend ignores it.

## Approval

`approval` is backend-portable intent, not a guarantee that every backend exposes the same gate semantics.

`approval.policy`, if present, MUST be one of:

- `manual`
- `auto-approve`
- `auto-reject`

`approval.risk_level`, if present, MUST be one of:

- `low`
- `medium`
- `high`

`approval.timeout_s`, if present, MUST be an integer greater than or equal to `1`.

`approval.auto`, if present, MUST be one of:

- `approve`
- `reject`

This field provides a direct override for the auto-resolution behavior when an approval gate times out. When `policy` is `auto-approve` or `auto-reject`, the corresponding `auto` value is implied. Explicit `auto` takes precedence over inference from `policy`.

`approval.approver_scope`, if present, MUST be a restricted token identifying the scope or group that may approve the gate.

`approval.required` is supported for compatibility, but `approval.policy` SHOULD be preferred in new manifests.

## Context

`context.retrieval`, if present, MUST be one of:

- `none`
- `recent`
- `hybrid`

`context.limit`, if present, MUST be an integer greater than or equal to `1`.

If both `context.limit` and `budgets.max_context_items` are present, implementations SHOULD prefer `context.limit`.

## Session

`session.preferred_key`, if present, MUST be a restricted token.

## Delete After Run

`delete_after_run`, if present, MUST be a boolean.

When true, the compiled job is removed from the scheduler after its first successful execution. This field applies to both top-level tasks and `on_failure` handlers.

## Definitions

A **restricted token** is a string matching the pattern `^[A-Za-z0-9@:_./-]+$`. This covers file paths, model identifiers, agent IDs, delivery channels, and session keys without allowing shell metacharacters or control characters.

## Validation and Warnings

Implementations MUST reject invalid manifests.

Implementations MAY emit warnings for:

- approval settings that compile ambiguously for some backends
- approval gates on root scheduled tasks
- backend-specific behavior shims
- planning/read-only intent on targets that only support advisory enforcement
- conflicting context budgets

## Compiler Targets

This spec does not require a single runtime.

A conforming control-plane implementation MUST support:

- schema access
- manifest validation
- at least one compile target

A target adapter MAY add backend-specific constraints, but MUST NOT silently reinterpret the meaning of `schedule`, `trigger`, or task ordering.
