import { createHash } from 'crypto';

export function stableId(workflowId, taskId) {
  return createHash('sha256').update(`${workflowId}:${taskId}`).digest('hex').slice(0, 32);
}

export function payloadKindForTask(task) {
  if (task.target?.payload_kind) return task.target.payload_kind;
  if (task.target?.session_target === 'shell') return 'shellCommand';
  if (task.target?.session_target === 'main') return 'systemEvent';
  return 'agentTurn';
}

export function payloadMessageForTask(task) {
  if (task.target?.session_target === 'shell') return task.command;
  return task.prompt;
}

export function approvalPolicyForTask(task) {
  const approval = task.approval || null;
  const policy = approval?.policy || (approval?.required ? 'manual' : null);
  const required = policy === 'manual'
    ? Number(approval?.required ?? true)
    : Number(approval?.required ?? false);
  const auto = policy === 'auto-approve'
    ? 'approve'
    : policy === 'auto-reject'
      ? 'reject'
      : approval?.auto || 'reject';

  return {
    required,
    timeout_s: approval?.timeout_s || 3600,
    auto,
    policy: policy || 'none',
    risk_level: approval?.risk_level || 'medium',
    approver_scope: approval?.approver_scope || null,
  };
}

export function taskInvocationForTask(task) {
  if (task.trigger) {
    return {
      mode: 'trigger',
      parent: task.trigger.parent,
      on: task.trigger.on,
      delay_s: task.trigger.delay_s || 0,
      condition: task.trigger.condition || null,
    };
  }

  return {
    mode: 'schedule',
    cron: task.schedule.cron,
    tz: task.schedule.tz || 'America/New_York',
  };
}

function resolveModelPolicy(workflow, task) {
  const workflowPolicy = workflow.model_policy || {};
  const taskPolicy = task.model_policy || {};
  const provider = taskPolicy.provider ?? workflowPolicy.provider ?? null;
  const model = taskPolicy.model ?? workflowPolicy.model ?? null;
  const thinking = taskPolicy.thinking ?? workflowPolicy.thinking ?? null;
  const schedulerModel = provider && model ? `${provider}/${model}` : model;
  return {
    provider,
    model,
    thinking,
    scheduler_model: schedulerModel || null,
  };
}

function resolveIntent(task) {
  return {
    mode: task.intent?.mode || 'execute',
    read_only: Boolean(task.intent?.read_only),
  };
}

function resolveOutput(task) {
  return {
    preview_bytes: task.output?.preview_bytes || 2000,
    offload: task.output?.offload || 'auto',
    retrieve: task.output?.retrieve || 'on-demand',
  };
}

function resolveBudgets(task) {
  return {
    max_iterations: task.budgets?.max_iterations || null,
    max_fanout: task.budgets?.max_fanout || 25,
    max_context_items: task.budgets?.max_context_items || task.context?.limit || 5,
    max_pending_approvals: task.budgets?.max_pending_approvals || 10,
    max_queued_dispatches: task.budgets?.max_queued_dispatches || 25,
  };
}

export function normalizedTaskPlan(workflow, task, taskIdToCompiledId) {
  const modelPolicy = resolveModelPolicy(workflow, task);
  const intent = resolveIntent(task);
  const output = resolveOutput(task);
  const budgets = resolveBudgets(task);

  return {
    id: stableId(workflow.id, task.id),
    source: {
      workflow_id: workflow.id,
      task_id: task.id,
    },
    name: `${workflow.name}: ${task.name}`,
    enabled: task.enabled ?? true,
    invocation: taskInvocationForTask(task),
    execution: {
      session_target: task.target.session_target,
      agent_id: task.target.agent_id || 'main',
      payload_kind: payloadKindForTask(task),
      payload_message: payloadMessageForTask(task),
      model_policy: modelPolicy,
    },
    intent,
    output,
    budgets,
    delivery: {
      mode: task.delivery?.mode || 'none',
      channel: task.delivery?.channel || null,
      to: task.delivery?.to || null,
    },
    reliability: {
      guarantee: task.reliability?.guarantee || 'at-most-once',
      overlap_policy: task.reliability?.overlap_policy || 'skip',
      max_retries: task.reliability?.max_retries || 0,
    },
    runtime: {
      timeout_ms: task.runtime?.timeout_ms || null,
    },
    approval: approvalPolicyForTask(task),
    context: {
      retrieval: task.context?.retrieval || 'none',
      limit: task.context?.limit || budgets.max_context_items || 5,
    },
    session: {
      preferred_key: task.session?.preferred_key || null,
    },
    delete_after_run: Boolean(task.delete_after_run),
    parent_compiled_id: task.trigger ? taskIdToCompiledId.get(task.trigger.parent) : null,
  };
}
