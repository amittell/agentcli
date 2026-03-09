import { validateManifest } from '../validate.js';
import { approvalPolicyForTask, normalizedTaskPlan, stableId } from './shared.js';
import { expandManifestShorthands } from '../shorthand.js';

function schedulerOutputPolicy(plan) {
  const previewBytes = Math.max(64, plan.output.preview_bytes || 2000);
  const outputStoreLimit = Math.max(previewBytes, plan.output.retrieve === 'inline' ? previewBytes * 4 : previewBytes);
  let offloadThreshold = 65536;
  if (plan.output.offload === 'always') offloadThreshold = 128;
  if (plan.output.offload === 'never') offloadThreshold = Math.max(outputStoreLimit, 1024 * 1024);
  if (plan.output.offload === 'auto') offloadThreshold = Math.max(outputStoreLimit, previewBytes * 8, 65536);
  return {
    output_store_limit_bytes: outputStoreLimit,
    output_excerpt_limit_bytes: previewBytes,
    output_summary_limit_bytes: Math.max(5000, previewBytes),
    output_offload_threshold_bytes: offloadThreshold,
  };
}

export function compileManifestToScheduler(manifest, { includeExplain = false } = {}) {
  const validation = validateManifest(manifest);
  if (!validation.ok) {
    const err = new Error('Manifest validation failed');
    err.validation = validation;
    throw err;
  }
  const expanded = expandManifestShorthands(manifest);

  const jobs = [];
  const explain = [];
  for (const workflow of expanded.workflows) {
    const taskIdToJobId = new Map();
    for (const task of workflow.tasks) {
      taskIdToJobId.set(task.id, stableId(workflow.id, task.id));
    }

    for (const task of workflow.tasks) {
      const plan = normalizedTaskPlan(workflow, task, taskIdToJobId);
      const approval = approvalPolicyForTask(task);
      const isTriggered = plan.invocation.mode === 'trigger';
      const outputPolicy = schedulerOutputPolicy(plan);
      jobs.push({
        id: plan.id,
        source: plan.source,
        name: plan.name,
        enabled: plan.enabled ? 1 : 0,
        schedule_cron: isTriggered ? '0 0 31 2 *' : plan.invocation.cron,
        schedule_tz: isTriggered ? 'UTC' : plan.invocation.tz,
        session_target: plan.execution.session_target,
        agent_id: plan.execution.agent_id,
        payload_kind: plan.execution.payload_kind,
        payload_message: plan.execution.payload_message,
        payload_model: plan.execution.model_policy.scheduler_model,
        payload_thinking: plan.execution.model_policy.thinking,
        execution_intent: plan.intent.mode,
        execution_read_only: plan.intent.read_only ? 1 : 0,
        run_timeout_ms: plan.runtime.timeout_ms,
        overlap_policy: plan.reliability.overlap_policy,
        max_retries: plan.reliability.max_retries,
        max_queued_dispatches: plan.budgets.max_queued_dispatches,
        max_pending_approvals: plan.budgets.max_pending_approvals,
        max_trigger_fanout: plan.budgets.max_fanout,
        delivery_mode: plan.delivery.mode,
        delivery_channel: plan.delivery.channel,
        delivery_to: plan.delivery.to,
        delivery_guarantee: plan.reliability.guarantee,
        parent_id: plan.parent_compiled_id,
        trigger_on: isTriggered ? plan.invocation.on : null,
        trigger_delay_s: isTriggered ? plan.invocation.delay_s : 0,
        trigger_condition: isTriggered ? plan.invocation.condition : null,
        approval_required: approval.required,
        approval_timeout_s: approval.timeout_s,
        approval_auto: approval.auto,
        context_retrieval: plan.context.retrieval,
        context_retrieval_limit: plan.context.limit,
        ...outputPolicy,
        preferred_session_key: plan.session.preferred_key,
        delete_after_run: plan.delete_after_run ? 1 : 0
      });

      explain.push({
        workflow_id: workflow.id,
        task_id: task.id,
        compiled_id: plan.id,
        target: 'openclaw-scheduler',
        invocation_mode: plan.invocation.mode,
        notes: isTriggered
          ? [
              'Scheduler jobs still require schedule_cron, so triggered tasks compile with a sentinel cron.',
              'Actual dispatch behavior comes from the scheduler runtime queue, not from the sentinel cron.'
            ]
          : ['Scheduled roots map directly to scheduler cron fields.'],
        model_policy: plan.execution.model_policy,
        intent: plan.intent,
        output: plan.output,
        budgets: plan.budgets,
      });
    }
  }

  return {
    target: 'openclaw-scheduler',
    version: '0.2',
    jobs,
    ...(includeExplain ? { explain } : {})
  };
}
