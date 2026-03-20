import { validateManifest } from '../validate.js';
import { normalizedTaskPlan, stableId } from './shared.js';
import { expandManifestShorthands } from '../shorthand.js';

export function compileManifestToStandalone(manifest, { includeExplain = false } = {}) {
  const validation = validateManifest(manifest);
  if (!validation.ok) {
    const err = new Error('Manifest validation failed');
    err.validation = validation;
    throw err;
  }
  const expanded = expandManifestShorthands(manifest);

  const workflows = [];
  const explain = [];

  for (const workflow of expanded.workflows) {
    const taskIdToCompiledId = new Map();
    for (const task of workflow.tasks) {
      taskIdToCompiledId.set(task.id, stableId(workflow.id, task.id));
    }

    const tasks = [];
    const edges = [];
    for (const task of workflow.tasks) {
      const plan = normalizedTaskPlan(workflow, task, taskIdToCompiledId);
      tasks.push(plan);
      if (plan.invocation.mode === 'trigger') {
        edges.push({
          from: plan.parent_compiled_id,
          to: plan.id,
          on: plan.invocation.on,
          condition: plan.invocation.condition,
          delay_s: plan.invocation.delay_s
        });
      }
      explain.push({
        workflow_id: workflow.id,
        task_id: task.id,
        compiled_id: plan.id,
        target: 'standalone',
        invocation_mode: plan.invocation.mode,
        notes: plan.invocation.mode === 'trigger'
          ? ['Retains trigger semantics directly; no scheduler-specific cron sentinel is needed.']
          : ['Retains cron schedule directly for backends that understand scheduled roots.']
      });
    }

    workflows.push({
      id: workflow.id,
      name: workflow.name,
      tasks,
      edges
    });
  }

  return {
    target: 'standalone',
    version: '0.2',
    capabilities: {
      authoring: true,
      planning: true,
      runtime_execution: false,
      rpc: true,
      model_policy: true,
      execution_intent: true,
      output_hints: true,
      budgets: true,
      identity: true,
      contracts: true,
    },
    workflows,
    ...(includeExplain ? { explain } : {})
  };
}
