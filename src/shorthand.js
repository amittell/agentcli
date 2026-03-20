function inferFailureTarget(parentTask, handler) {
  const sessionTarget = handler.target?.session_target || (handler.shell ? 'shell' : 'isolated');
  return {
    session_target: sessionTarget,
    agent_id: handler.target?.agent_id ?? parentTask.target?.agent_id ?? 'main',
    ...(handler.target?.payload_kind ? { payload_kind: handler.target.payload_kind } : {})
  };
}

export function onFailureTaskId(task) {
  if (!task?.on_failure) return null;
  return task.on_failure.id || `${task.id}.failure`;
}

export function buildOnFailureTask(parentTask) {
  if (!parentTask?.on_failure) return null;
  const handler = parentTask.on_failure;
  return {
    id: onFailureTaskId(parentTask),
    name: handler.name || `${parentTask.name} Failure Handler`,
    enabled: handler.enabled ?? parentTask.enabled,
    ...(handler.prompt ? { prompt: handler.prompt } : {}),
    ...(handler.shell ? { shell: structuredClone(handler.shell) } : {}),
    target: inferFailureTarget(parentTask, handler),
    trigger: {
      parent: parentTask.id,
      on: 'failure',
      delay_s: handler.delay_s ?? 0,
      condition: handler.condition ?? null
    },
    ...(handler.delivery ? { delivery: structuredClone(handler.delivery) } : {}),
    ...(handler.reliability ? { reliability: structuredClone(handler.reliability) } : {}),
    ...(handler.runtime ? { runtime: structuredClone(handler.runtime) } : {}),
    ...(handler.model_policy ? { model_policy: structuredClone(handler.model_policy) } : {}),
    ...(handler.intent ? { intent: structuredClone(handler.intent) } : {}),
    ...(handler.output ? { output: structuredClone(handler.output) } : {}),
    ...(handler.budgets ? { budgets: structuredClone(handler.budgets) } : {}),
    ...(handler.approval ? { approval: structuredClone(handler.approval) } : {}),
    ...(handler.context ? { context: structuredClone(handler.context) } : {}),
    ...(handler.session ? { session: structuredClone(handler.session) } : {}),
    ...(handler.identity ? { identity: structuredClone(handler.identity) } : {}),
    ...(handler.contract ? { contract: structuredClone(handler.contract) } : {}),
    ...(handler.delete_after_run != null ? { delete_after_run: handler.delete_after_run } : {})
  };
}

export function expandManifestShorthands(manifest) {
  const expanded = structuredClone(manifest);
  expanded.workflows = (expanded.workflows || []).map(workflow => ({
    ...workflow,
    tasks: (workflow.tasks || []).flatMap(task => {
      const baseTask = { ...task };
      delete baseTask.on_failure;
      const generated = buildOnFailureTask(task);
      return generated ? [baseTask, generated] : [baseTask];
    })
  }));
  return expanded;
}
