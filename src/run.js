import { executeTask } from './exec.js';
import { normalizeShellExecution } from './shell.js';
import { expandManifestShorthands } from './shorthand.js';
import { validateManifest } from './validate.js';

function resolveWorkflow(manifest, workflowId) {
  if (workflowId) {
    const workflow = manifest.workflows.find(item => item.id === workflowId);
    if (!workflow) {
      throw Object.assign(
        new Error(`Workflow not found: ${workflowId}`),
        { code: 'invalid_argument' }
      );
    }
    return workflow;
  }

  if (manifest.workflows.length === 1) {
    return manifest.workflows[0];
  }

  throw Object.assign(
    new Error(`Multiple workflows found; specify --workflow. Available: ${manifest.workflows.map(workflow => workflow.id).join(', ')}`),
    { code: 'invalid_argument' }
  );
}

function buildGraph(workflow) {
  const tasksById = new Map();
  const childrenByParent = new Map();
  const rootTaskIds = [];
  const order = new Map();

  workflow.tasks.forEach((task, index) => {
    tasksById.set(task.id, task);
    order.set(task.id, index);
    if (task.trigger?.parent) {
      const siblings = childrenByParent.get(task.trigger.parent) || [];
      siblings.push(task.id);
      childrenByParent.set(task.trigger.parent, siblings);
    } else {
      rootTaskIds.push(task.id);
    }
  });

  return { tasksById, childrenByParent, rootTaskIds, order };
}

function selectRootTaskIds(workflow, graph, { rootTaskId, allRoots }) {
  if (rootTaskId && allRoots) {
    throw Object.assign(
      new Error('Specify either --root or --all-roots, not both.'),
      { code: 'invalid_argument' }
    );
  }

  if (rootTaskId) {
    const task = graph.tasksById.get(rootTaskId);
    if (!task) {
      throw Object.assign(
        new Error(`Task not found: ${rootTaskId} in workflow ${workflow.id}. Available: ${workflow.tasks.map(taskItem => taskItem.id).join(', ')}`),
        { code: 'invalid_argument' }
      );
    }
    if (task.trigger) {
      throw Object.assign(
        new Error(`Task "${rootTaskId}" is not a root task. Use a scheduled task id for --root.`),
        { code: 'invalid_argument' }
      );
    }
    return [rootTaskId];
  }

  if (graph.rootTaskIds.length === 0) {
    throw Object.assign(
      new Error(`Workflow "${workflow.id}" has no scheduled root tasks to run.`),
      { code: 'invalid_argument' }
    );
  }

  if (graph.rootTaskIds.length === 1 || allRoots) {
    return [...graph.rootTaskIds];
  }

  throw Object.assign(
    new Error(`Multiple root tasks found; specify --root or --all-roots. Available roots: ${graph.rootTaskIds.join(', ')}`),
    { code: 'invalid_argument' }
  );
}

function detectCycles(rootTaskIds, childrenByParent) {
  const visiting = new Set();
  const visited = new Set();

  function visit(taskId, path) {
    if (visiting.has(taskId)) {
      const cycleStart = path.indexOf(taskId);
      const cyclePath = [...path.slice(cycleStart), taskId];
      throw Object.assign(
        new Error(`Trigger cycle detected: ${cyclePath.join(' -> ')}`),
        { code: 'validation_error' }
      );
    }
    if (visited.has(taskId)) return;

    visiting.add(taskId);
    for (const childId of childrenByParent.get(taskId) || []) {
      visit(childId, [...path, taskId]);
    }
    visiting.delete(taskId);
    visited.add(taskId);
  }

  for (const rootTaskId of rootTaskIds) {
    visit(rootTaskId, []);
  }
}

function collectReachableTaskIds(rootTaskIds, childrenByParent) {
  const queue = [...rootTaskIds];
  const reachable = [];
  const seen = new Set();

  while (queue.length > 0) {
    const taskId = queue.shift();
    if (seen.has(taskId)) continue;
    seen.add(taskId);
    reachable.push(taskId);
    for (const childId of childrenByParent.get(taskId) || []) {
      queue.push(childId);
    }
  }

  return reachable;
}

function assertShellOnlyGraph(workflow, graph, selectedTaskIds) {
  const unsupported = selectedTaskIds
    .map(taskId => graph.tasksById.get(taskId))
    .filter(task => task.target?.session_target !== 'shell')
    .map(task => `${task.id} (${task.target?.session_target || 'unknown'})`);

  if (unsupported.length > 0) {
    throw Object.assign(
      new Error(
        `agentcli run only supports shell tasks. Unsupported tasks in workflow "${workflow.id}": ${unsupported.join(', ')}`
      ),
      { code: 'invalid_argument' }
    );
  }
}

function commandPreview(task, cwd) {
  const shell = normalizeShellExecution(task.shell);
  return {
    program: shell.program,
    args: shell.args,
    cwd: shell.cwd || cwd,
    env_keys: Object.keys(shell.env),
    stdin_present: shell.stdin != null,
  };
}

function invocationSummary(task) {
  if (task.trigger) {
    return {
      mode: 'trigger',
      parent: task.trigger.parent,
      on: task.trigger.on,
      delay_s: task.trigger.delay_s ?? 0,
      condition: task.trigger.condition ?? null,
    };
  }

  return {
    mode: 'schedule',
    cron: task.schedule?.cron ?? null,
    tz: task.schedule?.tz ?? 'UTC',
  };
}

function evaluateTrigger(task, outcome, stdout) {
  const trigger = task.trigger;
  if (!trigger) {
    return { matched: true, reason: null };
  }

  if (trigger.on !== 'complete' && trigger.on !== outcome) {
    return {
      matched: false,
      reason: `trigger.on=${trigger.on} did not match parent outcome ${outcome}`,
    };
  }

  if (!trigger.condition) {
    return { matched: true, reason: null };
  }

  const output = stdout || '';
  if (trigger.condition.startsWith('contains:')) {
    const needle = trigger.condition.slice('contains:'.length);
    if (output.includes(needle)) {
      return { matched: true, reason: null };
    }
    return {
      matched: false,
      reason: `trigger condition ${JSON.stringify(trigger.condition)} did not match parent stdout`,
    };
  }

  if (trigger.condition.startsWith('regex:')) {
    const pattern = trigger.condition.slice('regex:'.length);
    if (new RegExp(pattern).test(output)) {
      return { matched: true, reason: null };
    }
    return {
      matched: false,
      reason: `trigger condition ${JSON.stringify(trigger.condition)} did not match parent stdout`,
    };
  }

  return {
    matched: false,
    reason: `unsupported trigger condition ${JSON.stringify(trigger.condition)}`,
  };
}

function normalizeTaskError(error) {
  if (!error) return null;
  return {
    message: error.message,
    code: error.code || 'internal_error',
    ...(error.execution_id ? { execution_id: error.execution_id } : {}),
    ...(error.source ? { source: error.source } : {}),
    ...(error.verify ? { verify: error.verify } : {}),
    ...(error.violations ? { violations: error.violations } : {}),
    ...(error.validation ? { validation: error.validation } : {}),
    ...(error.capability_errors ? { capability_errors: error.capability_errors } : {}),
  };
}

function summarizeCounts(tasks, dryRun) {
  const summary = {
    total: tasks.length,
    planned: 0,
    succeeded: 0,
    failed: 0,
    skipped: 0,
  };

  for (const task of tasks) {
    if (dryRun) {
      if (task.status === 'skipped') summary.skipped += 1;
      else summary.planned += 1;
      continue;
    }

    if (task.status === 'success') summary.succeeded += 1;
    else if (task.status === 'failed') summary.failed += 1;
    else if (task.status === 'skipped') summary.skipped += 1;
  }

  return summary;
}

function selectedTaskWarnings(tasksById, selectedTaskIds) {
  const disabledTaskIds = selectedTaskIds
    .map(taskId => tasksById.get(taskId))
    .filter(task => task?.enabled === false)
    .map(task => task.id);

  if (disabledTaskIds.length === 0) return [];

  return [
    `Disabled tasks and their dependent trigger branches will be skipped: ${disabledTaskIds.join(', ')}`,
  ];
}

function disabledBlocker(task, tasksById) {
  let current = task;
  const visited = new Set();
  while (current && !visited.has(current.id)) {
    visited.add(current.id);
    if (current.enabled === false) return current.id;
    current = current.trigger?.parent
      ? tasksById.get(current.trigger.parent)
      : null;
  }
  return null;
}

function buildDryRunTasks(workflow, graph, selectedTaskIds, rootTaskIds, cwd) {
  const rootTaskIdSet = new Set(rootTaskIds);

  return selectedTaskIds.map(taskId => {
    const task = graph.tasksById.get(taskId);
    const blockedBy = disabledBlocker(task, graph.tasksById);
    return {
      source: { workflow_id: workflow.id, task_id: task.id },
      name: task.name,
      status: blockedBy ? 'skipped' : 'planned',
      selected_as_root: rootTaskIdSet.has(task.id),
      invocation: invocationSummary(task),
      command: commandPreview(task, cwd),
      trigger: task.trigger ? {
        parent: task.trigger.parent,
        on: task.trigger.on,
        delay_s: task.trigger.delay_s ?? 0,
        condition: task.trigger.condition ?? null,
        matched: null,
      } : null,
      reason: blockedBy
        ? (blockedBy === task.id
            ? 'task is disabled'
            : `ancestor task "${blockedBy}" is disabled`)
        : (task.trigger ? 'dry-run does not evaluate trigger outcomes or conditions' : null),
    };
  });
}

function isTaskSuccessful(taskRecord) {
  return taskRecord.status === 'success';
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export async function runWorkflow(manifest, {
  workflowId,
  rootTaskId,
  allRoots = false,
  dryRun = false,
  timeoutMs,
  signer,
  signingKey: explicitSigningKey,
  evidenceProvider,
  instanceId,
  requireEvidence = false,
  requireAuthorization = false,
  identityDebug = false,
  presentationDebug = false,
  cwd = process.cwd(),
  env = process.env,
  sleepFn = sleep,
} = {}) {
  const validation = validateManifest(manifest);
  if (!validation.ok) {
    const err = new Error('Manifest validation failed');
    err.code = 'validation_error';
    err.validation = validation;
    throw err;
  }

  const expanded = expandManifestShorthands(manifest);
  const workflow = resolveWorkflow(expanded, workflowId);
  const graph = buildGraph(workflow);
  const selectedRootTaskIds = selectRootTaskIds(workflow, graph, { rootTaskId, allRoots });
  detectCycles(selectedRootTaskIds, graph.childrenByParent);
  const selectedTaskIds = collectReachableTaskIds(selectedRootTaskIds, graph.childrenByParent);
  assertShellOnlyGraph(workflow, graph, selectedTaskIds);

  const warnings = selectedTaskWarnings(graph.tasksById, selectedTaskIds);

  if (dryRun) {
    const tasks = buildDryRunTasks(workflow, graph, selectedTaskIds, selectedRootTaskIds, cwd);
    return {
      ok: true,
      dry_run: true,
      mode: 'run',
      workflow_id: workflow.id,
      root_task_ids: selectedRootTaskIds,
      selected_task_ids: selectedTaskIds,
      summary: summarizeCounts(tasks, true),
      warnings,
      tasks,
    };
  }

  const selectedTaskIdSet = new Set(selectedTaskIds);
  const rootTaskIdSet = new Set(selectedRootTaskIds);
  const taskRuns = [];
  const pending = selectedRootTaskIds.map((taskId, index) => ({
    taskId,
    readyAt: Date.now(),
    sequence: index,
    triggerContext: null,
    skipReason: null,
  }));
  let sequence = pending.length;

  while (pending.length > 0) {
    pending.sort((left, right) => left.readyAt - right.readyAt || left.sequence - right.sequence);
    const next = pending.shift();
    const waitMs = next.readyAt - Date.now();
    if (waitMs > 0) {
      await sleepFn(waitMs);
    }

    const task = graph.tasksById.get(next.taskId);
    const record = {
      source: { workflow_id: workflow.id, task_id: task.id },
      name: task.name,
      selected_as_root: rootTaskIdSet.has(task.id),
      invocation: invocationSummary(task),
      command: commandPreview(task, cwd),
      trigger: task.trigger ? {
        parent: task.trigger.parent,
        on: task.trigger.on,
        delay_s: task.trigger.delay_s ?? 0,
        condition: task.trigger.condition ?? null,
        matched: next.triggerContext?.matched ?? null,
        parent_outcome: next.triggerContext?.parentOutcome ?? null,
      } : null,
      execution_id: null,
      execution: null,
      error: null,
      status: 'failed',
      reason: null,
    };

    const skipReason = next.skipReason || (task.enabled === false ? 'task is disabled' : null);
    if (skipReason) {
      record.status = 'skipped';
      record.reason = skipReason;
      taskRuns.push(record);

      for (const childId of graph.childrenByParent.get(task.id) || []) {
        if (!selectedTaskIdSet.has(childId)) continue;
        pending.push({
          taskId: childId,
          readyAt: Date.now(),
          sequence,
          triggerContext: {
            matched: false,
            parentOutcome: 'skipped',
          },
          skipReason: `ancestor task "${task.id}" was skipped: ${skipReason}`,
        });
        sequence += 1;
      }
      continue;
    }

    let payload = null;
    try {
      payload = await executeTask(manifest, {
        workflowId: workflow.id,
        taskId: task.id,
        dryRun: false,
        timeoutMs,
        signer,
        signingKey: explicitSigningKey,
        evidenceProvider,
        instanceId,
        requireEvidence,
        requireAuthorization,
        identityDebug,
        presentationDebug,
        cwd,
        env,
      });
      record.execution_id = payload.execution_id ?? null;
      record.execution = payload;
      record.status = payload.ok ? 'success' : 'failed';
      record.reason = payload.ok ? null : `task exited with code ${payload.result?.exit_code ?? 'unknown'}`;
    } catch (error) {
      const failure = normalizeTaskError(error);
      record.execution_id = failure?.execution_id ?? null;
      record.error = failure;
      record.status = 'failed';
      record.reason = failure?.message || 'task execution failed';
    }

    taskRuns.push(record);

    const outcome = isTaskSuccessful(record) ? 'success' : 'failure';
    const stdout = payload?.result?.stdout ?? '';

    for (const childId of graph.childrenByParent.get(task.id) || []) {
      if (!selectedTaskIdSet.has(childId)) continue;

      const childTask = graph.tasksById.get(childId);
      const triggerEvaluation = evaluateTrigger(childTask, outcome, stdout);
      if (!triggerEvaluation.matched) {
        taskRuns.push({
          source: { workflow_id: workflow.id, task_id: childTask.id },
          name: childTask.name,
          selected_as_root: false,
          invocation: invocationSummary(childTask),
          command: commandPreview(childTask, cwd),
          trigger: {
            parent: childTask.trigger.parent,
            on: childTask.trigger.on,
            delay_s: childTask.trigger.delay_s ?? 0,
            condition: childTask.trigger.condition ?? null,
            matched: false,
            parent_outcome: outcome,
          },
          execution_id: null,
          execution: null,
          error: null,
          status: 'skipped',
          reason: triggerEvaluation.reason,
        });
        continue;
      }

      pending.push({
        taskId: childTask.id,
        readyAt: Date.now() + ((childTask.trigger?.delay_s ?? 0) * 1000),
        sequence,
        triggerContext: {
          matched: true,
          parentOutcome: outcome,
        },
        skipReason: null,
      });
      sequence += 1;
    }
  }

  const summary = summarizeCounts(taskRuns, false);
  return {
    ok: summary.failed === 0,
    dry_run: false,
    mode: 'run',
    workflow_id: workflow.id,
    root_task_ids: selectedRootTaskIds,
    selected_task_ids: selectedTaskIds,
    summary,
    warnings,
    tasks: taskRuns,
  };
}
