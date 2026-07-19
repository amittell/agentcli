/**
 * OpenClaw Scheduler runtime adapter.
 *
 * Handles session_targets "main" and "isolated" by compiling the manifest
 * into a scheduler job spec and delegating execution to the scheduler CLI.
 */

import { compileManifestToScheduler } from '../compiler/openclaw-scheduler.js';
import {
  createSchedulerCliRunner,
  negotiateSchedulerFieldVersion,
  schedulerCreateSpec,
} from '../apply.js';
import {
  querySchedulerCapabilities,
  resolveEffectiveFeatures,
  supportsSchedulerHandoffV4,
  validateManifestCapabilities,
} from '../capabilities.js';

export function compileManifestForDispatch(manifest, options = {}) {
  // Manifests are ordinary mutable JavaScript objects. Recompile on every
  // dispatch so a caller cannot receive a stale job after an in-place edit.
  return compileManifestToScheduler(manifest, options);
}

export const schedulerAdapter = {
  name: 'openclaw-scheduler',
  capabilities: { session_targets: ['main', 'isolated'], stateless: true },

  /**
   * Check whether this adapter can execute the given task in the provided context.
   *
   * @param {object} task - The resolved task object from the manifest.
   * @param {object} ctx  - Context with optional schedulerPrefix / schedulerBin.
   * @returns {{ supported: boolean, reason?: string }}
   */
  canExecute(task, ctx) {
    if (!ctx?.schedulerPrefix && !ctx?.schedulerBin) {
      return { supported: false, reason: 'No scheduler configured' };
    }
    const target = task.target?.session_target;
    if (target !== 'main' && target !== 'isolated') {
      return { supported: false, reason: `Unsupported session target: ${target}` };
    }
    return { supported: true };
  },

  /**
   * Delegate a task to the openclaw-scheduler runtime.
   *
   * Compiles the manifest, locates the matching job, marks it for one-off
   * execution, and either returns a dry-run receipt or hands it off to the
   * scheduler CLI via `jobs add`.
   *
   * @param {object} manifest  - The full (unexpanded) manifest.
   * @param {object} task      - The resolved task object.
   * @param {object} workflow  - The parent workflow object.
   * @param {object} options   - Execution options.
   * @returns {object} Delegation receipt.
   */
  dispatch(manifest, task, workflow, options) {
    const { schedulerPrefix, schedulerBin, dbPath, dryRun, cwd, env } = options;
    const taskId = task.id || task.name;
    const workflowId = workflow.id;
    let runner = null;
    let effectiveResult = null;
    let schedulerHandoffVersion = '3';

    if (!dryRun) {
      runner = createSchedulerCliRunner({
        schedulerPrefix,
        schedulerBin,
        dbPath,
        cwd,
        env,
      });
      const runtimeCaps = querySchedulerCapabilities(runner);
      effectiveResult = resolveEffectiveFeatures('openclaw-scheduler', runtimeCaps);
      if (supportsSchedulerHandoffV4(runtimeCaps)) {
        schedulerHandoffVersion = '4';
      }
    }

    // The one-off lifecycle value is set before v4 artifact construction so
    // the artifact and persisted scheduler projection bind the same job.
    const compiled = compileManifestForDispatch(manifest, {
      schedulerHandoffVersion,
      cwd,
      env,
      oneOffSource: { workflow_id: workflowId, task_id: taskId },
    });

    // Match the compiled job to the requested workflow/task pair.
    const job = compiled.jobs.find(
      j => j.source?.workflow_id === workflowId && j.source?.task_id === taskId
    );

    if (!job) {
      throw Object.assign(
        new Error(`Could not find compiled job for task "${taskId}" in workflow "${workflowId}"`),
        { code: 'delegation_error' }
      );
    }

    const jobSpec = job;

    if (dryRun) {
      return {
        ok: true,
        dry_run: true,
        delegated: true,
        runtime: 'openclaw-scheduler',
        job_id: jobSpec.id,
        job_spec: jobSpec,
        session_target: task.target?.session_target,
        note: 'Dry run: task would be delegated to openclaw-scheduler.',
      };
    }

    const {
      errors: capabilityErrors,
      warnings: capabilityWarnings,
    } = validateManifestCapabilities({ jobs: [jobSpec] }, effectiveResult);
    if (capabilityErrors.length > 0) {
      throw Object.assign(
        new Error(capabilityErrors.map(error => error.message).join('; ')),
        { code: 'unsupported_capability', capability_errors: capabilityErrors }
      );
    }
    const handoffVersion = negotiateSchedulerFieldVersion(
      [jobSpec],
      effectiveResult.handoff_version || '1'
    );

    const spec = schedulerCreateSpec(jobSpec, { fieldVersion: handoffVersion });
    runner.addJob(spec);

    return {
      ok: true,
      delegated: true,
      execution_mode: 'scheduler-dispatch',
      runtime: 'openclaw-scheduler',
      job_id: jobSpec.id,
      session_target: task.target?.session_target,
      payload_kind: jobSpec.payload_kind,
      status: 'dispatched',
      handoff_version: handoffVersion,
      ...(capabilityWarnings.length > 0
        ? {
            warnings: capabilityWarnings.map(warning => warning.message),
            capability_warnings: capabilityWarnings,
          }
        : {}),
      note: 'Task delegated to openclaw-scheduler. The scheduler will execute it on its next tick.',
    };
  },
};
