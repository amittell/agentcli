/**
 * OpenClaw Scheduler runtime adapter.
 *
 * Handles session_targets "main" and "isolated" by compiling the manifest
 * into a scheduler job spec and delegating execution to the scheduler CLI.
 */

import { compileManifestToScheduler } from '../compiler/openclaw-scheduler.js';
import { createSchedulerCliRunner } from '../apply.js';
import {
  querySchedulerCapabilities,
  resolveEffectiveFeatures,
  validateManifestCapabilities,
} from '../capabilities.js';
import { SCHEDULER_FIELD_VERSIONS, SCHEDULER_FIELDS_V1 } from '../scheduler-fields.js';

const JSON_BLOB_FIELDS = new Set([
  'identity',
  'authorization_proof',
  'authorization',
  'evidence',
]);

/**
 * Project a compiled job object down to the fields accepted by a given
 * scheduler handoff version.  This mirrors the private `schedulerCreateSpec`
 * helper in apply.js without creating a cross-module dependency on it.
 */
function projectJobToSpec(job, { fieldVersion = '1' } = {}) {
  const fields = SCHEDULER_FIELD_VERSIONS[fieldVersion] || SCHEDULER_FIELDS_V1;
  const { source: _source, ...specBody } = job;
  const spec = {};
  for (const field of fields) {
    if (!(field in specBody)) continue;
    let value = field === 'enabled' ? Boolean(specBody[field]) : specBody[field];
    if (value === undefined) continue;
    if (value === null) continue;
    if (typeof value === 'object' && JSON_BLOB_FIELDS.has(field)) {
      value = JSON.stringify(value);
    }
    spec[field] = value;
  }
  return spec;
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

    // Compile the full manifest to get job specs for every task
    const compiled = compileManifestToScheduler(manifest);
    const taskId = task.id || task.name;
    const workflowId = workflow.id;

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

    // Mark as one-off so the scheduler deletes the job after a single run.
    // Spread to avoid mutating the compiler output in case it is cached/reused.
    const jobSpec = { ...job, delete_after_run: 1 };

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

    // Build a runner and negotiate capabilities
    const runner = createSchedulerCliRunner({
      schedulerPrefix,
      schedulerBin,
      dbPath,
      cwd,
      env,
    });

    const runtimeCaps = querySchedulerCapabilities(runner);
    const effectiveResult = resolveEffectiveFeatures('openclaw-scheduler', runtimeCaps);
    const handoffVersion = effectiveResult.handoff_version || '1';
    const capabilityErrors = validateManifestCapabilities({ jobs: [jobSpec] }, effectiveResult);
    if (capabilityErrors.length > 0) {
      throw Object.assign(
        new Error(capabilityErrors.map(error => error.message).join('; ')),
        { code: 'unsupported_capability', capability_errors: capabilityErrors }
      );
    }

    const spec = projectJobToSpec(jobSpec, { fieldVersion: handoffVersion });
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
      note: 'Task delegated to openclaw-scheduler. The scheduler will execute it on its next tick.',
    };
  },
};
