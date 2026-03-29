import { spawnSync } from 'node:child_process';
import process from 'node:process';
import { compileManifestToScheduler } from './compiler/openclaw-scheduler.js';
import { resolveCommandValue } from './command.js';
import {
  mergeAuthorizationProofProfile,
  normalizedTaskPlan,
  stableId
} from './compiler/shared.js';
import { expandManifestShorthands } from './shorthand.js';
import { TARGETS } from './targets.js';
import { querySchedulerCapabilities, resolveEffectiveFeatures } from './capabilities.js';
export { shellCommandInvocation } from './command.js';

function npmCommandForPlatform(platform = process.platform) {
  return platform === 'win32' ? 'npm.cmd' : 'npm';
}

function formatCommand(invocation, extraArgs = []) {
  return [invocation.command, ...invocation.prefixArgs, ...extraArgs].join(' ');
}

export function resolveSchedulerInvocation({
  schedulerPrefix = '',
  schedulerBin = '',
  platform = process.platform
} = {}) {
  if (schedulerPrefix) {
    return {
      command: npmCommandForPlatform(platform),
      prefixArgs: ['exec', '--prefix', schedulerPrefix, 'openclaw-scheduler', '--'],
      label: `npm exec --prefix ${schedulerPrefix} openclaw-scheduler --`
    };
  }

  const bin = schedulerBin || 'openclaw-scheduler';
  if (bin.endsWith('.js')) {
    return {
      command: process.execPath,
      prefixArgs: [bin],
      label: `${process.execPath} ${bin}`
    };
  }

  return {
    command: bin,
    prefixArgs: [],
    label: bin
  };
}

function spawnSchedulerJson(invocation, args, { cwd, env, runner = spawnSync } = {}) {
  const result = runner(invocation.command, [...invocation.prefixArgs, '--json', ...args], {
    cwd,
    env,
    encoding: 'utf8'
  });

  if (result.error) {
    throw Object.assign(
      new Error(`Failed to execute scheduler command: ${formatCommand(invocation, ['--json', ...args])}: ${result.error.message}`),
      { code: 'scheduler_error' }
    );
  }

  if (typeof result.status === 'number' && result.status !== 0) {
    const stderr = String(result.stderr || '').trim();
    throw Object.assign(
      new Error(stderr || `Scheduler command failed (${result.status}): ${formatCommand(invocation, ['--json', ...args])}`),
      { code: 'scheduler_error' }
    );
  }

  const stdout = String(result.stdout || '').trim();
  if (!stdout) return null;

  try {
    return JSON.parse(stdout);
  } catch (err) {
    throw Object.assign(
      new Error(`Scheduler command returned invalid JSON: ${formatCommand(invocation, ['--json', ...args])}`),
      { code: 'parse_error', cause: err }
    );
  }
}

const SCHEDULER_CREATE_FIELDS = [
  'id',
  'name',
  'enabled',
  'schedule_cron',
  'schedule_tz',
  'session_target',
  'agent_id',
  'payload_kind',
  'payload_message',
  'payload_model',
  'payload_thinking',
  'execution_intent',
  'execution_read_only',
  'run_timeout_ms',
  'overlap_policy',
  'max_retries',
  'max_queued_dispatches',
  'max_pending_approvals',
  'max_trigger_fanout',
  'delivery_mode',
  'delivery_channel',
  'delivery_to',
  'delivery_opt_out_reason',
  'delivery_guarantee',
  'origin',
  'parent_id',
  'trigger_on',
  'trigger_delay_s',
  'trigger_condition',
  'approval_required',
  'approval_timeout_s',
  'approval_auto',
  'context_retrieval',
  'context_retrieval_limit',
  'output_store_limit_bytes',
  'output_excerpt_limit_bytes',
  'output_summary_limit_bytes',
  'output_offload_threshold_bytes',
  'preferred_session_key',
  'delete_after_run'
];

const SCHEDULER_UPDATE_FIELDS = SCHEDULER_CREATE_FIELDS.filter(field => field !== 'id' && field !== 'origin');

function projectSchedulerSpec(job, fields, { includeNulls = false } = {}) {
  const spec = {};
  for (const field of fields) {
    if (!(field in job)) continue;
    const value = field === 'enabled' ? Boolean(job[field]) : job[field];
    if (value === undefined) continue;
    if (value === null && !includeNulls) continue;
    spec[field] = value;
  }
  return spec;
}

function schedulerCreateSpec(job, { originOverride } = {}) {
  const { source, ...spec } = job;
  const projected = projectSchedulerSpec(spec, SCHEDULER_CREATE_FIELDS, { includeNulls: false });
  if (originOverride != null) {
    projected.origin = originOverride;
  }
  return projected;
}

function schedulerUpdateSpec(job) {
  const { source, ...spec } = job;
  return projectSchedulerSpec(spec, SCHEDULER_UPDATE_FIELDS, { includeNulls: true });
}

function duplicateNames(items) {
  const counts = new Map();
  for (const item of items) {
    if (!item?.name) continue;
    counts.set(item.name, (counts.get(item.name) || 0) + 1);
  }
  return [...counts.entries()]
    .filter(([, count]) => count > 1)
    .map(([name]) => name);
}

export function createSchedulerCliRunner(options = {}) {
  const invocation = resolveSchedulerInvocation(options);
  const baseEnv = { ...process.env, ...(options.env || {}) };
  if (options.dbPath) baseEnv.SCHEDULER_DB = options.dbPath;

  const invoke = (args) => spawnSchedulerJson(invocation, args, {
    cwd: options.cwd,
    env: baseEnv,
    runner: options.runner
  });

  return {
    invocation,
    queryCapabilities() {
      try { return invoke(['capabilities']); }
      catch { return null; }
    },
    listJobs() {
      const payload = invoke(['jobs', 'list']);
      return Array.isArray(payload) ? payload : [];
    },
    addJob(spec) {
      return invoke(['jobs', 'add', JSON.stringify(spec)]);
    },
    updateJob(id, spec) {
      return invoke(['jobs', 'update', id, JSON.stringify(spec)]);
    },
    deleteJob(id) {
      return invoke(['jobs', 'delete', id]);
    }
  };
}

function buildResolvedAuthorizationProofsByTask(manifest) {
  const expanded = expandManifestShorthands(manifest);
  const resolvedProofs = new Map();

  for (const workflow of expanded.workflows || []) {
    const taskIdToJobId = new Map();
    for (const task of workflow.tasks || []) {
      taskIdToJobId.set(task.id, stableId(workflow.id, task.id));
    }

    for (const task of workflow.tasks || []) {
      const plan = normalizedTaskPlan(workflow, task, taskIdToJobId);
      const proofProfile = plan.authorization_proof?.ref
        ? expanded.authorization_proof_profiles?.find(profile => profile.id === plan.authorization_proof.ref) ?? null
        : null;
      const resolvedProof = plan.authorization_proof
        ? mergeAuthorizationProofProfile(proofProfile, plan.authorization_proof)
        : null;

      resolvedProofs.set(`${workflow.id}:${task.id}`, resolvedProof);
    }
  }

  return resolvedProofs;
}

export async function applyManifestToScheduler(
  manifest,
  {
    dryRun = false,
    includeExplain = false,
    adoptBy = 'id',
    runner = null,
    schedulerPrefix = '',
    schedulerBin = '',
    dbPath = '',
    cwd = process.cwd(),
    env = process.env
  } = {}
) {
  const compiled = compileManifestToScheduler(manifest, { includeExplain });
  const verificationByTask = new Map();
  const resolvedProofsByTask = buildResolvedAuthorizationProofsByTask(manifest);

  // Construct the scheduler runner early so we can query its capabilities
  const schedulerRunner = runner || createSchedulerCliRunner({
    schedulerPrefix,
    schedulerBin,
    dbPath,
    cwd,
    env
  });

  // Runtime capability negotiation
  const runtimeCaps = querySchedulerCapabilities(schedulerRunner);
  const effectiveResult = resolveEffectiveFeatures('openclaw-scheduler', runtimeCaps);
  const effectiveFeatures = effectiveResult.features;

  // v0.2: Authorization proof verification for backends lacking the capability
  if (!effectiveFeatures.authorization_proof_verification && manifest.authorization_proof_profiles?.length > 0) {
    // Target cannot verify proofs at runtime; verify locally during apply
    const { readFileSync } = await import('node:fs');
    const { resolveVerifier } = await import('./authorization-proof/index.js');
    await import('./authorization-proof/none.js');
    await import('./authorization-proof/jwt.js');
    await import('./authorization-proof/detached-signature.js');
    await import('./authorization-proof/certificate.js');

    for (const job of compiled.jobs) {
      const proof = resolvedProofsByTask.get(`${job.source.workflow_id}:${job.source.task_id}`) ?? null;
      if (!proof?.ref || proof.verify?.required !== true) continue;

      const verifier = resolveVerifier(proof.method || 'none');

      let proofValue = null;
      if (proof.proof?.value_from?.env) {
        proofValue = env[proof.proof.value_from.env] || null;
      } else if (proof.proof?.value_from?.file) {
        try {
          proofValue = readFileSync(proof.proof.value_from.file, 'utf8').trim();
        } catch {
          proofValue = null;
        }
      } else if (proof.proof?.value_from?.literal) {
        proofValue = proof.proof.value_from.literal;
      } else if (proof.proof?.value_from?.command) {
        proofValue = resolveCommandValue(proof.proof.value_from.command, { env, cwd });
      }

      if (!proofValue) {
        throw Object.assign(
          new Error(`Authorization proof not available for profile "${proof.ref}" (value_from did not resolve)`),
          { code: 'authorization_proof_failed' }
        );
      }

      const result = verifier.verifyProof(proofValue, proof, { env });
      if (!result.verified) {
        throw Object.assign(
          new Error(`Authorization proof verification failed for profile "${proof.ref}": ${result.reason || 'verification failed'}`),
          { code: 'authorization_proof_failed' }
        );
      }

      const summary = verifier.describeVerification(result, {});
      const verificationEntry = {
        source: job.source,
        authorization_proof_ref: proof.ref,
        verification: summary,
      };
      verificationByTask.set(`${job.source.workflow_id}:${job.source.task_id}`, verificationEntry);
    }
  }

  // v0.2: Reject manifests with authorization blocks when target lacks authorization_hook
  if (!effectiveFeatures.authorization_hook) {
    for (const job of compiled.jobs) {
      if (job.authorization_ref || job.authorization?.ref) {
        throw Object.assign(
          new Error(
            `Task "${job.source.task_id}" in workflow "${job.source.workflow_id}" has an authorization block ` +
            'but target "openclaw-scheduler" does not support authorization_hook'
          ),
          { code: 'unsupported_capability' }
        );
      }
    }
  }

  const existingJobs = schedulerRunner.listJobs();
  const existingById = new Map(existingJobs.map(job => [job.id, job]));
  const existingByName = new Map();
  for (const job of existingJobs) {
    if (!job?.name) continue;
    const bucket = existingByName.get(job.name) || [];
    bucket.push(job);
    existingByName.set(job.name, bucket);
  }

  if (adoptBy === 'name') {
    const duplicateCompiledNames = duplicateNames(compiled.jobs);
    if (duplicateCompiledNames.length > 0) {
      throw Object.assign(
        new Error(
          `Cannot use --adopt-by name when compiled job names are not unique: ${duplicateCompiledNames.join(', ')}`
        ),
        { code: 'invalid_argument' }
      );
    }
  }

  const actions = [];
  for (const job of compiled.jobs) {
    const verificationEntry = verificationByTask.get(`${job.source.workflow_id}:${job.source.task_id}`) ?? null;

    let action;
    let existingId;
    let existingJob;
    let duplicateLegacyJobs = [];

    if (adoptBy === 'name') {
      const sameNameJobs = existingByName.get(job.name) || [];
      const exactMatch = existingById.get(job.id) || null;

      if (exactMatch) {
        action = 'updated';
      } else {
        duplicateLegacyJobs = sameNameJobs;
      }

      if (!exactMatch && duplicateLegacyJobs.length > 1) {
        throw Object.assign(
          new Error(
            `Cannot use --adopt-by name because existing scheduler jobs have duplicate names: ${job.name}`
          ),
          { code: 'invalid_argument' }
        );
      }

      if (!exactMatch) {
        existingJob = duplicateLegacyJobs[0];
        if (existingJob) {
          action = 'adopted';
          existingId = existingJob.id;
        } else {
          action = 'created';
        }
      }
    } else {
      if (existingById.has(job.id)) {
        action = 'updated';
      } else {
        action = 'created';
      }
    }

    if (!dryRun) {
      if (action === 'created') {
        schedulerRunner.addJob(schedulerCreateSpec(job));
      } else if (action === 'updated') {
        schedulerRunner.updateJob(job.id, schedulerUpdateSpec(job));
      } else if (action === 'adopted') {
        if (typeof schedulerRunner.deleteJob !== 'function') {
          throw Object.assign(
            new Error('Scheduler runner does not support deleteJob(); cannot adopt legacy rows by name'),
            { code: 'scheduler_error' }
          );
        }
        schedulerRunner.addJob(
          schedulerCreateSpec(job, { originOverride: existingJob?.origin ?? 'system' })
        );
        try {
          schedulerRunner.deleteJob(existingId);
        } catch (err) {
          try {
            schedulerRunner.deleteJob(job.id);
          } catch (rollbackErr) {
            throw Object.assign(
              new Error(
                `Failed to adopt legacy row "${existingId}" to stable id "${job.id}": ` +
                `legacy delete failed after create, and rollback delete also failed. Manual cleanup may be required.`
              ),
              { code: 'scheduler_error', cause: err, rollbackCause: rollbackErr }
            );
          }
          throw Object.assign(
            new Error(
              `Failed to adopt legacy row "${existingId}" to stable id "${job.id}": ` +
              'legacy delete failed after create, but the created stable row was rolled back.'
            ),
            { code: 'scheduler_error', cause: err }
          );
        }
      }
    }

    actions.push({
      action,
      job_id: job.id,
      ...(existingId ? { adopted_from_job_id: existingId } : {}),
      name: job.name,
      invocation_mode: job.parent_id ? 'trigger' : 'schedule',
      ...(verificationEntry ? { authorization_proof_verification: verificationEntry.verification } : {})
    });
  }

  return {
    ok: true,
    target: 'openclaw-scheduler',
    dry_run: Boolean(dryRun),
    scheduler: {
      command: schedulerRunner.invocation?.label || 'custom-runner',
      db_path: dbPath || null
    },
    capabilities: {
      source: effectiveResult.source,
      negotiated: effectiveResult.negotiated,
      handoff_version: effectiveResult.handoff_version || null,
    },
    job_count: compiled.jobs.length,
    actions,
    ...(verificationByTask.size > 0
      ? { authorization_proof_verifications: [...verificationByTask.values()] }
      : {}),
    ...(includeExplain ? { explain: compiled.explain } : {})
  };
}
