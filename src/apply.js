import { spawnSync } from 'node:child_process';
import process from 'node:process';
import { compileManifestToScheduler } from './compiler/openclaw-scheduler.js';
import { resolveValueFrom } from './command.js';
import { canonicalDigest, canonicalStringify } from './canonical.js';
import {
  mergeAuthorizationProofProfile,
  normalizedTaskPlan,
  stableId
} from './compiler/shared.js';
import { expandManifestShorthands } from './shorthand.js';
import {
  querySchedulerCapabilities,
  resolveEffectiveFeatures,
  supportsSchedulerHandoffV4,
  validateManifestCapabilities,
} from './capabilities.js';
import {
  SCHEDULER_FIELDS_V1,
  SCHEDULER_FIELDS_V02,
  SCHEDULER_FIELDS_V03,
  SCHEDULER_FIELDS_V04,
  SCHEDULER_FIELD_VERSIONS,
} from './scheduler-fields.js';
import {
  assertValidSchedulerHandoffV4Job,
  rebindSchedulerHandoffV4Job,
  schedulerHandoffV4RebindableOverrides,
} from './handoff/v4.js';
export { shellCommandInvocation } from './command.js';
export {
  SCHEDULER_FIELDS_V1,
  SCHEDULER_FIELDS_V02,
  SCHEDULER_FIELDS_V03,
  SCHEDULER_FIELDS_V04,
  SCHEDULER_FIELD_VERSIONS,
};

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

// Fields that the scheduler stores as JSON text blobs rather than scalar columns.
const JSON_BLOB_FIELDS = new Set([
  'identity', 'authorization_proof', 'authorization', 'evidence',
  'handoff_artifact_payload',
]);

function projectSchedulerSpec(job, fields, {
  includeNulls = false,
  canonicalJsonBlobs = false,
} = {}) {
  const spec = {};
  for (const field of fields) {
    if (!(field in job)) continue;
    let value = field === 'enabled' ? Boolean(job[field]) : job[field];
    if (value === undefined) continue;
    if (value === null && !includeNulls) continue;
    // Scheduler expects JSON blob fields as stringified JSON, not raw objects
    if (value !== null && typeof value === 'object' && JSON_BLOB_FIELDS.has(field)) {
      value = canonicalJsonBlobs ? canonicalStringify(value) : JSON.stringify(value);
    }
    spec[field] = value;
  }
  return spec;
}

export function schedulerCreateSpec(job, { originOverride, fieldVersion = '1' } = {}) {
  const fields = SCHEDULER_FIELD_VERSIONS[fieldVersion] || SCHEDULER_FIELDS_V1;
  const { source, ...spec } = job;
  const projected = projectSchedulerSpec(spec, fields, {
    includeNulls: false,
    canonicalJsonBlobs: String(fieldVersion) === '4',
  });
  if (originOverride != null) {
    projected.origin = originOverride;
  }
  return projected;
}

export function requiredSchedulerFieldVersion(jobs = []) {
  if (jobs.some(job => SCHEDULER_FIELDS_V04.some(field => job[field] != null))) return 4;
  if (jobs.some(job => SCHEDULER_FIELDS_V03.some(field => job[field] != null))) return 3;
  if (jobs.some(job => SCHEDULER_FIELDS_V02.some(field => job[field] != null))) return 2;
  return 1;
}

export function negotiateSchedulerFieldVersion(jobs, advertisedVersion = '1') {
  const requiredVersion = requiredSchedulerFieldVersion(jobs);
  const parsedVersion = Number.parseInt(String(advertisedVersion), 10);
  if (!Number.isInteger(parsedVersion) || parsedVersion < requiredVersion) {
    throw Object.assign(
      new Error(
        `Scheduler handoff version ${JSON.stringify(advertisedVersion)} cannot preserve fields requiring version ${requiredVersion}`
      ),
      {
        code: 'unsupported_capability',
        required_handoff_version: String(requiredVersion),
        advertised_handoff_version: advertisedVersion == null ? null : String(advertisedVersion),
      }
    );
  }
  return String(Math.min(parsedVersion, requiredVersion >= 4 ? 4 : 3));
}

function schedulerUpdateSpec(job, { fieldVersion = '1' } = {}) {
  const fields = (SCHEDULER_FIELD_VERSIONS[fieldVersion] || SCHEDULER_FIELDS_V1)
    .filter(f => f !== 'id' && f !== 'origin');
  const { source, ...spec } = job;
  return projectSchedulerSpec(spec, fields, {
    includeNulls: true,
    canonicalJsonBlobs: String(fieldVersion) === '4',
  });
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
    listJobs(options = {}) {
      const includeHandoffArtifacts = options?.includeHandoffArtifacts === true;
      const args = ['jobs', 'list'];
      if (includeHandoffArtifacts === true) {
        args.push('--include-handoff-artifacts');
      }
      const payload = invoke(args);
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
    env = process.env,
    allowValueFromCommand = false
  } = {}
) {
  let compiled = compileManifestToScheduler(manifest, { includeExplain });
  const schedulerEnv = { ...process.env, ...(env || {}) };
  const verificationByTask = new Map();
  const resolvedProofsByTask = buildResolvedAuthorizationProofsByTask(manifest);

  // Construct the scheduler runner once. Every apply probes capabilities so a
  // basic v0.1 job receives a v4 artifact when the runtime supports the exact
  // contract, while an unavailable capability command still falls back safely.
  const schedulerRunner = runner || createSchedulerCliRunner({
    schedulerPrefix,
    schedulerBin,
    dbPath,
    cwd,
    env: schedulerEnv,
  });

  const runtimeCaps = querySchedulerCapabilities(schedulerRunner);
  const effectiveResult = resolveEffectiveFeatures('openclaw-scheduler', runtimeCaps);
  let handoffVersion;

  if (supportsSchedulerHandoffV4(runtimeCaps)) {
    compiled = compileManifestToScheduler(manifest, {
      includeExplain,
      schedulerHandoffVersion: '4',
      cwd,
      env,
    });
  }

  const {
    errors: capabilityErrors,
    warnings: capabilityWarnings,
  } = validateManifestCapabilities(compiled, effectiveResult);
  if (capabilityErrors.length > 0) {
    throw Object.assign(
      new Error(capabilityErrors.map(error => error.message).join('; ')),
      { code: 'unsupported_capability', capability_errors: capabilityErrors }
    );
  }
  handoffVersion = negotiateSchedulerFieldVersion(
    compiled.jobs,
    effectiveResult.handoff_version || '1'
  );
  if (capabilityWarnings.length > 0) {
    for (const warning of capabilityWarnings) {
      process.stderr.write(`warning: ${warning.message}\n`);
    }
  }
  const effectiveFeatures = effectiveResult.features;

  // v0.2: Authorization proof verification for backends lacking the capability
  if (!effectiveFeatures.authorization_proof_verification && manifest.authorization_proof_profiles?.length > 0) {
    // Target cannot verify proofs at runtime; verify locally during apply
    const {
      assertValidAuthorizationProofProfile,
      verifyAuthorizationProof,
    } = await import('./authorization-proof/index.js');
    await import('./authorization-proof/none.js');
    await import('./authorization-proof/jwt.js');
    await import('./authorization-proof/detached-signature.js');
    await import('./authorization-proof/certificate.js');
    const manifestDigest = canonicalDigest(manifest);

    for (const job of compiled.jobs) {
      const proof = resolvedProofsByTask.get(`${job.source.workflow_id}:${job.source.task_id}`) ?? null;
      if (!proof?.ref) continue;
      const mustVerify = proof.method !== 'none' || proof.verify?.required === true;
      if (!mustVerify) continue;

      const verifier = assertValidAuthorizationProofProfile(proof, { env, cwd });
      let proofValue;
      try {
        proofValue = resolveValueFrom(proof.proof?.value_from, {
          env,
          cwd,
          allowCommand: allowValueFromCommand,
        });
      } catch (error) {
        throw Object.assign(
          new Error(`Authorization proof not available for profile "${proof.ref}": ${error.message}`),
          { code: 'authorization_proof_failed' }
        );
      }

      const result = await verifyAuthorizationProof(proofValue, proof, {
        manifest,
        env,
        cwd,
        manifestDigest,
      });
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

  const existingJobs = schedulerRunner.listJobs({
    includeHandoffArtifacts: handoffVersion === '4',
  });
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

  const plannedActions = [];
  for (const job of compiled.jobs) {
    let action;
    let existingId;
    let existingJob;
    let duplicateLegacyJobs = [];

    if (adoptBy === 'name') {
      const sameNameJobs = existingByName.get(job.name) || [];
      const exactMatch = existingById.get(job.id) || null;

      if (exactMatch) {
        action = 'updated';
        existingJob = exactMatch;
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
      existingJob = existingById.get(job.id) || null;
      if (existingJob) {
        action = 'updated';
      } else {
        action = 'created';
      }
    }

    plannedActions.push({ job, action, existingId, existingJob });
  }

  for (const { job, action, existingJob } of plannedActions) {
    if ((action === 'updated' || action === 'adopted')
      && Number(existingJob?.handoff_version) === 4
      && Number(job.handoff_version) !== 4) {
      throw Object.assign(
        new Error(
          `Cannot ${action === 'adopted' ? 'adopt' : 'update'} handoff v4 scheduler job ` +
          `"${existingJob?.id ?? job.id}" after runtime capability downgrade; ` +
          'restore the exact v4 runtime contract before applying changes'
        ),
        { code: 'unsupported_capability' }
      );
    }
    if ((action === 'updated' || action === 'adopted')
      && Number(existingJob?.handoff_version) === 4) {
      assertValidSchedulerHandoffV4Job(existingJob);
    }
    if (!dryRun && action === 'adopted' && typeof schedulerRunner.deleteJob !== 'function') {
      throw Object.assign(
        new Error('Scheduler runner does not support deleteJob(); cannot adopt legacy rows by name'),
        { code: 'scheduler_error' }
      );
    }
  }

  const actions = [];
  for (const { job, action, existingId, existingJob } of plannedActions) {
    const verificationEntry = verificationByTask.get(`${job.source.workflow_id}:${job.source.task_id}`) ?? null;

    if (!dryRun) {
      if (action === 'created') {
        schedulerRunner.addJob(schedulerCreateSpec(job, { fieldVersion: handoffVersion }));
      } else if (action === 'updated') {
        const existingOrigin = existingJob?.origin ?? job.origin ?? 'system';
        const updateJob = Number(job.handoff_version) === 4
          ? rebindSchedulerHandoffV4Job(job, {
              ...schedulerHandoffV4RebindableOverrides(existingJob),
              origin: existingOrigin,
            })
          : job;
        schedulerRunner.updateJob(job.id, schedulerUpdateSpec(updateJob, { fieldVersion: handoffVersion }));
      } else if (action === 'adopted') {
        const adoptedOrigin = existingJob?.origin ?? 'system';
        const adoptedJob = Number(job.handoff_version) === 4
          ? rebindSchedulerHandoffV4Job(job, {
              ...schedulerHandoffV4RebindableOverrides(existingJob),
              origin: adoptedOrigin,
            })
          : job;
        schedulerRunner.addJob(schedulerCreateSpec(adoptedJob, {
          originOverride: adoptedOrigin,
          fieldVersion: handoffVersion,
        }));
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
      schema_version: effectiveResult.schema_version || null,
      handoff_contract: effectiveResult.handoff_contract || null,
      ...(capabilityWarnings?.length > 0 ? { warnings: capabilityWarnings } : {}),
    },
    handoff: {
      field_version: handoffVersion,
      projected_fields: (SCHEDULER_FIELD_VERSIONS[handoffVersion] || SCHEDULER_FIELDS_V1).length,
      v02_fields_included: handoffVersion !== '1',
    },
    job_count: compiled.jobs.length,
    actions,
    ...(verificationByTask.size > 0
      ? { authorization_proof_verifications: [...verificationByTask.values()] }
      : {}),
    ...(includeExplain ? { explain: compiled.explain } : {})
  };
}
