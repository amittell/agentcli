import { spawnSync } from 'child_process';
import process from 'process';
import { compileManifestToScheduler } from './compiler/openclaw-scheduler.js';

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
    throw new Error(`Failed to execute scheduler command: ${formatCommand(invocation, ['--json', ...args])}: ${result.error.message}`);
  }

  if (typeof result.status === 'number' && result.status !== 0) {
    const stderr = String(result.stderr || '').trim();
    throw new Error(stderr || `Scheduler command failed (${result.status}): ${formatCommand(invocation, ['--json', ...args])}`);
  }

  const stdout = String(result.stdout || '').trim();
  if (!stdout) return null;

  try {
    return JSON.parse(stdout);
  } catch (err) {
    throw new Error(`Scheduler command returned invalid JSON: ${formatCommand(invocation, ['--json', ...args])}`, { cause: err });
  }
}

function schedulerJobSpec(job) {
  const { source, ...spec } = job;
  const normalized = {
    ...spec,
    enabled: Boolean(spec.enabled)
  };
  return Object.fromEntries(
    Object.entries(normalized).filter(([, value]) => value !== null && value !== undefined)
  );
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
    listJobs() {
      const payload = invoke(['jobs', 'list']);
      return Array.isArray(payload) ? payload : [];
    },
    addJob(spec) {
      return invoke(['jobs', 'add', JSON.stringify(spec)]);
    },
    updateJob(id, spec) {
      return invoke(['jobs', 'update', id, JSON.stringify(spec)]);
    }
  };
}

export function applyManifestToScheduler(
  manifest,
  {
    dryRun = false,
    includeExplain = false,
    runner = null,
    schedulerPrefix = '',
    schedulerBin = '',
    dbPath = '',
    cwd = process.cwd(),
    env = process.env
  } = {}
) {
  const compiled = compileManifestToScheduler(manifest, { includeExplain });
  const schedulerRunner = runner || createSchedulerCliRunner({
    schedulerPrefix,
    schedulerBin,
    dbPath,
    cwd,
    env
  });

  const existingById = new Map(
    schedulerRunner.listJobs().map(job => [job.id, job])
  );

  const actions = [];
  for (const job of compiled.jobs) {
    const action = existingById.has(job.id) ? 'updated' : 'created';
    const spec = schedulerJobSpec(job);
    if (!dryRun) {
      if (action === 'created') schedulerRunner.addJob(spec);
      else schedulerRunner.updateJob(job.id, spec);
    }
    actions.push({
      action,
      job_id: job.id,
      name: job.name,
      invocation_mode: job.parent_id ? 'trigger' : 'schedule'
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
    job_count: compiled.jobs.length,
    actions,
    ...(includeExplain ? { explain: compiled.explain } : {})
  };
}
