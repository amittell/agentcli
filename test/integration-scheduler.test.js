import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';

import { applyManifestToScheduler, createSchedulerCliRunner, resolveSchedulerInvocation } from '../src/apply.js';
import { compileManifestToScheduler } from '../src/compiler/openclaw-scheduler.js';

const SCHEDULER_PATH = process.env.SCHEDULER_PATH || resolve(import.meta.dirname, '../../openclaw-scheduler');
const schedulerPkg = join(SCHEDULER_PATH, 'package.json');

function readExample(name) {
  return JSON.parse(readFileSync(new URL(`../examples/${name}`, import.meta.url), 'utf8'));
}

function stableId(workflowId, taskId) {
  return createHash('sha256').update(`${workflowId}:${taskId}`).digest('hex').slice(0, 32);
}

function summarizeProbeFailure(stderr, status) {
  const lines = String(stderr || '')
    .split('\n')
    .map(line => line.trim())
    .filter(Boolean);
  const summary = lines.find(line => line.startsWith('Error:')) || lines[0];
  return summary || `capabilities exited with status ${status}`;
}

function probeSchedulerRuntime() {
  const invocation = resolveSchedulerInvocation({ schedulerPrefix: SCHEDULER_PATH });
  const probeDb = join(tmpdir(), `agentcli-integ-probe-${process.pid}.db`);
  const result = spawnSync(
    invocation.command,
    [...invocation.prefixArgs, '--json', 'capabilities'],
    {
      env: { ...process.env, SCHEDULER_DB: probeDb },
      encoding: 'utf8',
    }
  );

  if (result.error) {
    return { ok: false, reason: result.error.message, capabilities: null };
  }
  if (result.status !== 0) {
    return {
      ok: false,
      reason: summarizeProbeFailure(result.stderr, result.status),
      capabilities: null,
    };
  }

  const stdout = String(result.stdout || '').trim();
  if (!stdout) {
    return { ok: false, reason: 'capabilities returned empty stdout', capabilities: null };
  }

  try {
    return { ok: true, reason: null, capabilities: JSON.parse(stdout) };
  } catch (err) {
    return {
      ok: false,
      reason: `capabilities returned invalid JSON: ${err.message}`,
      capabilities: null,
    };
  }
}

const schedulerRuntime = existsSync(schedulerPkg)
  ? probeSchedulerRuntime()
  : {
      ok: false,
      reason: `openclaw-scheduler not found at ${SCHEDULER_PATH}`,
      capabilities: null,
    };

const v02RuntimeSkipReason = schedulerRuntime.ok
  && Number.parseInt(schedulerRuntime.capabilities?.handoff_version || '0', 10) >= 2
  && schedulerRuntime.capabilities?.features?.trust_evaluation === true
  && schedulerRuntime.capabilities?.features?.authorization_hook === true
  ? null
  : 'scheduler under test does not advertise handoff_version>=2 with trust_evaluation=true and authorization_hook=true';

if (!schedulerRuntime.ok) {
  describe('integration-scheduler (skipped)', { skip: schedulerRuntime.reason }, () => {
    it('records a concrete scheduler probe failure', () => {
      assert.equal(schedulerRuntime.ok, false);
      assert.equal(typeof schedulerRuntime.reason, 'string');
      assert.ok(schedulerRuntime.reason.length > 0);
    });
  });
} else {
  describe('integration-scheduler', () => {
    let tmpDir;

    before(() => {
      tmpDir = mkdtempSync(join(tmpdir(), 'agentcli-integ-'));
    });

    after(() => {
      rmSync(tmpDir, { recursive: true, force: true });
    });

    function dbPath(suffix = 'default') {
      return join(tmpDir, `test-${suffix}.db`);
    }

    it('apply hello-world manifest creates jobs', async () => {
      const manifest = readExample('hello-world.json');
      const db = dbPath('create');

      const result = await applyManifestToScheduler(manifest, {
        schedulerPrefix: SCHEDULER_PATH,
        dbPath: db
      });

      assert.equal(result.ok, true);
      assert.ok(result.job_count >= 1, `expected at least 1 job, got ${result.job_count}`);
      assert.equal(result.dry_run, false);
      assert.equal(result.target, 'openclaw-scheduler');

      for (const action of result.actions) {
        assert.equal(action.action, 'created', `expected action 'created' for job ${action.job_id}, got '${action.action}'`);
      }
    });

    it('re-apply is idempotent (updates, not duplicates)', async () => {
      const manifest = readExample('hello-world.json');
      const db = dbPath('idempotent');

      // First apply -- creates
      const first = await applyManifestToScheduler(manifest, {
        schedulerPrefix: SCHEDULER_PATH,
        dbPath: db
      });
      assert.equal(first.ok, true);
      for (const action of first.actions) {
        assert.equal(action.action, 'created');
      }

      // Second apply -- same db, should update
      const second = await applyManifestToScheduler(manifest, {
        schedulerPrefix: SCHEDULER_PATH,
        dbPath: db
      });
      assert.equal(second.ok, true);
      assert.equal(second.job_count, first.job_count, 'job count should be identical on re-apply');

      for (const action of second.actions) {
        assert.equal(action.action, 'updated', `expected action 'updated' on re-apply for job ${action.job_id}, got '${action.action}'`);
      }
    });

    it('apply with dryRun does not create jobs', async () => {
      const manifest = readExample('hello-world.json');
      const db = dbPath('dryrun');

      // Dry run first
      const dry = await applyManifestToScheduler(manifest, {
        schedulerPrefix: SCHEDULER_PATH,
        dbPath: db,
        dryRun: true
      });

      assert.equal(dry.ok, true);
      assert.equal(dry.dry_run, true);
      assert.ok(dry.job_count >= 1);

      // Now apply for real -- jobs should be created (not updated),
      // proving the dry run wrote nothing to the database
      const real = await applyManifestToScheduler(manifest, {
        schedulerPrefix: SCHEDULER_PATH,
        dbPath: db
      });

      assert.equal(real.ok, true);
      for (const action of real.actions) {
        assert.equal(action.action, 'created', `expected 'created' after dry run for job ${action.job_id}, got '${action.action}'`);
      }
    });

    it('triggered child has correct parent linkage', async () => {
      const manifest = readExample('hello-world.json');
      const db = dbPath('trigger');

      const result = await applyManifestToScheduler(manifest, {
        schedulerPrefix: SCHEDULER_PATH,
        dbPath: db
      });

      assert.equal(result.ok, true);

      // hello-world.json has workflow "daily-report" with tasks "collect" (root)
      // and "alert-followup" (triggered by "collect")
      const parentJobId = stableId('daily-report', 'collect');
      const childAction = result.actions.find(a => a.invocation_mode === 'trigger');
      assert.ok(childAction, 'expected at least one triggered child action');
      assert.equal(childAction.job_id, stableId('daily-report', 'alert-followup'));
      assert.equal(childAction.invocation_mode, 'trigger');

      const rootAction = result.actions.find(a => a.invocation_mode === 'schedule');
      assert.ok(rootAction, 'expected at least one scheduled root action');
      assert.equal(rootAction.job_id, parentJobId);
    });

    it('apply with different manifest replaces jobs', async () => {
      const helloManifest = readExample('hello-world.json');
      const shellManifest = readExample('shell-workflow.json');
      delete shellManifest.workflows[0].tasks[1].approval.risk_level;
      const db = dbPath('replace');

      // Apply hello-world first
      const first = await applyManifestToScheduler(helloManifest, {
        schedulerPrefix: SCHEDULER_PATH,
        dbPath: db
      });
      assert.equal(first.ok, true);
      const firstIds = new Set(first.actions.map(a => a.job_id));

      // Apply shell-workflow to the same database
      const second = await applyManifestToScheduler(shellManifest, {
        schedulerPrefix: SCHEDULER_PATH,
        dbPath: db
      });
      assert.equal(second.ok, true);

      // shell-workflow has different workflow/task ids, so its jobs should be created (not updated)
      for (const action of second.actions) {
        assert.equal(action.action, 'created', `expected 'created' for new manifest job ${action.job_id}, got '${action.action}'`);
        assert.ok(!firstIds.has(action.job_id), 'new manifest job ids should not overlap with first manifest');
      }
    });

    // -- v0.2 capability negotiation and field projection tests --

    it('queries scheduler capabilities successfully', async () => {
      const runner = createSchedulerCliRunner({
        schedulerPrefix: SCHEDULER_PATH,
        dbPath: dbPath('caps'),
      });

      const caps = runner.queryCapabilities();

      assert.ok(caps !== null, 'capabilities response should not be null');
      assert.equal(typeof caps, 'object');
      assert.ok(caps.features, 'capabilities should include features');
      assert.equal(
        caps.scheduler_version ?? null,
        schedulerRuntime.capabilities?.scheduler_version ?? null,
        'scheduler_version should match the probe result'
      );
      assert.equal(
        caps.handoff_version ?? null,
        schedulerRuntime.capabilities?.handoff_version ?? null,
        'handoff_version should match the probe result'
      );
      assert.deepEqual(
        caps.features,
        schedulerRuntime.capabilities?.features,
        'capability feature map should match the probe result'
      );
    });

    it('apply sends v0.2 fields at the negotiated scheduler handoff version', { skip: v02RuntimeSkipReason || false }, async () => {
      const v02Manifest = {
        version: '0.2',
        identity_profiles: [{
          id: 'test-profile',
          provider: 'none',
          subject: { kind: 'service', principal: 'agent://test/integ-principal' },
          trust: { level: 'supervised' },
        }],
        workflows: [{
          id: 'test-v02',
          name: 'v02 integration test',
          tasks: [{
            id: 'check',
            name: 'health check',
            shell: { program: 'echo', args: ['ok'] },
            target: { session_target: 'shell' },
            schedule: { cron: '0 9 * * *' },
            identity: { ref: 'test-profile' },
            contract: { required_trust_level: 'supervised', trust_enforcement: 'strict' },
          }],
        }],
      };

      const db = dbPath('v02-apply');
      const result = await applyManifestToScheduler(v02Manifest, {
        schedulerPrefix: SCHEDULER_PATH,
        dbPath: db,
      });

      assert.equal(result.ok, true);
      assert.ok(result.capabilities, 'result should include capabilities metadata');
      assert.equal(result.capabilities.negotiated, true, 'capabilities should be negotiated');
      assert.ok(result.handoff, 'result should include handoff metadata');
      assert.equal(result.handoff.v02_fields_included, true, 'v0.2 fields should be included');
      const expectedVersion = String(Math.min(
        Number.parseInt(schedulerRuntime.capabilities.handoff_version, 10),
        4,
      ));
      assert.equal(result.handoff.field_version, expectedVersion, 'field_version should match the negotiated runtime version');
    });

    it('v0.2 identity fields are stored in scheduler', { skip: v02RuntimeSkipReason || false }, async () => {
      const v02Manifest = {
        version: '0.2',
        identity_profiles: [{
          id: 'stored-profile',
          provider: 'none',
          subject: { kind: 'agent', principal: 'agent://test/stored-agent', delegation_mode: 'none' },
          trust: { level: 'supervised' },
        }],
        workflows: [{
          id: 'v02-stored',
          name: 'v02 stored fields test',
          tasks: [{
            id: 'stored-check',
            name: 'stored field check',
            shell: { program: 'echo', args: ['stored'] },
            target: { session_target: 'shell' },
            schedule: { cron: '0 10 * * *' },
            identity: { ref: 'stored-profile' },
            contract: { required_trust_level: 'restricted', trust_enforcement: 'advisory' },
          }],
        }],
      };

      const db = dbPath('v02-stored');
      const applyResult = await applyManifestToScheduler(v02Manifest, {
        schedulerPrefix: SCHEDULER_PATH,
        dbPath: db,
      });
      assert.equal(applyResult.ok, true);

      const runner = createSchedulerCliRunner({
        schedulerPrefix: SCHEDULER_PATH,
        dbPath: db,
      });
      const jobs = runner.listJobs();
      assert.ok(jobs.length >= 1, `expected at least 1 stored job, got ${jobs.length}`);

      const expectedJobId = stableId('v02-stored', 'stored-check');
      const job = jobs.find(j => j.id === expectedJobId);
      assert.ok(job, `expected to find job with id ${expectedJobId}`);
      assert.equal(job.identity_ref, 'stored-profile', 'identity_ref should match the profile id');
      assert.equal(job.identity_trust_level, 'supervised', 'identity_trust_level should match the profile trust level');
      assert.equal(job.identity_subject_kind, 'agent', 'identity_subject_kind should match the profile subject kind');
      assert.equal(job.identity_subject_principal, 'agent://test/stored-agent', 'identity_subject_principal should match');
      assert.equal(job.contract_required_trust_level, 'restricted', 'contract_required_trust_level should be stored');
      assert.equal(job.contract_trust_enforcement, 'advisory', 'contract_trust_enforcement should be stored');
    });

    it('apply response includes capability negotiation metadata when v0.2 fields require it', { skip: v02RuntimeSkipReason || false }, async () => {
      const manifest = {
        version: '0.2',
        identity_profiles: [{
          id: 'caps-profile',
          provider: 'none',
          subject: { kind: 'service', principal: 'agent://test/caps-meta' },
          trust: { level: 'supervised' },
        }],
        workflows: [{
          id: 'caps-meta',
          name: 'Capability metadata test',
          tasks: [{
            id: 'check',
            name: 'capability metadata check',
            shell: { program: 'echo', args: ['caps'] },
            target: { session_target: 'shell' },
            schedule: { cron: '0 11 * * *' },
            identity: { ref: 'caps-profile' },
            contract: { required_trust_level: 'supervised', trust_enforcement: 'strict' },
          }],
        }],
      };
      const db = dbPath('caps-meta');

      const result = await applyManifestToScheduler(manifest, {
        schedulerPrefix: SCHEDULER_PATH,
        dbPath: db,
      });

      assert.equal(result.ok, true);
      assert.ok(result.capabilities, 'result should include capabilities');
      assert.equal(result.capabilities.source, 'runtime', 'capabilities source should be runtime');
      assert.equal(result.capabilities.negotiated, true, 'capabilities should be negotiated');
    });

    it('apply response includes handoff metadata', async () => {
      const manifest = readExample('hello-world.json');
      const db = dbPath('handoff-meta');

      const result = await applyManifestToScheduler(manifest, {
        schedulerPrefix: SCHEDULER_PATH,
        dbPath: db,
      });

      assert.equal(result.ok, true);
      assert.ok(result.handoff, 'result should include handoff metadata');
      assert.ok(
        ['1', '2', '3', '4'].includes(result.handoff.field_version),
        `field_version should be a supported handoff version, got '${result.handoff.field_version}'`
      );
      assert.equal(typeof result.handoff.projected_fields, 'number', 'projected_fields should be a number');
      assert.ok(result.handoff.projected_fields > 0, 'projected_fields should be positive');
    });

    it('adopts existing job by name', async () => {
      const db = dbPath('adopt');
      const runner = createSchedulerCliRunner({
        schedulerPrefix: SCHEDULER_PATH,
        dbPath: db,
      });

      // Compile the hello-world manifest to get a valid job spec, then
      // pre-seed it under a legacy id that differs from the stable id.
      const manifest = readExample('hello-world.json');
      const compiled = compileManifestToScheduler(manifest);
      const collectJob = compiled.jobs.find(j => j.source.task_id === 'collect');
      const legacyId = 'legacy-collect-' + Date.now();

      // Build a valid scheduler spec from the compiled job but with the legacy id.
      // Strip the internal 'source' field (not a scheduler column).
      const { source: _source, id: _stableId, ...legacySpec } = collectJob;
      runner.addJob({ id: legacyId, ...legacySpec });

      // Verify the legacy job exists
      const beforeJobs = runner.listJobs();
      const legacyJob = beforeJobs.find(j => j.id === legacyId);
      assert.ok(legacyJob, 'legacy job should exist before adoption');

      // Apply hello-world manifest with adoptBy: 'name'.
      // The manifest produces a job with the same name but a different stable id,
      // so the apply should adopt (re-key) the existing job.
      const result = await applyManifestToScheduler(manifest, {
        schedulerPrefix: SCHEDULER_PATH,
        dbPath: db,
        adoptBy: 'name',
      });

      assert.equal(result.ok, true);

      const adoptedAction = result.actions.find(a => a.action === 'adopted');
      assert.ok(adoptedAction, 'expected at least one adopted action');
      assert.equal(adoptedAction.name, collectJob.name, 'adopted job should match by name');
      assert.equal(adoptedAction.adopted_from_job_id, legacyId, 'adopted_from_job_id should reference the legacy id');

      // The stable id should now exist and the legacy id should be gone
      const afterJobs = runner.listJobs();
      const expectedStableId = stableId('daily-report', 'collect');
      assert.ok(afterJobs.find(j => j.id === expectedStableId), 'stable id job should exist after adoption');
      assert.ok(!afterJobs.find(j => j.id === legacyId), 'legacy id job should be removed after adoption');
    });

    it('v0.1 manifest backward compatibility with the current scheduler', async () => {
      // hello-world.json is a v0.1 manifest. This test explicitly verifies
      // that v0.1 manifests still produce successful results against the
      // current scheduler after all v0.2 capability negotiation changes.
      const manifest = readExample('hello-world.json');
      assert.equal(manifest.version, '0.1', 'hello-world.json should be a v0.1 manifest');

      const db = dbPath('backcompat');
      const result = await applyManifestToScheduler(manifest, {
        schedulerPrefix: SCHEDULER_PATH,
        dbPath: db,
      });

      assert.equal(result.ok, true, 'v0.1 manifest should apply successfully');
      assert.ok(result.job_count >= 1, `expected at least 1 job, got ${result.job_count}`);
      assert.equal(result.target, 'openclaw-scheduler');
      assert.equal(result.dry_run, false);

      // Every apply probes capabilities so v0.1 jobs also receive immutable v4
      // artifacts when the runtime advertises the exact contract.
      assert.ok(result.capabilities, 'v0.1 apply should include capability metadata');
      assert.equal(result.capabilities.source, 'runtime', 'v0.1 apply should use live capabilities');
      assert.equal(result.capabilities.negotiated, true, 'v0.1 apply should negotiate the handoff');

      // All jobs should be created successfully
      for (const action of result.actions) {
        assert.equal(action.action, 'created', `expected 'created' for v0.1 job ${action.job_id}, got '${action.action}'`);
      }
    });
  });
}
