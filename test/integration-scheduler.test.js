import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';

import { applyManifestToScheduler, createSchedulerCliRunner } from '../src/apply.js';

const SCHEDULER_PATH = process.env.SCHEDULER_PATH || resolve(import.meta.dirname, '../../openclaw-scheduler');
const schedulerPkg = join(SCHEDULER_PATH, 'package.json');

function readExample(name) {
  return JSON.parse(readFileSync(new URL(`../examples/${name}`, import.meta.url), 'utf8'));
}

function stableId(workflowId, taskId) {
  return createHash('sha256').update(`${workflowId}:${taskId}`).digest('hex').slice(0, 32);
}

if (!existsSync(schedulerPkg)) {
  describe('integration-scheduler (skipped)', { skip: 'openclaw-scheduler not found at ' + SCHEDULER_PATH }, () => {
    it('placeholder', () => {});
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
      assert.ok(caps.scheduler_version, 'capabilities should include scheduler_version');
      assert.equal(caps.handoff_version, '2', 'scheduler should report handoff_version 2');
      assert.equal(caps.features.trust_evaluation, true, 'trust_evaluation should be true');
      assert.equal(caps.features.authorization_hook, true, 'authorization_hook should be true');
    });

    it('apply sends v0.2 fields when scheduler supports handoff v2', async () => {
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
      assert.equal(result.handoff.field_version, '2', 'field_version should be 2');
    });

    it('v0.2 identity fields are stored in scheduler', async () => {
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

    it('apply response includes capability negotiation metadata', async () => {
      const manifest = readExample('hello-world.json');
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
        result.handoff.field_version === '1' || result.handoff.field_version === '2',
        `field_version should be '1' or '2', got '${result.handoff.field_version}'`
      );
      assert.equal(typeof result.handoff.projected_fields, 'number', 'projected_fields should be a number');
      assert.ok(result.handoff.projected_fields > 0, 'projected_fields should be positive');
    });
  });
}
