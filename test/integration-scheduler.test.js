import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';

import { applyManifestToScheduler } from '../src/apply.js';

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
  });
}
