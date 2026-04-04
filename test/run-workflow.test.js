import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { runCli, runWorkflow } from '../src/index.js';

function makeTempHome() {
  return mkdtempSync(join(tmpdir(), 'agentcli-run-'));
}

test('runWorkflow executes a shell DAG and evaluates trigger conditions', async () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'ops',
      name: 'Ops',
      tasks: [
        {
          id: 'collect',
          name: 'Collect',
          shell: { program: 'printf', args: ['ALERT\n'] },
          target: { session_target: 'shell' },
          schedule: { cron: '0 * * * *' },
          contract: { audit: 'none' },
        },
        {
          id: 'notify',
          name: 'Notify',
          shell: { program: 'echo', args: ['notify'] },
          target: { session_target: 'shell' },
          trigger: { parent: 'collect', on: 'success', condition: 'contains:ALERT' },
          contract: { audit: 'none' },
        },
        {
          id: 'no-match',
          name: 'No Match',
          shell: { program: 'echo', args: ['skip'] },
          target: { session_target: 'shell' },
          trigger: { parent: 'collect', on: 'success', condition: 'contains:NOPE' },
          contract: { audit: 'none' },
        },
      ],
    }],
  };

  const result = await runWorkflow(manifest, {
    rootTaskId: 'collect',
    signer: 'none',
  });

  assert.equal(result.ok, true);
  assert.equal(result.summary.total, 3);
  assert.equal(result.summary.succeeded, 2);
  assert.equal(result.summary.skipped, 1);
  assert.deepEqual(result.root_task_ids, ['collect']);

  const notify = result.tasks.find(task => task.source.task_id === 'notify');
  const skipped = result.tasks.find(task => task.source.task_id === 'no-match');
  assert.equal(notify.status, 'success');
  assert.equal(notify.trigger.matched, true);
  assert.equal(skipped.status, 'skipped');
  assert.match(skipped.reason, /did not match parent stdout/);
});

test('runWorkflow treats verify failures as failed parents and still runs failure children', async () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'verify-flow',
      name: 'Verify Flow',
      tasks: [
        {
          id: 'check',
          name: 'Check',
          shell: { program: 'echo', args: ['ok'] },
          target: { session_target: 'shell' },
          schedule: { cron: '0 * * * *' },
          verify: { shell: 'exit 1', on_failure: 'error' },
          contract: { audit: 'none' },
        },
        {
          id: 'diagnose',
          name: 'Diagnose',
          shell: { program: 'echo', args: ['diagnose'] },
          target: { session_target: 'shell' },
          trigger: { parent: 'check', on: 'failure' },
          contract: { audit: 'none' },
        },
      ],
    }],
  };

  const result = await runWorkflow(manifest, {
    rootTaskId: 'check',
    signer: 'none',
  });

  assert.equal(result.ok, false);
  const check = result.tasks.find(task => task.source.task_id === 'check');
  const diagnose = result.tasks.find(task => task.source.task_id === 'diagnose');
  assert.equal(check.status, 'failed');
  assert.equal(check.error.code, 'verify_failed');
  assert.equal(diagnose.status, 'success');
  assert.equal(diagnose.trigger.parent_outcome, 'failure');
});

test('runWorkflow dry-run returns a static plan for the selected shell DAG', async () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'plan-flow',
      name: 'Plan Flow',
      tasks: [
        {
          id: 'root',
          name: 'Root',
          shell: { program: 'echo', args: ['root'] },
          target: { session_target: 'shell' },
          schedule: { cron: '0 * * * *' },
        },
        {
          id: 'child',
          name: 'Child',
          shell: { program: 'echo', args: ['child'] },
          target: { session_target: 'shell' },
          trigger: { parent: 'root', on: 'success', condition: 'contains:root' },
        },
      ],
    }],
  };

  const result = await runWorkflow(manifest, {
    rootTaskId: 'root',
    dryRun: true,
  });

  assert.equal(result.ok, true);
  assert.equal(result.dry_run, true);
  assert.equal(result.summary.planned, 2);
  assert(result.tasks.every(task => task.status === 'planned'));
  assert.equal(result.tasks[1].trigger.matched, null);
});

test('runWorkflow rejects selected graphs that include non-shell tasks', async () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'mixed',
      name: 'Mixed',
      tasks: [
        {
          id: 'root',
          name: 'Root',
          shell: { program: 'echo', args: ['root'] },
          target: { session_target: 'shell' },
          schedule: { cron: '0 * * * *' },
        },
        {
          id: 'prompt-child',
          name: 'Prompt Child',
          prompt: 'Summarize the root output.',
          target: { session_target: 'isolated' },
          trigger: { parent: 'root', on: 'success' },
        },
      ],
    }],
  };

  await assert.rejects(
    runWorkflow(manifest, { rootTaskId: 'root' }),
    /only supports shell tasks/
  );
});

test('cli run requires explicit root selection when a workflow has multiple roots', async () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'multi-root',
      name: 'Multi Root',
      tasks: [
        {
          id: 'first',
          name: 'First',
          shell: { program: 'echo', args: ['first'] },
          target: { session_target: 'shell' },
          schedule: { cron: '0 * * * *' },
        },
        {
          id: 'second',
          name: 'Second',
          shell: { program: 'echo', args: ['second'] },
          target: { session_target: 'shell' },
          schedule: { cron: '5 * * * *' },
        },
      ],
    }],
  };

  await assert.rejects(
    runCli(['run', JSON.stringify(manifest), '--dry-run']),
    /Multiple root tasks found/
  );
});

test('cli run --all-roots dry-run plans every selected root graph', async () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'multi-root',
      name: 'Multi Root',
      tasks: [
        {
          id: 'first',
          name: 'First',
          shell: { program: 'echo', args: ['first'] },
          target: { session_target: 'shell' },
          schedule: { cron: '0 * * * *' },
        },
        {
          id: 'second',
          name: 'Second',
          shell: { program: 'echo', args: ['second'] },
          target: { session_target: 'shell' },
          schedule: { cron: '5 * * * *' },
        },
      ],
    }],
  };

  const tempHome = makeTempHome();
  try {
    const output = JSON.parse(await runCli(
      ['run', JSON.stringify(manifest), '--all-roots', '--dry-run'],
      { env: { ...process.env, AGENTCLI_HOME: tempHome } }
    ));
    assert.equal(output.ok, true);
    assert.equal(output.dry_run, true);
    assert.deepEqual(output.root_task_ids, ['first', 'second']);
    assert.equal(output.summary.planned, 2);
  } finally {
    rmSync(tempHome, { recursive: true, force: true });
  }
});
