import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  applyManifestToScheduler,
  negotiateSchedulerFieldVersion,
  requiredSchedulerFieldVersion,
  schedulerCreateSpec,
} from '../src/apply.js';
import { validateManifestCapabilities } from '../src/capabilities.js';
import { compileManifestToScheduler } from '../src/compiler/openclaw-scheduler.js';
import { compileManifestToStandalone } from '../src/compiler/standalone.js';
import { compileManifestForDispatch } from '../src/runtime/openclaw-scheduler.js';
import { TARGETS } from '../src/targets.js';

function governedManifest({ approvalPolicy = 'manual', inlineSecrets = false } = {}) {
  return {
    version: '0.2',
    identity_profiles: [{
      id: 'operator',
      provider: 'none',
      provider_config: { client_secret: 'identity-secret' },
      subject: {
        kind: 'agent',
        principal: 'agent://tests/operator',
        attributes: { tenant_secret: 'tenant-secret' },
      },
      auth: {
        provider_config: { token: 'auth-secret' },
        inputs: { password: 'input-secret' },
      },
      presentation: { handoff: 'none', cleanup: 'always' },
    }],
    workflows: [{
      id: 'governed',
      name: 'Governed',
      identity: { ref: 'operator' },
      tasks: [{
        id: 'root',
        name: 'Root',
        target: { session_target: 'shell' },
        shell: {
          program: 'printf',
          args: ['{"ok":true}'],
          ...(inlineSecrets
            ? { env: { API_TOKEN: 'task-secret' }, stdin: 'stdin-secret' }
            : {}),
        },
        schedule: { cron: '0 * * * *' },
        approval: {
          policy: approvalPolicy,
          risk_level: 'high',
          approver_scope: 'domain:example.com',
        },
        output: { format: 'json' },
        contract: { sandbox: 'permissive', network: 'unrestricted', audit: 'always' },
      }],
    }],
  };
}

function schedulerRunner({ handoffVersion = '3', features = {} } = {}) {
  return {
    invocation: { label: 'mock-scheduler' },
    queryCapabilities() {
      return {
        scheduler_version: 'test',
        handoff_version: handoffVersion,
        features: {
          root_approval_gate: true,
          approval_scope_enforcement: true,
          structured_output_format: true,
          ...features,
        },
      };
    },
    listJobs() { return []; },
    addJob() { throw new Error('dry-run must not add jobs'); },
    updateJob() { throw new Error('dry-run must not update jobs'); },
    deleteJob() { throw new Error('dry-run must not delete jobs'); },
  };
}

test('scheduler compiler disables auto-reject jobs instead of dispatching them', () => {
  const compiled = compileManifestToScheduler(governedManifest({ approvalPolicy: 'auto-reject' }));
  assert.equal(compiled.jobs[0].enabled, 0);
});

test('standalone and scheduler artifacts do not persist raw execution or profile secrets', () => {
  const manifest = governedManifest();
  const standalone = JSON.stringify(compileManifestToStandalone(manifest));
  const scheduler = JSON.stringify(compileManifestToScheduler(manifest));
  for (const secret of [
    'identity-secret',
    'tenant-secret',
    'auth-secret',
    'input-secret',
  ]) {
    assert.equal(standalone.includes(secret), false, `standalone leaked ${secret}`);
    assert.equal(scheduler.includes(secret), false, `scheduler leaked ${secret}`);
  }
});

test('scheduler compiler refuses inline shell environment and stdin persistence', () => {
  const manifest = governedManifest({ inlineSecrets: true });
  assert.throws(
    () => compileManifestToScheduler(manifest),
    error => {
      const paths = error.validation?.errors?.map(item => item.path) || [];
      return paths.some(path => path.endsWith('.shell.env'))
        && paths.some(path => path.endsWith('.shell.stdin'));
    }
  );
});

test('scheduler verification runs in the shell task cwd with the runtime environment', {
  skip: process.platform === 'win32' ? 'scheduler shell handoff uses POSIX command rendering' : false,
}, () => {
  const root = mkdtempSync(join(tmpdir(), 'agentcli-scheduler-verify-'));
  const taskCwd = join(root, "work dir's");
  const dispatcherCwd = join(root, 'dispatcher');
  mkdirSync(taskCwd);
  mkdirSync(dispatcherCwd);

  try {
    const manifest = governedManifest();
    const task = manifest.workflows[0].tasks[0];
    task.approval = undefined;
    task.shell = {
      program: 'sh',
      args: ['-c', 'printf ready > marker.txt'],
      cwd: taskCwd,
    };
    task.verify = {
      shell: 'test "$VERIFY_RUNTIME_VALUE" = runtime && test -f marker.txt',
    };

    const job = compileManifestToScheduler(manifest).jobs[0];
    const env = { ...process.env, VERIFY_RUNTIME_VALUE: 'runtime' };
    const primary = spawnSync('/bin/sh', ['-c', job.payload_message], {
      cwd: dispatcherCwd,
      env,
      encoding: 'utf8',
    });
    const verify = spawnSync('/bin/sh', ['-c', job.verify_shell], {
      cwd: dispatcherCwd,
      env,
      encoding: 'utf8',
    });

    assert.equal(primary.status, 0, primary.stderr);
    assert.equal(verify.status, 0, verify.stderr);
    assert.match(job.verify_shell, /^cd /);
    assert.equal(job.verify_shell.includes('VERIFY_RUNTIME_VALUE=runtime'), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('scheduler compiler rejects a verifier whose cwd wrapper exceeds the runtime limit', () => {
  const manifest = governedManifest();
  const task = manifest.workflows[0].tasks[0];
  task.approval = undefined;
  task.shell = {
    program: 'true',
    cwd: '/tmp/a scheduler verification working directory',
  };
  task.verify = { shell: 'x'.repeat(99_999) };

  assert.throws(
    () => compileManifestToScheduler(manifest),
    error => error.validation?.errors?.some(item => (
      item.path.endsWith('.verify_shell')
      && item.message.includes('exceeds max length of 100000')
    )),
  );
});

test('scheduler capability validation rejects unenforceable root gates, scopes, and output formats', () => {
  const compiled = compileManifestToScheduler(governedManifest());
  const result = validateManifestCapabilities(compiled, {
    features: {
      root_approval_gate: false,
      approval_scope_enforcement: false,
      structured_output_format: false,
    },
  });
  assert.deepEqual(
    new Set(result.errors.map(error => error.feature)),
    new Set(['root_approval_gate', 'approval_scope_enforcement', 'structured_output_format'])
  );
});

test('handoff negotiation never silently drops fields required by a newer version', async () => {
  const jobs = compileManifestToScheduler(governedManifest()).jobs;
  assert.equal(requiredSchedulerFieldVersion(jobs), 3);
  assert.throws(
    () => negotiateSchedulerFieldVersion(jobs, '2'),
    error => error.code === 'unsupported_capability' && error.required_handoff_version === '3'
  );
  await assert.rejects(
    applyManifestToScheduler(governedManifest(), {
      dryRun: true,
      runner: schedulerRunner({ handoffVersion: '2' }),
    }),
    error => error.code === 'unsupported_capability'
  );

  const result = await applyManifestToScheduler(governedManifest(), {
    dryRun: true,
    runner: schedulerRunner({ handoffVersion: '3' }),
  });
  assert.equal(result.handoff.field_version, '3');
});

test('versioned scheduler projection includes governed v3 fields only at v3', () => {
  const job = compileManifestToScheduler(governedManifest()).jobs[0];
  const v2 = schedulerCreateSpec(job, { fieldVersion: '2' });
  const v3 = schedulerCreateSpec(job, { fieldVersion: '3' });
  assert.equal('approval_risk_level' in v2, false);
  assert.equal('approval_approver_scope' in v2, false);
  assert.equal('output_format' in v2, false);
  assert.equal(v3.approval_risk_level, 'high');
  assert.equal(v3.approval_approver_scope, 'domain:example.com');
  assert.equal(v3.output_format, 'json');
});

test('dispatch compilation reflects in-place manifest edits instead of returning stale cached output', () => {
  const manifest = governedManifest();
  const first = compileManifestForDispatch(manifest);
  manifest.workflows[0].tasks[0].shell.args = ['{"ok":false}'];
  const second = compileManifestForDispatch(manifest);
  assert.notEqual(first.jobs[0].payload_message, second.jobs[0].payload_message);
});

test('standalone compiler capabilities agree with target discovery', () => {
  const compiled = compileManifestToStandalone(governedManifest());
  for (const [feature, support] of Object.entries(TARGETS.standalone.features)) {
    assert.deepEqual(compiled.capabilities[feature], support, feature);
  }
});
