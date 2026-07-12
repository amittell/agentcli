import test from 'node:test';
import assert from 'node:assert/strict';
import { closeSync, constants as fsConstants, mkdtempSync, openSync, readFileSync, realpathSync, writeFileSync, appendFileSync, existsSync, rmSync, mkdirSync, statSync, symlinkSync, utimesSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Worker } from 'node:worker_threads';
import { spawnSync } from 'node:child_process';

import {
  grantApproval,
  listApprovals,
  findValidApproval,
  consumeApproval,
  revokeApproval,
  claimApproval,
  computeTaskApprovalHash,
  approvalPolicyRequiresApproval,
  approvalPolicyAutoRejects,
  verifyApprovalSignature,
} from '../src/approvals.js';
import { executeTask } from '../src/exec.js';
import { readAuditLog } from '../src/audit.js';
import { getAgentcliPaths } from '../src/home.js';
import {
  buildEffectiveExecutionBinding,
  canonicalExecutionBindingString,
} from '../src/compiler/shared.js';

function makeManifest({ approval, program = 'printf', args = ['ok'] } = {}) {
  return {
    version: '0.2',
    workflows: [
      {
        id: 'test-wf',
        name: 'Test workflow',
        contract: { sandbox: 'permissive', network: 'unrestricted', audit: 'always' },
        tasks: [
          {
            id: 'echo-task',
            name: 'Echo task',
            shell: { program, args },
            target: { session_target: 'shell' },
            output: { format: 'text' },
            schedule: { cron: '0 * * * *' },
            ...(approval ? { approval } : {}),
          },
        ],
      },
    ],
  };
}

function isolatedEnv() {
  const home = mkdtempSync(join(tmpdir(), 'agentcli-approval-'));
  return {
    home,
    env: {
      ...process.env,
      AGENTCLI_HOME: home,
      AGENTCLI_SIGNER: 'none',
    },
    cleanup() {
      rmSync(home, { recursive: true, force: true });
    },
  };
}

function createEphemeralSshKey(directory) {
  const keyPath = join(directory, 'approval-signing-key');
  const generated = spawnSync('ssh-keygen', [
    '-q', '-t', 'ed25519', '-N', '', '-f', keyPath,
  ], { encoding: 'utf8' });
  assert.equal(
    generated.status,
    0,
    `ssh-keygen failed: ${generated.stderr || generated.error?.message || 'unknown error'}`
  );
  return keyPath;
}

function trustEphemeralSshKey({ env, keyPath, principal }) {
  const paths = getAgentcliPaths({ env });
  mkdirSync(paths.state, { recursive: true });
  const publicKey = readFileSync(`${keyPath}.pub`, 'utf8').trim();
  writeFileSync(paths.allowed_signers, `${principal} ${publicKey}\n`, {
    encoding: 'utf8',
    mode: 0o600,
  });
  return paths;
}

test('policy predicates', () => {
  assert.equal(approvalPolicyRequiresApproval({ policy: 'manual' }), true);
  assert.equal(approvalPolicyRequiresApproval({ required: true }), true);
  assert.equal(approvalPolicyRequiresApproval({ policy: 'auto-approve' }), false);
  assert.equal(approvalPolicyRequiresApproval({ policy: 'auto-reject' }), false);
  assert.equal(approvalPolicyRequiresApproval(null), false);
  assert.equal(approvalPolicyAutoRejects({ policy: 'auto-reject' }), true);
  assert.equal(approvalPolicyAutoRejects({ policy: 'manual' }), false);
});

test('task hash is stable and binds shell+identity+risk', () => {
  const m = makeManifest({
    approval: { policy: 'manual', risk_level: 'high' },
  });
  const task = m.workflows[0].tasks[0];
  const h1 = computeTaskApprovalHash({ workflowId: 'test-wf', task });
  const h2 = computeTaskApprovalHash({ workflowId: 'test-wf', task });
  assert.equal(h1, h2);

  const task2 = { ...task, shell: { ...task.shell, args: ['different'] } };
  const h3 = computeTaskApprovalHash({ workflowId: 'test-wf', task: task2 });
  assert.notEqual(h1, h3);

  const task3 = { ...task, approval: { policy: 'manual', risk_level: 'low' } };
  const h4 = computeTaskApprovalHash({ workflowId: 'test-wf', task: task3 });
  assert.notEqual(h1, h4);
});

test('task hash binds effective cwd, operational environment, timeout, and instance without raw values', () => {
  const firstCwd = mkdtempSync(join(tmpdir(), 'agentcli-approval-cwd-a-'));
  const secondCwd = mkdtempSync(join(tmpdir(), 'agentcli-approval-cwd-b-'));
  try {
    const manifest = makeManifest({ approval: { policy: 'manual', risk_level: 'high' } });
    manifest.workflows[0].tasks[0].shell.cwd = '.';
    const workflow = manifest.workflows[0];
    const task = workflow.tasks[0];
    const envA = { PATH: '/approval/path-a', HOME: '/approval/home-a' };
    const envB = { PATH: '/approval/path-b', HOME: '/approval/home-a' };
    const base = {
      manifest,
      expanded: manifest,
      workflow,
      task,
      env: envA,
      cwd: firstCwd,
      timeoutMs: 1000,
      instanceId: 'instance-a',
    };
    const binding = buildEffectiveExecutionBinding(base);
    const serialized = canonicalExecutionBindingString(binding);

    assert.notEqual(computeTaskApprovalHash(base), computeTaskApprovalHash({ ...base, cwd: secondCwd }));
    assert.notEqual(computeTaskApprovalHash(base), computeTaskApprovalHash({ ...base, env: envB }));
    assert.notEqual(computeTaskApprovalHash(base), computeTaskApprovalHash({ ...base, timeoutMs: 2000 }));
    assert.notEqual(computeTaskApprovalHash(base), computeTaskApprovalHash({ ...base, instanceId: 'instance-b' }));
    assert.equal(serialized.includes('/approval/path-a'), false);
    assert.equal(serialized.includes('/approval/home-a'), false);
    assert.match(binding.command.env_hashes.PATH, /^sha256:[a-f0-9]{64}$/);
  } finally {
    rmSync(firstCwd, { recursive: true, force: true });
    rmSync(secondCwd, { recursive: true, force: true });
  }
});

test('exec refuses approvals minted for a different cwd, PATH, or timeout', async () => {
  const { env, cleanup } = isolatedEnv();
  const firstCwd = mkdtempSync(join(tmpdir(), 'agentcli-approval-exec-a-'));
  const secondCwd = mkdtempSync(join(tmpdir(), 'agentcli-approval-exec-b-'));
  try {
    const manifest = makeManifest({ approval: { policy: 'manual', risk_level: 'high' } });
    manifest.workflows[0].tasks[0].shell.cwd = '.';

    grantApproval({
      manifest,
      taskId: 'echo-task',
      approver: 'alice',
      cwd: firstCwd,
      env,
    });
    await assert.rejects(
      executeTask(manifest, { taskId: 'echo-task', cwd: secondCwd, env }),
      error => error.code === 'approval_required'
    );

    const pathA = { ...env, PATH: '/approval/path-a' };
    const pathB = { ...env, PATH: '/approval/path-b' };
    grantApproval({
      manifest,
      taskId: 'echo-task',
      approver: 'alice',
      cwd: firstCwd,
      env: pathA,
    });
    await assert.rejects(
      executeTask(manifest, { taskId: 'echo-task', cwd: firstCwd, env: pathB }),
      error => error.code === 'approval_required'
    );

    grantApproval({
      manifest,
      taskId: 'echo-task',
      approver: 'alice',
      cwd: firstCwd,
      timeoutMs: 1000,
      env,
    });
    await assert.rejects(
      executeTask(manifest, { taskId: 'echo-task', cwd: firstCwd, timeoutMs: 2000, env }),
      error => error.code === 'approval_required'
    );
  } finally {
    rmSync(firstCwd, { recursive: true, force: true });
    rmSync(secondCwd, { recursive: true, force: true });
    cleanup();
  }
});

test('exec refuses an approval after a symlinked cwd is retargeted', {
  skip: process.platform === 'win32',
}, async () => {
  const { env, cleanup } = isolatedEnv();
  const root = mkdtempSync(join(tmpdir(), 'agentcli-approval-cwd-link-'));
  const first = join(root, 'first');
  const second = join(root, 'second');
  const linked = join(root, 'current');
  try {
    mkdirSync(first);
    mkdirSync(second);
    symlinkSync(first, linked);
    const manifest = makeManifest({ approval: { policy: 'manual', risk_level: 'high' } });
    manifest.workflows[0].tasks[0].shell.cwd = '.';
    grantApproval({
      manifest,
      taskId: 'echo-task',
      approver: 'alice',
      cwd: linked,
      env,
    });
    rmSync(linked);
    symlinkSync(second, linked);
    await assert.rejects(
      executeTask(manifest, { taskId: 'echo-task', cwd: linked, env }),
      error => error.code === 'approval_required'
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
    cleanup();
  }
});

test('exec uses the same bound relative cwd after approval', async () => {
  const { env, cleanup } = isolatedEnv();
  const cwd = mkdtempSync(join(tmpdir(), 'agentcli-approval-bound-cwd-'));
  try {
    const manifest = makeManifest({
      approval: { policy: 'manual', risk_level: 'high' },
      program: process.execPath,
      args: ['-e', 'process.stdout.write(process.cwd())'],
    });
    manifest.workflows[0].tasks[0].shell.cwd = '.';
    grantApproval({
      manifest,
      taskId: 'echo-task',
      approver: 'alice',
      cwd,
      env,
    });
    const result = await executeTask(manifest, { taskId: 'echo-task', cwd, env });
    assert.equal(result.result.stdout, realpathSync(cwd));
  } finally {
    rmSync(cwd, { recursive: true, force: true });
    cleanup();
  }
});

test('grant writes a pending approval; list + find work', () => {
  const { env, cleanup } = isolatedEnv();
  try {
    const m = makeManifest({ approval: { policy: 'manual', risk_level: 'high' } });
    const taskHash = computeTaskApprovalHash({
      manifest: m,
      workflowId: 'test-wf',
      taskId: 'echo-task',
    });

    const rec = grantApproval({
      manifest: m,
      taskId: 'echo-task',
      approver: 'alice',
      reason: 'testing',
      env,
    });
    assert.ok(rec.approval_id);
    assert.equal(rec.approver, 'alice');
    assert.equal(rec.task_hash, taskHash);

    const list = listApprovals({ env });
    assert.equal(list.length, 1);
    assert.equal(list[0].status, 'pending');

    const found = findValidApproval({
      workflowId: 'test-wf',
      taskId: 'echo-task',
      taskHash,
      env,
    });
    assert.ok(found);
    assert.equal(found.approval_id, rec.approval_id);
    if (process.platform !== 'win32') {
      const paths = getAgentcliPaths({ env });
      assert.equal(statSync(paths.state).mode & 0o777, 0o700);
      assert.equal(statSync(paths.approvals).mode & 0o777, 0o600);
    }
  } finally {
    cleanup();
  }
});

test('approval writes refuse symbolic-link log destinations', { skip: process.platform === 'win32' }, () => {
  const { home, env, cleanup } = isolatedEnv();
  try {
    const paths = getAgentcliPaths({ env });
    mkdirSync(paths.state, { recursive: true });
    const target = join(home, 'outside-approvals.ndjson');
    writeFileSync(target, 'unchanged\n', 'utf8');
    symlinkSync(target, paths.approvals);
    const manifest = makeManifest({ approval: { policy: 'manual', risk_level: 'high' } });
    assert.throws(
      () => grantApproval({
        manifest,
        taskId: 'echo-task',
        approver: 'alice',
        signer: 'none',
        env,
      }),
      error => error.code === 'ELOOP' || error.code === 'EACCES'
    );
    assert.equal(readFileSync(target, 'utf8'), 'unchanged\n');
  } finally {
    cleanup();
  }
});

test('approval writes refuse FIFO log destinations without blocking', {
  skip: process.platform === 'win32',
}, () => {
  const { env, cleanup } = isolatedEnv();
  let reader;
  try {
    const paths = getAgentcliPaths({ env });
    mkdirSync(paths.state, { recursive: true });
    const created = spawnSync('mkfifo', [paths.approvals], { encoding: 'utf8' });
    assert.equal(created.status, 0, created.stderr || created.error?.message);
    reader = openSync(paths.approvals, fsConstants.O_RDONLY | fsConstants.O_NONBLOCK);
    const manifest = makeManifest({ approval: { policy: 'manual', risk_level: 'high' } });
    assert.throws(
      () => grantApproval({
        manifest,
        taskId: 'echo-task',
        approver: 'alice',
        signer: 'none',
        env,
      }),
      error => error.code === 'approval_log_invalid' && /non-regular file/.test(error.message)
    );
  } finally {
    if (reader !== undefined) closeSync(reader);
    cleanup();
  }
});

test('consume moves a grant out of pending', () => {
  const { env, cleanup } = isolatedEnv();
  try {
    const m = makeManifest({ approval: { policy: 'manual', risk_level: 'medium' } });
    const rec = grantApproval({
      manifest: m,
      taskId: 'echo-task',
      approver: 'alice',
      env,
    });
    consumeApproval({ approvalId: rec.approval_id, executionId: 'exec-xyz', env });
    const all = listApprovals({ env });
    assert.equal(all[0].status, 'consumed');
    assert.equal(all[0].consumed_by_execution_id, 'exec-xyz');

    const taskHash = rec.task_hash;
    const second = findValidApproval({
      workflowId: 'test-wf',
      taskId: 'echo-task',
      taskHash,
      env,
    });
    assert.equal(second, null);
  } finally {
    cleanup();
  }
});

test('expiry: grants past expires_at are not pending', () => {
  const { env, cleanup } = isolatedEnv();
  try {
    const m = makeManifest({ approval: { policy: 'manual', risk_level: 'low' } });
    const rec = grantApproval({
      manifest: m,
      taskId: 'echo-task',
      approver: 'alice',
      ttlS: 1,
      env,
      now: Date.now(),
    });
    const taskHash = rec.task_hash;

    // Search at a "future" time past expiry
    const future = Date.parse(rec.expires_at) + 1000;
    const found = findValidApproval({
      workflowId: 'test-wf',
      taskId: 'echo-task',
      taskHash,
      env,
      now: future,
    });
    assert.equal(found, null);

    const list = listApprovals({ env });
    // listApprovals uses real Date.now; set a very short TTL to ensure expiry
    // is reflected. If the test runs faster than 1s the status may still
    // register as pending, which is fine -- the above future-dated check is
    // the authoritative one.
    assert.ok(list[0].status === 'expired' || list[0].status === 'pending');
  } finally {
    cleanup();
  }
});

test('revoke moves grant out of pending', () => {
  const { env, cleanup } = isolatedEnv();
  try {
    const m = makeManifest({ approval: { policy: 'manual', risk_level: 'high' } });
    const rec = grantApproval({
      manifest: m,
      taskId: 'echo-task',
      approver: 'alice',
      env,
    });
    revokeApproval({ approvalId: rec.approval_id, revokedBy: 'bob', env });
    const list = listApprovals({ env });
    assert.equal(list[0].status, 'revoked');
    assert.equal(list[0].revoked_by, 'bob');

    const found = findValidApproval({
      workflowId: 'test-wf',
      taskId: 'echo-task',
      taskHash: rec.task_hash,
      env,
    });
    assert.equal(found, null);
  } finally {
    cleanup();
  }
});

test('grant refuses task with no approval policy', () => {
  const { env, cleanup } = isolatedEnv();
  try {
    const m = makeManifest(); // no approval
    assert.throws(
      () => grantApproval({ manifest: m, taskId: 'echo-task', approver: 'alice', env }),
      /no approval policy/
    );
  } finally {
    cleanup();
  }
});

test('grant refuses auto-reject policy', () => {
  const { env, cleanup } = isolatedEnv();
  try {
    const m = makeManifest({ approval: { policy: 'auto-reject', risk_level: 'high' } });
    assert.throws(
      () => grantApproval({ manifest: m, taskId: 'echo-task', approver: 'alice', env }),
      /auto-reject/
    );
  } finally {
    cleanup();
  }
});

test('exec: gated task without approval is refused', async () => {
  const { env, cleanup } = isolatedEnv();
  try {
    const m = makeManifest({ approval: { policy: 'manual', risk_level: 'high' } });
    await assert.rejects(
      () => executeTask(m, { taskId: 'echo-task', env }),
      err => err.code === 'approval_required'
    );
  } finally {
    cleanup();
  }
});

test('exec: auto-reject policy refuses even with an approval record', async () => {
  const { env, cleanup } = isolatedEnv();
  try {
    // auto-reject: grantApproval refuses to mint a grant, so just prove exec refuses
    const m = makeManifest({ approval: { policy: 'auto-reject', risk_level: 'high' } });
    await assert.rejects(
      () => executeTask(m, { taskId: 'echo-task', env }),
      err => err.code === 'approval_auto_rejected'
    );
  } finally {
    cleanup();
  }
});

test('exec: dry-run of gated task bypasses approval gate', async () => {
  const { env, cleanup } = isolatedEnv();
  try {
    const m = makeManifest({ approval: { policy: 'manual', risk_level: 'high' } });
    const result = await executeTask(m, { taskId: 'echo-task', dryRun: true, env });
    assert.equal(result.ok, true);
    assert.equal(result.dry_run, true);
    // No approvals should have been consumed
    const list = listApprovals({ env });
    assert.equal(list.length, 0);
  } finally {
    cleanup();
  }
});

test('exec: valid approval permits single execution then consumes it', async () => {
  const { env, cleanup } = isolatedEnv();
  try {
    const m = makeManifest({ approval: { policy: 'manual', risk_level: 'medium' } });
    const rec = grantApproval({
      manifest: m,
      taskId: 'echo-task',
      approver: 'alice',
      reason: 'test run',
      env,
    });

    const result = await executeTask(m, { taskId: 'echo-task', env });
    assert.equal(result.ok, true);
    assert.ok(result.approval_used);
    assert.equal(result.approval_used.approval_id, rec.approval_id);
    assert.equal(result.approval_used.approver, 'alice');

    // Second call should now be refused (approval consumed)
    await assert.rejects(
      () => executeTask(m, { taskId: 'echo-task', env }),
      err => err.code === 'approval_required'
    );

    // Audit record includes approval_used
    const paths = getAgentcliPaths({ env });
    const audit = readAuditLog({ auditPath: paths.audit });
    const liveRecords = audit.filter(r => r.dry_run === false);
    assert.ok(liveRecords.length >= 1);
    const last = liveRecords[liveRecords.length - 1];
    assert.equal(last.approval_used.approval_id, rec.approval_id);
    assert.equal(last.approval_used.approver, 'alice');
  } finally {
    cleanup();
  }
});

test('exec: approval is scoped to the exact task hash (manifest drift refused)', async () => {
  const { env, cleanup } = isolatedEnv();
  try {
    // Grant for the original manifest
    const original = makeManifest({ approval: { policy: 'manual', risk_level: 'medium' } });
    grantApproval({ manifest: original, taskId: 'echo-task', approver: 'alice', env });

    // Now try to execute a DIFFERENT command under the same workflow/task id
    const tampered = makeManifest({
      approval: { policy: 'manual', risk_level: 'medium' },
      program: 'printf',
      args: ['tampered'],
    });
    await assert.rejects(
      () => executeTask(tampered, { taskId: 'echo-task', env }),
      err => err.code === 'approval_required'
    );

    // The original grant is still pending (never consumed by the mismatched exec)
    const list = listApprovals({ env });
    assert.equal(list[0].status, 'pending');
  } finally {
    cleanup();
  }
});

test('exec: --approval-id targets a specific grant', async () => {
  const { env, cleanup } = isolatedEnv();
  try {
    const m = makeManifest({ approval: { policy: 'manual', risk_level: 'medium' } });
    // Grant two approvals for the same task
    const a = grantApproval({ manifest: m, taskId: 'echo-task', approver: 'alice', env });
    const b = grantApproval({ manifest: m, taskId: 'echo-task', approver: 'bob', env });

    const result = await executeTask(m, {
      taskId: 'echo-task',
      approvalId: b.approval_id,
      env,
    });
    assert.equal(result.approval_used.approval_id, b.approval_id);
    assert.equal(result.approval_used.approver, 'bob');

    const list = listApprovals({ env });
    const aRec = list.find(r => r.approval_id === a.approval_id);
    const bRec = list.find(r => r.approval_id === b.approval_id);
    assert.equal(aRec.status, 'pending');
    assert.equal(bRec.status, 'consumed');
  } finally {
    cleanup();
  }
});

test('exec: bad --approval-id does not fall back to other grants', async () => {
  const { env, cleanup } = isolatedEnv();
  try {
    const m = makeManifest({ approval: { policy: 'manual', risk_level: 'medium' } });
    grantApproval({ manifest: m, taskId: 'echo-task', approver: 'alice', env });

    await assert.rejects(
      () => executeTask(m, { taskId: 'echo-task', approvalId: 'does-not-exist', env }),
      err => err.code === 'approval_required'
    );
  } finally {
    cleanup();
  }
});

test('exec: non-gated task runs without any approval', async () => {
  const { env, cleanup } = isolatedEnv();
  try {
    const m = makeManifest(); // no approval at all
    const result = await executeTask(m, { taskId: 'echo-task', env });
    assert.equal(result.ok, true);
    assert.equal(result.approval_used, null);
  } finally {
    cleanup();
  }
});

test('exec: auto-approve policy bypasses approval gate', async () => {
  const { env, cleanup } = isolatedEnv();
  try {
    const m = makeManifest({ approval: { policy: 'auto-approve', risk_level: 'low' } });
    const result = await executeTask(m, { taskId: 'echo-task', env });
    assert.equal(result.ok, true);
    assert.equal(result.approval_used, null);
  } finally {
    cleanup();
  }
});

test('exec: revoked approval is refused', async () => {
  const { env, cleanup } = isolatedEnv();
  try {
    const m = makeManifest({ approval: { policy: 'manual', risk_level: 'high' } });
    const rec = grantApproval({ manifest: m, taskId: 'echo-task', approver: 'alice', env });
    revokeApproval({ approvalId: rec.approval_id, revokedBy: 'bob', env });

    await assert.rejects(
      () => executeTask(m, { taskId: 'echo-task', env }),
      err => err.code === 'approval_required'
    );
  } finally {
    cleanup();
  }
});

test('verifyApprovalSignature returns unsigned for signer=none grants', () => {
  const { env, cleanup } = isolatedEnv();
  try {
    const m = makeManifest({ approval: { policy: 'manual', risk_level: 'high' } });
    const rec = grantApproval({
      manifest: m,
      taskId: 'echo-task',
      approver: 'alice',
      signer: 'none',
      env,
    });
    // With signer=none the grant has no signature
    assert.equal(rec.signature, null);
    const raw = JSON.parse(
      readFileSync(getAgentcliPaths({ env }).approvals, 'utf8').trim().split('\n')[0]
    );
    const check = verifyApprovalSignature(raw, { env });
    assert.equal(check.verified, null); // "unsigned"
  } finally {
    cleanup();
  }
});

test('unexpected unsigned approval records are rejected', () => {
  const check = verifyApprovalSignature({
    approval_id: 'unsigned',
    workflow_id: 'test-wf',
    task_id: 'echo-task',
    task_hash: 'sha256:deadbeef',
    approver: 'alice',
    granted_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 1000).toISOString(),
    signature: null,
  });
  assert.equal(check.verified, false);
  assert.match(check.reason, /unexpectedly unsigned/);
});

test('approval signing failure does not silently write an unsigned grant', () => {
  const { env, cleanup } = isolatedEnv();
  try {
    delete env.AGENTCLI_SIGNER;
    const m = makeManifest({ approval: { policy: 'manual', risk_level: 'high' } });
    assert.throws(
      () => grantApproval({
        manifest: m,
        taskId: 'echo-task',
        approver: 'alice',
        signer: 'ssh',
        signingKey: '/definitely/missing/agentcli-key',
        env,
      }),
      error => error.code === 'approval_signature_invalid'
    );
    assert.deepEqual(listApprovals({ env }), []);
  } finally {
    cleanup();
  }
});

test('approver scope and manifest timeout are enforced when granting', () => {
  const { env, cleanup } = isolatedEnv();
  try {
    const m = makeManifest({
      approval: {
        policy: 'manual',
        risk_level: 'high',
        approver_scope: 'domain:example.com',
        timeout_s: 30,
      },
    });
    assert.throws(
      () => grantApproval({ manifest: m, taskId: 'echo-task', approver: 'alice@other.test', env }),
      error => error.code === 'approval_scope_mismatch'
    );
    assert.throws(
      () => grantApproval({
        manifest: m,
        taskId: 'echo-task',
        approver: 'alice@example.com',
        ttlS: 31,
        env,
      }),
      error => error.code === 'invalid_argument'
    );
    const rec = grantApproval({
      manifest: m,
      taskId: 'echo-task',
      approver: 'alice@example.com',
      env,
      now: 1_000,
    });
    assert.equal(rec.approver_scope, 'domain:example.com');
    assert.equal(Date.parse(rec.expires_at) - Date.parse(rec.granted_at), 30_000);
  } finally {
    cleanup();
  }
});

test('corrupted approvals.ndjson does not DoS subsequent exec', async () => {
  const { env, cleanup } = isolatedEnv();
  try {
    const m = makeManifest({ approval: { policy: 'manual', risk_level: 'medium' } });
    // Grant a real approval
    const rec = grantApproval({
      manifest: m,
      taskId: 'echo-task',
      approver: 'alice',
      env,
    });
    // Inject a garbage line between the grant and any future events.
    // Simulates a partial write from a crashed process.
    const paths = getAgentcliPaths({ env });
    appendFileSync(paths.approvals, '{"kind":"grant","approval_id":"trunca', 'utf8');

    // listApprovals and findValidApproval must still work
    const list = listApprovals({ env });
    assert.equal(list.length, 1);
    assert.equal(list[0].approval_id, rec.approval_id);

    // And exec must still find the grant and run
    const result = await executeTask(m, { taskId: 'echo-task', env });
    assert.equal(result.ok, true);
    assert.equal(result.approval_used.approval_id, rec.approval_id);
  } finally {
    cleanup();
  }
});

test('ssh-signed grant round-trips with an isolated explicit trust store', async () => {
  // End-to-end: approve with signer=ssh, trust the generated public key, then
  // execute and verify without reading a developer's personal SSH identity.

  const home = mkdtempSync(join(tmpdir(), 'agentcli-approval-signed-'));
  const env = { ...process.env, AGENTCLI_HOME: home };
  delete env.AGENTCLI_SIGNER; // use default (ssh)
  try {
    const signingKey = createEphemeralSshKey(home);
    const m = makeManifest({ approval: { policy: 'manual', risk_level: 'high' } });
    const rec = grantApproval({
      manifest: m,
      taskId: 'echo-task',
      approver: 'alice',
      signer: 'ssh',
      signingKey,
      env,
    });
    assert.ok(rec.signature, 'grant should carry a signature');
    assert.equal(rec.signature.method, 'ssh-signature');

    const paths = trustEphemeralSshKey({ env, keyPath: signingKey, principal: 'alice' });
    assert.equal(existsSync(paths.allowed_signers), true);

    const result = await executeTask(m, { taskId: 'echo-task', env });
    assert.equal(result.ok, true);
    assert.ok(result.approval_used);
    assert.equal(result.approval_used.approval_id, rec.approval_id);
    assert.equal(result.approval_used.signature_verified, true);

    if (process.platform !== 'win32') {
      assert.equal(statSync(paths.allowed_signers).mode & 0o777, 0o600);
    }
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

// --- Concurrency: claimApproval is atomic across workers ---

const CLAIM_WORKER_SOURCE = `
import { parentPort, workerData } from 'node:worker_threads';
import { claimApproval } from '${new URL('../src/approvals.js', import.meta.url).href}';

const { workflowId, taskId, taskHash, env, executionId, approvalId } = workerData;
try {
  const grant = claimApproval({
    workflowId, taskId, taskHash,
    approvalId: approvalId || undefined,
    executionId,
    env,
  });
  parentPort.postMessage({ ok: true, grant });
} catch (err) {
  parentPort.postMessage({ ok: false, error: err.message, code: err.code });
}
`;

function runClaimWorker({ workflowId, taskId, taskHash, env, executionId, approvalId }) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(CLAIM_WORKER_SOURCE, {
      eval: true,
      workerData: { workflowId, taskId, taskHash, env, executionId, approvalId },
    });
    worker.once('message', resolve);
    worker.once('error', reject);
  });
}

test('concurrency: N parallel claims on one grant serialize to exactly one winner', async () => {
  const { env, cleanup } = isolatedEnv();
  try {
    const m = makeManifest({ approval: { policy: 'manual', risk_level: 'medium' } });
    const taskHash = computeTaskApprovalHash({
      manifest: m,
      workflowId: 'test-wf',
      taskId: 'echo-task',
    });
    const rec = grantApproval({
      manifest: m,
      taskId: 'echo-task',
      approver: 'alice',
      env,
    });

    const N = 8;
    const workerArgs = Array.from({ length: N }, (_, i) => ({
      workflowId: 'test-wf',
      taskId: 'echo-task',
      taskHash,
      env,
      executionId: `exec-${i}`,
      approvalId: rec.approval_id,
    }));
    const results = await Promise.all(workerArgs.map(runClaimWorker));

    const winners = results.filter(r => r.ok && r.grant);
    const empties = results.filter(r => r.ok && !r.grant);
    const errors = results.filter(r => !r.ok);

    assert.equal(winners.length, 1, `expected exactly one winner, got ${winners.length}`);
    assert.equal(empties.length, N - 1, 'losers should receive null, not errors');
    assert.equal(errors.length, 0, `no worker should error: ${JSON.stringify(errors)}`);
    assert.equal(winners[0].grant.approval_id, rec.approval_id);

    // Only one consume event was written
    const list = listApprovals({ env });
    assert.equal(list.length, 1);
    assert.equal(list[0].status, 'consumed');
  } finally {
    cleanup();
  }
});

test('concurrency: two pending grants + two concurrent claims → both succeed with distinct grants', async () => {
  const { env, cleanup } = isolatedEnv();
  try {
    const m = makeManifest({ approval: { policy: 'manual', risk_level: 'medium' } });
    const taskHash = computeTaskApprovalHash({
      manifest: m,
      workflowId: 'test-wf',
      taskId: 'echo-task',
    });
    const a = grantApproval({ manifest: m, taskId: 'echo-task', approver: 'alice', env });
    const b = grantApproval({ manifest: m, taskId: 'echo-task', approver: 'bob', env });

    const workerArgs = [
      { workflowId: 'test-wf', taskId: 'echo-task', taskHash, env, executionId: 'exec-1' },
      { workflowId: 'test-wf', taskId: 'echo-task', taskHash, env, executionId: 'exec-2' },
    ];
    const results = await Promise.all(workerArgs.map(runClaimWorker));
    const winners = results.filter(r => r.ok && r.grant);
    assert.equal(winners.length, 2, 'both claims should succeed because two grants exist');
    const ids = new Set(winners.map(w => w.grant.approval_id));
    assert.equal(ids.size, 2, 'winners should hold distinct grants');
    assert.ok(ids.has(a.approval_id));
    assert.ok(ids.has(b.approval_id));
  } finally {
    cleanup();
  }
});

test('concurrency: stale lock is broken and claim proceeds', () => {
  const { env, cleanup } = isolatedEnv();
  try {
    const m = makeManifest({ approval: { policy: 'manual', risk_level: 'low' } });
    const rec = grantApproval({ manifest: m, taskId: 'echo-task', approver: 'alice', env });
    const taskHash = rec.task_hash;

    // Plant a lock file dated far in the past to simulate a crashed holder.
    const paths = getAgentcliPaths({ env });
    const lockPath = `${paths.approvals}.lock`;
    mkdirSync(paths.state, { recursive: true });
    writeFileSync(lockPath, 'stale pid\n', 'utf8');
    const hourAgo = (Date.now() - 60 * 60 * 1000) / 1000;
    utimesSync(lockPath, hourAgo, hourAgo);

    // Claim should detect staleness, break the lock, and succeed.
    const grant = claimApproval({
      workflowId: 'test-wf',
      taskId: 'echo-task',
      taskHash,
      executionId: 'exec-stale',
      env,
    });
    assert.ok(grant, 'claim should succeed after breaking stale lock');
    assert.equal(grant.approval_id, rec.approval_id);

    // Lock file cleaned up after claim
    assert.equal(existsSync(lockPath), false);
  } finally {
    cleanup();
  }
});

test('tamper: edit to approver/reason/expires_at in ndjson fails verification', async () => {
  const home = mkdtempSync(join(tmpdir(), 'agentcli-approval-tamper-'));
  const env = { ...process.env, AGENTCLI_HOME: home };
  delete env.AGENTCLI_SIGNER;
  try {
    const signingKey = createEphemeralSshKey(home);
    const m = makeManifest({ approval: { policy: 'manual', risk_level: 'high' } });
    const rec = grantApproval({
      manifest: m,
      taskId: 'echo-task',
      approver: 'alice',
      reason: 'original reason',
      signer: 'ssh',
      signingKey,
      env,
    });
    assert.ok(rec.signature, 'grant should be signed');

    const paths = trustEphemeralSshKey({ env, keyPath: signingKey, principal: 'alice' });
    const raw = readFileSync(paths.approvals, 'utf8').trim().split('\n');
    const grantEvent = JSON.parse(raw[0]);

    // 1. Unmodified grant: verifies cleanly (also exercises bootstrap)
    const clean = verifyApprovalSignature(grantEvent, { env });
    assert.equal(clean.verified, true, `clean grant should verify, got: ${clean.reason}`);

    // 2. Tamper with approver field: should fail with tamper reason
    const tampered = { ...grantEvent, approver: 'mallory' };
    const bad = verifyApprovalSignature(tampered, { env });
    assert.equal(bad.verified, false);
    assert.match(bad.reason || '', /tamper|signed payload/i);

    // 3. Tamper with reason field: should also fail
    const tamperedReason = { ...grantEvent, reason: 'escalated privileges' };
    const bad2 = verifyApprovalSignature(tamperedReason, { env });
    assert.equal(bad2.verified, false);

    // 4. Tamper with expires_at: should fail (could be used to extend a grant)
    const tamperedExpiry = {
      ...grantEvent,
      expires_at: new Date(Date.now() + 10 * 365 * 24 * 3600 * 1000).toISOString(),
    };
    const bad3 = verifyApprovalSignature(tamperedExpiry, { env });
    assert.equal(bad3.verified, false);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('multi-workflow manifest: grantApproval requires --workflow disambiguation', () => {
  const { env, cleanup } = isolatedEnv();
  try {
    const multi = {
      version: '0.2',
      workflows: [
        {
          id: 'wf-a',
          name: 'Workflow A',
          contract: { sandbox: 'permissive', network: 'unrestricted', audit: 'always' },
          tasks: [
            {
              id: 'task-x',
              name: 'Task X',
              shell: { program: 'printf', args: ['a'] },
              target: { session_target: 'shell' },
              output: { format: 'text' },
              schedule: { cron: '0 * * * *' },
              approval: { policy: 'manual', risk_level: 'medium' },
            },
          ],
        },
        {
          id: 'wf-b',
          name: 'Workflow B',
          contract: { sandbox: 'permissive', network: 'unrestricted', audit: 'always' },
          tasks: [
            {
              id: 'task-x',
              name: 'Task X in B',
              shell: { program: 'printf', args: ['b'] },
              target: { session_target: 'shell' },
              output: { format: 'text' },
              schedule: { cron: '0 * * * *' },
              approval: { policy: 'manual', risk_level: 'medium' },
            },
          ],
        },
      ],
    };

    // No --workflow with multiple workflows → throws
    assert.throws(
      () => grantApproval({ manifest: multi, taskId: 'task-x', approver: 'alice', env }),
      /multiple workflows|--workflow/
    );

    // --workflow=nonexistent → throws
    assert.throws(
      () => grantApproval({ manifest: multi, workflowId: 'wf-ghost', taskId: 'task-x', approver: 'alice', env }),
      /not found/
    );

    // --workflow=wf-a → works, grant scoped to wf-a
    const recA = grantApproval({ manifest: multi, workflowId: 'wf-a', taskId: 'task-x', approver: 'alice', env });
    assert.equal(recA.workflow_id, 'wf-a');

    // --workflow=wf-b → works, distinct grant for same task-id in different workflow
    const recB = grantApproval({ manifest: multi, workflowId: 'wf-b', taskId: 'task-x', approver: 'alice', env });
    assert.equal(recB.workflow_id, 'wf-b');
    assert.notEqual(recA.approval_id, recB.approval_id);
    assert.notEqual(recA.task_hash, recB.task_hash, 'different workflows → different task hashes');

    // Grant for wf-a does not satisfy wf-b: findValidApproval on wf-b sees only recB
    const foundB = findValidApproval({
      workflowId: 'wf-b',
      taskId: 'task-x',
      taskHash: recB.task_hash,
      env,
    });
    assert.equal(foundB.approval_id, recB.approval_id);
  } finally {
    cleanup();
  }
});

test('concurrency: lock held past timeout throws approval_lock_timeout', () => {
  const { env, cleanup } = isolatedEnv();
  try {
    const m = makeManifest({ approval: { policy: 'manual', risk_level: 'low' } });
    const rec = grantApproval({ manifest: m, taskId: 'echo-task', approver: 'alice', env });

    // Plant a fresh lock file so the claim cannot acquire it.
    const paths = getAgentcliPaths({ env });
    const lockPath = `${paths.approvals}.lock`;
    mkdirSync(paths.state, { recursive: true });
    writeFileSync(lockPath, 'another pid\n', 'utf8');
    // Leave mtime fresh (now) so staleness check doesn't fire.

    assert.throws(
      () => claimApproval({
        workflowId: 'test-wf',
        taskId: 'echo-task',
        taskHash: rec.task_hash,
        executionId: 'exec-blocked',
        env,
        lockOptions: { timeoutMs: 100, staleMs: 60000, pollMs: 20 },
      }),
      err => err.code === 'approval_lock_timeout'
    );

    // Clean up the planted lock
    rmSync(lockPath, { force: true });
  } finally {
    cleanup();
  }
});
