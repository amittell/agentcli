import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, appendFileSync, existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  grantApproval,
  listApprovals,
  findValidApproval,
  consumeApproval,
  revokeApproval,
  computeTaskApprovalHash,
  approvalPolicyRequiresApproval,
  approvalPolicyAutoRejects,
  verifyApprovalSignature,
} from '../src/approvals.js';
import { executeTask } from '../src/exec.js';
import { readAuditLog } from '../src/audit.js';
import { getAgentcliPaths } from '../src/home.js';

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

test('grant writes a pending approval; list + find work', () => {
  const { env, cleanup } = isolatedEnv();
  try {
    const m = makeManifest({ approval: { policy: 'manual', risk_level: 'high' } });
    const task = m.workflows[0].tasks[0];
    const taskHash = computeTaskApprovalHash({ workflowId: 'test-wf', task });

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
  } finally {
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

test('ssh-signed grant: round-trip with allowed_signers auto-bootstrap', async (t) => {
  // End-to-end: approve with signer=ssh on a fresh AGENTCLI_HOME (no
  // allowed_signers file yet), then exec and confirm the auto-bootstrap kicks
  // in and signature_verified is true. If the test host has no SSH key
  // available, skip gracefully.
  const { existsSync: fsExists } = await import('node:fs');
  const { homedir } = await import('node:os');
  const sshCandidates = ['id_ed25519', 'id_ecdsa', 'id_rsa']
    .map(k => join(homedir(), '.ssh', k))
    .filter(p => fsExists(p) && fsExists(`${p}.pub`));
  if (sshCandidates.length === 0) {
    t.skip('no local SSH key pair found; skipping signed round-trip');
    return;
  }

  const home = mkdtempSync(join(tmpdir(), 'agentcli-approval-signed-'));
  const env = { ...process.env, AGENTCLI_HOME: home };
  delete env.AGENTCLI_SIGNER; // use default (ssh)
  try {
    const m = makeManifest({ approval: { policy: 'manual', risk_level: 'high' } });
    const rec = grantApproval({
      manifest: m,
      taskId: 'echo-task',
      approver: 'alice',
      signer: 'ssh',
      env,
    });
    assert.ok(rec.signature, 'grant should carry a signature');
    assert.equal(rec.signature.method, 'ssh-signature');

    // Pre-condition: allowed_signers file should NOT exist yet
    const paths = getAgentcliPaths({ env });
    assert.equal(existsSync(paths.allowed_signers), false, 'allowed_signers should not pre-exist');

    // Run the gated task; verifyApprovalSignature should auto-bootstrap
    // allowed_signers and verify cleanly.
    const result = await executeTask(m, { taskId: 'echo-task', env });
    assert.equal(result.ok, true);
    assert.ok(result.approval_used);
    assert.equal(result.approval_used.approval_id, rec.approval_id);
    assert.equal(result.approval_used.signature_verified, true);

    // Post-condition: allowed_signers was generated
    assert.equal(existsSync(paths.allowed_signers), true, 'allowed_signers should have been bootstrapped');
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
