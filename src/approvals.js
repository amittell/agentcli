import {
  closeSync, constants as fsConstants, existsSync, fchmodSync, lstatSync,
  openSync, readFileSync, statSync, unlinkSync, writeSync,
} from 'node:fs';
import { dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import { getProvider, resolveProvider } from './signing/index.js';
import { resolveAllowedSigners, generateAllowedSigners } from './signing/ssh.js';
import {
  assertRegularFileDescriptor,
  ensurePrivateDirectory,
  getAgentcliPaths,
} from './home.js';
import { canonicalStringify } from './canonical.js';
import {
  buildEffectiveExecutionBinding,
  computeEffectiveTaskHash,
} from './compiler/shared.js';
import { expandManifestShorthands } from './shorthand.js';

// Concurrency: `claimApproval` is the atomic public primitive that
// enforceApprovalGate uses. It acquires an fs-lock on <approvals>.lock
// (openSync 'wx'), re-reads the log inside the critical section, finds a
// matching pending grant, appends a consume event, and releases the lock.
// Concurrent claims of the same grant serialize to exactly one winner;
// losers re-read and either find a different pending grant or throw
// approval_required. Locks older than LOCK_STALE_MS are treated as
// abandoned (crashed holder) and removed.

const APPROVAL_RECORD_VERSION = 2;
const DEFAULT_TTL_S = 3600;
const LOCK_SUFFIX = '.lock';
const LOCK_TIMEOUT_MS = 5000;
const LOCK_STALE_MS = 30000;
const LOCK_POLL_MS = 25;

// Shared memory used for sync sleep during lock backoff. Allocated once per
// process rather than per-retry.
const LOCK_SLEEP_BUF = new Int32Array(new SharedArrayBuffer(4));

function sleepSync(ms) {
  Atomics.wait(LOCK_SLEEP_BUF, 0, 0, ms);
}

function withApprovalsLock(approvalsPath, fn, {
  timeoutMs = LOCK_TIMEOUT_MS,
  staleMs = LOCK_STALE_MS,
  pollMs = LOCK_POLL_MS,
  now = () => Date.now(),
} = {}) {
  const stateDirectory = dirname(approvalsPath);
  ensurePrivateDirectory(stateDirectory);
  const lockPath = `${approvalsPath}${LOCK_SUFFIX}`;
  const deadline = now() + timeoutMs;
  let fd;
  while (true) {
    try {
      fd = openSync(
        lockPath,
        fsConstants.O_WRONLY |
          fsConstants.O_CREAT |
          fsConstants.O_EXCL |
          (fsConstants.O_NOFOLLOW || 0),
        0o600
      );
      writeSync(fd, `${process.pid}\n`);
      break;
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
      // Lock held. Check staleness and potentially break it.
      try {
        const st = statSync(lockPath);
        if (now() - st.mtimeMs > staleMs) {
          try { unlinkSync(lockPath); } catch { /* someone else cleaned up */ }
          continue;
        }
      } catch {
        // Lock vanished between EEXIST and stat; retry immediately.
        continue;
      }
      if (now() >= deadline) {
        throw Object.assign(
          new Error(`Timed out acquiring approvals lock at ${lockPath} after ${timeoutMs}ms`),
          { code: 'approval_lock_timeout' }
        );
      }
      sleepSync(pollMs);
    }
  }
  try {
    closeSync(fd);
    return fn();
  } finally {
    try { unlinkSync(lockPath); } catch { /* already removed */ }
  }
}

export function approvalPolicyRequiresApproval(approval) {
  if (!approval) return false;
  const policy = approval.policy || (approval.required ? 'manual' : null);
  return policy === 'manual';
}

export function approvalPolicyAutoRejects(approval) {
  return approval?.policy === 'auto-reject';
}

export function computeTaskApprovalHash({
  binding,
  manifest,
  expanded: suppliedExpanded,
  workflow: suppliedWorkflow,
  workflowId,
  task: suppliedTask,
  taskId,
  cwd = process.cwd(),
  env = process.env,
  timeoutMs,
  instanceId,
} = {}) {
  if (binding) return computeEffectiveTaskHash(binding);

  const expanded = suppliedExpanded || (manifest ? expandManifestShorthands(manifest) : null);
  const workflows = expanded?.workflows || [];
  const workflow = suppliedWorkflow || (
    workflowId
      ? workflows.find(candidate => candidate.id === workflowId)
      : workflows.length === 1
        ? workflows[0]
        : null
  );
  const compatibilityWorkflow = !workflow && suppliedTask && workflowId
    ? { id: workflowId, name: workflowId, tasks: [suppliedTask] }
    : workflow;
  const task = suppliedTask || compatibilityWorkflow?.tasks?.find(candidate => candidate.id === taskId);
  if (!compatibilityWorkflow || !task) {
    throw Object.assign(
      new Error('manifest/workflow/task or a prebuilt binding is required to compute an approval hash'),
      { code: 'invalid_argument' }
    );
  }

  return computeEffectiveTaskHash(buildEffectiveExecutionBinding({
    manifest,
    expanded,
    workflow: compatibilityWorkflow,
    task,
    cwd,
    env,
    timeoutMs,
    instanceId,
  }));
}

export function approverMatchesScope(approver, scope) {
  if (!scope) return true;
  if (typeof approver !== 'string' || approver.length === 0) return false;
  const separator = scope.indexOf(':');
  const kind = separator === -1 ? 'exact' : scope.slice(0, separator);
  const expected = separator === -1 ? scope : scope.slice(separator + 1);
  if (!expected) return false;
  if (kind === 'principal' || kind === 'user' || kind === 'exact') {
    return approver === expected;
  }
  if (kind === 'domain') {
    const at = approver.lastIndexOf('@');
    return at > 0 && approver.slice(at + 1).toLowerCase() === expected.toLowerCase();
  }
  return approver === scope;
}

function readApprovalsLog(approvalsPath) {
  if (!approvalsPath || !existsSync(approvalsPath)) return [];
  const approvalsState = lstatSync(approvalsPath);
  if (approvalsState.isSymbolicLink() || !approvalsState.isFile()) {
    throw Object.assign(
      new Error('Refusing to read approvals from a non-regular file'),
      { code: 'approval_log_invalid' }
    );
  }
  const content = readFileSync(approvalsPath, 'utf8').trim();
  if (!content) return [];
  const events = [];
  for (const line of content.split('\n')) {
    if (!line.trim()) continue;
    try {
      events.push(JSON.parse(line));
    } catch {
      // Skip malformed lines (partial writes, crash-interrupted appends) so
      // one bad record cannot DoS every subsequent exec. The corresponding
      // grant is simply ignored rather than blocking the whole file.
    }
  }
  return events;
}

function appendApprovalEventUnlocked(event, approvalsPath) {
  let descriptor;
  try {
    descriptor = openSync(
      approvalsPath,
      fsConstants.O_WRONLY |
        fsConstants.O_APPEND |
        fsConstants.O_CREAT |
        (fsConstants.O_NONBLOCK || 0) |
        (fsConstants.O_NOFOLLOW || 0),
      0o600
    );
    assertRegularFileDescriptor(descriptor, approvalsPath, { code: 'approval_log_invalid' });
    if (process.platform !== 'win32') fchmodSync(descriptor, 0o600);
    writeSync(descriptor, JSON.stringify(event) + '\n', null, 'utf8');
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function writeApprovalEvent(event, { approvalsPath }) {
  return withApprovalsLock(
    approvalsPath,
    () => appendApprovalEventUnlocked(event, approvalsPath)
  );
}

function generateApprovalId() {
  return randomBytes(16).toString('hex');
}

function foldEvents(events) {
  const grants = new Map();
  const consumed = new Map();
  const revoked = new Map();
  for (const e of events) {
    if (e.kind === 'grant') {
      grants.set(e.approval_id, e);
    } else if (e.kind === 'consume') {
      consumed.set(e.approval_id, e);
    } else if (e.kind === 'revoke') {
      revoked.set(e.approval_id, e);
    }
  }
  return { grants, consumed, revoked };
}

function effectiveStatus(grant, consumed, revoked, nowMs) {
  if (revoked.has(grant.approval_id)) return 'revoked';
  if (consumed.has(grant.approval_id)) return 'consumed';
  if (grant.expires_at && Date.parse(grant.expires_at) <= nowMs) return 'expired';
  return 'pending';
}

export function listApprovals({ env = process.env, status: statusFilter, workflowId, taskId } = {}) {
  const paths = getAgentcliPaths({ env });
  const events = readApprovalsLog(paths.approvals);
  const { grants, consumed, revoked } = foldEvents(events);
  const now = Date.now();
  const records = [];
  for (const grant of grants.values()) {
    const status = effectiveStatus(grant, consumed, revoked, now);
    if (statusFilter && statusFilter !== 'all' && status !== statusFilter) continue;
    if (workflowId && grant.workflow_id !== workflowId) continue;
    if (taskId && grant.task_id !== taskId) continue;
    const consume = consumed.get(grant.approval_id);
    const revoke = revoked.get(grant.approval_id);
    records.push({
      approval_id: grant.approval_id,
      workflow_id: grant.workflow_id,
      task_id: grant.task_id,
      task_hash: grant.task_hash,
      approver: grant.approver,
      reason: grant.reason,
      granted_at: grant.granted_at,
      expires_at: grant.expires_at,
      status,
      consumed_at: consume?.consumed_at ?? null,
      consumed_by_execution_id: consume?.execution_id ?? null,
      revoked_at: revoke?.revoked_at ?? null,
      revoked_by: revoke?.revoked_by ?? null,
      revoke_reason: revoke?.reason ?? null,
      signature: grant.signature
        ? { method: grant.signature.method, key_fingerprint: grant.signature.key_fingerprint }
        : null,
      approver_scope: grant.approver_scope ?? null,
      unsigned_explicit: grant.unsigned_explicit === true,
    });
  }
  records.sort((a, b) => (a.granted_at < b.granted_at ? -1 : 1));
  return records;
}

export function findValidApproval({
  workflowId,
  taskId,
  taskHash,
  approvalId,
  env = process.env,
  now = Date.now(),
}) {
  const paths = getAgentcliPaths({ env });
  const events = readApprovalsLog(paths.approvals);
  const { grants, consumed, revoked } = foldEvents(events);

  const candidates = [];
  for (const grant of grants.values()) {
    if (approvalId && grant.approval_id !== approvalId) continue;
    if (grant.workflow_id !== workflowId) continue;
    if (grant.task_id !== taskId) continue;
    if (grant.task_hash !== taskHash) continue;
    const status = effectiveStatus(grant, consumed, revoked, now);
    if (status !== 'pending') continue;
    candidates.push(grant);
  }
  if (candidates.length === 0) return null;
  candidates.sort((a, b) => (a.granted_at < b.granted_at ? -1 : 1));
  return candidates[0];
}

// Atomically find a matching pending grant and mark it consumed.
// Returns the consumed grant object, or null if no match. Concurrent callers
// serialize on the approvals lockfile; at most one wins per grant.
export function claimApproval({
  workflowId,
  taskId,
  taskHash,
  approvalId,
  executionId,
  env = process.env,
  now = () => Date.now(),
  lockOptions,
}) {
  const paths = getAgentcliPaths({ env });
  return withApprovalsLock(paths.approvals, () => {
    const grant = findValidApproval({
      workflowId, taskId, taskHash, approvalId, env, now: now(),
    });
    if (!grant) return null;
    const consumedAt = new Date(now()).toISOString();
    appendApprovalEventUnlocked({
      v: APPROVAL_RECORD_VERSION,
      kind: 'consume',
      approval_id: grant.approval_id,
      execution_id: executionId,
      consumed_at: consumedAt,
    }, paths.approvals);
    return grant;
  }, lockOptions);
}

function buildApprovalSignaturePayload(grant) {
  return canonicalStringify({
    v: APPROVAL_RECORD_VERSION,
    kind: 'approval',
    approval_id: grant.approval_id,
    workflow_id: grant.workflow_id,
    task_id: grant.task_id,
    task_hash: grant.task_hash,
    risk_level: grant.risk_level ?? null,
    approver_scope: grant.approver_scope ?? null,
    approver: grant.approver,
    reason: grant.reason ?? null,
    granted_at: grant.granted_at,
    expires_at: grant.expires_at,
  });
}

export function verifyApprovalSignature(grant, { env = process.env } = {}) {
  if (!grant.signature) {
    return grant.unsigned_explicit === true
      ? { verified: null, reason: 'signing explicitly disabled' }
      : { verified: false, reason: 'approval record is unexpectedly unsigned' };
  }
  const provider = getProvider(grant.signature.method?.replace(/-signature$/, '') || 'ssh');
  if (!provider) return { verified: false, reason: `unknown signer "${grant.signature.method}"` };

  // Tamper check: rebuild the canonical payload from the current grant fields
  // and compare against the payload that was signed at grant time. An attacker
  // who edits approver/reason/expires_at/task_hash in the ndjson after signing
  // would leave signature.signed_payload untouched; the divergence catches it.
  // The ssh provider only re-verifies that signature matches signed_payload,
  // so without this check, post-sign field edits would go undetected.
  const expectedPayload = buildApprovalSignaturePayload(grant);
  if (grant.signature.signed_payload !== expectedPayload) {
    return {
      verified: false,
      reason: 'grant fields do not match signed payload (possible tampering)',
    };
  }

  const paths = getAgentcliPaths({ env });
  let allowedSigners = resolveAllowedSigners({ env, statePath: paths.allowed_signers });
  if (!allowedSigners && grant.signature.method === 'ssh-signature') {
    // First-use bootstrap: mirror the `agentcli verify` command's behavior
    // so a fresh install can round-trip grants without a manual setup step.
    allowedSigners = generateAllowedSigners({
      principal: grant.approver,
      outputPath: paths.allowed_signers,
    });
    if (!allowedSigners) {
      return {
        verified: false,
        reason: 'no allowed_signers file and no SSH public keys found to generate one',
      };
    }
  }
  return provider.verify(grant.signature, {
    allowedSignersPath: allowedSigners,
    principal: grant.approver,
  });
}

export function grantApproval({
  manifest,
  workflowId,
  taskId,
  approver,
  reason,
  ttlS,
  signer,
  signingKey,
  env = process.env,
  cwd = process.cwd(),
  timeoutMs,
  instanceId,
  now = Date.now(),
}) {
  if (!manifest || typeof manifest !== 'object') {
    throw Object.assign(new Error('manifest is required'), { code: 'invalid_argument' });
  }
  if (!taskId) {
    throw Object.assign(new Error('taskId is required'), { code: 'invalid_argument' });
  }
  if (!approver) {
    throw Object.assign(new Error('approver is required (pass --by <principal>)'), { code: 'invalid_argument' });
  }
  const expanded = expandManifestShorthands(manifest);
  const workflows = Array.isArray(expanded.workflows) ? expanded.workflows : [];
  const workflow = workflowId
    ? workflows.find(w => w.id === workflowId)
    : (workflows.length === 1 ? workflows[0] : null);
  if (!workflow) {
    throw Object.assign(
      new Error(workflowId ? `workflow "${workflowId}" not found` : 'manifest has multiple workflows; pass --workflow <id>'),
      { code: 'invalid_argument' }
    );
  }
  const task = (workflow.tasks || []).find(t => t.id === taskId);
  if (!task) {
    throw Object.assign(new Error(`task "${taskId}" not found in workflow "${workflow.id}"`), { code: 'invalid_argument' });
  }
  if (!task.approval) {
    throw Object.assign(
      new Error(`task "${taskId}" has no approval policy; nothing to approve`),
      { code: 'invalid_argument' }
    );
  }
  if (!approvalPolicyRequiresApproval(task.approval) && !approvalPolicyAutoRejects(task.approval)) {
    throw Object.assign(
      new Error(`task "${taskId}" policy is "${task.approval.policy || 'none'}"; approval grant not meaningful`),
      { code: 'invalid_argument' }
    );
  }
  if (approvalPolicyAutoRejects(task.approval)) {
    throw Object.assign(
      new Error(`task "${taskId}" policy is "auto-reject"; approvals cannot override`),
      { code: 'policy_forbids_approval' }
    );
  }

  const approverScope = task.approval.approver_scope ?? null;
  if (!approverMatchesScope(approver, approverScope)) {
    throw Object.assign(
      new Error(`approver "${approver}" does not satisfy approval.approver_scope "${approverScope}"`),
      { code: 'approval_scope_mismatch', approver_scope: approverScope }
    );
  }

  const taskTimeoutS = task.approval.timeout_s ?? null;
  const effectiveTtlS = ttlS ?? taskTimeoutS ?? DEFAULT_TTL_S;
  if (!Number.isInteger(effectiveTtlS) || effectiveTtlS < 1) {
    throw Object.assign(new Error('approval TTL must be an integer >= 1'), { code: 'invalid_argument' });
  }
  if (taskTimeoutS != null && effectiveTtlS > taskTimeoutS) {
    throw Object.assign(
      new Error(`approval TTL ${effectiveTtlS}s exceeds task approval.timeout_s ${taskTimeoutS}s`),
      { code: 'invalid_argument' }
    );
  }

  const binding = buildEffectiveExecutionBinding({
    manifest,
    expanded,
    workflow,
    task,
    cwd,
    env,
    timeoutMs,
    instanceId,
  });
  const taskHash = computeTaskApprovalHash({ binding });
  const grantedAt = new Date(now).toISOString();
  const expiresAt = new Date(now + effectiveTtlS * 1000).toISOString();
  const approvalId = generateApprovalId();

  const grant = {
    v: APPROVAL_RECORD_VERSION,
    kind: 'grant',
    approval_id: approvalId,
    workflow_id: workflow.id,
    task_id: task.id,
    task_hash: taskHash,
    risk_level: task.approval.risk_level ?? null,
    approver_scope: approverScope,
    approver,
    reason: reason ?? null,
    granted_at: grantedAt,
    expires_at: expiresAt,
    signature: null,
    unsigned_explicit: false,
  };

  const provider = resolveProvider({ signer, env });
  const unsignedExplicit = provider.name === 'none' && (signer === 'none' || env.AGENTCLI_SIGNER === 'none');
  if (provider.name === 'none') {
    if (!unsignedExplicit) {
      throw Object.assign(
        new Error('unsigned approvals require an explicit signer="none" selection'),
        { code: 'approval_signature_invalid' }
      );
    }
    grant.unsigned_explicit = true;
  } else {
    const config = provider.resolve({ env, signingKey });
    if (!config) {
      throw Object.assign(
        new Error(`signing provider "${provider.name}" has no usable signing credentials`),
        { code: 'approval_signature_invalid' }
      );
    }
    const payload = buildApprovalSignaturePayload(grant);
    const sigResult = provider.sign(payload, config);
    if (!sigResult.signed) {
      throw Object.assign(
        new Error(`approval signing failed: ${sigResult.reason || 'provider did not return a signature'}`),
        { code: 'approval_signature_invalid' }
      );
    }
    grant.signature = sigResult.attestation;
  }

  const paths = getAgentcliPaths({ env });
  writeApprovalEvent(grant, { approvalsPath: paths.approvals });

  return {
    approval_id: approvalId,
    workflow_id: workflow.id,
    task_id: task.id,
    task_hash: taskHash,
    risk_level: task.approval.risk_level ?? null,
    approver_scope: approverScope,
    approver,
    reason: reason ?? null,
    granted_at: grantedAt,
    expires_at: expiresAt,
    signature: grant.signature
      ? { method: grant.signature.method, key_fingerprint: grant.signature.key_fingerprint }
      : null,
    unsigned_explicit: grant.unsigned_explicit,
  };
}

export function consumeApproval({ approvalId, executionId, env = process.env, now = Date.now() }) {
  const paths = getAgentcliPaths({ env });
  const event = {
    v: APPROVAL_RECORD_VERSION,
    kind: 'consume',
    approval_id: approvalId,
    execution_id: executionId,
    consumed_at: new Date(now).toISOString(),
  };
  writeApprovalEvent(event, { approvalsPath: paths.approvals });
}

export function revokeApproval({ approvalId, revokedBy, reason, env = process.env, now = Date.now() }) {
  const paths = getAgentcliPaths({ env });
  const event = {
    v: APPROVAL_RECORD_VERSION,
    kind: 'revoke',
    approval_id: approvalId,
    revoked_by: revokedBy ?? null,
    reason: reason ?? null,
    revoked_at: new Date(now).toISOString(),
  };
  writeApprovalEvent(event, { approvalsPath: paths.approvals });
}
