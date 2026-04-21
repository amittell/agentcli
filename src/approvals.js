import { appendFileSync, readFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { getProvider, resolveProvider } from './signing/index.js';
import { resolveSigningKey, resolveAllowedSigners, generateAllowedSigners } from './signing/ssh.js';
import { getAgentcliPaths } from './home.js';

// Concurrency note: grantApproval, findValidApproval, and consumeApproval read
// and append to an NDJSON log without advisory locking. Two concurrent
// `agentcli exec` invocations of the same gated task can both observe the
// same pending grant and both consume it. This is an accepted limitation of
// the local single-machine enforcement model; workflows that require
// multi-dispatcher approval coordination should use openclaw-scheduler.

const APPROVAL_RECORD_VERSION = 1;
const DEFAULT_TTL_S = 3600;

export function approvalPolicyRequiresApproval(approval) {
  if (!approval) return false;
  const policy = approval.policy || (approval.required ? 'manual' : null);
  return policy === 'manual';
}

export function approvalPolicyAutoRejects(approval) {
  return approval?.policy === 'auto-reject';
}

function canonicalStringify(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalStringify).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map(k => `${JSON.stringify(k)}:${canonicalStringify(value[k])}`).join(',')}}`;
}

export function computeTaskApprovalHash({ workflowId, task }) {
  const material = {
    workflow_id: workflowId,
    task_id: task.id,
    shell: {
      program: task.shell?.program ?? null,
      args: task.shell?.args ?? [],
      cwd: task.shell?.cwd ?? null,
    },
    identity_ref: task.identity?.ref ?? null,
    approval_policy: task.approval?.policy ?? (task.approval?.required ? 'manual' : null),
    approval_risk_level: task.approval?.risk_level ?? null,
  };
  return `sha256:${createHash('sha256').update(canonicalStringify(material)).digest('hex')}`;
}

function readApprovalsLog(approvalsPath) {
  if (!approvalsPath || !existsSync(approvalsPath)) return [];
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

function writeApprovalEvent(event, { approvalsPath }) {
  mkdirSync(dirname(approvalsPath), { recursive: true });
  appendFileSync(approvalsPath, JSON.stringify(event) + '\n', 'utf8');
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

function buildApprovalSignaturePayload(grant) {
  return canonicalStringify({
    v: APPROVAL_RECORD_VERSION,
    kind: 'approval',
    approval_id: grant.approval_id,
    workflow_id: grant.workflow_id,
    task_id: grant.task_id,
    task_hash: grant.task_hash,
    approver: grant.approver,
    reason: grant.reason ?? null,
    granted_at: grant.granted_at,
    expires_at: grant.expires_at,
  });
}

export function verifyApprovalSignature(grant, { env = process.env } = {}) {
  if (!grant.signature) return { verified: null, reason: 'unsigned' };
  const provider = getProvider(grant.signature.method?.replace(/-signature$/, '') || 'ssh');
  if (!provider) return { verified: false, reason: `unknown signer "${grant.signature.method}"` };
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
  const payload = buildApprovalSignaturePayload(grant);
  const attestation = { ...grant.signature, payload };
  return provider.verify(attestation, {
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
  ttlS = DEFAULT_TTL_S,
  signer,
  signingKey,
  env = process.env,
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
  const workflows = Array.isArray(manifest.workflows) ? manifest.workflows : [];
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

  const taskHash = computeTaskApprovalHash({ workflowId: workflow.id, task });
  const grantedAt = new Date(now).toISOString();
  const expiresAt = new Date(now + ttlS * 1000).toISOString();
  const approvalId = generateApprovalId();

  const grant = {
    v: APPROVAL_RECORD_VERSION,
    kind: 'grant',
    approval_id: approvalId,
    workflow_id: workflow.id,
    task_id: task.id,
    task_hash: taskHash,
    risk_level: task.approval.risk_level ?? null,
    approver,
    reason: reason ?? null,
    granted_at: grantedAt,
    expires_at: expiresAt,
    signature: null,
  };

  const provider = resolveProvider({ signer, env });
  if (provider.name !== 'none') {
    const config = provider.resolve({ env, signingKey });
    if (config) {
      const payload = buildApprovalSignaturePayload(grant);
      const sigResult = provider.sign(payload, config);
      if (sigResult.signed) {
        grant.signature = sigResult.attestation;
      } else {
        grant.signature = null;
      }
    }
  }

  const paths = getAgentcliPaths({ env });
  writeApprovalEvent(grant, { approvalsPath: paths.approvals });

  return {
    approval_id: approvalId,
    workflow_id: workflow.id,
    task_id: task.id,
    task_hash: taskHash,
    risk_level: task.approval.risk_level ?? null,
    approver,
    reason: reason ?? null,
    granted_at: grantedAt,
    expires_at: expiresAt,
    signature: grant.signature
      ? { method: grant.signature.method, key_fingerprint: grant.signature.key_fingerprint }
      : null,
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
