import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { isAbsolute, relative, resolve as resolvePath } from 'node:path';
import { validateManifest } from './validate.js';
import { resolveValueFrom } from './command.js';
import { expandManifestShorthands } from './shorthand.js';
import { normalizeShellExecution } from './shell.js';
import {
  mergeAuthorizationProfile,
  mergeAuthorizationProofProfile,
  mergeEvidenceProfile,
  mergeIdentityProfile,
  buildEffectiveExecutionBinding,
  computeEffectiveTaskHash,
  resolveAuthorization,
  resolveAuthorizationProof,
  resolveContract,
  resolveEvidence,
  resolveIdentity,
  resolveVerify
} from './compiler/shared.js';
import { generateExecutionId, writeAuditRecord } from './audit.js';
import { getAgentcliPaths } from './home.js';
import { buildAttestationPayload, commandHash } from './attestation.js';
import { resolveProvider } from './signing/index.js';
import { resolveRuntimeAdapter } from './runtime/index.js';
import { buildActorContext, buildStepUpContext } from './actor-context.js';
import {
  approvalPolicyRequiresApproval,
  approvalPolicyAutoRejects,
  computeTaskApprovalHash,
  claimApproval,
  verifyApprovalSignature,
  approverMatchesScope,
} from './approvals.js';

// Ensure the ssh signing provider is registered on import
import './signing/ssh.js';

// v0.2 identity providers
import { resolveProvider as resolveIdentityProvider } from './identity/index.js';
import './identity/none.js';
import './identity/env-bearer.js';
import './identity/file-bearer.js';
import './identity/oidc-client-credentials.js';
import './identity/oidc-token-exchange.js';
import './identity/azure-managed-identity.js';
import './identity/aws-sts-assume-role.js';
import './identity/gcp-workload-identity.js';
import './identity/spiffe-jwt-svid.js';
import './identity/entra-agent-id.js';
import { compareTrustLevels, redactSession, buildCredentialSummary } from './identity/session.js';

// v0.2 evidence providers
import { resolveEvidenceProvider } from './evidence/index.js';
import './evidence/none.js';
import './evidence/ssh.js';
import {
  buildCompleteEvidencePayload,
  serializePayload,
  collectComplianceContext,
} from './evidence/payload.js';

// v0.2 authorization proof verifiers
import {
  assertValidAuthorizationProofProfile,
  verifyAuthorizationProof,
} from './authorization-proof/index.js';
import './authorization-proof/none.js';
import './authorization-proof/jwt.js';
import './authorization-proof/detached-signature.js';
import './authorization-proof/certificate.js';

// v0.2 authorization providers
import { resolveAuthorizationProvider, normalizeAuthorizationRequest, normalizeDecision } from './authorization/index.js';
import './authorization/none.js';
import './authorization/opa.js';
import { prepareSandboxedShellCommand } from './sandbox.js';

function isPathWithin(targetPath, rootPath) {
  const rel = relative(rootPath, targetPath);
  return rel === '' || (!rel.startsWith('..') && rel !== '..' && !isAbsolute(rel));
}

function preflightContractChecks(contract, shell, { cwd = process.cwd() } = {}) {
  const violations = [];
  const warnings = [];
  const executionCwd = resolvePath(cwd, shell.cwd || '.');

  if (contract.allowed_paths?.length) {
    const allowed = contract.allowed_paths.some(p =>
      isPathWithin(executionCwd, resolvePath(cwd, p))
    );
    if (!allowed) {
      violations.push({
        field: 'contract.allowed_paths',
        message: `execution cwd "${executionCwd}" is not under any allowed path`
      });
    }
  }

  return { violations, warnings };
}

/**
 * Run the verify command after a task completes successfully.
 *
 * @param {object} verify  - Resolved verify block (shell, timeout_seconds, on_failure).
 * @param {object} options - { cwd, env, sandboxCommand } for spawn context.
 * @returns {object} { passed, exit_code, stdout, stderr, timed_out, duration_ms }
 */
function runVerify(verify, {
  cwd = process.cwd(),
  env = process.env,
  sandboxCommand = null,
} = {}) {
  const timeoutMs = (verify.timeout_seconds ?? 30) * 1000;
  const startMs = Date.now();
  const verifyProgram = 'sh';
  const verifyArgs = ['-c', verify.shell];
  const usesSandbox =
    sandboxCommand?.sandboxed === true &&
    sandboxCommand?.support?.kind === 'sandbox-exec' &&
    typeof sandboxCommand?.profile === 'string';

  const proc = spawnSync(
    usesSandbox ? sandboxCommand.support.command : verifyProgram,
    usesSandbox ? ['-p', sandboxCommand.profile, verifyProgram, ...verifyArgs] : verifyArgs,
    {
    cwd,
    env: { ...process.env, ...env },
    encoding: 'utf8',
    timeout: timeoutMs,
    maxBuffer: 1 * 1024 * 1024,
    }
  );
  const durationMs = Date.now() - startMs;
  const stdout = proc.stdout || '';
  const stderr = proc.stderr || '';
  const exitCode = proc.status;
  const timedOut = Boolean(proc.error && proc.error.code === 'ETIMEDOUT') || proc.signal === 'SIGTERM';

  return {
    passed: exitCode === 0 && !timedOut,
    exit_code: exitCode,
    stdout,
    stderr,
    timed_out: timedOut,
    duration_ms: durationMs,
  };
}

function resolvePrincipal(identity) {
  if (identity.principal) return identity.principal;
  if (identity.subject?.principal) return identity.subject.principal;
  const user = process.env.USER || process.env.USERNAME || 'unknown';
  const host = process.env.HOSTNAME || process.env.HOST || 'localhost';
  return `${user}@${host}`;
}

const OPERATIONAL_ENV_KEYS = new Set([
  'PATH', 'HOME', 'TMPDIR', 'TMP', 'TEMP',
  'LANG', 'SHELL', 'USER', 'LOGNAME', 'TZ', 'TERM',
  'SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT',
]);

function buildChildEnvironment(env, declaredEnv = {}) {
  const inherited = {};
  for (const [key, value] of Object.entries(env || {})) {
    if (OPERATIONAL_ENV_KEYS.has(key) || key.startsWith('LC_')) {
      inherited[key] = value;
    }
  }
  return { ...inherited, ...declaredEnv };
}

function safeCommandMetadata(binding, shell, cwd) {
  return {
    program: shell.program,
    cwd: shell.cwd || cwd,
    args_count: binding.command?.args_count ?? shell.args.length,
    args_hashes: binding.command?.args_hashes ?? [],
    env_keys: binding.command?.env_keys ?? Object.keys(shell.env),
    env_hashes: binding.command?.env_hashes ?? {},
    stdin_present: shell.stdin != null,
    stdin_hash: binding.command?.stdin_hash ?? null,
  };
}

async function assertProviderProfileValid(provider, profile, kind, context = {}) {
  if (!provider?.validateProfile) return;
  const validation = await provider.validateProfile(profile, context);
  if (validation?.valid === false) {
    const details = Array.isArray(validation.errors)
      ? validation.errors.map(error => typeof error === 'string' ? error : error.message).join('; ')
      : 'provider rejected the profile';
    throw Object.assign(
      new Error(`${kind} profile validation failed: ${details}`),
      { code: 'validation_error', provider: provider.name, validation }
    );
  }
}

function summarizeMaterialization(materialization) {
  if (!materialization) return null;
  return {
    materialized: Boolean(materialization.materialized),
    cleanup_required: Boolean(materialization.cleanup_required),
    env_keys: Object.keys(materialization.env_vars || {}),
    temp_file_count: (materialization.temp_files || []).length,
  };
}

function normalizeIdentitySessionResult(result, providerName) {
  if (
    result &&
    typeof result === 'object' &&
    Object.prototype.hasOwnProperty.call(result, 'ok')
  ) {
    if (!result.ok) {
      throw Object.assign(
        new Error(
          result.error || `Identity provider "${providerName}" failed to resolve credentials`
        ),
        {
          code: result.code || 'resolution_failed',
          retryable: Boolean(result.transient),
        }
      );
    }

    if (!result.session || typeof result.session !== 'object') {
      throw Object.assign(
        new Error(
          `Identity provider "${providerName}" returned ok=true without a session payload`
        ),
        {
          code: 'resolution_failed',
          retryable: false,
        }
      );
    }

    return result.session;
  }

  return result;
}

function handoffPrepared(handoffResult) {
  return Boolean(handoffResult?.prepared ?? handoffResult?.session?.handoff?.prepared);
}

function summarizeHandoff(handoffResult, mode) {
  if (!handoffResult && !mode) return null;
  const credentialSet = handoffResult?.credentials ?? handoffResult?.session?.credentials ?? {};
  return {
    mode: mode ?? handoffResult?.mode ?? handoffResult?.session?.handoff?.mode ?? null,
    prepared: handoffPrepared(handoffResult),
    credential_types: Object.keys(credentialSet),
    reason: handoffResult?.reason ?? handoffResult?.error ?? null,
  };
}

async function cleanupProviderArtifacts(identityProviderInstance, {
  materialization = null,
  session = null,
  providerConfig = {},
  env = process.env,
  commandEnv = buildChildEnvironment(env),
  cwd = process.cwd(),
  runtimeCapabilities = {},
  warningPrefix = 'Credential cleanup',
} = {}, warnings = []) {
  if (!identityProviderInstance?.cleanup) return;

  const effectiveSession = session || materialization?.session || null;
  const cleanupRequired =
    Boolean(materialization?.cleanup_required) ||
    Boolean(effectiveSession?.provider_assertions?.key_strategy === 'dynamic');

  if (!cleanupRequired) return;

  const cleanupMaterialization = materialization || {
    materialized: false,
    env_vars: {},
    cleanup_required: true,
    ...(effectiveSession ? { session: effectiveSession } : {}),
  };

  try {
    const cleanupResult = await identityProviderInstance.cleanup(cleanupMaterialization, {
      session: effectiveSession,
      env,
      commandEnv,
      cwd,
      provider_config: providerConfig,
      runtimeCapabilities,
    });
    for (const warning of cleanupResult?.warnings || []) {
      warnings.push(`${warningPrefix} warning: ${warning}`);
    }
  } catch (cleanupErr) {
    warnings.push(`${warningPrefix} warning: ${cleanupErr.message}`);
  }
}

/**
 * Validate and resolve common execution state shared by both v0.1 and v0.2 paths.
 *
 * Performs manifest validation, workflow/task lookup, shell-target check,
 * contract preflight, without resolving providers or probing the host.
 *
 * @returns {object} All resolved common state fields.
 */
function resolveCommonState(manifest, {
  workflowId,
  taskId,
  signer,
  signingKey: explicitSigningKey,
  cwd = process.cwd(),
  env = process.env,
  timeoutMs,
  allowUnsupportedHandoff = false,
}) {
  if (!taskId) {
    throw Object.assign(
      new Error('taskId is required'),
      { code: 'invalid_argument' }
    );
  }

  const validation = validateManifest(manifest);
  if (!validation.ok) {
    throw Object.assign(
      new Error('Manifest validation failed'),
      { code: 'validation_error', validation }
    );
  }

  const expanded = expandManifestShorthands(manifest);

  let workflow;
  if (workflowId) {
    workflow = expanded.workflows.find(w => w.id === workflowId);
    if (!workflow) {
      throw Object.assign(
        new Error(`Workflow not found: ${workflowId}`),
        { code: 'invalid_argument' }
      );
    }
  } else if (expanded.workflows.length === 1) {
    workflow = expanded.workflows[0];
  } else {
    throw Object.assign(
      new Error(`Multiple workflows found; specify --workflow. Available: ${expanded.workflows.map(w => w.id).join(', ')}`),
      { code: 'invalid_argument' }
    );
  }

  const task = workflow.tasks.find(t => t.id === taskId);
  if (!task) {
    throw Object.assign(
      new Error(`Task not found: ${taskId} in workflow ${workflow.id}. Available: ${workflow.tasks.map(t => t.id).join(', ')}`),
      { code: 'invalid_argument' }
    );
  }

  if (task.target?.session_target !== 'shell') {
    const identity = resolveIdentity(workflow, task);
    const contract = resolveContract(workflow, task);
    return {
      requiresDelegation: true,
      manifest: expanded,
      expanded,
      workflow,
      task,
      isV2: manifest.version === '0.2' || Boolean(manifest.identity_profiles),
      identity,
      contract,
      verify: resolveVerify(workflow, task),
      auditPolicy: contract.audit ?? 'always',
      shell: null,
      effectiveTimeout: timeoutMs ?? task.runtime?.timeout_ms ?? null,
      violations: [],
      warnings: [],
      signer,
      explicitSigningKey,
      cwd,
      env,
    };
  }

  if (!task.shell) {
    throw Object.assign(
      new Error(`Task "${taskId}" is a shell target but has no shell block`),
      { code: 'validation_error' }
    );
  }

  const isV2 = manifest.version === '0.2' || Boolean(manifest.identity_profiles);

  const identity = resolveIdentity(workflow, task);
  const identityDeclaration = mergeIdentityProfile(
    identity.ref
      ? expanded.identity_profiles?.find(profile => profile.id === identity.ref) ?? null
      : null,
    identity
  );
  const declaredHandoff = identityDeclaration.presentation?.handoff ?? 'none';
  if (declaredHandoff !== 'none' && !allowUnsupportedHandoff) {
    throw Object.assign(
      new Error(`Credential handoff "${declaredHandoff}" is unsupported by the local shell runtime`),
      { code: 'unsupported_capability' }
    );
  }
  const contract = resolveContract(workflow, task);
  const verify = resolveVerify(workflow, task);
  const auditPolicy = contract.audit ?? 'always';
  const shell = normalizeShellExecution(task.shell);
  const effectiveTimeout = timeoutMs ?? task.runtime?.timeout_ms ?? null;
  const { violations, warnings: preflightWarnings } = preflightContractChecks(contract, shell, { cwd });
  const warnings = [...preflightWarnings];

  if (violations.length > 0) {
    throw Object.assign(
      new Error(`Contract violation: ${violations.map(v => v.message).join('; ')}`),
      { code: 'contract_violation', violations, warnings }
    );
  }

  return {
    expanded, workflow, task, isV2, identity, contract, verify,
    auditPolicy, shell, effectiveTimeout, violations, warnings,
    signer, explicitSigningKey, cwd, env,
  };
}

function buildDryRunResult(common, { binding, taskHash, timestamp, executionId }) {
  const { workflow, task, contract, shell, warnings, cwd } = common;
  const command = safeCommandMetadata(binding, shell, cwd);
  return {
    ok: true,
    dry_run: true,
    execution_id: executionId,
    timestamp,
    source: { workflow_id: workflow.id, task_id: task.id },
    effective_task_hash: taskHash,
    manifest_digest: binding.manifest_digest,
    identity: binding.identity,
    contract,
    command,
    approval: {
      policy: binding.approval.policy,
      required: binding.approval.required === 1,
      auto_reject: binding.approval.policy === 'auto-reject',
      risk_level: binding.approval.risk_level,
      approver_scope: binding.approval.approver_scope,
      timeout_s: binding.approval.timeout_s,
    },
    sandbox: {
      requested: contract.sandbox ?? 'permissive',
      network: contract.network ?? 'unrestricted',
      evaluated: false,
    },
    phases: {
      authorization_proof: 'skipped',
      identity_resolution: 'skipped',
      authorization: 'skipped',
      credential_materialization: 'skipped',
      handoff: 'skipped',
      signing: 'skipped',
      evidence: 'skipped',
      verify: 'skipped',
      audit: 'skipped',
    },
    warnings: [...warnings],
    result: { status: 'dry_run' },
  };
}

function prepareLiveCommon(common, { signer, signingKey, cwd, env }) {
  const sandboxCommand = prepareSandboxedShellCommand(common.shell, common.contract, { cwd, env });
  common.warnings.push(...sandboxCommand.warnings);
  const provider = resolveProvider({ signer, env });
  const providerConfig = provider.resolve({ env, signingKey });
  return { ...common, sandboxCommand, provider, providerConfig };
}

async function executeApprovedV2(common, options) {
  const approvalUsed = enforceApprovalGate({
    workflow: common.workflow,
    task: common.task,
    executionId: options.executionId,
    approvalId: options.approvalId,
    env: options.env,
    binding: options.binding,
    taskHash: options.taskHash,
  });
  const liveCommon = prepareLiveCommon(common, {
    signer: options.signer,
    signingKey: options.signingKey,
    cwd: options.cwd,
    env: options.env,
  });
  return executeV2(liveCommon, { ...options, approvalUsed });
}

/**
 * Execute a shell task from a manifest.
 *
 * For v0.1 manifests, returns the result synchronously.
 * For v0.2 manifests, returns a Promise (resolveSession may be async).
 *
 * All callers (cli.js, jsonrpc.js) already await the result, and await
 * is a no-op on non-Promises, so both paths work transparently.
 */
export function executeTask(manifest, {
  workflowId,
  taskId,
  dryRun = false,
  timeoutMs,
  signer,
  signingKey: explicitSigningKey,
  evidenceProvider: evidenceProviderOverride,
  instanceId,
  requireEvidence = false,
  requireAuthorization = false,
  identityDebug = false,
  presentationDebug = false,
  schedulerPrefix = '',
  schedulerBin = '',
  dbPath = '',
  approvalId,
  cwd = process.cwd(),
  env = process.env,
} = {}) {
  // Resolve only side-effect-free common state before the approval boundary.
  const common = resolveCommonState(manifest, {
    workflowId, taskId, signer, signingKey: explicitSigningKey,
    cwd, env, timeoutMs,
  });

  // Non-shell tasks are delegated to a runtime adapter (e.g. the scheduler)
  if (common.requiresDelegation) {
    return executeDelegated(common, {
      schedulerPrefix, schedulerBin, dbPath, dryRun, cwd, env,
    });
  }

  const timestamp = new Date().toISOString();
  const executionId = generateExecutionId(common.workflow.id, common.task.id, timestamp);
  const binding = buildEffectiveExecutionBinding({
    manifest,
    expanded: common.expanded,
    workflow: common.workflow,
    task: common.task,
    cwd,
  });
  const taskHash = computeEffectiveTaskHash(binding);

  if (dryRun) {
    const preview = buildDryRunResult(common, { binding, taskHash, timestamp, executionId });
    return common.isV2 ? Promise.resolve(preview) : preview;
  }

  if (common.isV2) {
    return executeApprovedV2(common, {
      evidenceProviderOverride,
      instanceId,
      requireEvidence,
      requireAuthorization,
      identityDebug,
      presentationDebug,
      approvalId,
      env,
      cwd,
      signer,
      signingKey: explicitSigningKey,
      binding,
      taskHash,
      timestamp,
      executionId,
    });
  }

  const approvalUsed = enforceApprovalGate({
    workflow: common.workflow,
    task: common.task,
    executionId,
    approvalId,
    env,
    binding,
    taskHash,
  });
  const liveCommon = prepareLiveCommon(common, {
    signer,
    signingKey: explicitSigningKey,
    cwd,
    env,
  });

  // v0.1 path: fully synchronous, preserves exact existing behavior
  return executeV1(liveCommon, { approvalUsed, binding, taskHash, timestamp, executionId });
}

async function inspectTaskGovernance(manifest, mode, {
  workflowId,
  taskId,
  instanceId,
  identityDebug = false,
  cwd = process.cwd(),
  env = process.env,
} = {}) {
  const common = resolveCommonState(manifest, {
    workflowId,
    taskId,
    cwd,
    env,
    allowUnsupportedHandoff: true,
  });
  const timestamp = new Date().toISOString();
  const executionId = generateExecutionId(common.workflow.id, common.task.id, timestamp);
  const binding = buildEffectiveExecutionBinding({
    manifest,
    expanded: common.expanded,
    workflow: common.workflow,
    task: common.task,
    cwd,
  });
  const taskHash = computeEffectiveTaskHash(binding);

  if (!common.isV2) {
    if (mode === 'authorization' || mode === 'proof') {
      throw Object.assign(
        new Error(`${mode === 'proof' ? 'Authorization proof verification' : 'Authorization evaluation'} requires a version 0.2 manifest`),
        { code: 'invalid_argument' }
      );
    }
    return {
      ok: true,
      mode,
      source: { workflow_id: common.workflow.id, task_id: common.task.id },
      declared_identity: binding.identity,
      resolved_identity: null,
      principal_used: resolvePrincipal(common.identity),
      trust: null,
      delegation: null,
      warnings: common.warnings,
    };
  }

  return executeV2(common, {
    inspectionMode: mode,
    instanceId,
    requireEvidence: false,
    requireAuthorization: mode === 'authorization',
    identityDebug: identityDebug || mode === 'delegation',
    presentationDebug: false,
    env,
    cwd,
    approvalUsed: null,
    binding,
    taskHash,
    timestamp,
    executionId,
  });
}

export function inspectTaskIdentity(manifest, options = {}) {
  return inspectTaskGovernance(manifest, 'identity', options);
}

export function validateTaskDelegation(manifest, options = {}) {
  return inspectTaskGovernance(manifest, 'delegation', options);
}

export function evaluateTaskAuthorization(manifest, options = {}) {
  return inspectTaskGovernance(manifest, 'authorization', options);
}

export function verifyTaskAuthorizationProof(manifest, options = {}) {
  return inspectTaskGovernance(manifest, 'proof', options);
}

function enforceApprovalGate({ workflow, task, executionId, approvalId, env, binding, taskHash }) {
  if (!task.approval) return null;
  if (approvalPolicyAutoRejects(task.approval)) {
    throw Object.assign(
      new Error(
        `Task "${task.id}" has approval.policy="auto-reject"; execution refused. ` +
        `Edit the manifest to change the policy, or run with --dry-run.`
      ),
      { code: 'approval_auto_rejected' }
    );
  }
  if (!approvalPolicyRequiresApproval(task.approval)) return null;
  const effectiveTaskHash = taskHash || computeTaskApprovalHash({ binding });
  const grant = claimApproval({
    workflowId: workflow.id,
    taskId: task.id,
    taskHash: effectiveTaskHash,
    approvalId,
    executionId,
    env,
  });
  if (!grant) {
    const approveCmd = `agentcli approve <manifest> ${task.id} --workflow ${workflow.id} --by <principal>`;
    const idHint = approvalId ? ` (--approval-id ${approvalId} did not match a pending grant)` : '';
    throw Object.assign(
      new Error(
        `Task "${task.id}" requires manual approval ` +
        `(policy=manual, risk=${task.approval.risk_level || 'unspecified'})${idHint}. ` +
        `No valid approval record found for this exact task. Run: ${approveCmd}`
      ),
      { code: 'approval_required' }
    );
  }
  const sigCheck = verifyApprovalSignature(grant, { env });
  if (sigCheck.verified === false) {
    // We have already consumed the grant atomically; a bad signature means
    // the record is corrupt or forged. Refuse execution and surface the
    // consumption in error context so an operator can audit.
    throw Object.assign(
      new Error(
        `Approval ${grant.approval_id} signature verification failed: ${sigCheck.reason || 'invalid signature'}. ` +
        `Refusing execution.`
      ),
      { code: 'approval_signature_invalid' }
    );
  }
  const currentScope = task.approval.approver_scope ?? null;
  if ((grant.approver_scope ?? null) !== currentScope || !approverMatchesScope(grant.approver, currentScope)) {
    throw Object.assign(
      new Error(`Approval ${grant.approval_id} does not satisfy the task's current approver scope`),
      { code: 'approval_scope_mismatch' }
    );
  }
  return {
    approval_id: grant.approval_id,
    task_hash: grant.task_hash,
    approver: grant.approver,
    reason: grant.reason ?? null,
    risk_level: grant.risk_level ?? null,
    approver_scope: grant.approver_scope ?? null,
    granted_at: grant.granted_at,
    expires_at: grant.expires_at,
    signature_verified: sigCheck.verified === true,
    signature: grant.signature
      ? { method: grant.signature.method, key_fingerprint: grant.signature.key_fingerprint }
      : null,
  };
}

// ---------------------------------------------------------------------------
// Delegation path -- non-shell tasks forwarded to a runtime adapter
// ---------------------------------------------------------------------------

function executeDelegated(common, options) {
  const { manifest, task, workflow } = common;
  const {
    schedulerPrefix, schedulerBin, dbPath, dryRun, cwd, env,
  } = options;

  const effectivePrefix = schedulerPrefix || env.AGENTCLI_SCHEDULER_PREFIX || '';
  const effectiveBin = schedulerBin || env.AGENTCLI_SCHEDULER_BIN || '';

  if (!dryRun && approvalPolicyAutoRejects(task.approval)) {
    throw Object.assign(
      new Error(`Task "${task.id}" has approval.policy="auto-reject"; runtime dispatch refused.`),
      { code: 'approval_auto_rejected' }
    );
  }

  if (!effectivePrefix && !effectiveBin && !dryRun) {
    throw Object.assign(
      new Error(
        `Task "${task.id || task.name}" requires runtime delegation ` +
        `(session_target: "${task.target?.session_target}") ` +
        'but no scheduler is configured. Set --scheduler-prefix, --scheduler-bin, AGENTCLI_SCHEDULER_PREFIX, or AGENTCLI_SCHEDULER_BIN.'
      ),
      { code: 'no_runtime' }
    );
  }

  const adapter = resolveRuntimeAdapter(task.target?.session_target);
  if (!adapter) {
    throw Object.assign(
      new Error(
        `No runtime adapter registered for session_target "${task.target?.session_target}"`
      ),
      { code: 'no_runtime' }
    );
  }

  return adapter.dispatch(manifest, task, workflow, {
    schedulerPrefix: effectivePrefix,
    schedulerBin: effectiveBin,
    dbPath,
    dryRun,
    cwd,
    env,
  });
}

// ---------------------------------------------------------------------------
// v0.1 execution path -- fully synchronous
// ---------------------------------------------------------------------------

function executeV1(common, { approvalUsed, binding, taskHash, timestamp, executionId }) {
  const {
    workflow, task, identity, contract, verify, auditPolicy, shell, sandboxCommand,
    effectiveTimeout, warnings, provider, providerConfig, cwd, env,
  } = common;

  let declaredIdentity = null;
  let resolvedIdentity = null;
  let trustInfo = null;
  const principal = resolvePrincipal(identity);

  const commandMeta = safeCommandMetadata(binding, shell, cwd);

  const cmdHash = commandHash(shell);

  function buildAndSign() {
    if (!providerConfig) {
      return {
        attestation: null,
        attestation_note: `no credentials found for signing provider "${provider.name}"`,
      };
    }

    const payload = buildAttestationPayload({
      executionId,
      timestamp,
      source: { workflow_id: workflow.id, task_id: task.id },
      commandHash: cmdHash,
      principal,
    });

    const sigResult = provider.sign(payload, providerConfig);
    if (!sigResult.signed) {
      return { attestation: null, attestation_note: sigResult.reason };
    }

    return { attestation: sigResult.attestation, attestation_note: null };
  }

  const spawnEnv = buildChildEnvironment(env, shell.env);

  const spawnOpts = {
    cwd: shell.cwd || cwd,
    env: spawnEnv,
    encoding: 'utf8',
    maxBuffer: 10 * 1024 * 1024,
  };

  if (effectiveTimeout) {
    spawnOpts.timeout = effectiveTimeout;
  }

  if (shell.stdin != null) {
    spawnOpts.input = shell.stdin;
  }

  const startMs = Date.now();
  const proc = spawnSync(sandboxCommand.program, sandboxCommand.args, spawnOpts);
  const durationMs = Date.now() - startMs;

  const stdout = proc.stdout || '';
  const stderr = proc.stderr || '';
  const exitCode = proc.status;
  const signal = proc.signal || null;
  const timedOut = Boolean(proc.error && proc.error.code === 'ETIMEDOUT') || signal === 'SIGTERM';

  const outputHash = createHash('sha256')
    .update(stdout)
    .update(stderr)
    .digest('hex');

  const outputFormat = task.output?.format ?? null;
  let structured = null;
  let structuredParseError = null;

  if (outputFormat === 'json' && stdout.trim()) {
    try {
      structured = JSON.parse(stdout);
    } catch (e) {
      structuredParseError = `output.format is "json" but stdout is not valid JSON: ${e.message}`;
    }
  } else if (outputFormat === 'ndjson' && stdout.trim()) {
    try {
      structured = stdout.trim().split('\n').map(line => JSON.parse(line));
    } catch (e) {
      structuredParseError = `output.format is "ndjson" but stdout contains invalid JSON lines: ${e.message}`;
    }
  }

  if (structuredParseError) {
    warnings.push(structuredParseError);
  }

  const result = {
    exit_code: exitCode,
    signal,
    timed_out: timedOut,
    duration_ms: durationMs,
    stdout,
    stderr,
    stdout_bytes: Buffer.byteLength(stdout, 'utf8'),
    stderr_bytes: Buffer.byteLength(stderr, 'utf8'),
    output_hash: `sha256:${outputHash}`,
    structured,
  };

  const { attestation, attestation_note } = buildAndSign();

  const auditResult = {
    exit_code: exitCode,
    signal,
    timed_out: timedOut,
    duration_ms: durationMs,
    stdout_bytes: result.stdout_bytes,
    stderr_bytes: result.stderr_bytes,
    output_hash: result.output_hash,
    structured_present: structured != null,
  };

  // ------------------------------------------------------------------
  // Post-execution verify phase
  // ------------------------------------------------------------------

  let verifyResult = null;
  let verifyFailed = false;
  if (verify && exitCode === 0) {
    verifyResult = runVerify(verify, {
      cwd: shell.cwd || cwd,
      env: spawnEnv,
      sandboxCommand,
    });
    if (!verifyResult.passed) {
      if (verify.on_failure === 'warn') {
        warnings.push(`Verify command failed (exit ${verifyResult.exit_code}): ${verifyResult.stderr || verifyResult.stdout || '(no output)'}`);
      } else {
        verifyFailed = true;
      }
    }
  }

  const effectiveOk = exitCode === 0 && !verifyFailed;

  const shouldAudit =
    auditPolicy === 'always' ||
    (auditPolicy === 'on-failure' && !effectiveOk);

  if (shouldAudit) {
    const record = {
      execution_id: executionId,
      timestamp,
      source: { workflow_id: workflow.id, task_id: task.id },
      declared_identity: declaredIdentity,
      resolved_identity: resolvedIdentity,
      identity: binding.identity,
      principal_used: principal,
      contract,
      command: commandMeta,
      command_hash: cmdHash,
      effective_task_hash: taskHash,
      manifest_digest: binding.manifest_digest,
      trust: trustInfo,
      signer: provider.name,
      attestation,
      attestation_note,
      verify: verifyResult,
      warnings,
      dry_run: false,
      result: auditResult,
      approval_used: approvalUsed,
    };
    const paths = getAgentcliPaths({ env: common.env });
    writeAuditRecord(record, { auditPath: paths.audit });
  }

  if (verifyFailed) {
    const verifyStdout = verifyResult.stdout || '';
    const verifyStderr = verifyResult.stderr || '';
    const detail = verifyStderr || verifyStdout || '(no output)';
    throw Object.assign(
      new Error(`Verify command failed (exit ${verifyResult.exit_code}): ${detail}`),
      {
        code: 'verify_failed',
        verify: verifyResult,
        execution_id: executionId,
        source: { workflow_id: workflow.id, task_id: task.id },
      }
    );
  }

  return {
    ok: effectiveOk,
    execution_id: executionId,
    source: { workflow_id: workflow.id, task_id: task.id },
    declared_identity: declaredIdentity,
    resolved_identity: resolvedIdentity,
    identity: binding.identity,
    principal_used: principal,
    contract,
    command: commandMeta,
    effective_task_hash: taskHash,
    manifest_digest: binding.manifest_digest,
    result,
    verify: verifyResult,
    trust: trustInfo,
    signer: provider.name,
    attestation: attestation ? { method: attestation.method, key_fingerprint: attestation.key_fingerprint } : null,
    attestation_note,
    warnings,
    audited: shouldAudit,
    approval_used: approvalUsed,
  };
}

// ---------------------------------------------------------------------------
// v0.2 execution path -- async (returns Promise)
// ---------------------------------------------------------------------------

async function executeV2(common, options) {
  const cleanupState = {};
  let primaryError = null;
  const warningStart = common.warnings.length;
  try {
    return await executeV2Core(common, options, cleanupState);
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    await cleanupProviderArtifacts(cleanupState.identityProviderInstance, {
      materialization: cleanupState.materialization,
      session: cleanupState.identitySession,
      providerConfig: cleanupState.providerConfig || {},
      env: common.env,
      commandEnv: cleanupState.commandEnv,
      cwd: common.cwd,
      runtimeCapabilities: cleanupState.runtimeCapabilities,
    }, common.warnings);
    await cleanupProviderArtifacts(cleanupState.identityProviderInstance, {
      session: cleanupState.handoffResult?.session ?? null,
      providerConfig: cleanupState.providerConfig || {},
      env: common.env,
      commandEnv: cleanupState.commandEnv,
      cwd: common.cwd,
      runtimeCapabilities: cleanupState.runtimeCapabilities,
      warningPrefix: 'Credential handoff cleanup',
    }, common.warnings);
    if (primaryError && common.warnings.length > warningStart) {
      primaryError.cleanup_warnings = common.warnings.slice(warningStart);
    }
  }
}

async function executeV2Core(common, {
  evidenceProviderOverride,
  instanceId,
  requireEvidence,
  requireAuthorization,
  identityDebug: includeIdentityDebug,
  presentationDebug: includePresentationDebug,
  env,
  approvalUsed,
  binding,
  taskHash,
  timestamp,
  executionId,
  inspectionMode = null,
}, cleanupState) {
  const {
    expanded, workflow, task, identity, contract, verify, auditPolicy, shell, sandboxCommand,
    effectiveTimeout, warnings, provider, providerConfig, cwd,
  } = common;

  const authorizationCommand = shell
    ? {
        program: shell.program,
        args: shell.args,
        cwd: shell.cwd || cwd,
        env_keys: Object.keys(shell.env),
        stdin_present: shell.stdin != null,
      }
    : {
        session_target: task.target?.session_target ?? null,
        payload_kind: task.target?.payload_kind ?? null,
      };
  const commandMeta = shell
    ? safeCommandMetadata(binding, shell, cwd)
    : binding.command;

  const cmdHash = shell
    ? commandHash(shell)
    : binding.command?.digest ?? binding.manifest_digest;
  const manifestDigest = binding.manifest_digest;
  const identityDeclaration = mergeIdentityProfile(
    identity.ref
      ? expanded.identity_profiles?.find(profile => profile.id === identity.ref) ?? null
      : null,
    identity
  );
  const authorizationProof = resolveAuthorizationProof(workflow, task);
  const authorization = resolveAuthorization(workflow, task);
  const evidence = resolveEvidence(workflow, task);
  const runtimeCapabilities = {
    credentialRefresh: false,
    credentialCache: false,
    credentialHandoff: false,
  };
  const identityCommandEnv = buildChildEnvironment(env, shell?.env || {});
  cleanupState.commandEnv = identityCommandEnv;
  cleanupState.runtimeCapabilities = runtimeCapabilities;

  // ------------------------------------------------------------------
  // Phase 1: Authorization Proof Verification
  // ------------------------------------------------------------------

  let authorizationProofSummary = null;
  const inspectIdentityOnly = inspectionMode === 'identity' || inspectionMode === 'delegation';
  const authorizationProofDeclaration = authorizationProof?.ref
    ? mergeAuthorizationProofProfile(
        expanded.authorization_proof_profiles?.find(profile => profile.id === authorizationProof.ref) ?? null,
        authorizationProof
      )
    : null;
  const proofRef = authorizationProofDeclaration?.ref ?? null;
  if (!inspectIdentityOnly && proofRef && authorizationProofDeclaration) {
    const proofBindingEnvironment = {
      AGENTCLI_MANIFEST_DIGEST: manifestDigest,
      AGENTCLI_EFFECTIVE_TASK_HASH: taskHash,
    };
    const proofEnv = { ...env, ...proofBindingEnvironment };
    const verifier = assertValidAuthorizationProofProfile(
      authorizationProofDeclaration,
      { env: proofEnv, cwd }
    );
    const method = authorizationProofDeclaration.method || 'none';
    const mustVerify = method !== 'none' || authorizationProofDeclaration.verify?.required === true;
    let verificationResult;
    try {
      const proofValue = authorizationProofDeclaration.proof?.value_from
        ? resolveValueFrom(authorizationProofDeclaration.proof.value_from, {
            env: proofEnv,
            commandEnv: buildChildEnvironment(env, proofBindingEnvironment),
            cwd,
            allowCommand: true,
          })
        : null;
      verificationResult = proofValue
        ? await verifyAuthorizationProof(proofValue, authorizationProofDeclaration, {
            manifest: expanded,
            manifestDigest,
            env: proofEnv,
            cwd,
          })
        : { verified: false, method, reason: 'proof value not available' };
    } catch (error) {
      verificationResult = {
        verified: false,
        method,
        reason: error.message,
      };
    }

    authorizationProofSummary = verifier.describeVerification(verificationResult, {});
    if (!verificationResult.verified && mustVerify) {
      if (auditPolicy !== 'none' && !inspectionMode) {
        const paths = getAgentcliPaths({ env });
        writeAuditRecord({
          execution_id: executionId,
          timestamp,
          source: { workflow_id: workflow.id, task_id: task.id },
          identity: binding.identity,
          authorization_proof: authorizationProofSummary,
          command: commandMeta,
          effective_task_hash: taskHash,
          manifest_digest: manifestDigest,
          result: null,
          warnings,
        }, { auditPath: paths.audit });
      }
      throw Object.assign(
        new Error(`Authorization proof verification failed: ${verificationResult.reason || 'verification failed'}`),
        { code: 'authorization_proof_failed' }
      );
    }
  }

  if (inspectionMode === 'proof') {
    if (!proofRef) {
      throw Object.assign(
        new Error('Authorization proof verification requires a resolved authorization_proof block'),
        { code: 'invalid_argument' }
      );
    }
    return {
      ok: true,
      mode: inspectionMode,
      source: { workflow_id: workflow.id, task_id: task.id },
      authorization_proof: authorizationProofSummary,
      effective_task_hash: taskHash,
      manifest_digest: manifestDigest,
      warnings,
    };
  }

  // ------------------------------------------------------------------
  // Phase 2: Identity Resolution (async -- resolveSession may return a Promise)
  // ------------------------------------------------------------------

  let declaredIdentity = null;
  let resolvedIdentity = null;
  let trustInfo = null;
  let principal;
  let identitySession = null;
  let identityProviderInstance = null;

  if (identity.ref) {
    const referencedIdentityProfile =
      expanded.identity_profiles?.find(profile => profile.id === identity.ref) ?? null;

    if (referencedIdentityProfile) {
      const providerName = identityDeclaration.provider || 'none';
      const idProvider = resolveIdentityProvider(providerName);
      identityProviderInstance = idProvider;
      cleanupState.identityProviderInstance = idProvider;
      cleanupState.providerConfig = identityDeclaration.auth?.provider_config || {};

      try {
        await assertProviderProfileValid(idProvider, identityDeclaration, 'Identity', {
          env,
          commandEnv: identityCommandEnv,
          cwd,
          runtimeCapabilities,
        });
        identitySession = normalizeIdentitySessionResult(
          await idProvider.resolveSession(
            {
              profile: identityDeclaration,
              instanceId,
              scope: identityDeclaration.scope ?? null,
              task_timeout_s: effectiveTimeout != null ? Math.max(1, Math.ceil(effectiveTimeout / 1000)) : null,
            },
            { env, commandEnv: identityCommandEnv, cwd, runtimeCapabilities }
          ),
          providerName
        );
        cleanupState.identitySession = identitySession;
        if (identitySession.delegation_validation?.valid === false) {
          throw Object.assign(
            new Error(`Identity provider "${providerName}" returned an invalid delegation chain`),
            {
              code: 'identity_resolution_failed',
              delegation_validation: identitySession.delegation_validation,
            }
          );
        }
        resolvedIdentity = idProvider.describeSession(identitySession, { env });
      } catch (resolveError) {
        // Write resolution failure audit record
        const subject = identityDeclaration.subject || {};
        const trustBlock = identityDeclaration.trust || {};
        declaredIdentity = {
          provider: providerName,
          subject: {
            principal: subject.principal || null,
            kind: subject.kind || null,
            issuer: subject.issuer || null,
          },
          trust_level: trustBlock.level || null,
        };

        const failRecord = {
          execution_id: executionId,
          timestamp,
          source: { workflow_id: workflow.id, task_id: task.id },
          declared_identity: declaredIdentity,
          resolved_identity: null,
          actor_context: buildActorContext({
            identityDeclaration,
            declaredIdentity,
            authorizationProofSummary,
            principal: subject.principal || resolvePrincipal(identityDeclaration),
            target: task.target,
          }),
          resolution_error: {
            phase: 'credential_acquisition',
            provider: providerName,
            code: resolveError.code || 'resolution_failed',
            message: resolveError.message,
            retryable: resolveError.retryable || false,
          },
          result: null,
          warnings,
        };
        if (auditPolicy !== 'none') {
          const paths = getAgentcliPaths({ env });
          writeAuditRecord(failRecord, { auditPath: paths.audit });
        }
        throw resolveError;
      }

      const subject = identityDeclaration.subject || {};
      const trustBlock = identityDeclaration.trust || {};
      declaredIdentity = {
        provider: providerName,
        subject: {
          principal: subject.principal || null,
          kind: subject.kind || null,
          issuer: subject.issuer || null,
        },
        trust_level: trustBlock.level || null,
      };

      const trustLevel = (identitySession.trust && identitySession.trust.declared_level) || trustBlock.level || null;
      trustInfo = {
        declared_level: trustLevel,
        effective_level: (identitySession.trust && identitySession.trust.effective_level) || trustLevel,
      };

      principal = (identitySession.subject && identitySession.subject.principal) || subject.principal || null;
      if (!principal) {
        principal = resolvePrincipal(identityDeclaration);
      }
    } else {
      principal = resolvePrincipal(identityDeclaration);
      declaredIdentity = {
        provider: 'none',
        subject: { principal: null, kind: null, issuer: null },
        trust_level: null,
      };
    }
  } else if (identityDeclaration.subject) {
    // v0.2 inline identity (no ref)
    const subject = identityDeclaration.subject || {};
    const trustBlock = identityDeclaration.trust || {};
    declaredIdentity = {
      provider: 'none',
      subject: {
        principal: subject.principal || null,
        kind: subject.kind || null,
        issuer: subject.issuer || null,
      },
      trust_level: trustBlock.level || null,
    };
    trustInfo = {
      declared_level: trustBlock.level || null,
      effective_level: trustBlock.level || null,
    };
    principal = subject.principal || resolvePrincipal(identityDeclaration);
  } else {
    principal = resolvePrincipal(identityDeclaration);
  }

  const identityDebug = includeIdentityDebug
    ? {
        session: identitySession ? redactSession(identitySession) : null,
        credential_summary: identitySession ? buildCredentialSummary(identitySession) : null,
      }
    : null;
  const actorContext = buildActorContext({
    identityDeclaration,
    declaredIdentity,
    resolvedIdentity,
    authorizationProofSummary,
    principal,
    target: task.target,
  });
  const stepUpContext = buildStepUpContext(authorizationProofSummary);
  let authorizationDecision = null;

  if (inspectIdentityOnly) {
    const safeDelegation = identityDebug?.session?.delegation_validation
      ?? resolvedIdentity?.delegation_validation
      ?? null;
    return {
      ok: true,
      mode: inspectionMode,
      source: { workflow_id: workflow.id, task_id: task.id },
      declared_identity: declaredIdentity,
      resolved_identity: resolvedIdentity,
      principal_used: principal,
      trust: trustInfo,
      delegation: safeDelegation,
      warnings,
      ...(includeIdentityDebug ? { identity_debug: identityDebug } : {}),
    };
  }

  function writePreExecutionFailureAuditRecord(failureKey, failureValue) {
    if (auditPolicy === 'none' || inspectionMode) return;
    const paths = getAgentcliPaths({ env });
    writeAuditRecord({
      execution_id: executionId,
      timestamp,
      source: { workflow_id: workflow.id, task_id: task.id },
      declared_identity: declaredIdentity,
      resolved_identity: resolvedIdentity,
      principal_used: principal,
      actor_context: actorContext,
      authorization_proof: authorizationProofSummary,
      authorization: authorizationDecision,
      trust: trustInfo,
      contract,
      command: commandMeta,
      warnings,
      dry_run: false,
      result: null,
      [failureKey]: failureValue,
    }, { auditPath: paths.audit });
  }

  // ------------------------------------------------------------------
  // Phase 4: Trust Level Enforcement
  // ------------------------------------------------------------------

  if (contract.required_trust_level) {
    const effectiveLevel = trustInfo?.effective_level || null;
    const enforcement = contract.trust_enforcement || 'none';
    if (!effectiveLevel) {
      if (enforcement === 'advisory') {
        warnings.push(`Trust level is not declared but contract requires "${contract.required_trust_level}" (advisory)`);
      } else if (enforcement === 'strict') {
        writePreExecutionFailureAuditRecord('trust_error', {
          code: 'trust_level_insufficient',
          message: `Trust level is not declared but contract requires "${contract.required_trust_level}"`,
        });
        throw Object.assign(
          new Error(`Trust level is not declared but contract requires "${contract.required_trust_level}"`),
          { code: 'trust_level_insufficient' }
        );
      }
      // enforcement === 'none': just record for audit
    } else {
    try {
      const cmp = compareTrustLevels(effectiveLevel, contract.required_trust_level);
      if (cmp < 0) {
        if (enforcement === 'advisory') {
          warnings.push(`Trust level "${effectiveLevel}" is below required "${contract.required_trust_level}" (advisory)`);
        } else if (enforcement === 'strict') {
          writePreExecutionFailureAuditRecord('trust_error', {
            code: 'trust_level_insufficient',
            message: `Trust level "${effectiveLevel}" is below required "${contract.required_trust_level}"`,
          });
          throw Object.assign(
            new Error(`Trust level "${effectiveLevel}" is below required "${contract.required_trust_level}"`),
            { code: 'trust_level_insufficient' }
          );
        }
        // enforcement === 'none': just record for audit
      }
    } catch (trustError) {
      if (trustError.code === 'trust_level_insufficient') {
        throw trustError;
      }
      if (enforcement === 'strict') {
        throw Object.assign(
          new Error(`Trust level comparison failed under strict enforcement: ${trustError.message}`),
          { code: 'trust_level_insufficient', cause: trustError }
        );
      }
      warnings.push(`Trust level comparison failed: ${trustError.message}`);
    }
    }
  }

  // ------------------------------------------------------------------
  // Phase 4.5: Authorization
  // ------------------------------------------------------------------

  const authorizationDeclaration = authorization?.ref
    ? mergeAuthorizationProfile(
        expanded.authorization_profiles?.find(profile => profile.id === authorization.ref) ?? null,
        authorization
      )
    : null;
  const authRef = authorizationDeclaration?.ref ?? null;
  if (authRef) {
    if (authorizationDeclaration) {
      const authProvider = resolveAuthorizationProvider(authorizationDeclaration.provider || 'none');
      await assertProviderProfileValid(authProvider, authorizationDeclaration, 'Authorization', { env, cwd });
      const includeFields = authorizationDeclaration.request?.include || ['identity', 'contract', 'command'];
      const authRequest = normalizeAuthorizationRequest({
        source: { workflow_id: workflow.id, task_id: task.id },
        identity: { principal, trust_level: trustInfo?.effective_level },
        contract,
        command: authorizationCommand,
        actor: actorContext,
        stepUp: stepUpContext,
        resource: null,
        trust: trustInfo,
        includeFields,
      });
      const rawDecision = await authProvider.authorize(authRequest, authorizationDeclaration, { env });
      const rawDecisionValue = typeof rawDecision === 'object' && rawDecision !== null
        ? (rawDecision.decision ?? rawDecision.result ?? rawDecision.value ?? rawDecision)
        : rawDecision;
      const decisionConfig = authorizationDeclaration.decision || {};
      const hasExplicitMapping = ['allow_values', 'deny_values', 'escalate_values']
        .some(key => Array.isArray(decisionConfig[key]) && decisionConfig[key].length > 0);
      const normalized = !hasExplicitMapping && ['permit', 'deny', 'require-escalation'].includes(rawDecisionValue)
        ? { decision: rawDecisionValue, original_value: rawDecisionValue, mapped: true }
        : normalizeDecision(rawDecisionValue, decisionConfig);
      authorizationDecision = authProvider.describeDecision(
        { ...(typeof rawDecision === 'object' && rawDecision !== null ? rawDecision : {}), decision: normalized.decision },
        {}
      );

      if (normalized.decision === 'deny') {
        if (inspectionMode !== 'authorization') {
          writePreExecutionFailureAuditRecord('authorization_error', {
            code: 'authorization_denied',
            message: 'Authorization denied',
          });
          throw Object.assign(
            new Error('Authorization denied'),
            { code: 'authorization_denied' }
          );
        }
      }
      if (normalized.decision === 'require-escalation') {
        if (inspectionMode !== 'authorization') {
          writePreExecutionFailureAuditRecord('authorization_error', {
            code: 'authorization_escalation_required',
            message: 'Authorization requires escalation',
          });
          throw Object.assign(
            new Error('Authorization requires escalation'),
            { code: 'authorization_escalation_required' }
          );
        }
      }
    }
  } else if (requireAuthorization) {
    throw Object.assign(
      new Error('--require-authorization specified but no authorization block resolved'),
      { code: 'invalid_argument' }
    );
  }

  if (inspectionMode === 'authorization') {
    return {
      ok: true,
      mode: inspectionMode,
      source: { workflow_id: workflow.id, task_id: task.id },
      declared_identity: declaredIdentity,
      resolved_identity: resolvedIdentity,
      principal_used: principal,
      trust: trustInfo,
      authorization_proof: authorizationProofSummary,
      authorization: authorizationDecision,
      warnings,
    };
  }

  // ------------------------------------------------------------------
  // Signing helper (shared by dry-run and live execution)
  // ------------------------------------------------------------------

  function buildAndSign() {
    if (!providerConfig) {
      return {
        attestation: null,
        attestation_note: `no credentials found for signing provider "${provider.name}"`,
      };
    }

    const payload = buildAttestationPayload({
      executionId,
      timestamp,
      source: { workflow_id: workflow.id, task_id: task.id },
      commandHash: cmdHash,
      principal,
    });

    const sigResult = provider.sign(payload, providerConfig);
    if (!sigResult.signed) {
      return { attestation: null, attestation_note: sigResult.reason };
    }

    return { attestation: sigResult.attestation, attestation_note: null };
  }

  // ------------------------------------------------------------------
  // Phase 3: Presentation Materialization
  // ------------------------------------------------------------------

  let materialization = null;
  const spawnEnv = { ...identityCommandEnv };

  if (identitySession && identityProviderInstance) {
    const presentation = identityDeclaration.presentation || {};
    materialization = await identityProviderInstance.materialize(
      identitySession,
      presentation,
      { env, commandEnv: identityCommandEnv, cwd, runtimeCapabilities }
    );
    cleanupState.materialization = materialization;
    // Merge materialized env vars into spawn environment
    if (materialization && materialization.env_vars) {
      Object.assign(spawnEnv, materialization.env_vars);
    }
  }

  // ------------------------------------------------------------------
  // Phase 3.5: Credential Handoff
  // ------------------------------------------------------------------

  let handoffResult = null;
  const declaredHandoff = identityDeclaration.presentation?.handoff || 'none';
  if (declaredHandoff !== 'none' && identitySession && identityProviderInstance) {
    throw Object.assign(
      new Error(
        `Credential handoff "${declaredHandoff}" cannot be enforced by the local shell runtime`
      ),
      { code: 'unsupported_capability' }
    );
  }

  const presentationDebug = includePresentationDebug
    ? {
        materialization: summarizeMaterialization(materialization),
        handoff: summarizeHandoff(handoffResult, declaredHandoff),
      }
    : null;

  const spawnOpts = {
    cwd: shell.cwd || cwd,
    env: spawnEnv,
    encoding: 'utf8',
    maxBuffer: 10 * 1024 * 1024,
  };

  if (effectiveTimeout) {
    spawnOpts.timeout = effectiveTimeout;
  }

  if (shell.stdin != null && materialization?.stdin != null) {
    throw Object.assign(
      new Error('Both shell.stdin and identity presentation target stdin; refusing ambiguous input'),
      { code: 'validation_error' }
    );
  }
  if (shell.stdin != null || materialization?.stdin != null) {
    spawnOpts.input = shell.stdin ?? materialization.stdin;
  }

  const startMs = Date.now();
  const proc = spawnSync(sandboxCommand.program, sandboxCommand.args, spawnOpts);
  const durationMs = Date.now() - startMs;

  const stdout = proc.stdout || '';
  const stderr = proc.stderr || '';
  const exitCode = proc.status;
  const signal = proc.signal || null;
  const timedOut = Boolean(proc.error && proc.error.code === 'ETIMEDOUT') || signal === 'SIGTERM';

  const outputHash = createHash('sha256')
    .update(stdout)
    .update(stderr)
    .digest('hex');

  const outputFormat = task.output?.format ?? null;
  let structured = null;
  let structuredParseError = null;

  if (outputFormat === 'json' && stdout.trim()) {
    try {
      structured = JSON.parse(stdout);
    } catch (e) {
      structuredParseError = `output.format is "json" but stdout is not valid JSON: ${e.message}`;
    }
  } else if (outputFormat === 'ndjson' && stdout.trim()) {
    try {
      structured = stdout.trim().split('\n').map(line => JSON.parse(line));
    } catch (e) {
      structuredParseError = `output.format is "ndjson" but stdout contains invalid JSON lines: ${e.message}`;
    }
  }

  if (structuredParseError) {
    warnings.push(structuredParseError);
  }

  const result = {
    exit_code: exitCode,
    signal,
    timed_out: timedOut,
    duration_ms: durationMs,
    stdout,
    stderr,
    stdout_bytes: Buffer.byteLength(stdout, 'utf8'),
    stderr_bytes: Buffer.byteLength(stderr, 'utf8'),
    output_hash: `sha256:${outputHash}`,
    structured,
  };

  const { attestation, attestation_note } = buildAndSign();

  let evidenceMetadata = null;
  const evidenceDeclaration = evidence?.ref
    ? mergeEvidenceProfile(
        expanded.evidence_profiles?.find(profile => profile.id === evidence.ref) ?? null,
        evidence
      )
    : null;
  const evidRef = evidenceDeclaration?.ref ?? null;

  const auditResult = {
    exit_code: exitCode,
    signal,
    timed_out: timedOut,
    duration_ms: durationMs,
    stdout_bytes: result.stdout_bytes,
    stderr_bytes: result.stderr_bytes,
    output_hash: result.output_hash,
    structured_present: structured != null,
  };

  // ------------------------------------------------------------------
  // Post-execution verify phase. Evidence is generated afterwards so its
  // signed payload binds this verification outcome as well as command output.
  // ------------------------------------------------------------------

  let verifyResult = null;
  let verifyFailed = false;
  if (verify && exitCode === 0) {
    verifyResult = runVerify(verify, {
      cwd: shell.cwd || cwd,
      env: spawnEnv,
      sandboxCommand,
    });
    if (!verifyResult.passed) {
      if (verify.on_failure === 'warn') {
        warnings.push(`Verify command failed (exit ${verifyResult.exit_code}): ${verifyResult.stderr || verifyResult.stdout || '(no output)'}`);
      } else {
        verifyFailed = true;
      }
    }
  }

  // ------------------------------------------------------------------
  // Phase 6: Complete, versioned evidence
  // ------------------------------------------------------------------

  const evidenceRequired = requireEvidence || evidenceDeclaration?.verify?.required === true;
  try {
    if (evidRef && evidenceDeclaration) {
      const evProvider = resolveEvidenceProvider({
        evidenceProvider: evidenceProviderOverride || evidenceDeclaration.provider,
        env,
      });
      const evConfig = evProvider.resolve(evidenceDeclaration.provider_config || {}, { env });
      const complianceCtx = collectComplianceContext(
        { compliance_context: {} },
        evidenceDeclaration.payload?.context || {}
      );
      const evPayload = buildCompleteEvidencePayload({
        executionId,
        timestamp,
        source: { workflow_id: workflow.id, task_id: task.id },
        manifestDigest: binding.manifest_digest,
        effectiveTaskHash: taskHash,
        declaredIdentity,
        resolvedIdentity,
        authorizationProof: authorizationProofSummary,
        authorization: authorizationDecision,
        actorContext,
        contract,
        command: {
          ...binding.command,
          env: spawnEnv,
          stdin: spawnOpts.input ?? null,
        },
        result,
        verify: verifyResult,
        complianceContext: complianceCtx,
      });
      const serialized = serializePayload(
        evPayload,
        evidenceDeclaration.payload?.format || 'canonical-json'
      );
      const attestResult = evProvider.attest(serialized, evConfig || {}, { env });
      if (attestResult.attested) {
        evidenceMetadata = {
          ...evProvider.describe(attestResult.envelope, {}),
          envelope: attestResult.envelope,
        };
      } else {
        evidenceMetadata = {
          provider: evProvider.name,
          attested: false,
          reason: attestResult.reason,
          envelope: null,
        };
      }
      if (evidenceRequired && !attestResult.attested) {
        throw Object.assign(
          new Error(`Evidence required but attestation failed: ${attestResult.reason}`),
          { code: 'evidence_failed' }
        );
      }
    } else if (evidenceRequired) {
      throw Object.assign(
        new Error('Evidence verification is required but no evidence block resolved'),
        { code: 'evidence_failed' }
      );
    }
  } catch (evidenceError) {
    const evidenceFailure = {
      code: evidenceError.code || 'evidence_failed',
      message: evidenceError.message,
    };
    if (auditPolicy !== 'none') {
      const paths = getAgentcliPaths({ env });
      writeAuditRecord({
        execution_id: executionId,
        timestamp,
        source: { workflow_id: workflow.id, task_id: task.id },
        declared_identity: declaredIdentity,
        resolved_identity: resolvedIdentity,
        principal_used: principal,
        actor_context: actorContext,
        authorization_proof: authorizationProofSummary,
        authorization: authorizationDecision,
        trust: trustInfo,
        contract,
        command: commandMeta,
        identity: binding.identity,
        effective_task_hash: taskHash,
        manifest_digest: binding.manifest_digest,
        verify: verifyResult,
        evidence: evidenceMetadata,
        evidence_error: evidenceFailure,
        warnings,
        dry_run: false,
        result: auditResult,
        approval_used: approvalUsed,
      }, { auditPath: paths.audit });
    }
    if (!evidenceError.code) evidenceError.code = 'evidence_failed';
    throw evidenceError;
  }

  const effectiveOk = exitCode === 0 && !verifyFailed;

  // ------------------------------------------------------------------
  // Phase 7: Enhanced Audit Record
  // ------------------------------------------------------------------

  const shouldAudit =
    auditPolicy === 'always' ||
    (auditPolicy === 'on-failure' && !effectiveOk);

  if (shouldAudit) {
    const record = {
      execution_id: executionId,
      timestamp,
      source: { workflow_id: workflow.id, task_id: task.id },
      declared_identity: declaredIdentity,
      resolved_identity: resolvedIdentity,
      principal_used: principal,
      actor_context: actorContext,
      step_up: stepUpContext,
      authorization_proof: authorizationProofSummary,
      authorization: authorizationDecision,
      trust: trustInfo,
      contract,
      command: commandMeta,
      hashes: { command: cmdHash, result: `sha256:${outputHash}` },
      handoff: { mode: declaredHandoff, prepared: handoffPrepared(handoffResult) },
      evidence: evidenceMetadata,
      identity: binding.identity,
      effective_task_hash: taskHash,
      manifest_digest: binding.manifest_digest,
      command_hash: cmdHash,
      signer: provider.name,
      attestation,
      attestation_note,
      verify: verifyResult,
      warnings,
      dry_run: false,
      result: auditResult,
      approval_used: approvalUsed,
    };
    const paths = getAgentcliPaths({ env });
    writeAuditRecord(record, { auditPath: paths.audit });
  }

  if (verifyFailed) {
    const verifyStdout = verifyResult.stdout || '';
    const verifyStderr = verifyResult.stderr || '';
    const detail = verifyStderr || verifyStdout || '(no output)';
    throw Object.assign(
      new Error(`Verify command failed (exit ${verifyResult.exit_code}): ${detail}`),
      {
        code: 'verify_failed',
        verify: verifyResult,
        execution_id: executionId,
        source: { workflow_id: workflow.id, task_id: task.id },
      }
    );
  }

  // ------------------------------------------------------------------
  // Return result
  // ------------------------------------------------------------------

  return {
    ok: effectiveOk,
    execution_id: executionId,
    source: { workflow_id: workflow.id, task_id: task.id },
    declared_identity: declaredIdentity,
    resolved_identity: resolvedIdentity,
    identity: binding.identity,
    principal_used: principal,
    actor_context: actorContext,
    step_up: stepUpContext,
    contract,
    command: commandMeta,
    effective_task_hash: taskHash,
    manifest_digest: binding.manifest_digest,
    result,
    verify: verifyResult,
    authorization_proof: authorizationProofSummary,
    authorization: authorizationDecision,
    trust: trustInfo,
    evidence: evidenceMetadata,
    hashes: { command: cmdHash, result: `sha256:${outputHash}` },
    handoff: { mode: declaredHandoff, prepared: handoffPrepared(handoffResult) },
    signer: provider.name,
    attestation: attestation ? { method: attestation.method, key_fingerprint: attestation.key_fingerprint } : null,
    attestation_note,
    warnings,
    audited: shouldAudit,
    approval_used: approvalUsed,
    ...(identityDebug ? { identity_debug: identityDebug } : {}),
    ...(presentationDebug ? { presentation_debug: presentationDebug } : {}),
  };
}
