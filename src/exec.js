import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { isAbsolute, relative, resolve as resolvePath } from 'node:path';
import { validateManifest } from './validate.js';
import { resolveCommandValue } from './command.js';
import { expandManifestShorthands } from './shorthand.js';
import { normalizeShellExecution } from './shell.js';
import {
  mergeAuthorizationProfile,
  mergeAuthorizationProofProfile,
  mergeEvidenceProfile,
  mergeIdentityProfile,
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
import { buildEvidencePayload, serializePayload, collectComplianceContext } from './evidence/payload.js';

// v0.2 authorization proof verifiers
import { resolveVerifier } from './authorization-proof/index.js';
import './authorization-proof/none.js';
import { resolveJwtVerificationContext } from './authorization-proof/jwt.js';
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

/**
 * Resolve a value_from indirection to a concrete string.
 *
 * Supports env (environment variable) and file (filesystem path) sources.
 *
 * @param {object} valueFrom - The value_from descriptor.
 * @param {object} envObj    - Environment variable map.
 * @returns {string|null} The resolved value, or null if unresolvable.
 */
function resolveValueFrom(valueFrom, envObj, { cwd = process.cwd() } = {}) {
  if (!valueFrom) return null;
  if (valueFrom.env) return envObj[valueFrom.env] || null;
  if (valueFrom.file) {
    try { return readFileSync(valueFrom.file, 'utf8').trim(); }
    catch { return null; }
  }
  if (valueFrom.literal) return valueFrom.literal;
  if (valueFrom.command) {
    return resolveCommandValue(valueFrom.command, { env: envObj, cwd });
  }
  return null;
}

function sortKeysDeep(value) {
  if (value === null || value === undefined) {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map(item => sortKeysDeep(item));
  }

  if (typeof value === 'object') {
    const sorted = {};
    for (const key of Object.keys(value).sort()) {
      sorted[key] = sortKeysDeep(value[key]);
    }
    return sorted;
  }

  return value;
}

function computeManifestDigest(manifest) {
  return createHash('sha256')
    .update(JSON.stringify(sortKeysDeep(manifest)))
    .digest('hex');
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
  cwd = process.cwd(),
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
      cwd,
      provider_config: providerConfig,
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
 * contract preflight, and signing provider resolution.
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
    return { requiresDelegation: true, manifest: expanded, workflow, task };
  }

  if (!task.shell) {
    throw Object.assign(
      new Error(`Task "${taskId}" is a shell target but has no shell block`),
      { code: 'validation_error' }
    );
  }

  const isV2 = manifest.version === '0.2' || Boolean(manifest.identity_profiles);

  const identity = resolveIdentity(workflow, task);
  const contract = resolveContract(workflow, task);
  const verify = resolveVerify(workflow, task);
  const auditPolicy = contract.audit ?? 'always';
  const shell = normalizeShellExecution(task.shell);
  const effectiveTimeout = timeoutMs ?? task.runtime?.timeout_ms ?? null;
  const { violations, warnings: preflightWarnings } = preflightContractChecks(contract, shell, { cwd });
  const sandboxCommand = prepareSandboxedShellCommand(shell, contract, { cwd, env });
  const warnings = [...preflightWarnings, ...sandboxCommand.warnings];

  if (violations.length > 0) {
    throw Object.assign(
      new Error(`Contract violation: ${violations.map(v => v.message).join('; ')}`),
      { code: 'contract_violation', violations, warnings }
    );
  }

  const provider = resolveProvider({ signer, env });
  const providerConfig = provider.resolve({ env, signingKey: explicitSigningKey });

  return {
    expanded, workflow, task, isV2, identity, contract, verify,
    auditPolicy, shell, sandboxCommand, effectiveTimeout, violations, warnings,
    provider, providerConfig, cwd, env,
  };
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
  // Resolve all common state (validation, lookup, preflight).
  // This throws synchronously for all error cases shared between v0.1 and v0.2.
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

  // v0.1 path: fully synchronous, preserves exact existing behavior
  if (!common.isV2) {
    return executeV1(common, { dryRun, approvalId });
  }

  // v0.2 path: returns a Promise (resolveSession may be async)
  return executeV2(common, {
    dryRun, evidenceProviderOverride, instanceId,
    requireEvidence, requireAuthorization,
    identityDebug, presentationDebug, approvalId, env,
  });
}

function enforceApprovalGate({ workflow, task, executionId, approvalId, env }) {
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
  const taskHash = computeTaskApprovalHash({ workflowId: workflow.id, task });
  const grant = claimApproval({
    workflowId: workflow.id,
    taskId: task.id,
    taskHash,
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
  return {
    approval_id: grant.approval_id,
    task_hash: grant.task_hash,
    approver: grant.approver,
    reason: grant.reason ?? null,
    risk_level: grant.risk_level ?? null,
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

function executeV1(common, { dryRun, approvalId }) {
  const {
    workflow, task, identity, contract, verify, auditPolicy, shell, sandboxCommand,
    effectiveTimeout, warnings, provider, providerConfig, cwd, env,
  } = common;

  let declaredIdentity = null;
  let resolvedIdentity = null;
  let trustInfo = null;
  const principal = resolvePrincipal(identity);

  const timestamp = new Date().toISOString();
  const executionId = generateExecutionId(workflow.id, task.id, timestamp);

  const commandMeta = {
    program: shell.program,
    args: shell.args,
    cwd: shell.cwd || cwd,
    env_keys: Object.keys(shell.env),
    stdin_present: shell.stdin != null,
  };

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

  if (dryRun) {
    const { attestation, attestation_note } = buildAndSign();

    const record = {
      execution_id: executionId,
      timestamp,
      source: { workflow_id: workflow.id, task_id: task.id },
      declared_identity: declaredIdentity,
      resolved_identity: resolvedIdentity,
      identity: {
        principal: identity.principal ?? (identity.subject?.principal ?? null),
        run_as: identity.run_as ?? null,
        attestation_present: identity.attestation != null,
      },
      principal_used: principal,
      contract,
      command: commandMeta,
      command_hash: cmdHash,
      authorization_proof: null,
      authorization: null,
      trust: trustInfo,
      signer: provider.name,
      attestation,
      attestation_note,
      warnings,
      dry_run: true,
      result: { status: 'dry_run' },
    };

    if (auditPolicy === 'always') {
      const paths = getAgentcliPaths({ env: common.env });
      writeAuditRecord(record, { auditPath: paths.audit });
    }

    return {
      ok: true,
      dry_run: true,
      execution_id: executionId,
      source: record.source,
      declared_identity: declaredIdentity,
      resolved_identity: resolvedIdentity,
      identity,
      principal_used: principal,
      contract,
      command: commandMeta,
      command_hash: cmdHash,
      authorization_proof: null,
      authorization: null,
      trust: trustInfo,
      signer: provider.name,
      attestation: attestation ? { method: attestation.method, key_fingerprint: attestation.key_fingerprint } : null,
      attestation_note,
      warnings,
    };
  }

  const approvalUsed = enforceApprovalGate({
    workflow, task, executionId, approvalId, env: common.env,
  });

  const spawnEnv = Object.keys(shell.env).length > 0
    ? { ...process.env, ...env, ...shell.env }
    : { ...process.env, ...env };

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
  if (verify && exitCode === 0 && !dryRun) {
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
      identity: {
        principal: identity.principal ?? (identity.subject?.principal ?? null),
        run_as: identity.run_as ?? null,
        attestation_present: identity.attestation != null,
      },
      principal_used: principal,
      contract,
      command: commandMeta,
      command_hash: cmdHash,
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
    identity,
    principal_used: principal,
    contract,
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

async function executeV2(common, {
  dryRun,
  evidenceProviderOverride,
  instanceId,
  requireEvidence,
  requireAuthorization,
  identityDebug: includeIdentityDebug,
  presentationDebug: includePresentationDebug,
  approvalId,
  env,
}) {
  const {
    expanded, workflow, task, identity, contract, verify, auditPolicy, shell, sandboxCommand,
    effectiveTimeout, warnings, provider, providerConfig, cwd,
  } = common;

  const timestamp = new Date().toISOString();
  const executionId = generateExecutionId(workflow.id, task.id, timestamp);

  const commandMeta = {
    program: shell.program,
    args: shell.args,
    cwd: shell.cwd || cwd,
    env_keys: Object.keys(shell.env),
    stdin_present: shell.stdin != null,
  };

  const cmdHash = commandHash(shell);
  const manifestDigest = computeManifestDigest(expanded);
  const identityDeclaration = mergeIdentityProfile(
    identity.ref
      ? expanded.identity_profiles?.find(profile => profile.id === identity.ref) ?? null
      : null,
    identity
  );
  const authorizationProof = resolveAuthorizationProof(workflow, task);
  const authorization = resolveAuthorization(workflow, task);
  const evidence = resolveEvidence(workflow, task);

  // ------------------------------------------------------------------
  // Phase 1: Authorization Proof Verification
  // ------------------------------------------------------------------

  let authorizationProofSummary = null;
  const authorizationProofDeclaration = authorizationProof?.ref
    ? mergeAuthorizationProofProfile(
        expanded.authorization_proof_profiles?.find(profile => profile.id === authorizationProof.ref) ?? null,
        authorizationProof
      )
    : null;
  const proofRef = authorizationProofDeclaration?.ref ?? null;
  if (proofRef) {
    if (authorizationProofDeclaration) {
      const verifier = resolveVerifier(authorizationProofDeclaration.method || 'none');
      const verifyRequired = authorizationProofDeclaration.verify?.required === true;

      let proofValue = null;
      if (authorizationProofDeclaration.proof?.value_from) {
        proofValue = resolveValueFrom(authorizationProofDeclaration.proof.value_from, env, { cwd });
      }

      if (proofValue) {
        let verificationContext = {
          env,
          manifestDigest,
        };
        if (authorizationProofDeclaration.method === 'jwt') {
          verificationContext = await resolveJwtVerificationContext(
            proofValue,
            authorizationProofDeclaration,
            verificationContext,
          );
        }
        const verifyResult = await verifier.verifyProof(
          proofValue,
          authorizationProofDeclaration,
          verificationContext,
        );
        authorizationProofSummary = verifier.describeVerification(verifyResult, {});

        if (verifyRequired && !verifyResult.verified) {
          const failRecord = {
            execution_id: executionId,
            timestamp,
            source: { workflow_id: workflow.id, task_id: task.id },
            declared_identity: {
              provider: identityDeclaration.provider || 'none',
              subject: {
                principal: identityDeclaration.subject?.principal || null,
                kind: identityDeclaration.subject?.kind || null,
                issuer: identityDeclaration.subject?.issuer || null,
              },
              trust_level: identityDeclaration.trust?.level || null,
            },
            actor_context: buildActorContext({
              identityDeclaration,
              authorizationProofSummary,
              principal: resolvePrincipal(identityDeclaration),
              target: task.target,
            }),
            authorization_proof: authorizationProofSummary,
            resolved_identity: null,
            result: null,
            warnings,
          };
          const paths = getAgentcliPaths({ env });
          writeAuditRecord(failRecord, { auditPath: paths.audit });
          throw Object.assign(
            new Error(`Authorization proof verification failed: ${verifyResult.reason || 'verification failed'}`),
            { code: 'authorization_proof_failed' }
          );
        }
      } else if (verifyRequired) {
        const failRecord = {
          execution_id: executionId,
          timestamp,
          source: { workflow_id: workflow.id, task_id: task.id },
          declared_identity: {
            provider: identityDeclaration.provider || 'none',
            subject: {
              principal: identityDeclaration.subject?.principal || null,
              kind: identityDeclaration.subject?.kind || null,
              issuer: identityDeclaration.subject?.issuer || null,
            },
            trust_level: identityDeclaration.trust?.level || null,
          },
          actor_context: buildActorContext({
            identityDeclaration,
            authorizationProofSummary: {
              method: authorizationProofDeclaration.method,
              verified: false,
              reason: 'proof value not available',
            },
            principal: resolvePrincipal(identityDeclaration),
            target: task.target,
          }),
          authorization_proof: {
            method: authorizationProofDeclaration.method,
            verified: false,
            reason: 'proof value not available'
          },
          resolved_identity: null,
          result: null,
          warnings,
        };
        const paths = getAgentcliPaths({ env });
        writeAuditRecord(failRecord, { auditPath: paths.audit });
        throw Object.assign(
          new Error(`Authorization proof value not available for "${proofRef}"`),
          { code: 'authorization_proof_failed' }
        );
      }
    }
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

      try {
        identitySession = normalizeIdentitySessionResult(
          await idProvider.resolveSession(
            {
              profile: identityDeclaration,
              instanceId,
              scope: identityDeclaration.scope ?? null,
              task_timeout_s: effectiveTimeout != null ? Math.max(1, Math.ceil(effectiveTimeout / 1000)) : null,
            },
            { env, cwd }
          ),
          providerName
        );
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

  function writePreExecutionFailureAuditRecord(failureKey, failureValue) {
    if (auditPolicy === 'none') return;
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

  if (contract.required_trust_level && trustInfo) {
    const effectiveLevel = trustInfo.effective_level || null;
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
      // Unknown trust levels: treat as warning
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
      const includeFields = authorizationDeclaration.request?.include || ['identity', 'contract', 'command'];
      const authRequest = normalizeAuthorizationRequest({
        source: { workflow_id: workflow.id, task_id: task.id },
        identity: { principal, trust_level: trustInfo?.effective_level },
        contract,
        command: commandMeta,
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
      const normalized = normalizeDecision(rawDecisionValue, authorizationDeclaration.decision || {});
      authorizationDecision = authProvider.describeDecision(
        { ...(typeof rawDecision === 'object' && rawDecision !== null ? rawDecision : {}), decision: normalized.decision },
        {}
      );

      if (normalized.decision === 'deny') {
        writePreExecutionFailureAuditRecord('authorization_error', {
          code: 'authorization_denied',
          message: 'Authorization denied',
        });
        throw Object.assign(
          new Error('Authorization denied'),
          { code: 'authorization_denied' }
        );
      }
      if (normalized.decision === 'require-escalation') {
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
  } else if (requireAuthorization) {
    throw Object.assign(
      new Error('--require-authorization specified but no authorization block resolved'),
      { code: 'invalid_argument' }
    );
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
  const spawnEnv = Object.keys(shell.env).length > 0
    ? { ...process.env, ...common.env, ...shell.env }
    : { ...process.env, ...common.env };

  if (identitySession && identityProviderInstance) {
    const presentation = identityDeclaration.presentation || {};
    materialization = identityProviderInstance.materialize(identitySession, presentation, { env });
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
    if (identityProviderInstance.prepareHandoff && identityProviderInstance.capabilities?.handoff_modes?.includes(declaredHandoff)) {
      try {
        handoffResult = await identityProviderInstance.prepareHandoff(
          identitySession,
          {
            mode: declaredHandoff,
            target_scope: identityDeclaration.scope ?? identityDeclaration.auth?.scopes?.[0] ?? null,
            parent_profile: identityDeclaration,
          },
          { env, cwd }
        );
      } catch (err) {
        warnings.push(`Credential handoff (${declaredHandoff}) failed: ${err.message}`);
      }
    } else {
      warnings.push(`Credential handoff "${declaredHandoff}" requested but provider does not support it`);
    }
  }

  const presentationDebug = includePresentationDebug
    ? {
        materialization: summarizeMaterialization(materialization),
        handoff: summarizeHandoff(handoffResult, declaredHandoff),
      }
    : null;

  // ------------------------------------------------------------------
  // Dry-run exit point
  // ------------------------------------------------------------------

  if (dryRun) {
    const identityProviderConfig = identityDeclaration.auth?.provider_config || {};
    await cleanupProviderArtifacts(identityProviderInstance, {
      materialization,
      session: identitySession,
      providerConfig: identityProviderConfig,
      env,
      cwd,
    }, warnings);
    await cleanupProviderArtifacts(identityProviderInstance, {
      session: handoffResult?.session ?? null,
      providerConfig: identityProviderConfig,
      env,
      cwd,
      warningPrefix: 'Credential handoff cleanup',
    }, warnings);

    const { attestation, attestation_note } = buildAndSign();

    const record = {
      execution_id: executionId,
      timestamp,
      source: { workflow_id: workflow.id, task_id: task.id },
      declared_identity: declaredIdentity,
      resolved_identity: resolvedIdentity,
      identity: identityDeclaration,
      principal_used: principal,
      actor_context: actorContext,
      step_up: stepUpContext,
      authorization_proof: authorizationProofSummary,
      authorization: authorizationDecision,
      contract,
      command: commandMeta,
      command_hash: cmdHash,
      trust: trustInfo,
      hashes: { command: cmdHash, result: null },
      handoff: { mode: declaredHandoff, prepared: handoffPrepared(handoffResult) },
      signer: provider.name,
      attestation,
      attestation_note,
      warnings,
      dry_run: true,
      result: { status: 'dry_run' },
    };

    if (auditPolicy === 'always') {
      const paths = getAgentcliPaths({ env });
      writeAuditRecord(record, { auditPath: paths.audit });
    }

    return {
      ok: true,
      dry_run: true,
      execution_id: executionId,
      source: record.source,
      declared_identity: declaredIdentity,
      resolved_identity: resolvedIdentity,
      identity: identityDeclaration,
      principal_used: principal,
      actor_context: actorContext,
      step_up: stepUpContext,
      contract,
      command: commandMeta,
      command_hash: cmdHash,
      authorization_proof: authorizationProofSummary,
      authorization: authorizationDecision,
      trust: trustInfo,
      hashes: { command: cmdHash, result: null },
      handoff: { mode: declaredHandoff, prepared: handoffPrepared(handoffResult) },
      signer: provider.name,
      attestation: attestation ? { method: attestation.method, key_fingerprint: attestation.key_fingerprint } : null,
      attestation_note,
      warnings,
      ...(identityDebug ? { identity_debug: identityDebug } : {}),
      ...(presentationDebug ? { presentation_debug: presentationDebug } : {}),
    };
  }

  // ------------------------------------------------------------------
  // Live execution: spawn the process
  // ------------------------------------------------------------------

  const approvalUsed = enforceApprovalGate({
    workflow, task, executionId, approvalId, env,
  });

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

  // ------------------------------------------------------------------
  // Phase 6: Evidence
  // ------------------------------------------------------------------

  let evidenceMetadata = null;
  const evidenceDeclaration = evidence?.ref
    ? mergeEvidenceProfile(
        expanded.evidence_profiles?.find(profile => profile.id === evidence.ref) ?? null,
        evidence
      )
    : null;
  const evidRef = evidenceDeclaration?.ref ?? null;
  if (evidRef) {
    if (evidenceDeclaration) {
      const evProvider = resolveEvidenceProvider({
        evidenceProvider: evidenceProviderOverride || evidenceDeclaration.provider,
        env
      });
      const evConfig = evProvider.resolve(evidenceDeclaration.provider_config || {}, { env });
      const bindTargets = evidenceDeclaration.payload?.bind || ['execution_id', 'command', 'result'];
      const complianceCtx = collectComplianceContext({ compliance_context: {} }, evidenceDeclaration.payload?.context || {});
      const evPayload = buildEvidencePayload({
        executionId,
        timestamp,
        source: { workflow_id: workflow.id, task_id: task.id },
        declaredIdentity,
        resolvedIdentity,
        authorizationProof: authorizationProofSummary,
        authorization: authorizationDecision,
        actorContext,
        contract,
        command: commandMeta,
        result: {
          exit_code: exitCode,
          duration_ms: durationMs,
          stdout_bytes: result.stdout_bytes,
          stderr_bytes: result.stderr_bytes,
          structured_present: structured != null,
          output_hash: result.output_hash,
        },
        complianceContext: complianceCtx,
        bindTargets,
      });
      const serialized = serializePayload(evPayload, evidenceDeclaration.payload?.format || 'canonical-json');
      const attestResult = evProvider.attest(serialized, evConfig || {}, { env });
      if (attestResult.attested) {
        evidenceMetadata = evProvider.describe(attestResult.envelope, {});
      } else {
        evidenceMetadata = { provider: evProvider.name, attested: false, reason: attestResult.reason };
      }

      if (requireEvidence && !attestResult.attested) {
        throw Object.assign(
          new Error(`Evidence required but attestation failed: ${attestResult.reason}`),
          { code: 'evidence_failed' }
        );
      }
    }
  } else if (requireEvidence) {
    throw Object.assign(
      new Error('--require-evidence specified but no evidence block resolved'),
      { code: 'invalid_argument' }
    );
  }

  // ------------------------------------------------------------------
  // Post-execution verify phase
  //
  // Runs AFTER evidence attestation. Evidence proves what the command did
  // (exit status, output hashes); verify is an operator-local check that
  // the expected deliverable exists. These are complementary, not sequential
  // dependencies. If end-to-end proof including verify is needed, extend the
  // evidence payload rather than reordering phases.
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

  const identityProviderConfig = identityDeclaration.auth?.provider_config || {};
  await cleanupProviderArtifacts(identityProviderInstance, {
    materialization,
    session: identitySession,
    providerConfig: identityProviderConfig,
    env,
    cwd,
  }, warnings);
  await cleanupProviderArtifacts(identityProviderInstance, {
    session: handoffResult?.session ?? null,
    providerConfig: identityProviderConfig,
    env,
    cwd,
    warningPrefix: 'Credential handoff cleanup',
  }, warnings);

  // ------------------------------------------------------------------
  // Phase 7: Enhanced Audit Record
  // ------------------------------------------------------------------

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
      identity: identityDeclaration,
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
    identity: identityDeclaration,
    principal_used: principal,
    actor_context: actorContext,
    step_up: stepUpContext,
    contract,
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
