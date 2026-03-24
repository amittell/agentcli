import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { validateManifest } from './validate.js';
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
  resolveIdentity
} from './compiler/shared.js';
import { generateExecutionId, writeAuditRecord } from './audit.js';
import { getAgentcliPaths } from './home.js';
import { buildAttestationPayload, commandHash } from './attestation.js';
import { resolveProvider } from './signing/index.js';

// Ensure the ssh signing provider is registered on import
import './signing/ssh.js';

// v0.2 identity providers
import { resolveProvider as resolveIdentityProvider } from './identity/index.js';
import './identity/none.js';
import './identity/env-bearer.js';
import './identity/file-bearer.js';
import './identity/oidc-client-credentials.js';
import './identity/oidc-token-exchange.js';
import { compareTrustLevels, redactSession, buildCredentialSummary } from './identity/session.js';

// v0.2 evidence providers
import { resolveEvidenceProvider } from './evidence/index.js';
import './evidence/none.js';
import './evidence/ssh.js';
import { buildEvidencePayload, serializePayload, collectComplianceContext } from './evidence/payload.js';

// v0.2 authorization proof verifiers
import { resolveVerifier } from './authorization-proof/index.js';
import './authorization-proof/none.js';
import './authorization-proof/jwt.js';
import './authorization-proof/detached-signature.js';
import './authorization-proof/certificate.js';

// v0.2 authorization providers
import { resolveAuthorizationProvider, normalizeAuthorizationRequest, normalizeDecision } from './authorization/index.js';
import './authorization/none.js';
import './authorization/opa.js';

function preflightContractChecks(contract, shell) {
  const violations = [];
  const warnings = [];

  if (contract.allowed_paths && shell.cwd) {
    const allowed = contract.allowed_paths.some(p =>
      shell.cwd === p || shell.cwd.startsWith(p.endsWith('/') ? p : `${p}/`)
    );
    if (!allowed) {
      violations.push({
        field: 'contract.allowed_paths',
        message: `shell.cwd "${shell.cwd}" is not under any allowed path`
      });
    }
  }

  if (contract.sandbox === 'strict') {
    warnings.push('contract.sandbox is "strict" but OS-level sandboxing is not yet enforced by agentcli exec');
  }
  if (contract.sandbox === 'permissive') {
    warnings.push('contract.sandbox is "permissive"; execution proceeds with advisory logging');
  }
  if (contract.network === 'none') {
    warnings.push('contract.network is "none" but network blocking is not yet enforced by agentcli exec');
  }
  if (contract.network === 'restricted') {
    warnings.push('contract.network is "restricted"; execution proceeds with advisory logging');
  }

  return { violations, warnings };
}

function resolvePrincipal(identity) {
  if (identity.principal) return identity.principal;
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
function resolveValueFrom(valueFrom, envObj) {
  if (!valueFrom) return null;
  if (valueFrom.env) return envObj[valueFrom.env] || null;
  if (valueFrom.file) {
    try { return readFileSync(valueFrom.file, 'utf8').trim(); }
    catch { return null; }
  }
  if (valueFrom.literal) return valueFrom.literal;
  return null;
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

function summarizeHandoff(handoffResult, mode) {
  if (!handoffResult && !mode) return null;
  return {
    mode: mode ?? handoffResult?.mode ?? null,
    prepared: Boolean(handoffResult?.prepared),
    credential_types: handoffResult?.credentials ? Object.keys(handoffResult.credentials) : [],
    reason: handoffResult?.reason ?? null,
  };
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
    throw Object.assign(
      new Error(
        `exec only supports shell-target tasks. Task "${taskId}" has session_target "${task.target?.session_target}". ` +
        'Prompt-based tasks require an agent runtime.'
      ),
      { code: 'invalid_argument' }
    );
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
  const auditPolicy = contract.audit ?? 'always';
  const shell = normalizeShellExecution(task.shell);
  const effectiveTimeout = timeoutMs ?? task.runtime?.timeout_ms ?? null;
  const { violations, warnings } = preflightContractChecks(contract, shell);

  if (violations.length > 0) {
    throw Object.assign(
      new Error(`Contract violation: ${violations.map(v => v.message).join('; ')}`),
      { code: 'contract_violation', violations, warnings }
    );
  }

  const provider = resolveProvider({ signer, env });
  const providerConfig = provider.resolve({ env, signingKey: explicitSigningKey });

  return {
    expanded, workflow, task, isV2, identity, contract,
    auditPolicy, shell, effectiveTimeout, violations, warnings,
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
  cwd = process.cwd(),
  env = process.env,
} = {}) {
  // Resolve all common state (validation, lookup, preflight).
  // This throws synchronously for all error cases shared between v0.1 and v0.2.
  const common = resolveCommonState(manifest, {
    workflowId, taskId, signer, signingKey: explicitSigningKey,
    cwd, env, timeoutMs,
  });

  // v0.1 path: fully synchronous, preserves exact existing behavior
  if (!common.isV2) {
    return executeV1(common, { dryRun });
  }

  // v0.2 path: returns a Promise (resolveSession may be async)
  return executeV2(common, {
    dryRun, evidenceProviderOverride, instanceId,
    requireEvidence, requireAuthorization,
    identityDebug, presentationDebug, env,
  });
}

// ---------------------------------------------------------------------------
// v0.1 execution path -- fully synchronous
// ---------------------------------------------------------------------------

function executeV1(common, { dryRun }) {
  const {
    workflow, task, identity, contract, auditPolicy, shell,
    effectiveTimeout, warnings, provider, providerConfig, cwd,
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

  const spawnEnv = Object.keys(shell.env).length > 0
    ? { ...process.env, ...shell.env }
    : process.env;

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
  const proc = spawnSync(shell.program, shell.args, spawnOpts);
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

  const shouldAudit =
    auditPolicy === 'always' ||
    (auditPolicy === 'on-failure' && exitCode !== 0);

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
      warnings,
      dry_run: false,
      result: auditResult,
    };
    const paths = getAgentcliPaths({ env: common.env });
    writeAuditRecord(record, { auditPath: paths.audit });
  }

  return {
    ok: exitCode === 0,
    execution_id: executionId,
    source: { workflow_id: workflow.id, task_id: task.id },
    declared_identity: declaredIdentity,
    resolved_identity: resolvedIdentity,
    identity,
    principal_used: principal,
    contract,
    result,
    trust: trustInfo,
    signer: provider.name,
    attestation: attestation ? { method: attestation.method, key_fingerprint: attestation.key_fingerprint } : null,
    attestation_note,
    warnings,
    audited: shouldAudit,
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
  env,
}) {
  const {
    expanded, workflow, task, identity, contract, auditPolicy, shell,
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
        proofValue = resolveValueFrom(authorizationProofDeclaration.proof.value_from, env);
      }

      if (proofValue) {
        const verifyResult = verifier.verifyProof(proofValue, authorizationProofDeclaration, { env });
        authorizationProofSummary = verifier.describeVerification(verifyResult, {});

        if (verifyRequired && !verifyResult.verified) {
          const failRecord = {
            execution_id: executionId,
            timestamp,
            source: { workflow_id: workflow.id, task_id: task.id },
            declared_identity: null,
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
          declared_identity: null,
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
  const identityDeclaration = mergeIdentityProfile(
    identity.ref
      ? expanded.identity_profiles?.find(profile => profile.id === identity.ref) ?? null
      : null,
    identity
  );

  if (identity.ref) {
    const referencedIdentityProfile =
      expanded.identity_profiles?.find(profile => profile.id === identity.ref) ?? null;

    if (referencedIdentityProfile) {
      const providerName = identityDeclaration.provider || 'none';
      const idProvider = resolveIdentityProvider(providerName);
      identityProviderInstance = idProvider;

      try {
        identitySession = await idProvider.resolveSession({ profile: identityDeclaration, instanceId }, { env });
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

  // ------------------------------------------------------------------
  // Phase 4: Trust Level Enforcement
  // ------------------------------------------------------------------

  if (contract.required_trust_level && trustInfo) {
    const effectiveLevel = trustInfo.effective_level || 'supervised';
    try {
      const cmp = compareTrustLevels(effectiveLevel, contract.required_trust_level);
      if (cmp < 0) {
        const enforcement = contract.trust_enforcement || 'none';
        if (enforcement === 'advisory') {
          warnings.push(`Trust level "${effectiveLevel}" is below required "${contract.required_trust_level}" (advisory)`);
        } else if (enforcement === 'strict') {
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

  // ------------------------------------------------------------------
  // Phase 4.5: Authorization
  // ------------------------------------------------------------------

  let authorizationDecision = null;
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
        throw Object.assign(
          new Error('Authorization denied'),
          { code: 'authorization_denied' }
        );
      }
      if (normalized.decision === 'require-escalation') {
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
    ? { ...process.env, ...shell.env }
    : { ...process.env };

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
        handoffResult = identityProviderInstance.prepareHandoff(identitySession, { mode: declaredHandoff }, { env });
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
    const { attestation, attestation_note } = buildAndSign();

    const record = {
      execution_id: executionId,
      timestamp,
      source: { workflow_id: workflow.id, task_id: task.id },
      declared_identity: declaredIdentity,
      resolved_identity: resolvedIdentity,
      identity: identityDeclaration,
      principal_used: principal,
      authorization_proof: authorizationProofSummary,
      authorization: authorizationDecision,
      contract,
      command: commandMeta,
      command_hash: cmdHash,
      trust: trustInfo,
      hashes: { command: cmdHash, result: null },
      handoff: { mode: declaredHandoff, prepared: Boolean(handoffResult) },
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

    // Phase 8: Cleanup (even on dry-run if materialization occurred)
    if (materialization && materialization.cleanup_required && identityProviderInstance) {
      try {
        identityProviderInstance.cleanup(materialization, { env });
      } catch (cleanupErr) {
        warnings.push(`Credential cleanup warning: ${cleanupErr.message}`);
      }
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
      contract,
      command: commandMeta,
      command_hash: cmdHash,
      authorization_proof: authorizationProofSummary,
      authorization: authorizationDecision,
      trust: trustInfo,
      hashes: { command: cmdHash, result: null },
      handoff: { mode: declaredHandoff, prepared: Boolean(handoffResult) },
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
  const proc = spawnSync(shell.program, shell.args, spawnOpts);
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
    (auditPolicy === 'on-failure' && exitCode !== 0);

  if (shouldAudit) {
    const record = {
      execution_id: executionId,
      timestamp,
      source: { workflow_id: workflow.id, task_id: task.id },
      declared_identity: declaredIdentity,
      resolved_identity: resolvedIdentity,
      principal_used: principal,
      authorization_proof: authorizationProofSummary,
      authorization: authorizationDecision,
      trust: trustInfo,
      contract,
      command: commandMeta,
      hashes: { command: cmdHash, result: `sha256:${outputHash}` },
      handoff: { mode: declaredHandoff, prepared: Boolean(handoffResult) },
      evidence: evidenceMetadata,
      identity: identityDeclaration,
      command_hash: cmdHash,
      signer: provider.name,
      attestation,
      attestation_note,
      warnings,
      dry_run: false,
      result: auditResult,
    };
    const paths = getAgentcliPaths({ env });
    writeAuditRecord(record, { auditPath: paths.audit });
  }

  // ------------------------------------------------------------------
  // Phase 8: Cleanup
  // ------------------------------------------------------------------

  if (materialization && materialization.cleanup_required && identityProviderInstance) {
    try {
      identityProviderInstance.cleanup(materialization, { env });
    } catch (cleanupErr) {
      warnings.push(`Credential cleanup warning: ${cleanupErr.message}`);
    }
  }

  // ------------------------------------------------------------------
  // Return result
  // ------------------------------------------------------------------

  return {
    ok: exitCode === 0,
    execution_id: executionId,
    source: { workflow_id: workflow.id, task_id: task.id },
    declared_identity: declaredIdentity,
    resolved_identity: resolvedIdentity,
    identity: identityDeclaration,
    principal_used: principal,
    contract,
    result,
    authorization_proof: authorizationProofSummary,
    authorization: authorizationDecision,
    trust: trustInfo,
    evidence: evidenceMetadata,
    hashes: { command: cmdHash, result: `sha256:${outputHash}` },
    handoff: { mode: declaredHandoff, prepared: Boolean(handoffResult) },
    signer: provider.name,
    attestation: attestation ? { method: attestation.method, key_fingerprint: attestation.key_fingerprint } : null,
    attestation_note,
    warnings,
    audited: shouldAudit,
    ...(identityDebug ? { identity_debug: identityDebug } : {}),
    ...(presentationDebug ? { presentation_debug: presentationDebug } : {}),
  };
}
