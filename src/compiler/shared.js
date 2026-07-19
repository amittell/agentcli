import { createHash } from 'node:crypto';
import { realpathSync } from 'node:fs';
import { resolve as resolvePath } from 'node:path';
import { normalizeShellExecution, renderShellExecution } from '../shell.js';
import { canonicalDigest, canonicalStringify, hashNullableString, hashString } from '../canonical.js';

export const OPERATIONAL_ENV_KEYS = new Set([
  'PATH', 'HOME', 'TMPDIR', 'TMP', 'TEMP',
  'LANG', 'SHELL', 'USER', 'LOGNAME', 'TZ', 'TERM',
  'SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT',
]);

export function buildChildEnvironment(env = {}, declaredEnv = {}) {
  const inherited = {};
  for (const [key, value] of Object.entries(env || {})) {
    if (OPERATIONAL_ENV_KEYS.has(key) || key.startsWith('LC_')) {
      inherited[key] = value;
    }
  }
  return { ...inherited, ...declaredEnv };
}

export function resolveExecutionCwd(shellCwd, cwd = process.cwd()) {
  const resolved = resolvePath(cwd, shellCwd || '.');
  try {
    return realpathSync(resolved);
  } catch (error) {
    if (error?.code === 'ENOENT' || error?.code === 'ENOTDIR') return resolved;
    throw error;
  }
}

function isObjectLike(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

export function stableId(workflowId, taskId) {
  return createHash('sha256').update(`${workflowId}:${taskId}`).digest('hex').slice(0, 32);
}

export function payloadKindForTask(task) {
  if (task.target?.session_target === 'shell') return 'shellCommand';
  if (task.target?.payload_kind) return task.target.payload_kind;
  if (task.target?.session_target === 'main') return 'systemEvent';
  return 'agentTurn';
}

export function payloadForTask(task) {
  if (task.target?.session_target === 'shell') return normalizeShellExecution(task.shell);
  return { prompt: task.prompt };
}

export function payloadMessageForExecution(execution) {
  if (execution.payload_kind === 'shellCommand') return renderShellExecution(execution.payload);
  return execution.payload.prompt;
}

export function approvalPolicyForTask(task) {
  const approval = task.approval || null;
  if (!approval) {
    return {
      required: 0,
      timeout_s: null,
      auto: null,
      policy: 'none',
      risk_level: null,
      approver_scope: null,
    };
  }

  const policy = approval.policy || (approval.required ? 'manual' : null);
  const required = policy === 'manual'
    ? 1
    : Number(Boolean(approval.required ?? false));
  const auto = policy === 'auto-approve'
    ? 'approve'
    : policy === 'auto-reject'
      ? 'reject'
      : policy === 'manual'
        ? (approval.auto ?? 'reject')
        : approval.auto ?? null;

  return {
    required,
    timeout_s: approval.timeout_s ?? 3600,
    auto,
    policy: policy || 'none',
    risk_level: approval.risk_level ?? 'medium',
    approver_scope: approval.approver_scope ?? null,
  };
}

export function taskInvocationForTask(task) {
  if (task.trigger) {
    return {
      mode: 'trigger',
      parent: task.trigger.parent,
      on: task.trigger.on,
      delay_s: task.trigger.delay_s ?? 0,
      condition: task.trigger.condition ?? null,
    };
  }

  return {
    mode: 'schedule',
    cron: task.schedule.cron,
    tz: task.schedule.tz ?? 'UTC',
  };
}

function resolveModelPolicy(workflow, task) {
  const workflowPolicy = workflow.model_policy || {};
  const taskPolicy = task.model_policy || {};
  const provider = taskPolicy.provider ?? workflowPolicy.provider ?? null;
  const model = taskPolicy.model ?? workflowPolicy.model ?? null;
  const thinking = taskPolicy.thinking ?? workflowPolicy.thinking ?? null;
  const schedulerModel = provider && model ? `${provider}/${model}` : model;
  return {
    provider,
    model,
    thinking,
    scheduler_model: schedulerModel ?? null,
  };
}

export function resolveIdentity(workflow, task) {
  const workflowIdentity = workflow.identity || {};
  const taskIdentity = task.identity || {};

  // v0.2 path: identity has ref or subject
  if (
    taskIdentity.ref ||
    taskIdentity.scope ||
    taskIdentity.subject ||
    taskIdentity.auth ||
    taskIdentity.trust ||
    taskIdentity.presentation ||
    workflowIdentity.ref ||
    workflowIdentity.scope ||
    workflowIdentity.subject ||
    workflowIdentity.auth ||
    workflowIdentity.trust ||
    workflowIdentity.presentation
  ) {
    return resolveIdentityV2(workflowIdentity, taskIdentity);
  }

  // v0.1 path: flat identity
  return {
    principal: taskIdentity.principal ?? workflowIdentity.principal ?? null,
    run_as: taskIdentity.run_as ?? workflowIdentity.run_as ?? null,
    attestation: taskIdentity.attestation ?? workflowIdentity.attestation ?? null,
  };
}

export function resolveIdentityV2(workflowIdentity, taskIdentity) {
  // ref: task replaces workflow
  const ref = taskIdentity.ref ?? workflowIdentity.ref ?? null;
  const scope = taskIdentity.scope ?? workflowIdentity.scope ?? null;

  // subject: merge key by key
  const workflowSubject = workflowIdentity.subject || {};
  const taskSubject = taskIdentity.subject || {};
  const subject = {
    kind: taskSubject.kind ?? workflowSubject.kind ?? null,
    principal: taskSubject.principal ?? workflowSubject.principal ?? null,
    display_name: taskSubject.display_name ?? workflowSubject.display_name ?? null,
    run_as: taskSubject.run_as ?? workflowSubject.run_as ?? null,
    issuer: taskSubject.issuer ?? workflowSubject.issuer ?? null,
    delegation_mode: taskSubject.delegation_mode ?? workflowSubject.delegation_mode ?? null,
    attributes: taskSubject.attributes ?? workflowSubject.attributes ?? null,
  };

  // auth: merge key by key, delegation_policy merges key by key
  const workflowAuth = workflowIdentity.auth || {};
  const taskAuth = taskIdentity.auth || {};
  const workflowDelegation = workflowAuth.delegation_policy || {};
  const taskDelegation = taskAuth.delegation_policy || {};
  const providerConfig = {
    ...(isObjectLike(workflowAuth.provider_config) ? workflowAuth.provider_config : {}),
    ...(isObjectLike(taskAuth.provider_config) ? taskAuth.provider_config : {}),
  };
  const inputs = {
    ...(isObjectLike(workflowAuth.inputs) ? workflowAuth.inputs : {}),
    ...(isObjectLike(taskAuth.inputs) ? taskAuth.inputs : {}),
  };
  const delegationPolicy = {
    max_depth: taskDelegation.max_depth ?? workflowDelegation.max_depth ?? null,
    allowed_delegators: taskDelegation.allowed_delegators ?? workflowDelegation.allowed_delegators ?? null,
    require_grant_per_hop: taskDelegation.require_grant_per_hop ?? workflowDelegation.require_grant_per_hop ?? null,
  };
  const auth = {
    mode: taskAuth.mode ?? workflowAuth.mode ?? null,
    scopes: taskAuth.scopes ?? workflowAuth.scopes ?? null,
    audience: taskAuth.audience ?? workflowAuth.audience ?? null,
    resource: taskAuth.resource ?? workflowAuth.resource ?? null,
    cache: taskAuth.cache ?? workflowAuth.cache ?? null,
    refresh: taskAuth.refresh ?? workflowAuth.refresh ?? null,
    required: taskAuth.required ?? workflowAuth.required ?? null,
    delegation_policy: Object.values(delegationPolicy).some(value => value != null)
      ? delegationPolicy
      : null,
    provider_config: Object.keys(providerConfig).length > 0 ? providerConfig : null,
    inputs: Object.keys(inputs).length > 0 ? inputs : null,
  };

  // trust: merge key by key, constraints merge key by key
  const workflowTrust = workflowIdentity.trust || {};
  const taskTrust = taskIdentity.trust || {};
  const workflowConstraints = workflowTrust.constraints || {};
  const taskConstraints = taskTrust.constraints || {};
  const trust = {
    level: taskTrust.level ?? workflowTrust.level ?? null,
    constraints: {
      escalation: taskConstraints.escalation ?? workflowConstraints.escalation ?? null,
      max_autonomy: taskConstraints.max_autonomy ?? workflowConstraints.max_autonomy ?? null,
      escalation_timeout: taskConstraints.escalation_timeout ?? workflowConstraints.escalation_timeout ?? null,
      require_justification: taskConstraints.require_justification ?? workflowConstraints.require_justification ?? null,
    },
  };

  // presentation: bindings REPLACE (not merge), other fields merge
  const workflowPres = workflowIdentity.presentation || {};
  const taskPres = taskIdentity.presentation || {};
  const presentation = {
    bindings: taskPres.bindings ?? workflowPres.bindings ?? null,
    handoff: taskPres.handoff ?? workflowPres.handoff ?? null,
    cleanup: taskPres.cleanup ?? workflowPres.cleanup ?? null,
    default_redaction: taskPres.default_redaction ?? workflowPres.default_redaction ?? null,
  };

  return { ref, scope, subject, auth, trust, presentation };
}

export function resolveContract(workflow, task) {
  const workflowContract = workflow.contract || {};
  const taskContract = task.contract || {};
  return {
    sandbox: taskContract.sandbox ?? workflowContract.sandbox ?? null,
    allowed_paths: taskContract.allowed_paths ?? workflowContract.allowed_paths ?? null,
    network: taskContract.network ?? workflowContract.network ?? null,
    max_cost_usd: taskContract.max_cost_usd ?? workflowContract.max_cost_usd ?? null,
    audit: taskContract.audit ?? workflowContract.audit ?? null,
    required_trust_level: taskContract.required_trust_level ?? workflowContract.required_trust_level ?? null,
    trust_enforcement: taskContract.trust_enforcement ?? workflowContract.trust_enforcement ?? null,
  };
}

export function resolveAuthorizationProof(workflow, task) {
  const workflowProof = workflow.authorization_proof || {};
  const taskProof = task.authorization_proof || {};
  const ref = taskProof.ref ?? workflowProof.ref ?? null;
  if (!ref) return null;

  const workflowClaims = isObjectLike(workflowProof.claims) ? workflowProof.claims : {};
  const taskClaims = isObjectLike(taskProof.claims) ? taskProof.claims : {};
  const claims = { ...workflowClaims, ...taskClaims };

  const workflowRequired = workflowProof.verify?.required ?? null;
  const taskRequired = taskProof.verify?.required ?? null;
  let required;
  if (workflowRequired === true && taskRequired === false) {
    required = true;
  } else {
    required = taskRequired ?? workflowRequired ?? null;
  }

  return { ref, claims: Object.keys(claims).length > 0 ? claims : null, verify: { required } };
}

export function resolveAuthorization(workflow, task) {
  const workflowAuth = workflow.authorization || {};
  const taskAuth = task.authorization || {};
  const ref = taskAuth.ref ?? workflowAuth.ref ?? null;
  if (!ref) return null;

  const providerConfig = {
    ...(isObjectLike(workflowAuth.provider_config) ? workflowAuth.provider_config : {}),
    ...(isObjectLike(taskAuth.provider_config) ? taskAuth.provider_config : {}),
  };

  const workflowOnError = workflowAuth.on_error ?? null;
  const taskOnError = taskAuth.on_error ?? null;
  let onError;
  if (workflowOnError === 'deny' && taskOnError === 'warn') {
    onError = 'deny';
  } else {
    onError = taskOnError ?? workflowOnError ?? null;
  }

  const request = isObjectLike(taskAuth.request)
    ? taskAuth.request
    : isObjectLike(workflowAuth.request)
      ? workflowAuth.request
      : null;
  const decision = isObjectLike(taskAuth.decision)
    ? taskAuth.decision
    : isObjectLike(workflowAuth.decision)
      ? workflowAuth.decision
      : null;

  return {
    ref,
    provider_config: Object.keys(providerConfig).length > 0 ? providerConfig : null,
    on_error: onError,
    request,
    decision,
  };
}

export function resolveEvidence(workflow, task) {
  const workflowEvidence = workflow.evidence || {};
  const taskEvidence = task.evidence || {};
  const ref = taskEvidence.ref ?? workflowEvidence.ref ?? null;
  if (!ref) return null;

  const workflowPayload = workflowEvidence.payload || {};
  const taskPayload = taskEvidence.payload || {};
  const payload = {
    bind: taskPayload.bind ?? workflowPayload.bind ?? null,
    context: isObjectLike(taskPayload.context)
      ? taskPayload.context
      : isObjectLike(workflowPayload.context)
        ? workflowPayload.context
        : null,
    format: taskPayload.format ?? workflowPayload.format ?? null,
  };

  const workflowRequired = workflowEvidence.verify?.required ?? null;
  const taskRequired = taskEvidence.verify?.required ?? null;
  let required;
  if (workflowRequired === true && taskRequired === false) {
    required = true;
  } else {
    required = taskRequired ?? workflowRequired ?? null;
  }

  return { ref, payload, verify: { required } };
}

function mergeRequiredFlag(baseRequired, overrideRequired) {
  if (baseRequired === true && overrideRequired === false) {
    return true;
  }
  return overrideRequired ?? baseRequired ?? null;
}

function mergeDenyFirst(baseMode, overrideMode) {
  if (baseMode === 'deny' && overrideMode === 'warn') {
    return 'deny';
  }
  return overrideMode ?? baseMode ?? null;
}

export function mergeIdentityProfile(profile, identity) {
  const base = profile || {};
  const declaration = identity || {};

  const baseSubject = base.subject || {};
  const declarationSubject = declaration.subject || {};
  const baseAuth = base.auth || {};
  const declarationAuth = declaration.auth || {};
  const baseTrust = base.trust || {};
  const declarationTrust = declaration.trust || {};
  const baseConstraints = baseTrust.constraints || {};
  const declarationConstraints = declarationTrust.constraints || {};
  const basePresentation = base.presentation || {};
  const declarationPresentation = declaration.presentation || {};

  const providerConfig = {
    ...(isObjectLike(baseAuth.provider_config) ? baseAuth.provider_config : {}),
    ...(isObjectLike(declarationAuth.provider_config) ? declarationAuth.provider_config : {}),
  };
  const inputs = {
    ...(isObjectLike(baseAuth.inputs) ? baseAuth.inputs : {}),
    ...(isObjectLike(declarationAuth.inputs) ? declarationAuth.inputs : {}),
  };
  const delegationPolicy = {
    max_depth: declarationAuth.delegation_policy?.max_depth ?? baseAuth.delegation_policy?.max_depth ?? null,
    allowed_delegators: declarationAuth.delegation_policy?.allowed_delegators ?? baseAuth.delegation_policy?.allowed_delegators ?? null,
    require_grant_per_hop: declarationAuth.delegation_policy?.require_grant_per_hop ?? baseAuth.delegation_policy?.require_grant_per_hop ?? null,
  };

  return {
    ref: declaration.ref ?? base.id ?? null,
    scope: declaration.scope ?? base.scope ?? null,
    provider: base.provider ?? null,
    subject: {
      kind: declarationSubject.kind ?? baseSubject.kind ?? null,
      principal: declarationSubject.principal ?? baseSubject.principal ?? null,
      display_name: declarationSubject.display_name ?? baseSubject.display_name ?? null,
      run_as: declarationSubject.run_as ?? baseSubject.run_as ?? null,
      issuer: declarationSubject.issuer ?? baseSubject.issuer ?? null,
      delegation_mode: declarationSubject.delegation_mode ?? baseSubject.delegation_mode ?? null,
      attributes: declarationSubject.attributes ?? baseSubject.attributes ?? null,
    },
    auth: {
      mode: declarationAuth.mode ?? baseAuth.mode ?? null,
      scopes: declarationAuth.scopes ?? baseAuth.scopes ?? null,
      audience: declarationAuth.audience ?? baseAuth.audience ?? null,
      resource: declarationAuth.resource ?? baseAuth.resource ?? null,
      cache: declarationAuth.cache ?? baseAuth.cache ?? null,
      refresh: declarationAuth.refresh ?? baseAuth.refresh ?? null,
      required: declarationAuth.required ?? baseAuth.required ?? null,
      delegation_policy: Object.values(delegationPolicy).some(value => value != null)
        ? delegationPolicy
        : null,
      provider_config: Object.keys(providerConfig).length > 0 ? providerConfig : null,
      inputs: Object.keys(inputs).length > 0 ? inputs : null,
    },
    trust: {
      level: declarationTrust.level ?? baseTrust.level ?? null,
      constraints: {
        escalation: declarationConstraints.escalation ?? baseConstraints.escalation ?? null,
        max_autonomy: declarationConstraints.max_autonomy ?? baseConstraints.max_autonomy ?? null,
        escalation_timeout: declarationConstraints.escalation_timeout ?? baseConstraints.escalation_timeout ?? null,
        require_justification: declarationConstraints.require_justification ?? baseConstraints.require_justification ?? null,
      },
    },
    presentation: {
      bindings: declarationPresentation.bindings ?? basePresentation.bindings ?? null,
      handoff: declarationPresentation.handoff ?? basePresentation.handoff ?? null,
      cleanup: declarationPresentation.cleanup ?? basePresentation.cleanup ?? null,
      default_redaction: declarationPresentation.default_redaction ?? basePresentation.default_redaction ?? null,
    },
  };
}

export function mergeAuthorizationProofProfile(profile, declaration) {
  const base = profile || {};
  const overlay = declaration || {};
  const claims = {
    ...(isObjectLike(base.claims) ? base.claims : {}),
    ...(isObjectLike(overlay.claims) ? overlay.claims : {}),
  };

  return {
    ref: overlay.ref ?? base.id ?? null,
    method: base.method ?? null,
    issuer: base.issuer ?? null,
    audience: base.audience ?? null,
    jwks_uri: base.jwks_uri ?? null,
    public_key: base.public_key ?? null,
    allowed_signers: base.allowed_signers ?? null,
    principal: base.principal ?? null,
    namespace: base.namespace ?? null,
    ca_certificate: base.ca_certificate ?? null,
    ca_certificate_from: base.ca_certificate_from ?? null,
    proof: base.proof ?? null,
    claims: Object.keys(claims).length > 0 ? claims : null,
    verify: {
      required: mergeRequiredFlag(base.verify?.required ?? null, overlay.verify?.required ?? null),
    },
  };
}

export function mergeAuthorizationProfile(profile, declaration) {
  const base = profile || {};
  const overlay = declaration || {};
  const providerConfig = {
    ...(isObjectLike(base.provider_config) ? base.provider_config : {}),
    ...(isObjectLike(overlay.provider_config) ? overlay.provider_config : {}),
  };

  return {
    ref: overlay.ref ?? base.id ?? null,
    provider: base.provider ?? null,
    provider_config: Object.keys(providerConfig).length > 0 ? providerConfig : null,
    on_error: mergeDenyFirst(base.on_error ?? null, overlay.on_error ?? null),
    request: isObjectLike(overlay.request)
      ? overlay.request
      : isObjectLike(base.request)
        ? base.request
        : null,
    decision: isObjectLike(overlay.decision)
      ? overlay.decision
      : isObjectLike(base.decision)
        ? base.decision
        : null,
  };
}

export function mergeEvidenceProfile(profile, declaration) {
  const base = profile || {};
  const overlay = declaration || {};
  const basePayload = base.payload || {};
  const overlayPayload = overlay.payload || {};

  return {
    ref: overlay.ref ?? base.id ?? null,
    provider: base.provider ?? null,
    methods: base.methods ?? null,
    provider_config: isObjectLike(base.provider_config) ? base.provider_config : null,
    payload: {
      bind: overlayPayload.bind ?? basePayload.bind ?? null,
      context: isObjectLike(overlayPayload.context)
        ? overlayPayload.context
        : isObjectLike(basePayload.context)
          ? basePayload.context
          : null,
      format: overlayPayload.format ?? basePayload.format ?? null,
    },
    verify: {
      required: mergeRequiredFlag(base.verify?.required ?? null, overlay.verify?.required ?? null),
    },
  };
}

const VALID_CHILD_CREDENTIAL_POLICIES = ['none', 'inherit', 'downscope', 'independent'];

export function resolveChildCredentialPolicy(workflow, task) {
  const value = task.child_credential_policy ?? workflow.child_credential_policy ?? null;
  if (value === null) return null;
  if (!VALID_CHILD_CREDENTIAL_POLICIES.includes(value)) {
    throw new Error(
      `Invalid child_credential_policy "${value}"; must be one of: ${VALID_CHILD_CREDENTIAL_POLICIES.join(', ')}`,
    );
  }
  return value;
}

function resolveIntent(task) {
  if (!task.intent) {
    return { mode: 'execute', read_only: null };
  }
  return {
    mode: task.intent.mode ?? 'execute',
    read_only: task.intent.read_only != null ? Boolean(task.intent.read_only) : null,
  };
}

function resolveOutput(task) {
  return {
    format: task.output?.format ?? null,
    preview_bytes: task.output?.preview_bytes ?? 2000,
    offload: task.output?.offload ?? 'auto',
    retrieve: task.output?.retrieve ?? 'on-demand',
  };
}

function hashObject(value) {
  return value && typeof value === 'object' ? canonicalDigest(value) : null;
}

function bindIdentity(identity) {
  if (!identity) return null;
  return {
    ref: identity.ref ?? null,
    scope: identity.scope ?? null,
    provider: identity.provider ?? null,
    subject: identity.subject
      ? {
          kind: identity.subject.kind ?? null,
          principal: identity.subject.principal ?? null,
          display_name: identity.subject.display_name ?? null,
          run_as: identity.subject.run_as ?? null,
          issuer: identity.subject.issuer ?? null,
          delegation_mode: identity.subject.delegation_mode ?? null,
          attributes_hash: hashObject(identity.subject.attributes),
        }
      : null,
    auth: identity.auth
      ? {
          mode: identity.auth.mode ?? null,
          scopes: identity.auth.scopes ?? null,
          audience: identity.auth.audience ?? null,
          resource: identity.auth.resource ?? null,
          cache: identity.auth.cache ?? null,
          refresh: identity.auth.refresh ?? null,
          required: identity.auth.required ?? null,
          delegation_policy: identity.auth.delegation_policy ?? null,
          provider_config_hash: hashObject(identity.auth.provider_config),
          inputs_hash: hashObject(identity.auth.inputs),
        }
      : null,
    trust: identity.trust ?? null,
    presentation: identity.presentation ?? null,
  };
}

function bindAuthorizationProof(proof) {
  if (!proof) return null;
  return {
    ref: proof.ref ?? null,
    method: proof.method ?? null,
    issuer: proof.issuer ?? null,
    audience: proof.audience ?? null,
    jwks_uri: proof.jwks_uri ?? null,
    public_key_hash: hashNullableString(proof.public_key),
    allowed_signers: proof.allowed_signers ?? null,
    principal: proof.principal ?? null,
    namespace: proof.namespace ?? null,
    ca_certificate_hash: hashNullableString(proof.ca_certificate),
    ca_certificate_from_hash: hashObject(proof.ca_certificate_from),
    proof_hash: hashObject(proof.proof),
    claims_hash: hashObject(proof.claims),
    verify: proof.verify ?? null,
  };
}

function bindAuthorization(authorization) {
  if (!authorization) return null;
  return {
    ref: authorization.ref ?? null,
    provider: authorization.provider ?? null,
    provider_config_hash: hashObject(authorization.provider_config),
    on_error: authorization.on_error ?? null,
    request: authorization.request ?? null,
    decision: authorization.decision ?? null,
  };
}

function bindEvidence(evidence) {
  if (!evidence) return null;
  return {
    ref: evidence.ref ?? null,
    provider: evidence.provider ?? null,
    methods: evidence.methods ?? null,
    provider_config_hash: hashObject(evidence.provider_config),
    payload: evidence.payload ?? null,
    verify: evidence.verify ?? null,
  };
}

export function commandBindingForShell(shell, {
  cwd = process.cwd(),
  env = process.env,
} = {}) {
  const normalized = normalizeShellExecution(shell || {});
  const effectiveEnv = buildChildEnvironment(env, normalized.env || {});
  const envHashes = {};
  for (const key of Object.keys(effectiveEnv).sort()) {
    envHashes[key] = hashString(effectiveEnv[key]);
  }
  return {
    program: normalized.program,
    args_hashes: (normalized.args || []).map(arg => hashString(arg)),
    args_count: (normalized.args || []).length,
    cwd: resolveExecutionCwd(normalized.cwd, cwd),
    env_keys: Object.keys(envHashes),
    env_hashes: envHashes,
    stdin_hash: hashNullableString(normalized.stdin),
  };
}

export function buildEffectiveExecutionBinding({
  manifest = null,
  expanded = manifest,
  workflow,
  task,
  cwd = process.cwd(),
  env = process.env,
  timeoutMs,
  instanceId,
  bindingVersion = 1,
} = {}) {
  if (!workflow || !task) {
    throw new TypeError('workflow and task are required to build an execution binding');
  }
  if (!Number.isInteger(bindingVersion) || bindingVersion < 1) {
    throw new TypeError('bindingVersion must be a positive integer');
  }

  const resolvedIdentity = resolveIdentity(workflow, task);
  const identityProfile = resolvedIdentity?.ref
    ? expanded?.identity_profiles?.find(profile => profile.id === resolvedIdentity.ref) ?? null
    : null;
  const identity = mergeIdentityProfile(identityProfile, resolvedIdentity);

  const proofRef = resolveAuthorizationProof(workflow, task);
  const proofProfile = proofRef?.ref
    ? expanded?.authorization_proof_profiles?.find(profile => profile.id === proofRef.ref) ?? null
    : null;
  const proof = proofRef ? mergeAuthorizationProofProfile(proofProfile, proofRef) : null;

  const authorizationRef = resolveAuthorization(workflow, task);
  const authorizationProfile = authorizationRef?.ref
    ? expanded?.authorization_profiles?.find(profile => profile.id === authorizationRef.ref) ?? null
    : null;
  const authorization = authorizationRef
    ? mergeAuthorizationProfile(authorizationProfile, authorizationRef)
    : null;

  const evidenceRef = resolveEvidence(workflow, task);
  const evidenceProfile = evidenceRef?.ref
    ? expanded?.evidence_profiles?.find(profile => profile.id === evidenceRef.ref) ?? null
    : null;
  const evidence = evidenceRef ? mergeEvidenceProfile(evidenceProfile, evidenceRef) : null;

  return {
    binding_version: bindingVersion,
    manifest_version: expanded?.version ?? manifest?.version ?? null,
    manifest_digest: manifest
      ? canonicalDigest(manifest)
      : expanded
        ? canonicalDigest(expanded)
        : null,
    source: { workflow_id: workflow.id, task_id: task.id },
    enabled: task.enabled ?? true,
    target: task.target ?? null,
    command: task.shell ? commandBindingForShell(task.shell, { cwd, env }) : null,
    prompt_hash: hashNullableString(task.prompt),
    runtime: {
      timeout_ms: timeoutMs ?? task.runtime?.timeout_ms ?? null,
      instance_id: instanceId ?? null,
    },
    approval: approvalPolicyForTask(task),
    identity: bindIdentity(identity),
    contract: resolveContract(workflow, task),
    authorization_proof: bindAuthorizationProof(proof),
    authorization: bindAuthorization(authorization),
    evidence: bindEvidence(evidence),
    child_credential_policy: resolveChildCredentialPolicy(workflow, task),
    verify: resolveVerify(workflow, task),
    output: resolveOutput(task),
    intent: resolveIntent(task),
    delete_after_run: task.delete_after_run ?? null,
  };
}

export function computeEffectiveTaskHash(binding) {
  return canonicalDigest(binding);
}

export function canonicalExecutionBindingString(binding) {
  return canonicalStringify(binding);
}

function resolveBudgets(task) {
  return {
    max_iterations: task.budgets?.max_iterations ?? null,
    max_fanout: task.budgets?.max_fanout ?? 25,
    max_context_items: task.budgets?.max_context_items ?? task.context?.limit ?? 5,
    max_pending_approvals: task.budgets?.max_pending_approvals ?? 10,
    max_queued_dispatches: task.budgets?.max_queued_dispatches ?? 25,
  };
}

export function resolveVerify(workflow, task) {
  const workflowVerify = workflow.verify || null;
  const taskVerify = task.verify || null;
  if (!taskVerify && !workflowVerify) return null;
  const effective = taskVerify || workflowVerify;
  return {
    shell: effective.shell,
    timeout_seconds: effective.timeout_seconds ?? 30,
    on_failure: effective.on_failure ?? 'error',
  };
}

export function normalizedTaskPlan(workflow, task, taskIdToCompiledId, { namePrefix = true } = {}) {
  const modelPolicy = resolveModelPolicy(workflow, task);
  const identity = resolveIdentity(workflow, task);
  const contract = resolveContract(workflow, task);
  const childCredentialPolicy = resolveChildCredentialPolicy(workflow, task);
  const verify = resolveVerify(workflow, task);
  const intent = resolveIntent(task);
  const output = resolveOutput(task);
  const budgets = resolveBudgets(task);

  return {
    id: stableId(workflow.id, task.id),
    source: {
      workflow_id: workflow.id,
      task_id: task.id,
    },
    name: namePrefix ? `${workflow.name}: ${task.name}` : task.name,
    enabled: task.enabled ?? true,
    invocation: taskInvocationForTask(task),
    execution: {
      session_target: task.target.session_target,
      agent_id: task.target.agent_id ?? 'main',
      payload_kind: payloadKindForTask(task),
      payload: payloadForTask(task),
      model_policy: modelPolicy,
    },
    intent,
    output,
    budgets,
    delivery: {
      mode: task.delivery?.mode ?? 'none',
      channel: task.delivery?.channel ?? null,
      to: task.delivery?.to ?? null,
    },
    reliability: {
      guarantee: task.reliability?.guarantee ?? 'at-most-once',
      overlap_policy: task.reliability?.overlap_policy ?? 'skip',
      max_retries: task.reliability?.max_retries ?? 0,
    },
    runtime: {
      timeout_ms: task.runtime?.timeout_ms ?? null,
    },
    approval: approvalPolicyForTask(task),
    context: {
      retrieval: task.context?.retrieval ?? 'none',
      limit: task.context?.limit ?? budgets.max_context_items ?? 5,
    },
    session: {
      preferred_key: task.session?.preferred_key ?? null,
    },
    identity,
    contract,
    authorization_proof: resolveAuthorizationProof(workflow, task),
    authorization: resolveAuthorization(workflow, task),
    evidence: resolveEvidence(workflow, task),
    child_credential_policy: childCredentialPolicy,
    verify,
    auth_profile: task.auth_profile ?? null,
    delete_after_run: task.delete_after_run ?? null,
    parent_compiled_id: task.trigger ? taskIdToCompiledId.get(task.trigger.parent) : null,
  };
}
