import {
  canonicalDigest,
  canonicalStringify,
  hashNullableString,
  hashString,
} from '../canonical.js';
import {
  buildEffectiveExecutionBinding,
  computeEffectiveTaskHash,
} from '../compiler/shared.js';
import {
  HANDOFF_V4_SCHEMA,
  HANDOFF_V4_ARTIFACT_SCHEMA_VERSION,
  HANDOFF_V4_VERSION,
  HANDOFF_V4_SCHEDULER_SCHEMA_MIN,
  HANDOFF_V4_CANONICALIZATION,
  HANDOFF_V4_CANONICALIZATION_VERSION,
  HANDOFF_V4_EXECUTION_BINDING_VERSION,
  HANDOFF_V4_SCHEDULER_JOB_BINDING_VERSION,
  validateHandoffV4Structure,
} from './schema-v4.js';

export {
  HANDOFF_V4_SCHEMA,
  HANDOFF_V4_ARTIFACT_SCHEMA_VERSION,
  HANDOFF_V4_VERSION,
  HANDOFF_V4_SCHEDULER_SCHEMA_MIN,
  HANDOFF_V4_CANONICALIZATION,
  HANDOFF_V4_CANONICALIZATION_VERSION,
  HANDOFF_V4_EXECUTION_BINDING_VERSION,
  HANDOFF_V4_SCHEDULER_JOB_BINDING_VERSION,
} from './schema-v4.js';

const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const CRYPTOGRAPHIC_PROOF_METHODS = new Set(['jwt', 'detached-signature', 'certificate']);
const PRESENTATION_MEDIA = new Set(['none', 'env', 'temp-file', 'stdin', 'gateway-env-header']);
const SCHEDULER_JOB_REBINDABLE_FIELDS = new Set([
  'auth_profile_fallback',
  'job_class',
  'origin',
  'payload_model_fallback',
  'payload_scope',
  'payload_timeout_seconds',
  'resource_pool',
  'shell_env_policy',
  'watchdog_alert_channel',
  'watchdog_alert_target',
  'watchdog_check_cmd',
  'watchdog_self_destruct',
  'watchdog_started_at',
  'watchdog_target_label',
  'watchdog_timeout_min',
  'job_type',
]);

export function schedulerHandoffV4RebindableOverrides(job) {
  if (!job || typeof job !== 'object' || Array.isArray(job)) return {};
  return Object.fromEntries(
    [...SCHEDULER_JOB_REBINDABLE_FIELDS]
      .filter(field => Object.hasOwn(job, field))
      .map(field => [field, job[field]]),
  );
}

function hashObject(value) {
  return value == null ? null : canonicalDigest(value);
}

function normalizeJsonValue(value) {
  if (value == null || typeof value !== 'string') return value ?? null;
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function schedulerJobExecutionProjection(job) {
  return {
    invocation: {
      name: job.name ?? null,
      schedule_kind: job.schedule_kind ?? 'cron',
      schedule_at: job.schedule_at ?? null,
      schedule_cron: job.schedule_cron ?? null,
      schedule_tz: job.schedule_tz ?? 'UTC',
      parent_id: job.parent_id ?? null,
      trigger_on: job.trigger_on ?? null,
      trigger_delay_s: job.trigger_delay_s ?? 0,
      trigger_condition: job.trigger_condition ?? null,
      origin: job.origin ?? null,
    },
    reliability: {
      overlap_policy: job.overlap_policy ?? 'skip',
      resource_pool: job.resource_pool ?? null,
      job_class: job.job_class ?? 'standard',
      max_retries: job.max_retries ?? 0,
      max_queued_dispatches: job.max_queued_dispatches ?? 25,
      max_pending_approvals: job.max_pending_approvals ?? 10,
      max_trigger_fanout: job.max_trigger_fanout ?? 100,
      delivery_guarantee: job.delivery_guarantee ?? 'at-most-once',
    },
    delivery: {
      mode: job.delivery_mode ?? 'none',
      channel: job.delivery_channel ?? null,
      to: job.delivery_to ?? null,
      opt_out_reason: job.delivery_opt_out_reason ?? null,
    },
    context: {
      retrieval: job.context_retrieval ?? 'none',
      retrieval_limit: job.context_retrieval_limit ?? 5,
    },
    lifecycle: {
      enabled: Boolean(job.enabled),
      delete_after_run: Boolean(job.delete_after_run),
    },
    target: {
      session_target: job.session_target ?? null,
      agent_id: job.agent_id ?? 'main',
      payload_kind: job.payload_kind ?? null,
      payload_scope: job.payload_scope ?? 'own',
    },
    command: {
      payload_message_sha256: hashString(job.payload_message ?? ''),
    },
    watchdog: {
      job_type: job.job_type ?? 'standard',
      target_label: job.watchdog_target_label ?? null,
      check_cmd_sha256: job.watchdog_check_cmd == null
        ? null
        : hashString(String(job.watchdog_check_cmd)),
      timeout_min: job.watchdog_timeout_min ?? null,
      alert_channel: job.watchdog_alert_channel ?? null,
      alert_target: job.watchdog_alert_target ?? null,
      self_destruct: job.watchdog_self_destruct == null
        ? true
        : Boolean(job.watchdog_self_destruct),
      started_at: job.watchdog_started_at ?? null,
    },
    runtime: {
      run_timeout_ms: job.run_timeout_ms ?? 300000,
      payload_timeout_seconds: job.payload_timeout_seconds ?? 120,
      payload_model: job.payload_model ?? null,
      payload_model_fallback: job.payload_model_fallback ?? null,
      payload_thinking: job.payload_thinking ?? null,
      preferred_session_key: job.preferred_session_key ?? null,
      auth_profile: job.auth_profile ?? null,
      auth_profile_fallback: job.auth_profile_fallback ?? null,
      shell_env_policy: job.shell_env_policy ?? 'minimal',
    },
    approval: {
      required: Boolean(job.approval_required),
      timeout_s: job.approval_timeout_s ?? null,
      auto: job.approval_auto ?? null,
      risk_level: job.approval_risk_level ?? null,
      approver_scope: job.approval_approver_scope ?? null,
    },
    output: {
      format: job.output_format ?? null,
      store_limit_bytes: job.output_store_limit_bytes ?? null,
      excerpt_limit_bytes: job.output_excerpt_limit_bytes ?? null,
      summary_limit_bytes: job.output_summary_limit_bytes ?? null,
      offload_threshold_bytes: job.output_offload_threshold_bytes ?? null,
    },
    identity: {
      principal: job.identity_principal ?? null,
      run_as: job.identity_run_as ?? null,
      attestation: job.identity_attestation ?? null,
      ref: job.identity_ref ?? null,
      subject_kind: job.identity_subject_kind ?? null,
      subject_principal: job.identity_subject_principal ?? null,
      trust_level: job.identity_trust_level ?? null,
      delegation_mode: job.identity_delegation_mode ?? null,
      declaration: normalizeJsonValue(job.identity),
    },
    authorization_proof: {
      ref: job.authorization_proof_ref ?? null,
      declaration: normalizeJsonValue(job.authorization_proof),
    },
    authorization: {
      ref: job.authorization_ref ?? null,
      declaration: normalizeJsonValue(job.authorization),
    },
    evidence: {
      ref: job.evidence_ref ?? null,
      declaration: normalizeJsonValue(job.evidence),
    },
    contract: {
      required_trust_level: job.contract_required_trust_level ?? null,
      trust_enforcement: job.contract_trust_enforcement ?? null,
      sandbox: job.contract_sandbox ?? null,
      allowed_paths: normalizeJsonValue(job.contract_allowed_paths),
      network: job.contract_network ?? null,
      max_cost_usd: job.contract_max_cost_usd ?? null,
      audit: job.contract_audit ?? null,
    },
    verification: {
      shell_sha256: hashNullableString(job.verify_shell),
      timeout_s: job.verify_timeout_s ?? null,
      on_failure: job.verify_on_failure ?? null,
    },
    child_credential_policy: job.child_credential_policy ?? null,
    intent: {
      mode: job.execution_intent ?? 'execute',
      read_only: Boolean(job.execution_read_only),
    },
  };
}

function requiredBoolean(value, path, errors) {
  if (typeof value !== 'boolean') errors.push(`${path} must be a boolean`);
}

function validateHash(value, path, errors, { required = false } = {}) {
  if (value == null) {
    if (required) errors.push(`${path} is required`);
    return;
  }
  if (typeof value !== 'string' || !SHA256_PATTERN.test(value)) {
    errors.push(`${path} must be a lowercase sha256 digest`);
  }
}

function validateHashCollection(value, path, errors) {
  if (Array.isArray(value)) {
    value.forEach((item, index) => validateHash(item, `${path}[${index}]`, errors, { required: true }));
    return;
  }
  if (!value || typeof value !== 'object') {
    errors.push(`${path} must be an object or array of sha256 digests`);
    return;
  }
  for (const [key, digest] of Object.entries(value)) {
    validateHash(digest, `${path}.${key}`, errors, { required: true });
  }
}

function normalizePayload(payload) {
  if (typeof payload === 'string') {
    try {
      return JSON.parse(payload);
    } catch (error) {
      throw Object.assign(new TypeError(`Invalid handoff v4 JSON: ${error.message}`), {
        code: 'HANDOFF_ARTIFACT_INVALID',
      });
    }
  }
  return payload;
}

function presentationMediumForTarget(target, sessionTarget) {
  const kind = target?.kind ?? 'none';
  if (kind === 'env') {
    return sessionTarget === 'isolated' ? 'gateway-env-header' : 'env';
  }
  if (kind === 'file') return 'temp-file';
  if (kind === 'stdin') return 'stdin';
  if (kind === 'none') return 'none';
  throw Object.assign(new Error(`Unsupported credential presentation target kind: ${kind}`), {
    code: 'HANDOFF_PRESENTATION_UNSUPPORTED',
  });
}

function presentationBindings(identity, sessionTarget) {
  const presentation = identity?.presentation;
  if (!presentation || typeof presentation !== 'object') return [];
  const declared = presentation.bindings;
  if (!Array.isArray(declared)) return [];
  return declared.map(binding => {
    const target = binding.target ?? {};
    const medium = presentationMediumForTarget(target, sessionTarget);
    return {
      name: binding.name ?? binding.source ?? null,
      medium,
      env_key: target.kind === 'env'
        ? target.name ?? null
        : target.kind === 'file'
          ? target.expose_as ?? null
          : null,
      file_name: target.kind === 'file'
        ? target.name ?? target.prefix ?? null
        : null,
      source_hash: hashNullableString(binding.source),
      required: binding.required ?? true,
      redact: binding.redact ?? presentation.default_redaction ?? true,
      format: binding.format ?? 'raw',
    };
  });
}

function runtimePresentation(identity, sessionTarget) {
  const bindings = presentationBindings(identity, sessionTarget);
  const media = [...new Set(bindings.map(binding => binding.medium).filter(medium => medium !== 'none'))];
  if (media.length > 1) {
    throw Object.assign(
      new Error(`Handoff v4 requires one credential presentation medium per task, received: ${media.join(', ')}`),
      { code: 'HANDOFF_PRESENTATION_MIXED_MEDIA' },
    );
  }
  return {
    mode: identity?.presentation?.handoff ?? 'none',
    handoff: media[0] ?? 'none',
    bindings,
    default_redaction: identity?.presentation?.default_redaction ?? null,
    cleanup: identity?.presentation?.cleanup ?? 'always',
  };
}

function proofBinding(binding) {
  const proof = binding.authorization_proof;
  if (!proof) {
    return {
      ref: null,
      method: null,
      issuer: null,
      audience: null,
      claims_hash: null,
      proof_source_hash: null,
      verification_context_hash: null,
      artifact_binding_required: false,
      replay_protection_required: false,
      revocation_check_required: false,
    };
  }
  const cryptographic = CRYPTOGRAPHIC_PROOF_METHODS.has(proof.method);
  return {
    ref: proof.ref ?? null,
    method: proof.method ?? null,
    issuer: proof.issuer ?? null,
    audience: proof.audience ?? null,
    claims_hash: proof.claims_hash ?? null,
    proof_source_hash: proof.proof_hash ?? null,
    verification_context_hash: hashObject({
      jwks_uri: proof.jwks_uri ?? null,
      public_key_hash: proof.public_key_hash ?? null,
      allowed_signers: proof.allowed_signers ?? null,
      principal: proof.principal ?? null,
      namespace: proof.namespace ?? null,
      ca_certificate_hash: proof.ca_certificate_hash ?? null,
      ca_certificate_from_hash: proof.ca_certificate_from_hash ?? null,
      verify: proof.verify ?? null,
    }),
    artifact_binding_required: cryptographic,
    replay_protection_required: cryptographic,
    revocation_check_required: cryptographic,
  };
}

function identityBinding(binding) {
  const identity = binding.identity;
  if (!identity) {
    return {
      ref: null,
      provider: null,
      scope: null,
      subject_kind: null,
      subject_principal: null,
      subject_hash: null,
      auth_hash: null,
      trust_level: null,
      delegation_mode: null,
      presentation: {
        mode: 'none',
        handoff: 'none',
        bindings: [],
        default_redaction: null,
        cleanup: 'always',
      },
    };
  }
  const presentation = runtimePresentation(identity, binding.target?.session_target);
  return {
    ref: identity.ref ?? null,
    provider: identity.provider ?? null,
    scope: identity.scope ?? null,
    subject_kind: identity.subject?.kind ?? null,
    subject_principal: identity.subject?.principal ?? null,
    subject_hash: hashObject(identity.subject),
    auth_hash: hashObject(identity.auth),
    trust_level: identity.trust?.level ?? null,
    delegation_mode: identity.subject?.delegation_mode ?? null,
    presentation,
  };
}

function authorizationBinding(binding) {
  const authorization = binding.authorization;
  if (!authorization) {
    return {
      ref: null,
      provider: null,
      policy_digest: null,
      on_error: null,
      request_hash: null,
      decision_hash: null,
    };
  }
  return {
    ref: authorization.ref ?? null,
    provider: authorization.provider ?? null,
    policy_digest: authorization.provider_config_hash ?? null,
    on_error: authorization.on_error ?? null,
    request_hash: hashObject(authorization.request),
    decision_hash: hashObject(authorization.decision),
  };
}

function evidenceBinding(binding) {
  const evidence = binding.evidence;
  if (!evidence) {
    return {
      ref: null,
      provider: null,
      methods: [],
      payload_bind: [],
      payload_hash: null,
      provider_config_hash: null,
      verify_required: false,
      retention: null,
      signed_or_provider_verified_required: false,
    };
  }
  return {
    ref: evidence.ref ?? null,
    provider: evidence.provider ?? null,
    methods: Array.isArray(evidence.methods) ? evidence.methods : [],
    payload_bind: Array.isArray(evidence.payload?.bind)
      ? evidence.payload.bind
      : Array.isArray(evidence.payload?.bind_targets)
        ? evidence.payload.bind_targets
        : [],
    payload_hash: canonicalDigest(evidence.payload ?? {}),
    provider_config_hash: evidence.provider_config_hash ?? null,
    verify_required: evidence.verify?.required === true,
    retention: evidence.payload?.retention ?? null,
    signed_or_provider_verified_required: true,
  };
}

function validatePersistedEvidenceBinding(job, artifactEvidence) {
  const errors = [];
  const declaration = normalizeJsonValue(job.evidence);
  let expected;

  if (declaration == null) {
    if (job.evidence_ref != null) {
      errors.push('evidence_ref is set but the persisted evidence declaration is missing');
    }
    expected = evidenceBinding({ evidence: null });
  } else if (typeof declaration !== 'object' || Array.isArray(declaration)) {
    errors.push('persisted evidence declaration must be an object or null');
    return errors;
  } else {
    for (const field of ['payload_hash', 'provider_config_hash']) {
      if (!Object.hasOwn(declaration, field)) {
        errors.push(`persisted evidence declaration is missing ${field}`);
      } else {
        validateHash(declaration[field], `persisted evidence.${field}`, errors);
      }
    }
    if (declaration.provider_config != null) {
      errors.push('persisted evidence declaration must not contain raw provider_config');
    }
    const expectedPayloadHash = canonicalDigest(declaration.payload ?? {});
    if ((declaration.payload_hash ?? null) !== expectedPayloadHash) {
      errors.push('persisted evidence payload_hash does not match its payload');
    }
    if ((declaration.ref ?? null) !== (job.evidence_ref ?? null)) {
      errors.push('persisted evidence ref does not match evidence_ref');
    }
    expected = evidenceBinding({ evidence: declaration });
  }

  for (const field of [
    'ref',
    'provider',
    'methods',
    'payload_bind',
    'payload_hash',
    'provider_config_hash',
    'verify_required',
    'retention',
    'signed_or_provider_verified_required',
  ]) {
    if (canonicalStringify(artifactEvidence?.[field] ?? null)
      !== canonicalStringify(expected[field] ?? null)) {
      errors.push(`artifact evidence.${field} does not match the persisted evidence declaration`);
    }
  }
  return errors;
}

function commandBinding(binding, task, job) {
  const command = binding.command;
  const payloadKind = job.payload_kind ?? null;
  const kind = payloadKind === 'shellCommand'
    ? 'shell'
    : payloadKind === 'agentTurn'
      ? 'prompt'
      : 'system';
  const argsHashes = command?.args_hashes ?? [];
  const program = command?.program ?? null;
  return {
    kind,
    program,
    args_count: command?.args_count ?? 0,
    args_sha256: argsHashes,
    argv_sha256: canonicalDigest([program, ...argsHashes]),
    cwd: command?.cwd ?? null,
    stdin_sha256: command?.stdin_hash ?? null,
    prompt_sha256: hashNullableString(task.prompt),
    input_sha256: hashObject(task.input),
    payload_message_sha256: hashString(job.payload_message ?? ''),
    env: {
      declared_env_sha256: hashObject(task.shell?.env),
      effective_env_keys: command?.env_keys ?? [],
      effective_env_value_sha256: command?.env_hashes ?? {},
    },
  };
}

export function buildSchedulerHandoffV4Artifact({
  manifest,
  expanded = manifest,
  workflow,
  task,
  plan,
  job,
  cwd = process.cwd(),
  env = process.env,
} = {}) {
  if (!manifest || !workflow || !task || !plan || !job) {
    throw new TypeError('manifest, workflow, task, plan, and job are required');
  }

  const executionBinding = buildEffectiveExecutionBinding({
    manifest,
    expanded,
    workflow,
    task,
    cwd,
    env,
    timeoutMs: job.run_timeout_ms,
    instanceId: null,
    bindingVersion: HANDOFF_V4_EXECUTION_BINDING_VERSION,
  });
  const effectiveTaskHash = computeEffectiveTaskHash(executionBinding);
  const identity = identityBinding(executionBinding);
  const proof = proofBinding(executionBinding);
  const authorization = authorizationBinding(executionBinding);
  const evidence = evidenceBinding(executionBinding);
  const contract = executionBinding.contract ?? {};
  const allowedDelegators = Array.isArray(
    executionBinding.identity?.auth?.delegation_policy?.allowed_delegators,
  )
    ? [...new Set(executionBinding.identity.auth.delegation_policy.allowed_delegators)].sort()
    : [];
  const delegationPolicy = executionBinding.identity?.auth?.delegation_policy ?? {};

  const payload = {
    schema: HANDOFF_V4_SCHEMA,
    artifact_schema_version: HANDOFF_V4_ARTIFACT_SCHEMA_VERSION,
    handoff_version: HANDOFF_V4_VERSION,
    scheduler_schema_min: HANDOFF_V4_SCHEDULER_SCHEMA_MIN,
    canonicalization: {
      name: HANDOFF_V4_CANONICALIZATION,
      version: HANDOFF_V4_CANONICALIZATION_VERSION,
      digest: 'sha256',
      undefined: 'null',
    },
    execution_binding_version: HANDOFF_V4_EXECUTION_BINDING_VERSION,
    scheduler_job_binding: {
      version: HANDOFF_V4_SCHEDULER_JOB_BINDING_VERSION,
      digest: canonicalDigest(schedulerJobExecutionProjection(job)),
    },
    manifest: {
      version: expanded?.version ?? manifest.version ?? null,
      digest: canonicalDigest(manifest),
      workflow_id: workflow.id,
      task_id: task.id,
    },
    compiled: {
      target: 'openclaw-scheduler',
      job_id: job.id,
      effective_task_hash: effectiveTaskHash,
      source: {
        workflow_id: workflow.id,
        task_id: task.id,
      },
    },
    lifecycle: {
      enabled: Boolean(job.enabled),
      delete_after_run: Boolean(job.delete_after_run),
      target: {
        session_target: job.session_target,
        agent_id: job.agent_id ?? null,
        payload_kind: job.payload_kind,
      },
    },
    command: commandBinding(executionBinding, task, job),
    runtime: {
      timeout_ms: job.run_timeout_ms,
      instance_id: {
        kind: 'deferred',
        source: 'run.id',
      },
    },
    approval: {
      required: Boolean(job.approval_required),
      timeout_s: job.approval_timeout_s,
      auto: job.approval_auto,
      risk_level: job.approval_risk_level ?? null,
      approver_scope: job.approval_approver_scope ?? null,
    },
    identity,
    contract: {
      required_trust_level: contract.required_trust_level ?? null,
      trust_enforcement: contract.trust_enforcement ?? null,
      sandbox: contract.sandbox ?? null,
      allowed_paths_sha256: hashObject(contract.allowed_paths),
      network: contract.network ?? null,
      max_cost_usd: contract.max_cost_usd ?? null,
      audit: contract.audit ?? null,
      postcondition: {
        output_format: job.output_format ?? null,
        verify_shell_sha256: hashNullableString(job.verify_shell),
        verify_timeout_s: job.verify_timeout_s ?? null,
        verify_on_failure: job.verify_on_failure ?? null,
      },
    },
    authorization_proof: proof,
    authorization,
    evidence,
    verification: {
      shell_sha256: hashNullableString(job.verify_shell),
      timeout_s: job.verify_timeout_s ?? null,
      on_failure: job.verify_on_failure ?? null,
    },
    output: {
      format: job.output_format ?? null,
      store_limit_bytes: job.output_store_limit_bytes,
      excerpt_limit_bytes: job.output_excerpt_limit_bytes,
      summary_limit_bytes: job.output_summary_limit_bytes,
      offload_threshold_bytes: job.output_offload_threshold_bytes,
    },
    child_credential_policy: executionBinding.child_credential_policy ?? null,
    intent: {
      mode: executionBinding.intent?.mode ?? 'execute',
      read_only: Boolean(executionBinding.intent?.read_only),
    },
    delegation: {
      mode: identity.delegation_mode ?? null,
      source_binding: 'source_run_id',
      max_depth: delegationPolicy.max_depth ?? plan.budgets?.max_iterations ?? 16,
      target_scope: identity.scope ?? null,
      allowed_delegators: allowedDelegators,
      allowed_delegators_hash: hashObject(allowedDelegators),
      require_grant_per_hop: delegationPolicy.require_grant_per_hop
        ?? (identity.delegation_mode != null && identity.delegation_mode !== 'none'),
    },
  };

  const canonical = canonicalStringify(payload);
  const digest = hashString(canonical);
  const validation = validateSchedulerHandoffV4Artifact(payload, { expectedDigest: digest });
  if (!validation.ok) {
    throw Object.assign(
      new Error(`Generated handoff v4 artifact is invalid: ${validation.errors.join('; ')}`),
      { code: 'HANDOFF_ARTIFACT_INVALID', errors: validation.errors },
    );
  }
  return { payload, digest, effectiveTaskHash, canonical };
}

export function assertValidSchedulerHandoffV4Job(job) {
  if (!job || Number(job.handoff_version) !== HANDOFF_V4_VERSION) {
    throw new TypeError('assertValidSchedulerHandoffV4Job requires a handoff v4 job');
  }
  if (!SHA256_PATTERN.test(job.handoff_artifact_digest)) {
    throw Object.assign(
      new Error('Handoff v4 job does not have a valid original artifact digest'),
      {
        code: 'HANDOFF_ARTIFACT_INVALID',
        errors: ['handoff_artifact_digest must be a sha256 digest'],
      },
    );
  }
  const originalValidation = validateSchedulerHandoffV4Artifact(
    job.handoff_artifact_payload,
    { expectedDigest: job.handoff_artifact_digest },
  );
  if (!originalValidation.ok) {
    throw Object.assign(
      new Error(
        `Handoff v4 job has an invalid artifact: ${originalValidation.errors.join('; ')}`,
      ),
      { code: 'HANDOFF_ARTIFACT_INVALID', errors: originalValidation.errors },
    );
  }
  const compiledIdentityErrors = [];
  if (job.id !== originalValidation.payload.compiled.job_id) {
    compiledIdentityErrors.push('compiled.job_id does not match the current job id');
  }
  if (job.effective_task_hash !== originalValidation.payload.compiled.effective_task_hash) {
    compiledIdentityErrors.push(
      'compiled.effective_task_hash does not match the current job effective_task_hash',
    );
  }
  if (compiledIdentityErrors.length > 0) {
    throw Object.assign(
      new Error(
        `Handoff v4 job compiled identity no longer matches its artifact: ${compiledIdentityErrors.join('; ')}`,
      ),
      { code: 'HANDOFF_ARTIFACT_INVALID', errors: compiledIdentityErrors },
    );
  }
  const currentBindingDigest = canonicalDigest(schedulerJobExecutionProjection(job));
  if (originalValidation.payload.scheduler_job_binding.digest !== currentBindingDigest) {
    throw Object.assign(
      new Error('Handoff v4 job execution projection no longer matches its artifact'),
      {
        code: 'HANDOFF_ARTIFACT_INVALID',
        errors: ['scheduler_job_binding.digest does not match the current job projection'],
      },
    );
  }
  const evidenceErrors = validatePersistedEvidenceBinding(
    job,
    originalValidation.payload.evidence,
  );
  if (evidenceErrors.length > 0) {
    throw Object.assign(
      new Error(
        `Handoff v4 job evidence no longer matches its artifact: ${evidenceErrors.join('; ')}`,
      ),
      { code: 'HANDOFF_ARTIFACT_INVALID', errors: evidenceErrors },
    );
  }
  return originalValidation.payload;
}

export function rebindSchedulerHandoffV4Job(job, overrides = {}) {
  if (!job || Number(job.handoff_version) !== HANDOFF_V4_VERSION) {
    throw new TypeError('rebindSchedulerHandoffV4Job requires a handoff v4 job');
  }
  if (!overrides || typeof overrides !== 'object' || Array.isArray(overrides)) {
    throw new TypeError('rebindSchedulerHandoffV4Job overrides must be an object');
  }
  const invalidFields = Object.keys(overrides)
    .filter(field => !SCHEDULER_JOB_REBINDABLE_FIELDS.has(field));
  if (invalidFields.length > 0) {
    throw Object.assign(
      new TypeError(
        `rebindSchedulerHandoffV4Job cannot override artifact-bound field(s): ${invalidFields.join(', ')}`,
      ),
      { code: 'HANDOFF_REBIND_OVERRIDE_INVALID', fields: invalidFields },
    );
  }
  const originalPayload = assertValidSchedulerHandoffV4Job(job);
  const reboundJob = { ...job, ...overrides };
  const payload = structuredClone(originalPayload);
  if (!payload?.scheduler_job_binding || typeof payload.scheduler_job_binding !== 'object') {
    throw Object.assign(new Error('handoff v4 artifact is missing scheduler_job_binding'), {
      code: 'HANDOFF_ARTIFACT_INVALID',
    });
  }
  payload.scheduler_job_binding = {
    version: HANDOFF_V4_SCHEDULER_JOB_BINDING_VERSION,
    digest: canonicalDigest(schedulerJobExecutionProjection(reboundJob)),
  };
  const canonical = canonicalStringify(payload);
  const digest = hashString(canonical);
  const validation = validateSchedulerHandoffV4Artifact(payload, { expectedDigest: digest });
  if (!validation.ok) {
    throw Object.assign(
      new Error(`Rebound handoff v4 artifact is invalid: ${validation.errors.join('; ')}`),
      { code: 'HANDOFF_ARTIFACT_INVALID', errors: validation.errors },
    );
  }
  return {
    ...reboundJob,
    handoff_artifact_payload: payload,
    handoff_artifact_digest: digest,
  };
}

export function validateSchedulerHandoffV4Artifact(input, { expectedDigest } = {}) {
  let payload;
  try {
    payload = normalizePayload(input);
  } catch (error) {
    return { ok: false, digest: null, errors: [error.message] };
  }

  const errors = validateHandoffV4Structure(payload);
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { ok: false, digest: null, errors: ['artifact payload must be an object'] };
  }
  if (payload.schema !== HANDOFF_V4_SCHEMA) errors.push('schema is unsupported');
  if (payload.artifact_schema_version !== HANDOFF_V4_ARTIFACT_SCHEMA_VERSION) {
    errors.push('artifact_schema_version must be 1');
  }
  if (payload.handoff_version !== HANDOFF_V4_VERSION) errors.push('handoff_version must be 4');
  if (!Number.isInteger(payload.scheduler_schema_min)
    || payload.scheduler_schema_min !== HANDOFF_V4_SCHEDULER_SCHEMA_MIN) {
    errors.push('scheduler_schema_min must be exactly 29');
  }
  if (payload.canonicalization?.name !== HANDOFF_V4_CANONICALIZATION
    || payload.canonicalization?.version !== HANDOFF_V4_CANONICALIZATION_VERSION
    || payload.canonicalization?.digest !== 'sha256'
    || payload.canonicalization?.undefined !== 'null') {
    errors.push('canonicalization contract is unsupported');
  }
  if (payload.execution_binding_version !== HANDOFF_V4_EXECUTION_BINDING_VERSION) {
    errors.push('execution_binding_version must be 2');
  }

  if (payload.scheduler_job_binding?.version !== HANDOFF_V4_SCHEDULER_JOB_BINDING_VERSION) {
    errors.push('scheduler_job_binding.version must be 1');
  }
  validateHash(
    payload.scheduler_job_binding?.digest,
    'scheduler_job_binding.digest',
    errors,
    { required: true },
  );
  validateHash(payload.manifest?.digest, 'manifest.digest', errors, { required: true });
  validateHash(payload.compiled?.effective_task_hash, 'compiled.effective_task_hash', errors, { required: true });
  validateHash(payload.command?.payload_message_sha256, 'command.payload_message_sha256', errors, { required: true });
  const commandArgumentHashes = payload.command?.args_sha256;
  if (!Array.isArray(commandArgumentHashes)) {
    errors.push('command.args_sha256 must be an array');
  } else {
    validateHashCollection(commandArgumentHashes, 'command.args_sha256', errors);
    if (Number.isInteger(payload.command?.args_count)
      && payload.command.args_count !== commandArgumentHashes.length) {
      errors.push('command.args_count does not match command.args_sha256 length');
    }
  }
  validateHashCollection(
    payload.command?.env?.effective_env_value_sha256,
    'command.env.effective_env_value_sha256',
    errors,
  );
  for (const [path, value] of [
    ['command.argv_sha256', payload.command?.argv_sha256],
    ['command.stdin_sha256', payload.command?.stdin_sha256],
    ['command.prompt_sha256', payload.command?.prompt_sha256],
    ['command.input_sha256', payload.command?.input_sha256],
    ['command.env.declared_env_sha256', payload.command?.env?.declared_env_sha256],
    ['identity.subject_hash', payload.identity?.subject_hash],
    ['identity.auth_hash', payload.identity?.auth_hash],
    ['authorization_proof.claims_hash', payload.authorization_proof?.claims_hash],
    ['authorization_proof.proof_source_hash', payload.authorization_proof?.proof_source_hash],
    ['authorization.policy_digest', payload.authorization?.policy_digest],
    ['authorization.request_hash', payload.authorization?.request_hash],
    ['authorization.decision_hash', payload.authorization?.decision_hash],
    ['evidence.payload_hash', payload.evidence?.payload_hash],
    ['evidence.provider_config_hash', payload.evidence?.provider_config_hash],
    ['verification.shell_sha256', payload.verification?.shell_sha256],
    ['contract.allowed_paths_sha256', payload.contract?.allowed_paths_sha256],
    ['contract.postcondition.verify_shell_sha256', payload.contract?.postcondition?.verify_shell_sha256],
    ['delegation.allowed_delegators_hash', payload.delegation?.allowed_delegators_hash],
  ]) {
    validateHash(value, path, errors);
  }
  if (payload.command && Array.isArray(commandArgumentHashes)) {
    const expectedArgvHash = canonicalDigest([
      payload.command.program ?? null,
      ...commandArgumentHashes,
    ]);
    if (payload.command.argv_sha256 !== expectedArgvHash) {
      errors.push('command.argv_sha256 does not match command program and argument hashes');
    }
  }

  requiredBoolean(payload.lifecycle?.enabled, 'lifecycle.enabled', errors);
  requiredBoolean(payload.lifecycle?.delete_after_run, 'lifecycle.delete_after_run', errors);
  requiredBoolean(payload.approval?.required, 'approval.required', errors);
  requiredBoolean(payload.authorization_proof?.artifact_binding_required, 'authorization_proof.artifact_binding_required', errors);
  requiredBoolean(payload.authorization_proof?.replay_protection_required, 'authorization_proof.replay_protection_required', errors);
  requiredBoolean(payload.authorization_proof?.revocation_check_required, 'authorization_proof.revocation_check_required', errors);
  requiredBoolean(payload.evidence?.signed_or_provider_verified_required, 'evidence.signed_or_provider_verified_required', errors);
  requiredBoolean(payload.intent?.read_only, 'intent.read_only', errors);
  requiredBoolean(payload.delegation?.require_grant_per_hop, 'delegation.require_grant_per_hop', errors);
  const allowedDelegators = payload.delegation?.allowed_delegators;
  if (!Array.isArray(allowedDelegators)
    || allowedDelegators.some(value => typeof value !== 'string' || value.length === 0)
    || new Set(allowedDelegators).size !== allowedDelegators.length
    || allowedDelegators.some((value, index) => index > 0 && value < allowedDelegators[index - 1])) {
    errors.push('delegation.allowed_delegators must be a sorted unique array of non-empty strings');
  } else if (payload.delegation.allowed_delegators_hash !== hashObject(allowedDelegators)) {
    errors.push('delegation.allowed_delegators_hash does not match allowed_delegators');
  }

  const medium = payload.identity?.presentation?.handoff;
  if (!PRESENTATION_MEDIA.has(medium)) {
    errors.push('identity.presentation.handoff is unsupported');
  }
  const presentationBindings = payload.identity?.presentation?.bindings;
  if (Array.isArray(presentationBindings)) {
    for (const [index, binding] of presentationBindings.entries()) {
      if (!binding || typeof binding !== 'object') {
        errors.push(`identity.presentation.bindings[${index}] must be an object`);
        continue;
      }
      if ('value' in binding || 'credential' in binding || 'secret' in binding || 'token' in binding) {
        errors.push(`identity.presentation.bindings[${index}] contains raw credential material`);
      }
      if (!PRESENTATION_MEDIA.has(binding.medium)) {
        errors.push(`identity.presentation.bindings[${index}].medium is unsupported`);
      } else if (binding.medium !== 'none' && binding.medium !== medium) {
        errors.push(`identity.presentation.bindings[${index}].medium does not match presentation handoff`);
      }
      validateHash(binding.source_hash, `identity.presentation.bindings[${index}].source_hash`, errors);
      requiredBoolean(binding.required, `identity.presentation.bindings[${index}].required`, errors);
      requiredBoolean(binding.redact, `identity.presentation.bindings[${index}].redact`, errors);
    }
  }

  const proof = payload.authorization_proof ?? {};
  validateHash(
    proof.verification_context_hash,
    'authorization_proof.verification_context_hash',
    errors,
    { required: CRYPTOGRAPHIC_PROOF_METHODS.has(proof.method) },
  );
  if (CRYPTOGRAPHIC_PROOF_METHODS.has(proof.method)
    && (!proof.artifact_binding_required
      || !proof.replay_protection_required
      || !proof.revocation_check_required)) {
    errors.push('cryptographic proof methods require artifact binding, replay protection, and revocation');
  }
  if (payload.evidence?.provider && !payload.evidence.signed_or_provider_verified_required) {
    errors.push('declared evidence providers require signed or provider-verified evidence');
  }
  const artifactEvidence = payload.evidence ?? {};
  const hasEvidenceDeclaration = artifactEvidence.signed_or_provider_verified_required === true
    || artifactEvidence.ref != null
    || artifactEvidence.provider != null
    || (Array.isArray(artifactEvidence.methods) && artifactEvidence.methods.length > 0)
    || (Array.isArray(artifactEvidence.payload_bind) && artifactEvidence.payload_bind.length > 0)
    || artifactEvidence.verify_required === true
    || artifactEvidence.retention != null;
  if (!hasEvidenceDeclaration) {
    if (artifactEvidence.payload_hash != null) {
      errors.push('evidence.payload_hash must be null when evidence is not declared');
    }
    if (artifactEvidence.provider_config_hash != null) {
      errors.push('evidence.provider_config_hash must be null when evidence is not declared');
    }
  } else if (!SHA256_PATTERN.test(artifactEvidence.payload_hash)) {
    errors.push('evidence.payload_hash must be a lowercase SHA-256 digest when evidence is declared');
  }
  if (payload.delegation?.mode && payload.delegation.mode !== 'none'
    && payload.delegation.source_binding !== 'source_run_id') {
    errors.push('delegation must bind to source_run_id');
  }

  let digest = null;
  try {
    digest = canonicalDigest(payload);
  } catch (error) {
    errors.push(error.message);
  }
  if (expectedDigest != null) {
    validateHash(expectedDigest, 'expectedDigest', errors, { required: true });
    if (digest && digest !== expectedDigest) errors.push('artifact digest does not match payload');
  }

  return { ok: errors.length === 0, digest, errors, payload };
}
