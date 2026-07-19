import { validateManifest } from '../validate.js';
import {
  mergeAuthorizationProfile,
  mergeAuthorizationProofProfile,
  mergeEvidenceProfile,
  mergeIdentityProfile,
  normalizedTaskPlan,
  payloadMessageForExecution,
  stableId
} from './shared.js';
import { expandManifestShorthands } from '../shorthand.js';
import { canonicalDigest } from '../canonical.js';
import { renderShellExecution } from '../shell.js';
import { buildSchedulerHandoffV4Artifact } from '../handoff/v4.js';
import {
  SCHEDULER_FIELDS_V1,
  SCHEDULER_FIELDS_V02,
  SCHEDULER_FIELDS_V03,
  SCHEDULER_FIELDS_V04,
} from '../scheduler-fields.js';

const TRIGGERED_SENTINEL_CRON = '0 0 31 2 *';
const TRIGGERED_SENTINEL_TZ = 'UTC';
const SCHEDULER_DEFAULT_RUN_TIMEOUT_MS = 300000;
const SCHEDULER_DEFAULT_APPROVAL_TIMEOUT_S = 3600;
const SCHEDULER_DEFAULT_APPROVAL_AUTO = 'reject';
const SCHEDULER_SYSTEM_ORIGIN = 'system';
const DELIVERY_OPT_OUT_REASON =
  'delivery intentionally disabled by the agentcli manifest';
const SCHEDULER_STRING_LIMITS = {
  name: 200,
  payload_message: 100000,
  verify_shell: 100000,
  agent_id: 128,
  schedule_cron: 128,
  schedule_tz: 128,
  delivery_channel: 64,
  delivery_to: 256,
  trigger_condition: 1024,
  payload_model: 256,
  payload_thinking: 64,
  preferred_session_key: 512,
};

function schedulerOutputPolicy(plan) {
  const previewBytes = Math.max(64, plan.output.preview_bytes ?? 2000);
  const outputStoreLimit = plan.output.retrieve === 'inline'
    ? Math.max(previewBytes * 4, 65536)
    : Math.max(previewBytes, 65536);
  let offloadThreshold = 65536;
  if (plan.output.offload === 'always') offloadThreshold = 128;
  if (plan.output.offload === 'never') offloadThreshold = Math.max(outputStoreLimit, 1024 * 1024);
  if (plan.output.offload === 'auto') offloadThreshold = Math.max(outputStoreLimit, previewBytes * 8, 65536);
  return {
    output_store_limit_bytes: outputStoreLimit,
    output_excerpt_limit_bytes: previewBytes,
    output_summary_limit_bytes: Math.max(5000, previewBytes),
    output_offload_threshold_bytes: offloadThreshold,
  };
}

function schedulerDeliveryOptOutReason(plan) {
  const isRootAgentTurn =
    !plan.parent_compiled_id &&
    plan.execution.payload_kind === 'agentTurn';
  if (!isRootAgentTurn || plan.delivery.mode !== 'none') {
    return null;
  }
  return DELIVERY_OPT_OUT_REASON;
}

function schedulerVerificationShell(plan) {
  const verifyShell = plan.verify?.shell ?? null;
  if (verifyShell === null) return null;

  const taskCwd = plan.execution.payload_kind === 'shellCommand'
    ? plan.execution.payload?.cwd ?? null
    : null;
  if (!taskCwd) return verifyShell;

  return renderShellExecution({
    program: 'sh',
    args: ['-c', verifyShell],
    cwd: taskCwd,
  });
}

function isV2IdentityDeclaration(identity) {
  if (!identity || typeof identity !== 'object') return false;
  return (
    identity.ref != null ||
    identity.scope != null ||
    identity.subject != null ||
    identity.auth != null ||
    identity.trust != null ||
    identity.presentation != null
  );
}

function sanitizeIdentityDeclaration(identity) {
  if (!identity) return null;
  const presentation = identity.presentation;
  const hasPresentation = presentation && typeof presentation === 'object'
    && Object.values(presentation).some(v => v != null);
  return {
    ...identity,
    subject: identity.subject
      ? {
          ...identity.subject,
          attributes_hash: identity.subject.attributes == null
            ? null
            : canonicalDigest(identity.subject.attributes),
          attributes: null,
        }
      : null,
    auth: identity.auth
      ? {
          ...identity.auth,
          provider_config: null,
          inputs: null,
        }
      : null,
    presentation: hasPresentation ? presentation : null,
  };
}

function sanitizeIdentityProfile(profile) {
  if (!profile) return null;
  return {
    ...profile,
    provider_config: null,
    subject: profile.subject
      ? {
          ...profile.subject,
          attributes_hash: profile.subject.attributes == null
            ? null
            : canonicalDigest(profile.subject.attributes),
          attributes: null,
        }
      : null,
    auth: profile.auth
      ? {
          ...profile.auth,
          provider_config: null,
          inputs: null,
        }
      : null,
  };
}

function sanitizeAuthorizationDeclaration(authorization) {
  if (!authorization) return null;
  return {
    ...authorization,
    provider_config: null,
  };
}

function sanitizeAuthorizationProofValueFrom(valueFrom) {
  if (!valueFrom) return null;

  const sanitized = {};
  if (valueFrom.env != null) sanitized.env = valueFrom.env;
  if (valueFrom.file != null) sanitized.file = valueFrom.file;
  return Object.keys(sanitized).length > 0 ? sanitized : null;
}

function sanitizeAuthorizationProofDeclaration(authorizationProof) {
  if (!authorizationProof) return null;
  return {
    ...authorizationProof,
    proof: authorizationProof.proof
      ? {
          ...authorizationProof.proof,
          value_from: sanitizeAuthorizationProofValueFrom(authorizationProof.proof.value_from),
        }
      : null,
  };
}

function sanitizeAuthorizationProofProfile(profile) {
  if (!profile) return null;
  return {
    ...profile,
    proof: profile.proof
      ? {
          ...profile.proof,
          value_from: sanitizeAuthorizationProofValueFrom(profile.proof.value_from),
        }
      : null,
  };
}

function sanitizeAuthorizationProfile(profile) {
  if (!profile) return null;
  return {
    ...profile,
    provider_config: null,
  };
}

function sanitizeEvidenceDeclaration(evidence, { includeHashes = false } = {}) {
  if (!evidence) return null;
  return {
    ...evidence,
    ...(includeHashes
      ? {
          payload_hash: canonicalDigest(evidence.payload ?? {}),
          provider_config_hash: evidence.provider_config == null
            ? null
            : canonicalDigest(evidence.provider_config),
        }
      : {}),
    provider_config: null,
  };
}

function sanitizeEvidenceProfile(profile) {
  if (!profile) return null;
  return {
    ...profile,
    provider_config: null,
  };
}

function addTargetValidationError(errors, path, message) {
  errors.push({ path, message });
}

function validateSchedulerStringLimits(errors, taskPath, job) {
  for (const [field, maxLength] of Object.entries(SCHEDULER_STRING_LIMITS)) {
    const value = job[field];
    if (typeof value === 'string' && value.length > maxLength) {
      addTargetValidationError(
        errors,
        `${taskPath}.${field}`,
        `compiled openclaw-scheduler ${field} exceeds max length of ${maxLength}`
      );
    }
  }
}

function validateSchedulerReservedValues(errors, taskPath, job) {
  if (!job.parent_id && job.schedule_cron === TRIGGERED_SENTINEL_CRON) {
    addTargetValidationError(
      errors,
      `${taskPath}.schedule.cron`,
      'schedule_cron cannot use the reserved at-job sentinel for root cron jobs'
    );
  }
}

function validateSchedulerShellInputs(errors, taskPath, plan) {
  if (plan.execution.payload_kind !== 'shellCommand') return;
  const payload = plan.execution.payload || {};
  if (Object.keys(payload.env || {}).length > 0) {
    addTargetValidationError(
      errors,
      `${taskPath}.shell.env`,
      'openclaw-scheduler persists shell commands; shell.env values are refused to prevent credential disclosure. Use an identity provider or runtime-managed environment instead.'
    );
  }
  if (payload.stdin != null) {
    addTargetValidationError(
      errors,
      `${taskPath}.shell.stdin`,
      'openclaw-scheduler persists shell commands; inline stdin is refused because it may contain sensitive material.'
    );
  }
}

export function compileManifestToScheduler(
  manifest,
  {
    includeExplain = false,
    schedulerHandoffVersion = '3',
    cwd = process.cwd(),
    env = process.env,
    oneOffSource = null,
  } = {},
) {
  if (!['1', '2', '3', '4'].includes(String(schedulerHandoffVersion))) {
    throw new TypeError('schedulerHandoffVersion must be one of 1, 2, 3, or 4');
  }
  const validation = validateManifest(manifest);
  if (!validation.ok) {
    const err = new Error('Manifest validation failed');
    err.validation = validation;
    throw err;
  }
  const expanded = expandManifestShorthands(manifest);

  const jobs = [];
  const explain = [];
  const targetErrors = [];
  // Single-workflow manifests skip the workflow name prefix on compiled job
  // names. This keeps names clean for the common case and makes --adopt-by
  // name work with existing scheduler jobs. Multi-workflow manifests include
  // the prefix to avoid name collisions between workflows.
  const useNamePrefix = expanded.workflows.length > 1;

  for (const [workflowIndex, workflow] of expanded.workflows.entries()) {
    const taskIdToJobId = new Map();
    for (const task of workflow.tasks) {
      taskIdToJobId.set(task.id, stableId(workflow.id, task.id));
    }

    for (const [taskIndex, task] of workflow.tasks.entries()) {
      const taskPath = `$.workflows[${workflowIndex}].tasks[${taskIndex}]`;
      const plan = normalizedTaskPlan(workflow, task, taskIdToJobId, { namePrefix: useNamePrefix });
      const isTriggered = plan.invocation.mode === 'trigger';
      const outputPolicy = schedulerOutputPolicy(plan);
      const identityProfile = plan.identity?.ref
        ? expanded.identity_profiles?.find(profile => profile.id === plan.identity.ref) ?? null
        : null;
      const authorizationProofProfile = plan.authorization_proof?.ref
        ? expanded.authorization_proof_profiles?.find(profile => profile.id === plan.authorization_proof.ref) ?? null
        : null;
      const authorizationProfile = plan.authorization?.ref
        ? expanded.authorization_profiles?.find(profile => profile.id === plan.authorization.ref) ?? null
        : null;
      const evidenceProfile = plan.evidence?.ref
        ? expanded.evidence_profiles?.find(profile => profile.id === plan.evidence.ref) ?? null
        : null;

      const resolvedIdentity = isV2IdentityDeclaration(plan.identity)
        ? mergeIdentityProfile(identityProfile, plan.identity)
        : null;
      const resolvedAuthorizationProof = plan.authorization_proof
        ? mergeAuthorizationProofProfile(authorizationProofProfile, plan.authorization_proof)
        : null;
      const resolvedAuthorization = plan.authorization
        ? mergeAuthorizationProfile(authorizationProfile, plan.authorization)
        : null;
      const resolvedEvidence = plan.evidence
        ? mergeEvidenceProfile(evidenceProfile, plan.evidence)
        : null;
      const persistedIdentity = sanitizeIdentityDeclaration(resolvedIdentity);
      const persistedAuthorizationProof = sanitizeAuthorizationProofDeclaration(resolvedAuthorizationProof);
      const persistedAuthorization = sanitizeAuthorizationDeclaration(resolvedAuthorization);
      const persistedEvidence = sanitizeEvidenceDeclaration(resolvedEvidence, {
        includeHashes: String(schedulerHandoffVersion) === '4',
      });
      const deliveryOptOutReason = schedulerDeliveryOptOutReason(plan);
      const dispatchesOneOff = oneOffSource != null
        && oneOffSource.workflow_id === workflow.id
        && oneOffSource.task_id === task.id;
      const job = {
        id: plan.id,
        source: plan.source,
        name: plan.name,
        enabled: plan.enabled && plan.approval.policy !== 'auto-reject' ? 1 : 0,
        schedule_cron: isTriggered ? TRIGGERED_SENTINEL_CRON : plan.invocation.cron,
        schedule_tz: isTriggered ? TRIGGERED_SENTINEL_TZ : plan.invocation.tz,
        session_target: plan.execution.session_target,
        agent_id: plan.execution.agent_id,
        payload_kind: plan.execution.payload_kind,
        payload_message: payloadMessageForExecution(plan.execution),
        payload_model: plan.execution.model_policy.scheduler_model,
        payload_thinking: plan.execution.model_policy.thinking,
        execution_intent: plan.intent.mode,
        execution_read_only: plan.intent.read_only ? 1 : 0,
        run_timeout_ms: plan.runtime.timeout_ms ?? SCHEDULER_DEFAULT_RUN_TIMEOUT_MS,
        overlap_policy: plan.reliability.overlap_policy,
        max_retries: plan.reliability.max_retries,
        max_queued_dispatches: plan.budgets.max_queued_dispatches,
        max_pending_approvals: plan.budgets.max_pending_approvals,
        max_trigger_fanout: plan.budgets.max_fanout,
        delivery_mode: plan.delivery.mode,
        delivery_channel: plan.delivery.channel,
        delivery_to: plan.delivery.to,
        delivery_opt_out_reason: deliveryOptOutReason,
        delivery_guarantee: plan.reliability.guarantee,
        origin: SCHEDULER_SYSTEM_ORIGIN,
        parent_id: plan.parent_compiled_id,
        trigger_on: isTriggered ? plan.invocation.on : null,
        trigger_delay_s: isTriggered ? (plan.invocation.delay_s ?? 0) : 0,
        trigger_condition: isTriggered ? plan.invocation.condition : null,
        approval_required: plan.approval.required,
        approval_timeout_s: plan.approval.timeout_s ?? SCHEDULER_DEFAULT_APPROVAL_TIMEOUT_S,
        approval_auto: plan.approval.auto ?? SCHEDULER_DEFAULT_APPROVAL_AUTO,
        approval_risk_level: task.approval?.risk_level ?? null,
        approval_approver_scope: task.approval?.approver_scope ?? null,
        context_retrieval: plan.context.retrieval,
        context_retrieval_limit: plan.context.limit,
        ...outputPolicy,
        output_format: plan.output.format,
        preferred_session_key: plan.session.preferred_key,
        auth_profile: plan.auth_profile ?? null,
        identity_principal: plan.identity?.principal ?? null,
        identity_run_as: plan.identity?.run_as ?? null,
        identity_attestation: plan.identity?.attestation ?? null,
        contract_sandbox: plan.contract.sandbox,
        contract_allowed_paths: plan.contract.allowed_paths ? JSON.stringify(plan.contract.allowed_paths) : null,
        contract_network: plan.contract.network,
        contract_max_cost_usd: plan.contract.max_cost_usd,
        contract_audit: plan.contract.audit,

        // v0.2 identity fields (when present)
        identity_ref: persistedIdentity?.ref ?? null,
        identity_subject_kind: persistedIdentity?.subject?.kind ?? null,
        identity_subject_principal: persistedIdentity?.subject?.principal ?? null,
        identity_trust_level: persistedIdentity?.trust?.level ?? null,
        identity_delegation_mode: persistedIdentity?.subject?.delegation_mode ?? null,
        identity: persistedIdentity,

        // v0.2 authorization proof
        authorization_proof_ref: persistedAuthorizationProof?.ref ?? null,
        authorization_proof: persistedAuthorizationProof,

        // v0.2 authorization
        authorization_ref: resolvedAuthorization?.ref ?? null,
        authorization: persistedAuthorization,

        // v0.2 evidence
        evidence_ref: resolvedEvidence?.ref ?? null,
        evidence: persistedEvidence,

        // v0.2 contract trust fields
        contract_required_trust_level: plan.contract?.required_trust_level ?? null,
        contract_trust_enforcement: plan.contract?.trust_enforcement ?? null,

        child_credential_policy: plan.child_credential_policy ?? null,

        // verify fields
        verify_shell: schedulerVerificationShell(plan),
        verify_timeout_s: plan.verify?.timeout_seconds ?? null,
        verify_on_failure: plan.verify?.on_failure ?? null,

        delete_after_run: dispatchesOneOff || plan.delete_after_run ? 1 : 0
      };

      if (String(schedulerHandoffVersion) === '4') {
        const artifact = buildSchedulerHandoffV4Artifact({
          manifest,
          expanded,
          workflow,
          task,
          plan,
          job,
          cwd,
          env,
        });
        job.handoff_version = 4;
        job.handoff_artifact_digest = artifact.digest;
        job.handoff_artifact_payload = artifact.payload;
        job.effective_task_hash = artifact.effectiveTaskHash;
      }

      validateSchedulerStringLimits(targetErrors, taskPath, job);
      validateSchedulerReservedValues(targetErrors, taskPath, job);
      validateSchedulerShellInputs(targetErrors, taskPath, plan);

      if (isTriggered && task.trigger?.parent) {
        // The effective policy here uses a 3-level fallback (child -> parent task
        // -> workflow) to match the scheduler's runtime resolution. The STORED
        // value on the job (plan.child_credential_policy) only captures the
        // 2-level task/workflow resolution -- the parent-task fallback happens at
        // dispatch time when the scheduler reads the parent job's column.
        const parentTask = workflow.tasks.find(t => t.id === task.trigger.parent);
        const effectivePolicy =
          plan.child_credential_policy
          ?? (parentTask?.child_credential_policy ?? null)
          ?? (workflow.child_credential_policy ?? null);
        if (effectivePolicy === 'downscope') {
          const childIdentityScope = resolvedIdentity?.scope ?? null;
          if (!childIdentityScope) {
            const parentLabel = task.trigger.parent;
            addTargetValidationError(
              targetErrors,
              `${taskPath}.identity.scope`,
              `Task '${task.id}' inherits downscope policy from parent '${parentLabel}' but declares no identity scope. Add identity: { ref: ..., scope: ... } or set child_credential_policy: none.`
            );
          }
        }
      }

      jobs.push(job);

      explain.push({
        workflow_id: workflow.id,
        task_id: task.id,
        compiled_id: plan.id,
        target: 'openclaw-scheduler',
        invocation_mode: plan.invocation.mode,
        notes: isTriggered
          ? [
              'Scheduler jobs still require schedule_cron, so triggered tasks compile with a sentinel cron.',
              'Actual dispatch behavior comes from the scheduler runtime queue, not from the sentinel cron.'
            ]
          : ['Scheduled roots map directly to scheduler cron fields.'],
        model_policy: plan.execution.model_policy,
        intent: plan.intent,
        output: plan.output,
        budgets: plan.budgets,
      });
    }
  }

  if (targetErrors.length > 0) {
    const err = new Error('Manifest validation failed');
    err.validation = {
      ok: false,
      errors: targetErrors,
      warnings: validation.warnings || [],
    };
    throw err;
  }

  const profiles = {};
  if (Array.isArray(expanded.identity_profiles) && expanded.identity_profiles.length > 0) {
    profiles.identity_profiles = expanded.identity_profiles.map(sanitizeIdentityProfile);
  }
  if (Array.isArray(expanded.authorization_proof_profiles) && expanded.authorization_proof_profiles.length > 0) {
    profiles.authorization_proof_profiles = expanded.authorization_proof_profiles.map(sanitizeAuthorizationProofProfile);
  }
  if (Array.isArray(expanded.authorization_profiles) && expanded.authorization_profiles.length > 0) {
    profiles.authorization_profiles = expanded.authorization_profiles.map(sanitizeAuthorizationProfile);
  }
  if (Array.isArray(expanded.evidence_profiles) && expanded.evidence_profiles.length > 0) {
    profiles.evidence_profiles = expanded.evidence_profiles.map(sanitizeEvidenceProfile);
  }

  return {
    target: 'openclaw-scheduler',
    version: '0.2',
    handoff: {
      field_version: String(schedulerHandoffVersion),
      v1_field_count: SCHEDULER_FIELDS_V1.length,
      v2_field_count: SCHEDULER_FIELDS_V1.length + SCHEDULER_FIELDS_V02.length,
      v3_field_count: SCHEDULER_FIELDS_V1.length + SCHEDULER_FIELDS_V02.length + SCHEDULER_FIELDS_V03.length,
      v4_field_count: SCHEDULER_FIELDS_V1.length
        + SCHEDULER_FIELDS_V02.length
        + SCHEDULER_FIELDS_V03.length
        + SCHEDULER_FIELDS_V04.length,
    },
    jobs,
    ...profiles,
    ...(includeExplain ? { explain } : {})
  };
}
