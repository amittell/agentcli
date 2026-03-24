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

const TRIGGERED_SENTINEL_CRON = '0 0 31 2 *';
const TRIGGERED_SENTINEL_TZ = 'UTC';

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

export function compileManifestToScheduler(manifest, { includeExplain = false } = {}) {
  const validation = validateManifest(manifest);
  if (!validation.ok) {
    const err = new Error('Manifest validation failed');
    err.validation = validation;
    throw err;
  }
  const expanded = expandManifestShorthands(manifest);

  const jobs = [];
  const explain = [];
  for (const workflow of expanded.workflows) {
    const taskIdToJobId = new Map();
    for (const task of workflow.tasks) {
      taskIdToJobId.set(task.id, stableId(workflow.id, task.id));
    }

    for (const task of workflow.tasks) {
      const plan = normalizedTaskPlan(workflow, task, taskIdToJobId);
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

      const resolvedIdentity = plan.identity
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

      jobs.push({
        id: plan.id,
        source: plan.source,
        name: plan.name,
        enabled: plan.enabled ? 1 : 0,
        schedule_cron: isTriggered ? TRIGGERED_SENTINEL_CRON : plan.invocation.cron,
        schedule_tz: isTriggered ? TRIGGERED_SENTINEL_TZ : plan.invocation.tz,
        session_target: plan.execution.session_target,
        agent_id: plan.execution.agent_id,
        payload_kind: plan.execution.payload_kind,
        payload_message: payloadMessageForExecution(plan.execution),
        payload_model: plan.execution.model_policy.scheduler_model,
        payload_thinking: plan.execution.model_policy.thinking,
        execution_intent: plan.intent.mode,
        execution_read_only: plan.intent.read_only == null ? null : (plan.intent.read_only ? 1 : 0),
        run_timeout_ms: plan.runtime.timeout_ms,
        overlap_policy: plan.reliability.overlap_policy,
        max_retries: plan.reliability.max_retries,
        max_queued_dispatches: plan.budgets.max_queued_dispatches,
        max_pending_approvals: plan.budgets.max_pending_approvals,
        max_trigger_fanout: plan.budgets.max_fanout,
        delivery_mode: plan.delivery.mode,
        delivery_channel: plan.delivery.channel,
        delivery_to: plan.delivery.to,
        delivery_guarantee: plan.reliability.guarantee,
        parent_id: plan.parent_compiled_id,
        trigger_on: isTriggered ? plan.invocation.on : null,
        trigger_delay_s: isTriggered ? plan.invocation.delay_s : null,
        trigger_condition: isTriggered ? plan.invocation.condition : null,
        approval_required: plan.approval.required,
        approval_timeout_s: plan.approval.timeout_s,
        approval_auto: plan.approval.auto,
        context_retrieval: plan.context.retrieval,
        context_retrieval_limit: plan.context.limit,
        ...outputPolicy,
        preferred_session_key: plan.session.preferred_key,
        identity_principal: plan.identity?.principal ?? null,
        identity_run_as: plan.identity?.run_as ?? null,
        identity_attestation: plan.identity?.attestation ?? null,
        contract_sandbox: plan.contract.sandbox,
        contract_allowed_paths: plan.contract.allowed_paths ? JSON.stringify(plan.contract.allowed_paths) : null,
        contract_network: plan.contract.network,
        contract_max_cost_usd: plan.contract.max_cost_usd,
        contract_audit: plan.contract.audit,

        // v0.2 identity fields (when present)
        identity_ref: resolvedIdentity?.ref ?? null,
        identity_subject_kind: resolvedIdentity?.subject?.kind ?? null,
        identity_subject_principal: resolvedIdentity?.subject?.principal ?? null,
        identity_trust_level: resolvedIdentity?.trust?.level ?? null,
        identity_delegation_mode: resolvedIdentity?.subject?.delegation_mode ?? null,
        identity: resolvedIdentity,

        // v0.2 authorization proof
        authorization_proof_ref: resolvedAuthorizationProof?.ref ?? null,
        authorization_proof: resolvedAuthorizationProof,

        // v0.2 authorization
        authorization_ref: resolvedAuthorization?.ref ?? null,
        authorization: resolvedAuthorization,

        // v0.2 evidence
        evidence_ref: resolvedEvidence?.ref ?? null,
        evidence: resolvedEvidence,

        // v0.2 contract trust fields
        contract_required_trust_level: plan.contract?.required_trust_level ?? null,
        contract_trust_enforcement: plan.contract?.trust_enforcement ?? null,

        delete_after_run: plan.delete_after_run == null ? null : (plan.delete_after_run ? 1 : 0)
      });

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

  const profiles = {};
  if (Array.isArray(expanded.identity_profiles) && expanded.identity_profiles.length > 0) {
    profiles.identity_profiles = expanded.identity_profiles;
  }
  if (Array.isArray(expanded.authorization_proof_profiles) && expanded.authorization_proof_profiles.length > 0) {
    profiles.authorization_proof_profiles = expanded.authorization_proof_profiles;
  }
  if (Array.isArray(expanded.authorization_profiles) && expanded.authorization_profiles.length > 0) {
    profiles.authorization_profiles = expanded.authorization_profiles;
  }
  if (Array.isArray(expanded.evidence_profiles) && expanded.evidence_profiles.length > 0) {
    profiles.evidence_profiles = expanded.evidence_profiles;
  }

  return {
    target: 'openclaw-scheduler',
    version: '0.2',
    jobs,
    ...profiles,
    ...(includeExplain ? { explain } : {})
  };
}
