import { validateManifest } from '../validate.js';
import { normalizedTaskPlan, stableId } from './shared.js';
import { expandManifestShorthands } from '../shorthand.js';
import { canonicalDigest, hashNullableString } from '../canonical.js';

export const STANDALONE_FEATURES = Object.freeze({
  approvals: 'intent-only',
  model_policy: 'portable',
  execution_intent: 'portable',
  output_hints: 'portable',
  timeout_support: 'portable',
  context_retrieval: 'portable',
  runtime_execution: false,
  identity_declaration: true,
  runtime_identity_resolution: false,
  evidence_generation: false,
  audit_export: false,
  trust_evaluation: false,
  delegation_validation: false,
  credential_handoff: false,
  authorization_proof_verification: false,
  authorization_hook: false,
  root_approval_gate: false,
  approval_scope_enforcement: false,
  structured_output_format: false,
});

function sanitizeValueFrom(valueFrom) {
  if (!valueFrom) return null;
  if (valueFrom.env) return { env: valueFrom.env };
  if (valueFrom.file) return { file: valueFrom.file };
  return null;
}

function sanitizeIdentity(identity) {
  if (!identity) return null;
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
      ? { ...identity.auth, provider_config: null, inputs: null }
      : null,
  };
}

function sanitizeTaskPlan(plan) {
  const payload = plan.execution.payload;
  const safePayload = plan.execution.payload_kind === 'shellCommand' && payload
    ? {
        program: payload.program,
        args: payload.args,
        cwd: payload.cwd,
        env: null,
        env_keys: Object.keys(payload.env || {}).sort(),
        env_hash: canonicalDigest(payload.env || {}),
        stdin: null,
        stdin_hash: hashNullableString(payload.stdin),
      }
    : payload;
  return {
    ...plan,
    execution: { ...plan.execution, payload: safePayload },
    identity: sanitizeIdentity(plan.identity),
    authorization_proof: plan.authorization_proof
      ? {
          ...plan.authorization_proof,
          proof: plan.authorization_proof.proof
            ? {
                ...plan.authorization_proof.proof,
                value_from: sanitizeValueFrom(plan.authorization_proof.proof.value_from),
              }
            : null,
        }
      : null,
    authorization: plan.authorization
      ? { ...plan.authorization, provider_config: null }
      : null,
    evidence: plan.evidence
      ? { ...plan.evidence, provider_config: null }
      : null,
  };
}

function sanitizeIdentityProfile(profile) {
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
    auth: profile.auth ? { ...profile.auth, provider_config: null, inputs: null } : null,
  };
}

function sanitizeProofProfile(profile) {
  return {
    ...profile,
    proof: profile.proof
      ? { ...profile.proof, value_from: sanitizeValueFrom(profile.proof.value_from) }
      : null,
  };
}

export function compileManifestToStandalone(manifest, { includeExplain = false } = {}) {
  const validation = validateManifest(manifest);
  if (!validation.ok) {
    const err = new Error('Manifest validation failed');
    err.validation = validation;
    throw err;
  }
  const expanded = expandManifestShorthands(manifest);

  const workflows = [];
  const explain = [];

  const useNamePrefix = expanded.workflows.length > 1;

  for (const workflow of expanded.workflows) {
    const taskIdToCompiledId = new Map();
    for (const task of workflow.tasks) {
      taskIdToCompiledId.set(task.id, stableId(workflow.id, task.id));
    }

    const tasks = [];
    const edges = [];
    for (const task of workflow.tasks) {
      const plan = normalizedTaskPlan(workflow, task, taskIdToCompiledId, { namePrefix: useNamePrefix });
      tasks.push(sanitizeTaskPlan(plan));
      if (plan.invocation.mode === 'trigger') {
        edges.push({
          from: plan.parent_compiled_id,
          to: plan.id,
          on: plan.invocation.on,
          condition: plan.invocation.condition,
          delay_s: plan.invocation.delay_s
        });
      }
      explain.push({
        workflow_id: workflow.id,
        task_id: task.id,
        compiled_id: plan.id,
        target: 'standalone',
        invocation_mode: plan.invocation.mode,
        notes: plan.invocation.mode === 'trigger'
          ? ['Retains trigger semantics directly; no scheduler-specific cron sentinel is needed.']
          : ['Retains cron schedule directly for backends that understand scheduled roots.']
      });
    }

    workflows.push({
      id: workflow.id,
      name: workflow.name,
      tasks,
      edges
    });
  }

  const profiles = {};
  if (Array.isArray(expanded.identity_profiles) && expanded.identity_profiles.length > 0) {
    profiles.identity_profiles = expanded.identity_profiles.map(sanitizeIdentityProfile);
  }
  if (Array.isArray(expanded.authorization_proof_profiles) && expanded.authorization_proof_profiles.length > 0) {
    profiles.authorization_proof_profiles = expanded.authorization_proof_profiles.map(sanitizeProofProfile);
  }
  if (Array.isArray(expanded.authorization_profiles) && expanded.authorization_profiles.length > 0) {
    profiles.authorization_profiles = expanded.authorization_profiles.map(profile => ({
      ...profile,
      provider_config: null,
    }));
  }
  if (Array.isArray(expanded.evidence_profiles) && expanded.evidence_profiles.length > 0) {
    profiles.evidence_profiles = expanded.evidence_profiles.map(profile => ({
      ...profile,
      provider_config: null,
    }));
  }

  return {
    target: 'standalone',
    version: '0.2',
    capabilities: {
      ...STANDALONE_FEATURES,
      authoring: true,
      planning: true,
      rpc: true,
      budgets: true,
      identity: true,
      contracts: true,
    },
    ...profiles,
    workflows,
    ...(includeExplain ? { explain } : {})
  };
}
