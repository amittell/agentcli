import { compileManifestToScheduler } from './compiler/openclaw-scheduler.js';
import { compileManifestToStandalone, STANDALONE_FEATURES } from './compiler/standalone.js';

export const TARGETS = {
  standalone: {
    name: 'standalone',
    description: 'Portable execution plan for authoring, validation, and protocol use without a bound runtime.',
    capabilities: ['schema', 'validate', 'compile', 'describe', 'json-rpc'],
    features: { ...STANDALONE_FEATURES },
    compile: compileManifestToStandalone,
  },
  'openclaw-scheduler': {
    name: 'openclaw-scheduler',
    description: 'Compile manifest tasks into OpenClaw Scheduler job specs for the durable runtime.',
    capabilities: ['compile', 'apply', 'inspect', 'field-mask', 'sanitize-basic', 'ndjson'],
    // Static baseline features -- superseded by runtime capability negotiation when available.
    // These serve as the fallback when the scheduler is unreachable or does not support
    // the 'capabilities' command.
    features: {
      approvals: 'runtime',
      model_policy: 'model+thinking',
      execution_intent: 'runtime',
      output_hints: 'runtime',
      timeout_support: 'runtime',
      context_retrieval: 'runtime',
      runtime_execution: true,
      identity_declaration: true,
      runtime_identity_resolution: true,
      evidence_generation: true,
      audit_export: true,
      trust_evaluation: true,
      delegation_validation: true,
      credential_handoff: true,
      authorization_proof_verification: true,
      authorization_hook: true,
      root_approval_gate: true,
      approval_scope_enforcement: false,
      structured_output_format: true,
      handoff_v4_artifact: true,
      artifact_bound_proofs: true,
      signed_or_provider_verified_evidence: true,
      provider_session_cache: true,
      credential_presentation: true,
      source_run_bound_delegation: true,
      immutable_runtime_events: true,
    },
    compile: compileManifestToScheduler,
  },
};

export function registerTarget(target) {
  if (!target || typeof target.name !== 'string' || !target.name) {
    throw new Error('Target must have a non-empty string name');
  }
  if (typeof target.compile !== 'function') {
    throw new Error(`Target "${target.name}" must implement compile(manifest, options)`);
  }
  if (TARGETS[target.name]) {
    throw new Error(`Target "${target.name}" is already registered`);
  }
  TARGETS[target.name] = {
    name: target.name,
    description: target.description || '',
    capabilities: target.capabilities || [],
    features: target.features || {},
    compile: target.compile,
  };
}

export function getTarget(name) {
  const target = TARGETS[name];
  if (!target) {
    throw Object.assign(
      new Error(`Unsupported compile target: ${name}`),
      { code: 'invalid_argument' }
    );
  }
  return target;
}

export function listTargets() {
  return Object.values(TARGETS).map(({ name, description, capabilities, features }) => ({
    name,
    description,
    capabilities,
    features,
  }));
}
