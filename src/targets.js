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
    // Compile-shape declarations are available statically. Runtime enforcement
    // capabilities remain false until a live scheduler explicitly advertises
    // them, so an unavailable capabilities command cannot authorize execution.
    features: {
      approvals: 'runtime',
      model_policy: 'model+thinking',
      execution_intent: 'runtime',
      output_hints: 'runtime',
      timeout_support: 'runtime',
      context_retrieval: 'runtime',
      runtime_execution: false,
      identity_declaration: false,
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
      handoff_v4_artifact: false,
      artifact_bound_proofs: false,
      signed_or_provider_verified_evidence: false,
      provider_session_cache: false,
      credential_presentation: false,
      source_run_bound_delegation: false,
      immutable_runtime_events: false,
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
