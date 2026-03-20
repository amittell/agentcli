import { compileManifestToScheduler } from './compiler/openclaw-scheduler.js';
import { compileManifestToStandalone } from './compiler/standalone.js';

export const TARGETS = {
  standalone: {
    name: 'standalone',
    description: 'Portable execution plan for authoring, validation, and protocol use without a bound runtime.',
    capabilities: ['schema', 'validate', 'compile', 'describe', 'json-rpc'],
    features: {
      approvals: 'intent-only',
      model_policy: 'portable',
      execution_intent: 'portable',
      output_hints: 'portable',
      timeout_support: 'portable',
      context_retrieval: 'portable',
      runtime_execution: false,
    },
    compile: compileManifestToStandalone,
  },
  'openclaw-scheduler': {
    name: 'openclaw-scheduler',
    description: 'Compile manifest tasks into OpenClaw Scheduler job specs for the durable runtime.',
    capabilities: ['compile', 'apply', 'inspect', 'field-mask', 'sanitize-basic', 'ndjson'],
    features: {
      approvals: 'runtime',
      model_policy: 'model+thinking',
      execution_intent: 'runtime',
      output_hints: 'runtime',
      timeout_support: 'runtime',
      context_retrieval: 'runtime',
      runtime_execution: true,
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
