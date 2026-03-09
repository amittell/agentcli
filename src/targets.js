import { compileManifestToScheduler } from './compiler/openclaw-scheduler.js';
import { compileManifestToStandalone } from './compiler/standalone.js';

export const TARGETS = {
  standalone: {
    name: 'standalone',
    description: 'Portable execution plan for authoring, validation, and protocol use without a bound runtime.',
    capabilities: ['compile', 'describe', 'json-rpc'],
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
    capabilities: ['compile', 'apply', 'inspect'],
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

export function getTarget(name) {
  const target = TARGETS[name];
  if (!target) {
    throw new Error(`Unsupported compile target: ${name}`);
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
