import { TARGETS } from './targets.js';

/**
 * Query the scheduler for its runtime capabilities.
 * @param {object} runner - scheduler CLI runner with queryCapabilities() method
 * @returns {{ ok: boolean, features?: object, version?: string, handoff_version?: string, source: string }}
 */
export function querySchedulerCapabilities(runner) {
  if (!runner || typeof runner.queryCapabilities !== 'function') {
    return { ok: false, error: 'Runner does not support capability queries', source: 'static' };
  }
  try {
    const result = runner.queryCapabilities();
    if (!result || typeof result !== 'object' || !result.features) {
      return { ok: false, error: 'Invalid capabilities response', source: 'static' };
    }
    return {
      ok: true,
      features: result.features,
      version: result.scheduler_version || null,
      handoff_version: result.handoff_version || null,
      schema_version: result.schema_version || null,
      source: 'runtime',
    };
  } catch (err) {
    return { ok: false, error: err.message || String(err), source: 'static' };
  }
}

/**
 * Merge static features with runtime capabilities.
 * Static features are the floor -- runtime can upgrade false->true but never downgrade true->false.
 * String values are replaced by runtime values when present.
 */
export function resolveEffectiveFeatures(targetName, runtimeCapabilities) {
  const target = TARGETS[targetName];
  if (!target) throw new Error(`Unknown target: ${targetName}`);
  const staticFeatures = { ...target.features };

  if (!runtimeCapabilities || !runtimeCapabilities.ok || !runtimeCapabilities.features) {
    return { features: staticFeatures, source: 'static', negotiated: false };
  }

  const effective = { ...staticFeatures };
  const runtimeFeatures = runtimeCapabilities.features;

  for (const [key, runtimeValue] of Object.entries(runtimeFeatures)) {
    if (!(key in effective)) continue; // ignore unknown keys from runtime
    const staticValue = effective[key];

    if (typeof staticValue === 'boolean') {
      // Boolean: runtime can upgrade false->true, never downgrade true->false
      if (runtimeValue === true) effective[key] = true;
    } else if (typeof staticValue === 'string') {
      // String: runtime value replaces static if present and is a string
      if (typeof runtimeValue === 'string') effective[key] = runtimeValue;
    }
  }

  return {
    features: effective,
    source: 'runtime',
    negotiated: true,
    handoff_version: runtimeCapabilities.handoff_version || null,
  };
}

/**
 * Check if the manifest's requirements are satisfied by the effective features.
 * Returns an array of mismatch errors (empty if all satisfied).
 */
export function validateManifestCapabilities(compiledOutput, effectiveFeatures) {
  const errors = [];
  const features = effectiveFeatures.features || effectiveFeatures;

  if (!compiledOutput || !compiledOutput.jobs) return errors;

  // Apply-time gating is intentionally limited to features that must exist to
  // persist or hand off the compiled durable job spec. Runtime identity
  // resolution, delegation validation, and child_credential_policy remain
  // execution-time concerns: persisted identity declarations may already be
  // sufficient for dispatch, delegation chains are only known after a concrete
  // session is resolved, and child_credential_policy is a runtime column that
  // all v23+ schedulers accept regardless of whether providers are loaded.
  for (const job of compiledOutput.jobs) {
    // Check authorization hook requirement
    if (job.authorization || job.authorization_ref) {
      if (!features.authorization_hook) {
        errors.push({
          code: 'capability_mismatch',
          feature: 'authorization_hook',
          required_by: `job "${job.name || job.id}"`,
          message: `Job "${job.name || job.id}" declares authorization but the runtime does not support authorization_hook`,
        });
      }
    }

    // Check trust evaluation
    if (job.contract_required_trust_level) {
      if (!features.trust_evaluation) {
        errors.push({
          code: 'capability_mismatch',
          feature: 'trust_evaluation',
          required_by: `job "${job.name || job.id}"`,
          message: `Job "${job.name || job.id}" requires trust evaluation but the runtime does not support it`,
        });
      }
    }

    // Check evidence generation
    if (job.evidence || job.evidence_ref) {
      if (!features.evidence_generation) {
        errors.push({
          code: 'capability_mismatch',
          feature: 'evidence_generation',
          required_by: `job "${job.name || job.id}"`,
          message: `Job "${job.name || job.id}" declares evidence but the runtime does not support evidence_generation`,
        });
      }
    }

    const handoffMode = job.identity?.presentation?.handoff ?? null;
    if (handoffMode && handoffMode !== 'none') {
      if (!features.credential_handoff) {
        errors.push({
          code: 'capability_mismatch',
          feature: 'credential_handoff',
          required_by: `job "${job.name || job.id}"`,
          message: `Job "${job.name || job.id}" declares identity.presentation.handoff="${handoffMode}" but the runtime does not support credential_handoff`,
        });
      }
    }
  }

  return errors;
}
