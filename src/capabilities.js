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
 * Merge static declarations with observed runtime capabilities.
 * When a runtime reports a known feature, the observed value is authoritative.
 * Static values are used only for features omitted by the runtime or when no
 * runtime capability response is available.
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
    if (typeof runtimeValue === 'boolean' || typeof runtimeValue === 'string') {
      effective[key] = runtimeValue;
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
 * Returns { errors: [...], warnings: [...] } where errors are hard gates and
 * warnings are soft advisories that do not block apply.
 */
export function validateManifestCapabilities(compiledOutput, effectiveFeatures) {
  const errors = [];
  const warnings = [];
  const features = effectiveFeatures.features || effectiveFeatures;

  if (!compiledOutput || !compiledOutput.jobs) return { errors, warnings };

  // Hard gates: features that must exist to persist or hand off the compiled
  // durable job spec. These block apply when absent.
  //
  // Soft warnings: runtime_identity_resolution and credential_handoff (for
  // child_credential_policy) are checked here as advisories. Persisted identity
  // declarations may already be sufficient for dispatch and
  // child_credential_policy is a runtime column that all v23+ schedulers accept
  // regardless of whether providers are loaded, but a missing runtime feature
  // means execution will fail -- so we surface the gap early. Delegation
  // validation remains execution-time only (chains are only known after a
  // concrete session is resolved).
  for (const job of compiledOutput.jobs) {
    if (job.approval_required && !job.parent_id && !features.root_approval_gate) {
      errors.push({
        code: 'capability_mismatch',
        feature: 'root_approval_gate',
        required_by: `job "${job.name || job.id}"`,
        message: `Root job "${job.name || job.id}" requires manual approval but the runtime does not advertise root_approval_gate`,
      });
    }

    if (job.approval_approver_scope && !features.approval_scope_enforcement) {
      errors.push({
        code: 'capability_mismatch',
        feature: 'approval_scope_enforcement',
        required_by: `job "${job.name || job.id}"`,
        message: `Job "${job.name || job.id}" declares approver scope but the runtime cannot enforce it`,
      });
    }

    if (job.output_format && !features.structured_output_format) {
      errors.push({
        code: 'capability_mismatch',
        feature: 'structured_output_format',
        required_by: `job "${job.name || job.id}"`,
        message: `Job "${job.name || job.id}" declares output.format="${job.output_format}" but the runtime cannot persist that contract`,
      });
    }
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

    // Soft warning: identity with a real provider requires runtime resolution
    const identityProvider = job.identity?.provider ?? null;
    if (identityProvider && identityProvider !== 'none') {
      if (!features.runtime_identity_resolution) {
        warnings.push({
          code: 'capability_warning',
          feature: 'runtime_identity_resolution',
          required_by: `job "${job.name || job.id}"`,
          message: `Job "${job.name || job.id}" declares identity provider "${identityProvider}" but the runtime does not support runtime_identity_resolution; credentials will not resolve at execution time`,
        });
      }
    }

    // Soft warning: downscope policy requires credential_handoff at runtime.
    // Note: identity.presentation.handoff (above) is a hard error because
    // the scheduler cannot persist the handoff contract without the feature.
    // child_credential_policy is a soft warning because the column is always
    // accepted by v23+ schedulers -- enforcement happens at dispatch time.
    if (job.child_credential_policy === 'downscope') {
      if (!features.credential_handoff) {
        warnings.push({
          code: 'capability_warning',
          feature: 'credential_handoff',
          required_by: `job "${job.name || job.id}"`,
          message: `Job "${job.name || job.id}" declares child_credential_policy="downscope" but the runtime does not support credential_handoff; child credential scoping will not be enforced`,
        });
      }
    }
  }

  return { errors, warnings };
}
