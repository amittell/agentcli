/**
 * Manifest conversion utility -- v0.1 to v0.2.
 */

import { createHash } from 'node:crypto';
import { validateManifest } from './validate.js';

function shortHash(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex').slice(0, 10);
}

function identifierSlug(value, fallback) {
  const slug = String(value || '')
    .replace(/[^a-zA-Z0-9-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 32);
  return slug || fallback;
}

/**
 * Generate a deterministic profile ID from an attestation string.
 * @param {string} attestation
 * @returns {string}
 */
function attestationProfileId(attestation) {
  return `legacy-${identifierSlug(attestation, 'attestation')}-${shortHash(attestation)}`;
}

function mergeLegacyIdentity(workflowIdentity, scopedIdentity) {
  const base = workflowIdentity || {};
  const scoped = scopedIdentity || {};
  return {
    principal: scoped.principal ?? base.principal ?? null,
    run_as: scoped.run_as ?? base.run_as ?? null,
    attestation: scoped.attestation ?? base.attestation ?? null,
  };
}

/**
 * Add an authorization_proof_profile for the attestation if one does not
 * already exist in the converted manifest.
 * @param {object} converted
 * @param {string} attestation
 */
function ensureAttestationProfile(converted, attestation) {
  const id = attestationProfileId(attestation);
  if (converted.authorization_proof_profiles.find(p => p.id === id)) return;

  // v0.1 attestation values were declarations, not verifiable proof material.
  // Preserve the reference without claiming cryptographic verification. Users
  // can replace this profile with a configured verifier after conversion.
  converted.authorization_proof_profiles.push({
    id,
    method: 'none',
    verify: { required: false },
  });
}

/**
 * Convert a v0.1 manifest to v0.2 with safe defaults.
 *
 * Collects unique identity configurations from workflows and tasks, creates
 * identity_profiles entries for each unique configuration, and replaces inline
 * identity blocks with { ref: '<profile-id>' } references so that exec.js
 * takes the full provider lifecycle path instead of the inline "no provider"
 * fallback.
 *
 * @param {object} manifest
 * @returns {object}
 */
export function convertManifestV1toV2(manifest) {
  if (!manifest || manifest.version !== '0.1') {
    throw Object.assign(
      new Error('Input manifest must be version 0.1'),
      { code: 'invalid_argument' }
    );
  }

  const converted = {
    version: '0.2',
    identity_profiles: [],
    authorization_proof_profiles: [],
    authorization_profiles: [],
    evidence_profiles: [],
    workflows: [],
  };

  // Track unique identity configurations to generate profiles.
  // Key: serialized principal+run_as -> Value: profile id string
  const identityProfileMap = new Map();
  const identityProfileKeysById = new Map();

  function ensureIdentityProfile(identity) {
    if (!identity) return null;
    const { principal, run_as } = identity;
    if (!principal && !run_as) return null;

    // Generate a stable key from the identity fields
    const key = JSON.stringify({ principal: principal || null, run_as: run_as || null });
    if (identityProfileMap.has(key)) {
      return identityProfileMap.get(key);
    }

    // Generate a profile ID from the principal for readability, or fall back
    // to a counter-based name when no principal is present.
    const baseId = `converted-${identifierSlug(principal, 'identity')}`;
    const existingKey = identityProfileKeysById.get(baseId);
    const id = existingKey == null || existingKey === key
      ? baseId
      : `${baseId}-${shortHash(key)}`;

    const profile = {
      id,
      provider: 'none',
      subject: {
        kind: 'unknown',
        principal: principal || null,
        display_name: null,
        run_as: run_as || null,
        delegation_mode: 'none',
      },
      trust: {
        level: 'supervised',
      },
      presentation: {
        handoff: 'none',
        cleanup: 'always',
      },
    };

    converted.identity_profiles.push(profile);
    identityProfileMap.set(key, id);
    identityProfileKeysById.set(id, key);
    return id;
  }

  for (const workflow of (manifest.workflows || [])) {
    const workflowProfileRef = ensureIdentityProfile(workflow.identity);

    const convertedWorkflow = {
      ...workflow,
      identity: workflowProfileRef ? { ref: workflowProfileRef } : null,
      tasks: [],
    };
    // Remove v0.1 identity fields that were spread from ...workflow
    if (convertedWorkflow.identity === null) delete convertedWorkflow.identity;

    if (workflow.identity?.attestation) {
      ensureAttestationProfile(converted, workflow.identity.attestation);
      convertedWorkflow.authorization_proof = {
        ref: attestationProfileId(workflow.identity.attestation),
      };
    }

    for (const task of (workflow.tasks || [])) {
      const effectiveTaskIdentity = task.identity
        ? mergeLegacyIdentity(workflow.identity, task.identity)
        : null;
      const taskProfileRef = ensureIdentityProfile(effectiveTaskIdentity);

      const convertedTask = {
        ...task,
        identity: taskProfileRef ? { ref: taskProfileRef } : null,
      };
      if (convertedTask.identity === null) delete convertedTask.identity;

      if (task.identity?.attestation) {
        ensureAttestationProfile(converted, task.identity.attestation);
        convertedTask.authorization_proof = {
          ref: attestationProfileId(task.identity.attestation),
        };
      }

      if (task.on_failure?.identity) {
        const effectiveFailureIdentity = mergeLegacyIdentity(
          workflow.identity,
          task.on_failure.identity
        );
        const failureProfileRef = ensureIdentityProfile(effectiveFailureIdentity);
        convertedTask.on_failure = {
          ...task.on_failure,
          identity: failureProfileRef ? { ref: failureProfileRef } : null,
        };
        if (convertedTask.on_failure.identity === null) delete convertedTask.on_failure.identity;
        if (task.on_failure.identity.attestation) {
          ensureAttestationProfile(converted, task.on_failure.identity.attestation);
          convertedTask.on_failure.authorization_proof = {
            ref: attestationProfileId(task.on_failure.identity.attestation),
          };
        }
      }

      convertedWorkflow.tasks.push(convertedTask);
    }

    converted.workflows.push(convertedWorkflow);
  }

  // Remove empty profile arrays for cleanliness
  if (converted.identity_profiles.length === 0) delete converted.identity_profiles;
  if (converted.authorization_proof_profiles.length === 0) delete converted.authorization_proof_profiles;
  if (converted.authorization_profiles.length === 0) delete converted.authorization_profiles;
  if (converted.evidence_profiles.length === 0) delete converted.evidence_profiles;

  const validation = validateManifest(converted);
  if (!validation.ok) {
    throw Object.assign(
      new Error(`Converted manifest failed validation: ${validation.errors.map(error => error.message).join('; ')}`),
      { code: 'internal_error', validation }
    );
  }

  return converted;
}
