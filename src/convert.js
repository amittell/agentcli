/**
 * Manifest conversion utility -- v0.1 to v0.2.
 */

/**
 * Generate a deterministic profile ID from an attestation string.
 * @param {string} attestation
 * @returns {string}
 */
function attestationProfileId(attestation) {
  return `legacy-${attestation.replace(/[^a-zA-Z0-9-]/g, '-')}`;
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

  // Determine method from attestation string
  let method = 'none';
  if (attestation.startsWith('oidc:') || attestation.includes('jwt')) {
    method = 'jwt';
  } else if (attestation.includes('ssh') || attestation.includes('signature')) {
    method = 'detached-signature';
  } else if (attestation.includes('cert') || attestation.includes('x509')) {
    method = 'certificate';
  }

  converted.authorization_proof_profiles.push({
    id,
    method,
    issuer: null,
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
    const id = principal
      ? `converted-${principal.replace(/[^a-zA-Z0-9-]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '').slice(0, 40)}`
      : `converted-identity-${identityProfileMap.size + 1}`;

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
      const taskProfileRef = ensureIdentityProfile(task.identity);

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
        const failureProfileRef = ensureIdentityProfile(task.on_failure.identity);
        convertedTask.on_failure = {
          ...task.on_failure,
          identity: failureProfileRef ? { ref: failureProfileRef } : null,
        };
        if (convertedTask.on_failure.identity === null) delete convertedTask.on_failure.identity;
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

  return converted;
}
