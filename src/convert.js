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
 * Convert a v0.1 identity block to v0.2 format.
 * @param {object|null|undefined} identity
 * @returns {object|null}
 */
function convertIdentityBlock(identity) {
  if (!identity) return null;

  const { principal, run_as, attestation, ...rest } = identity;

  // If no v0.1 fields present, return as-is (might already be v0.2)
  if (!principal && !run_as && !attestation) return identity;

  return {
    subject: {
      kind: 'unknown',
      principal: principal || null,
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
    ...rest,
  };
}

/**
 * Convert a v0.1 manifest to v0.2 with safe defaults.
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

  for (const workflow of (manifest.workflows || [])) {
    const convertedWorkflow = {
      ...workflow,
      identity: convertIdentityBlock(workflow.identity),
      tasks: [],
    };

    // If workflow has attestation, create an authorization_proof_profiles entry
    if (workflow.identity?.attestation) {
      ensureAttestationProfile(converted, workflow.identity.attestation);
      convertedWorkflow.authorization_proof = {
        ref: attestationProfileId(workflow.identity.attestation),
      };
    }

    for (const task of (workflow.tasks || [])) {
      const convertedTask = {
        ...task,
        identity: convertIdentityBlock(task.identity),
      };

      if (task.identity?.attestation) {
        ensureAttestationProfile(converted, task.identity.attestation);
        convertedTask.authorization_proof = {
          ref: attestationProfileId(task.identity.attestation),
        };
      }

      // Handle on_failure identity
      if (task.on_failure?.identity) {
        convertedTask.on_failure = {
          ...task.on_failure,
          identity: convertIdentityBlock(task.on_failure.identity),
        };
      }

      convertedWorkflow.tasks.push(convertedTask);
    }

    converted.workflows.push(convertedWorkflow);
  }

  return converted;
}
