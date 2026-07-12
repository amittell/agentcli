/**
 * Authorization proof verifier registry and resolution.
 *
 * An authorization proof verifier implements:
 *   name                    - string identifier matching a method enum
 *   validateProfile         - (profile, ctx) => validate method-specific profile fields without resolving proof value
 *   verifyProof             - (proof, profile, ctx) => verify proof against declared method, return machine-readable result
 *   describeVerification    - (result, ctx) => return audit-safe verification summary
 */

const verifiers = new Map();

/**
 * Register an authorization proof verifier.
 *
 * Validates that the verifier has a string name and all required methods
 * before adding it to the registry.
 *
 * @param {object} verifier - The verifier to register.
 */
export function registerVerifier(verifier) {
  if (!verifier || typeof verifier.name !== 'string' || verifier.name === '') {
    throw new Error('Verifier must have a non-empty string name');
  }
  if (typeof verifier.validateProfile !== 'function') {
    throw new Error(`Verifier "${verifier.name}" must implement validateProfile(profile, ctx)`);
  }
  if (typeof verifier.verifyProof !== 'function') {
    throw new Error(`Verifier "${verifier.name}" must implement verifyProof(proof, profile, ctx)`);
  }
  if (typeof verifier.describeVerification !== 'function') {
    throw new Error(`Verifier "${verifier.name}" must implement describeVerification(result, ctx)`);
  }
  verifiers.set(verifier.name, verifier);
}

/**
 * Get a registered verifier by name.
 *
 * @param {string} name - Verifier name.
 * @returns {object|null} The verifier, or null if not found.
 */
export function getVerifier(name) {
  return verifiers.get(name) ?? null;
}

/**
 * List the names of all registered verifiers.
 *
 * @returns {string[]}
 */
export function listVerifiers() {
  return [...verifiers.keys()];
}

/**
 * Resolve a verifier by method name. Throws if not found.
 *
 * @param {string} methodName - The method name to resolve.
 * @returns {object} The resolved verifier.
 */
export function resolveVerifier(methodName) {
  const verifier = verifiers.get(methodName);
  if (!verifier) {
    const available = listVerifiers().join(', ');
    throw Object.assign(
      new Error(`Unknown authorization proof verifier: "${methodName}". Available: ${available || '(none)'}`),
      { code: 'unknown_verifier' }
    );
  }
  return verifier;
}

/**
 * Run method-specific validation and normalize malformed verifier responses
 * to a closed failure.
 */
export function validateAuthorizationProofProfile(profile, ctx = {}) {
  if (!profile || typeof profile !== 'object' || Array.isArray(profile)) {
    return {
      valid: false,
      errors: [{ field: '$', message: 'authorization proof profile must be an object' }],
    };
  }
  if (typeof profile.method !== 'string' || profile.method.length === 0) {
    return {
      valid: false,
      errors: [{ field: 'method', message: 'authorization proof method is required' }],
    };
  }

  let verifier;
  try {
    verifier = resolveVerifier(profile.method);
  } catch (error) {
    return {
      valid: false,
      errors: [{ field: 'method', message: error.message }],
    };
  }

  try {
    const result = verifier.validateProfile(profile, ctx);
    if (!result || result.valid !== true) {
      return {
        valid: false,
        errors: Array.isArray(result?.errors) && result.errors.length > 0
          ? result.errors
          : [{ field: '$', message: `verifier "${profile.method}" rejected the profile` }],
      };
    }
    return { valid: true, errors: [] };
  } catch (error) {
    return {
      valid: false,
      errors: [{ field: '$', message: `profile validation failed: ${error.message}` }],
    };
  }
}

/**
 * Throw a structured error when a proof profile is not executable.
 */
export function assertValidAuthorizationProofProfile(profile, ctx = {}) {
  const validation = validateAuthorizationProofProfile(profile, ctx);
  if (!validation.valid) {
    const detail = validation.errors
      .map(error => `${error.field}: ${error.message}`)
      .join('; ');
    throw Object.assign(
      new Error(`Invalid authorization proof profile: ${detail}`),
      {
        code: 'authorization_proof_invalid',
        validation,
      }
    );
  }
  return resolveVerifier(profile.method);
}

/**
 * Verify a proof after validating the profile. Any malformed provider result
 * is converted to verified:false so callers cannot accidentally treat it as
 * a successful verification.
 */
export async function verifyAuthorizationProof(proof, profile, ctx = {}) {
  const verifier = assertValidAuthorizationProofProfile(profile, ctx);
  let verificationContext = ctx;
  try {
    if (profile.method === 'jwt') {
      const { resolveJwtVerificationContext } = await import('./jwt.js');
      verificationContext = await resolveJwtVerificationContext(proof, profile, ctx);
    }
    const result = await verifier.verifyProof(proof, profile, verificationContext);
    if (!result || result.verified !== true) {
      return {
        ...(result && typeof result === 'object' ? result : {}),
        verified: false,
        method: result?.method || profile.method,
        reason: result?.reason || 'authorization proof verification did not succeed',
      };
    }
    return result;
  } catch (error) {
    return {
      verified: false,
      method: profile.method,
      reason: `authorization proof verification failed: ${error.message}`,
      manifest_digest: verificationContext.manifestDigest || null,
      verified_at: new Date().toISOString(),
    };
  }
}
