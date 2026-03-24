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
