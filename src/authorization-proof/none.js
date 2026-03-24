/**
 * No-op authorization proof verifier.
 *
 * Used for manifests that declare no authorization proof method.
 * Always returns unverified results.
 */

import { registerVerifier } from './index.js';

const noneVerifier = {
  name: 'none',

  /**
   * Validate a profile for the none verifier.
   *
   * If the profile declares verify.required as true, validation fails
   * because the none method cannot satisfy a verification requirement.
   *
   * @param {object} profile - The authorization proof profile.
   * @param {object} _ctx    - Validation context.
   * @returns {{ valid: boolean, errors?: Array<{ field: string, message: string }> }}
   */
  validateProfile(profile, _ctx) {
    if (profile && profile.verify && profile.verify.required === true) {
      return {
        valid: false,
        errors: [{
          field: 'verify.required',
          message: 'method "none" cannot satisfy verify.required: true',
        }],
      };
    }
    return { valid: true };
  },

  /**
   * Verify proof for the none method. Always returns unverified.
   *
   * @param {*} _proof    - The proof value (unused).
   * @param {object} _profile - The authorization proof profile.
   * @param {object} _ctx     - Verification context.
   * @returns {{ verified: boolean, method: string, reason: string }}
   */
  verifyProof(_proof, _profile, _ctx) {
    return {
      verified: false,
      method: 'none',
      reason: 'no authorization proof method configured',
    };
  },

  /**
   * Describe a verification result for audit purposes.
   *
   * @param {object} _result - The verification result.
   * @param {object} _ctx    - Description context.
   * @returns {object} Audit-safe verification summary.
   */
  describeVerification(_result, _ctx) {
    return {
      method: 'none',
      issuer: null,
      verified: false,
      verified_at: null,
      manifest_digest: null,
      verifier: 'none',
    };
  },
};

registerVerifier(noneVerifier);

export { noneVerifier };
