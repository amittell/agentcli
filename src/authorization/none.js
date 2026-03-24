/**
 * No-op authorization provider.
 *
 * Used as the default when no external authorization policy engine is
 * configured. Always permits execution unconditionally.
 */

import { registerAuthorizationProvider } from './index.js';

const noneAuthorizationProvider = {
  name: 'none',

  capabilities: {
    decision_kinds: ['permit', 'deny'],
    escalation: false,
    batch: false,
    dry_run: false,
  },

  /**
   * Validate a profile for the none provider. Always succeeds.
   *
   * @param {object} _profile - The authorization profile.
   * @param {object} _ctx     - Resolution context.
   * @returns {{ valid: boolean }}
   */
  validateProfile(_profile, _ctx) {
    return { valid: true };
  },

  /**
   * Evaluate an authorization request. Always permits.
   *
   * @param {object} _request - The normalized authorization request.
   * @param {object} _profile - The authorization profile.
   * @param {object} _ctx     - Resolution context.
   * @returns {object} The authorization decision.
   */
  authorize(_request, _profile, _ctx) {
    return {
      decision: 'permit',
      provider: 'none',
      reason: 'no external authorization configured; default permit',
      policy_ref: null,
    };
  },

  /**
   * Return an audit-safe description of a decision.
   *
   * @param {object} decision - The authorization decision to describe.
   * @param {object} _ctx     - Resolution context.
   * @returns {object} Audit-safe decision description.
   */
  describeDecision(decision, _ctx) {
    return {
      decision: decision.decision,
      provider: 'none',
      reason: decision.reason,
      policy_ref: null,
      escalation: null,
    };
  },
};

registerAuthorizationProvider(noneAuthorizationProvider);

export { noneAuthorizationProvider };
