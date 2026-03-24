/**
 * OPA (Open Policy Agent) authorization provider.
 *
 * Evaluates authorization decisions against a remote OPA instance via its
 * REST API. The provider sends the normalized authorization request as OPA
 * input and interprets the policy decision returned by the configured
 * endpoint.
 *
 * OPA endpoint format: POST /v1/data/<package>/<rule>
 * Response shape:      { result: true | false | { allow: bool, reason: string } | string }
 */

import { registerAuthorizationProvider } from './index.js';

const opaAuthorizationProvider = {
  name: 'opa',

  capabilities: {
    decision_kinds: ['permit', 'deny', 'require-escalation'],
    escalation: true,
    batch: false,
    dry_run: true,
  },

  /**
   * Validate that the authorization profile contains a valid OPA endpoint.
   *
   * @param {object} profile - The authorization profile.
   * @param {object} _ctx    - Resolution context.
   * @returns {{ valid: boolean, errors?: string[] }}
   */
  validateProfile(profile, _ctx) {
    const errors = [];

    const endpoint = profile?.provider_config?.endpoint;
    if (typeof endpoint !== 'string' || endpoint.trim() === '') {
      errors.push('provider_config.endpoint must be a non-empty string');
    }

    if (errors.length > 0) {
      return { valid: false, errors };
    }

    return { valid: true };
  },

  /**
   * Evaluate an authorization request against the configured OPA endpoint.
   *
   * Sends the normalized request as OPA input, parses the policy decision,
   * and normalizes it into the agentcli authorization decision format.
   *
   * @param {object} request - The normalized authorization request.
   * @param {object} profile - The authorization profile.
   * @param {object} _ctx    - Resolution context.
   * @returns {Promise<object>} The authorization decision.
   */
  async authorize(request, profile, _ctx) {
    const endpoint = profile.provider_config.endpoint;
    const onError = profile.on_error || 'deny';
    const input = { input: request };

    let response;
    try {
      response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
        signal: AbortSignal.timeout(10000),
      });
    } catch (err) {
      if (onError === 'warn') {
        return {
          decision: 'permit',
          provider: 'opa',
          reason: 'authorization provider error (on_error: warn)',
          policy_ref: endpoint,
        };
      }
      throw Object.assign(
        new Error(`OPA authorization request failed: ${err.message}`),
        { code: 'authorization_error' }
      );
    }

    if (!response.ok) {
      if (onError === 'warn') {
        return {
          decision: 'permit',
          provider: 'opa',
          reason: 'authorization provider error (on_error: warn)',
          policy_ref: endpoint,
        };
      }
      throw Object.assign(
        new Error(`OPA returned HTTP ${response.status}: ${response.statusText}`),
        { code: 'authorization_error' }
      );
    }

    let body;
    try {
      body = await response.json();
    } catch (err) {
      if (onError === 'warn') {
        return {
          decision: 'permit',
          provider: 'opa',
          reason: 'authorization provider error (on_error: warn)',
          policy_ref: endpoint,
        };
      }
      throw Object.assign(
        new Error(`Failed to parse OPA response as JSON: ${err.message}`),
        { code: 'authorization_error' }
      );
    }

    const result = body.result;
    let decision;
    let reason = null;

    if (typeof result === 'boolean') {
      decision = result ? 'permit' : 'deny';
    } else if (result !== null && typeof result === 'object' && 'allow' in result) {
      decision = result.allow ? 'permit' : 'deny';
      reason = result.reason || null;
    } else if (typeof result === 'string') {
      decision = result;
    } else {
      decision = 'deny';
      reason = 'unexpected OPA result type';
    }

    return {
      decision,
      provider: 'opa',
      reason,
      policy_ref: endpoint,
    };
  },

  /**
   * Return an audit-safe description of an OPA authorization decision.
   *
   * @param {object} decision - The authorization decision to describe.
   * @param {object} _ctx     - Resolution context.
   * @returns {object} Audit-safe decision description.
   */
  describeDecision(decision, _ctx) {
    return {
      decision: decision.decision,
      provider: 'opa',
      reason: decision.reason,
      policy_ref: decision.policy_ref,
      escalation: null,
    };
  },
};

registerAuthorizationProvider(opaAuthorizationProvider);

export { opaAuthorizationProvider };
