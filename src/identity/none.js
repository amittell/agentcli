/**
 * No-op identity provider.
 *
 * Used for tasks that require no authentication or identity context.
 * Produces minimal sessions with no credentials.
 */

import { registerProvider } from './index.js';

const noneProvider = {
  name: 'none',

  capabilities: {
    auth_modes: ['none'],
    credential_types: [],
    presentation_kinds: ['none'],
    handoff_modes: ['none'],
    refreshable: false,
    delegation: false,
    trust_levels: ['untrusted', 'restricted', 'supervised', 'autonomous'],
    approval_mechanisms: [],
  },

  /**
   * Validate a profile for the none provider. Always succeeds.
   *
   * @param {object} _profile - The identity profile.
   * @param {object} _ctx     - Resolution context.
   * @returns {{ valid: boolean }}
   */
  validateProfile(_profile, _ctx) {
    return { valid: true };
  },

  /**
   * Resolve a credential session. Returns a minimal session with no credentials.
   *
   * @param {object} request - The session request containing the profile.
   * @param {object} _ctx    - Resolution context.
   * @returns {object} A credential session.
   */
  resolveSession(request, _ctx) {
    const profile = request.profile || {};
    const trustLevel = (profile.trust && profile.trust.level) || 'supervised';

    return {
      provider: 'none',
      subject: {
        principal: (profile.subject && profile.subject.principal) || null,
        issuer: null,
        run_as: null,
      },
      instance: null,
      trust: {
        declared_level: trustLevel,
        effective_level: trustLevel,
      },
      delegation_chain: [],
      delegation_validation: {
        valid: true,
        depth: 0,
        acyclic: true,
        all_grants_present: true,
      },
      credentials: {},
      provider_assertions: {},
      refresh: {
        supported: false,
        expires_at: null,
      },
      handoff: {
        mode: 'none',
        prepared: false,
      },
    };
  },

  /**
   * Describe a session for audit purposes. The none provider has no
   * sensitive fields, so the session is returned as-is.
   *
   * @param {object} session - The credential session.
   * @param {object} _ctx    - Resolution context.
   * @returns {object} The audit-safe session description.
   */
  describeSession(session, _ctx) {
    return structuredClone(session);
  },

  /**
   * Materialize credentials for tool consumption. The none provider
   * has nothing to materialize.
   *
   * @param {object} _session      - The credential session.
   * @param {object} _presentation - Presentation bindings.
   * @param {object} _ctx          - Resolution context.
   * @returns {object} Materialization result.
   */
  materialize(_session, _presentation, _ctx) {
    return {
      materialized: false,
      cleanup_required: false,
    };
  },

  /**
   * Clean up materialized state. The none provider has nothing to clean.
   *
   * @param {object} _materialization - The materialization to clean up.
   * @param {object} _ctx             - Resolution context.
   * @returns {object} Cleanup result.
   */
  cleanup(_materialization, _ctx) {
    return { cleaned: true };
  },
};

registerProvider(noneProvider);

export { noneProvider };
