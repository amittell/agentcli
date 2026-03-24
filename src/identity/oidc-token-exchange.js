/**
 * OIDC Token Exchange identity provider.
 *
 * Implements OAuth 2.0 Token Exchange (RFC 8693) for exchanging one token
 * for another with different scope, audience, or type. Maps to
 * auth.mode: 'exchange' in the agentcli spec. Uses the global fetch() API
 * available in Node >= 22 (no external dependencies).
 */

import { readFileSync, writeFileSync, unlinkSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { registerProvider } from './index.js';
import { resolveSourcePath, formatMaterializationValue, buildCredentialSummary } from './session.js';

/**
 * Resolve a value_from indirection object to its concrete value.
 *
 * Supports env (environment variable) and file (filesystem path) sources.
 *
 * @param {object} valueFrom - The value_from descriptor.
 * @param {object} [env]     - Environment variable map, defaults to process.env.
 * @returns {string|null} The resolved value, or null if unresolvable.
 */
function resolveValueFrom(valueFrom, env = process.env) {
  if (!valueFrom) return null;
  if (valueFrom.env) {
    return env[valueFrom.env] || null;
  }
  if (valueFrom.file) {
    try {
      return readFileSync(valueFrom.file, 'utf8').trim();
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Resolve the subject token from provider_config or inputs.
 *
 * Checks provider_config.subject_token_env first (reads the named env var),
 * then falls back to inputs.subject_token.value_from indirection.
 *
 * @param {object} profile - The identity profile.
 * @param {object} env     - Environment variable map.
 * @returns {string|null} The resolved subject token, or null if unresolvable.
 */
function resolveSubjectToken(profile, env) {
  const providerConfig = (profile.auth && profile.auth.provider_config) || {};
  const inputs = (profile.auth && profile.auth.inputs) || {};

  // provider_config.subject_token_env: read the named environment variable
  if (typeof providerConfig.subject_token_env === 'string' && providerConfig.subject_token_env.length > 0) {
    const value = env[providerConfig.subject_token_env];
    if (typeof value === 'string' && value.length > 0) {
      return value;
    }
  }

  // inputs.subject_token.value_from: resolve indirection
  if (inputs.subject_token && inputs.subject_token.value_from) {
    const resolved = resolveValueFrom(inputs.subject_token.value_from, env);
    if (resolved) return resolved;
  }

  return null;
}

/**
 * Resolve the client secret from provider_config or inputs.
 *
 * Checks provider_config.client_secret first (inline string or value_from),
 * then falls back to inputs.client_secret.value_from.
 *
 * @param {object} profile - The identity profile.
 * @param {object} env     - Environment variable map.
 * @returns {string|null} The resolved client secret, or null if unresolvable.
 */
function resolveClientSecret(profile, env) {
  const providerConfig = (profile.auth && profile.auth.provider_config) || {};
  const inputs = (profile.auth && profile.auth.inputs) || {};

  // provider_config.client_secret: inline string
  if (typeof providerConfig.client_secret === 'string') {
    return providerConfig.client_secret;
  }

  // provider_config.client_secret: value_from object
  if (providerConfig.client_secret && typeof providerConfig.client_secret === 'object' && providerConfig.client_secret.value_from) {
    const resolved = resolveValueFrom(providerConfig.client_secret.value_from, env);
    if (resolved) return resolved;
  }

  // inputs.client_secret.value_from
  if (inputs.client_secret && inputs.client_secret.value_from) {
    const resolved = resolveValueFrom(inputs.client_secret.value_from, env);
    if (resolved) return resolved;
  }

  return null;
}

/**
 * Generate a unique temporary file path for credential materialization.
 *
 * @param {string} prefix - Filename prefix.
 * @returns {string} Absolute path to a temp file.
 */
function tempFilePath(prefix) {
  const rand = randomBytes(12).toString('hex');
  return join(tmpdir(), `${prefix}-${Date.now()}-${rand}`);
}

const oidcTokenExchangeProvider = {
  name: 'oidc-token-exchange',

  capabilities: {
    auth_modes: ['exchange'],
    credential_types: ['access_token'],
    presentation_kinds: ['env', 'file'],
    handoff_modes: ['none', 'downscope'],
    refreshable: false,
    delegation: true,
    trust_levels: ['untrusted', 'restricted', 'supervised', 'autonomous'],
    approval_mechanisms: [],
  },

  /**
   * Validate a profile for the oidc-token-exchange provider.
   *
   * Checks that the profile declares a valid token_endpoint and has a
   * subject token source available through either provider_config.subject_token_env
   * or inputs.subject_token.value_from.
   *
   * @param {object} profile - The identity profile.
   * @param {object} [ctx]   - Resolution context. ctx.allowInsecure permits http:// endpoints.
   * @returns {{ valid: boolean, errors?: string[] }}
   */
  validateProfile(profile, ctx) {
    const errors = [];
    const providerConfig = (profile.auth && profile.auth.provider_config) || {};
    const inputs = (profile.auth && profile.auth.inputs) || {};
    const allowInsecure = ctx && ctx.allowInsecure;

    // Validate token_endpoint
    if (typeof providerConfig.token_endpoint !== 'string' || providerConfig.token_endpoint.length === 0) {
      errors.push('auth.provider_config.token_endpoint is required and must be a non-empty string');
    } else if (!providerConfig.token_endpoint.startsWith('https://')) {
      if (providerConfig.token_endpoint.startsWith('http://') && allowInsecure) {
        // Allowed when insecure mode is explicitly enabled
      } else if (providerConfig.token_endpoint.startsWith('http://')) {
        errors.push('auth.provider_config.token_endpoint must use https:// (set allowInsecure to permit http://)');
      } else {
        errors.push('auth.provider_config.token_endpoint must start with https://');
      }
    }

    // Validate subject token source: either subject_token_env or inputs.subject_token.value_from
    const hasSubjectTokenEnv =
      typeof providerConfig.subject_token_env === 'string' &&
      providerConfig.subject_token_env.length > 0;

    const hasSubjectTokenInput =
      inputs.subject_token &&
      inputs.subject_token.value_from &&
      typeof inputs.subject_token.value_from === 'object';

    if (!hasSubjectTokenEnv && !hasSubjectTokenInput) {
      errors.push(
        'Subject token source is required: provide auth.provider_config.subject_token_env (env var name) ' +
        'or auth.inputs.subject_token with a value_from object'
      );
    }

    if (errors.length > 0) {
      return { valid: false, errors };
    }

    return { valid: true };
  },

  /**
   * Resolve a credential session by performing an OAuth 2.0 Token Exchange
   * (RFC 8693) against the configured token endpoint.
   *
   * Exchanges a subject token for a new access token, optionally scoped
   * to a specific audience, resource, or set of scopes.
   *
   * @param {object} request - The session request containing the profile and instanceId.
   * @param {object} [ctx]   - Resolution context. ctx.env defaults to process.env.
   * @returns {Promise<object>} A credential session.
   */
  async resolveSession(request, ctx) {
    const env = (ctx && ctx.env) || process.env;
    const profile = request.profile || {};
    const providerConfig = (profile.auth && profile.auth.provider_config) || {};
    const auth = profile.auth || {};
    const required = auth.required !== false;

    const tokenEndpoint = providerConfig.token_endpoint;
    const subjectTokenType = providerConfig.subject_token_type || 'urn:ietf:params:oauth:token-type:access_token';
    const clientId = providerConfig.client_id || null;

    const trustLevel = (profile.trust && profile.trust.level) || 'supervised';
    const subject = profile.subject || {};

    // Build empty session for non-required failure cases
    const buildEmptySession = () => ({
      provider: 'oidc-token-exchange',
      subject: {
        principal: subject.principal || null,
        issuer: subject.issuer || tokenEndpoint,
        run_as: subject.run_as || null,
      },
      instance: request.instanceId ? { id: request.instanceId, source: 'operator' } : null,
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
      provider_assertions: {
        token_endpoint: tokenEndpoint,
        exchange_grant: 'urn:ietf:params:oauth:grant-type:token-exchange',
      },
      refresh: {
        supported: false,
        expires_at: null,
      },
      handoff: {
        mode: 'none',
        prepared: false,
      },
    });

    // 1. Resolve subject token
    const subjectToken = resolveSubjectToken(profile, env);
    if (!subjectToken) {
      if (required) {
        throw Object.assign(
          new Error('Subject token could not be resolved from provider_config.subject_token_env or inputs.subject_token.value_from'),
          { code: 'token_request_failed' }
        );
      }
      return buildEmptySession();
    }

    // 2. Resolve optional client secret
    const clientSecret = resolveClientSecret(profile, env);

    // 3. Build the token exchange request per RFC 8693
    const params = new URLSearchParams();
    params.set('grant_type', 'urn:ietf:params:oauth:grant-type:token-exchange');
    params.set('subject_token', subjectToken);
    params.set('subject_token_type', subjectTokenType);
    params.set('requested_token_type', 'urn:ietf:params:oauth:token-type:access_token');

    if (auth.scopes && auth.scopes.length > 0) {
      params.set('scope', auth.scopes.join(' '));
    }

    if (auth.audience) {
      params.set('audience', auth.audience);
    }

    if (auth.resource) {
      params.set('resource', auth.resource);
    }

    if (clientId) {
      params.set('client_id', clientId);
    }

    if (clientSecret) {
      params.set('client_secret', clientSecret);
    }

    // 4. Call the token endpoint
    let tokenResponse;
    try {
      const response = await fetch(tokenEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params.toString(),
        signal: AbortSignal.timeout(30000),
      });

      if (!response.ok) {
        let errorBody;
        try {
          errorBody = await response.text();
        } catch {
          errorBody = '(unable to read response body)';
        }

        const err = new Error(
          `Token endpoint returned HTTP ${response.status}: ${errorBody}`
        );
        err.code = 'token_request_failed';
        err.status = response.status;
        err.body = errorBody;

        if (required) {
          throw err;
        }
        return buildEmptySession();
      }

      // 5. Parse response
      tokenResponse = await response.json();
    } catch (fetchErr) {
      if (fetchErr.code === 'token_request_failed') {
        throw fetchErr;
      }

      const err = new Error(
        `Token exchange request to ${tokenEndpoint} failed: ${fetchErr.message}`
      );
      err.code = 'token_request_failed';
      err.cause = fetchErr;

      if (required) {
        throw err;
      }
      return buildEmptySession();
    }

    // 6. Build credential session
    return {
      provider: 'oidc-token-exchange',
      subject: {
        principal: subject.principal || null,
        issuer: subject.issuer || tokenEndpoint,
        run_as: subject.run_as || null,
      },
      instance: request.instanceId ? { id: request.instanceId, source: 'operator' } : null,
      trust: {
        declared_level: trustLevel,
        effective_level: trustLevel,
      },
      delegation_chain: [
        {
          kind: 'exchange-source',
          principal: 'subject-token',
          grant: 'token-exchange',
          validated: true,
        },
        {
          kind: subject.kind || 'service',
          principal: subject.principal || null,
          grant: 'token-exchange',
          validated: true,
        },
      ],
      delegation_validation: oidcTokenExchangeProvider.validateDelegation(
        [
          { kind: 'exchange-source', principal: 'subject-token', grant: 'token-exchange', validated: true },
          { kind: subject.kind || 'service', principal: subject.principal || null, grant: 'token-exchange', validated: true },
        ],
        auth.delegation_policy || { max_depth: 3, allowed_delegators: [], require_grant_per_hop: true },
        {}
      ),
      credentials: {
        access_token: {
          kind: 'bearer',
          value: tokenResponse.access_token,
          audience: auth.audience || null,
          scopes: tokenResponse.scope
            ? tokenResponse.scope.split(' ')
            : (auth.scopes || []),
          expires_at: tokenResponse.expires_in
            ? new Date(Date.now() + tokenResponse.expires_in * 1000).toISOString()
            : null,
        },
      },
      provider_assertions: {
        token_type: tokenResponse.token_type || 'bearer',
        issued_token_type: tokenResponse.issued_token_type || 'urn:ietf:params:oauth:token-type:access_token',
        token_endpoint: tokenEndpoint,
        exchange_grant: 'urn:ietf:params:oauth:grant-type:token-exchange',
      },
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
   * Prepare a handoff by downscoping the current access token.
   *
   * When handoff.mode is 'downscope', performs a secondary token exchange
   * using the current access_token as the subject_token, requesting reduced
   * scopes. Falls back gracefully if the token endpoint does not support
   * downscoping.
   *
   * @param {object} session - The credential session from resolveSession.
   * @param {object} handoff - Handoff descriptor with mode and optional scopes/audience.
   * @param {object} [ctx]   - Resolution context.
   * @returns {Promise<object>} Handoff result with the downscoped credential or failure reason.
   */
  async prepareHandoff(session, handoff, _ctx) {
    if (!handoff || handoff.mode !== 'downscope') {
      return { prepared: false, reason: `unsupported handoff mode: ${handoff && handoff.mode}` };
    }

    const tokenEndpoint = session.provider_assertions && session.provider_assertions.token_endpoint;
    if (!tokenEndpoint) {
      return { prepared: false, reason: 'token_endpoint not available in session provider_assertions' };
    }

    const currentToken = session.credentials &&
      session.credentials.access_token &&
      session.credentials.access_token.value;

    if (!currentToken) {
      return { prepared: false, reason: 'no access_token in current session to downscope' };
    }

    // Build downscope exchange request using current token as subject_token
    const params = new URLSearchParams();
    params.set('grant_type', 'urn:ietf:params:oauth:grant-type:token-exchange');
    params.set('subject_token', currentToken);
    params.set('subject_token_type', 'urn:ietf:params:oauth:token-type:access_token');
    params.set('requested_token_type', 'urn:ietf:params:oauth:token-type:access_token');

    if (handoff.scopes && handoff.scopes.length > 0) {
      params.set('scope', handoff.scopes.join(' '));
    }

    if (handoff.audience) {
      params.set('audience', handoff.audience);
    }

    if (handoff.resource) {
      params.set('resource', handoff.resource);
    }

    let tokenResponse;
    try {
      const response = await fetch(tokenEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params.toString(),
        signal: AbortSignal.timeout(30000),
      });

      if (!response.ok) {
        let errorBody;
        try {
          errorBody = await response.text();
        } catch {
          errorBody = '(unable to read response body)';
        }
        return {
          prepared: false,
          reason: `downscope failed: token endpoint returned HTTP ${response.status}: ${errorBody}`,
        };
      }

      tokenResponse = await response.json();
    } catch (fetchErr) {
      return {
        prepared: false,
        reason: `downscope failed: ${fetchErr.message}`,
      };
    }

    return {
      prepared: true,
      mode: 'downscope',
      credentials: {
        access_token: {
          kind: 'bearer',
          value: tokenResponse.access_token,
          audience: handoff.audience || session.credentials.access_token.audience,
          scopes: tokenResponse.scope
            ? tokenResponse.scope.split(' ')
            : (handoff.scopes || session.credentials.access_token.scopes || []),
          expires_at: tokenResponse.expires_in
            ? new Date(Date.now() + tokenResponse.expires_in * 1000).toISOString()
            : null,
        },
      },
      provider_assertions: {
        token_type: tokenResponse.token_type || 'bearer',
        issued_token_type: tokenResponse.issued_token_type || 'urn:ietf:params:oauth:token-type:access_token',
        downscoped_from: 'parent-session',
      },
    };
  },

  /**
   * Describe a session for audit purposes. Redacts the access token value
   * and includes a credential summary.
   *
   * @param {object} session - The credential session.
   * @param {object} _ctx    - Resolution context.
   * @returns {object} Audit-safe session description.
   */
  describeSession(session, _ctx) {
    const described = structuredClone(session);

    if (described.credentials && described.credentials.access_token) {
      described.credentials.access_token.value = '[REDACTED]';
    }

    described.credential_summary = buildCredentialSummary(session);

    return described;
  },

  /**
   * Materialize credentials for tool consumption.
   *
   * Processes each binding in the presentation, resolving source paths
   * from the session and writing them to the specified target (env var
   * or temp file).
   *
   * @param {object} session      - The credential session.
   * @param {object} presentation - Presentation descriptor with bindings array.
   * @param {object} _ctx         - Resolution context.
   * @returns {object} Materialization result with env_vars, temp_files, and cleanup metadata.
   */
  materialize(session, presentation, _ctx) {
    const envVars = {};
    const tempFiles = [];
    const bindings = (presentation && presentation.bindings) || [];

    for (const binding of bindings) {
      const source = binding.source;
      const target = binding.target || {};
      const format = binding.format || 'raw';

      const rawValue = resolveSourcePath(session, source);
      if (rawValue === undefined) continue;

      const formatted = formatMaterializationValue(rawValue, format);

      switch (target.kind) {
        case 'env': {
          const envName = target.name;
          if (envName) {
            envVars[envName] = formatted;
          }
          break;
        }

        case 'file': {
          const prefix = target.prefix || 'agentcli-cred';
          const filePath = tempFilePath(prefix);
          mkdirSync(tmpdir(), { recursive: true });
          writeFileSync(filePath, formatted, { mode: 0o600 });
          tempFiles.push({ path: filePath, binding_source: source });
          break;
        }

        case 'none':
        default:
          break;
      }
    }

    return {
      materialized: true,
      cleanup_required: tempFiles.length > 0,
      env_vars: envVars,
      temp_files: tempFiles,
      stdin: null,
    };
  },

  /**
   * Clean up materialized state by deleting temporary files.
   *
   * @param {object} materialization - The materialization result from materialize().
   * @param {object} _ctx            - Resolution context.
   * @returns {{ cleaned: boolean, warnings: string[] }}
   */
  cleanup(materialization, _ctx) {
    const warnings = [];
    const files = (materialization && materialization.temp_files) || [];

    for (const entry of files) {
      const filePath = typeof entry === 'string' ? entry : entry.path;
      try {
        unlinkSync(filePath);
      } catch (err) {
        warnings.push(`Failed to delete temp file "${filePath}": ${err.message}`);
      }
    }

    return { cleaned: true, warnings };
  },

  /**
   * Validate a delegation chain against a policy.
   *
   * Checks that the chain is acyclic (no duplicate principals), that the
   * chain depth does not exceed the policy maximum, and that all hops
   * have a grant present.
   *
   * @param {Array<object>} chain  - Array of delegation chain entries.
   * @param {object}        policy - Delegation policy with max_depth and optional constraints.
   * @param {object}        [_ctx] - Resolution context.
   * @returns {{ valid: boolean, depth: number, acyclic: boolean, all_grants_present: boolean, hop_status: Array<object> }}
   */
  validateDelegation(chain, policy, _ctx) {
    const maxDepth = (policy && typeof policy.max_depth === 'number') ? policy.max_depth : 10;
    const entries = Array.isArray(chain) ? chain : [];
    const depth = entries.length;

    // Check for cycles: duplicate principals indicate a loop
    const seenPrincipals = new Set();
    let acyclic = true;
    for (const entry of entries) {
      // Null principals (anonymous hops) cannot form cycles
      if (entry.principal !== null && entry.principal !== undefined) {
        if (seenPrincipals.has(entry.principal)) {
          acyclic = false;
          break;
        }
        seenPrincipals.add(entry.principal);
      }
    }

    // Check that all hops have a grant present
    let allGrantsPresent = true;
    const hopStatus = entries.map((entry, index) => {
      const hasGrant = typeof entry.grant === 'string' && entry.grant.length > 0;
      if (!hasGrant) {
        allGrantsPresent = false;
      }
      return {
        index,
        kind: entry.kind || null,
        principal: entry.principal || null,
        grant: entry.grant || null,
        grant_present: hasGrant,
        validated: entry.validated === true,
      };
    });

    const depthOk = depth <= maxDepth;
    const valid = acyclic && depthOk && allGrantsPresent;

    return {
      valid,
      depth,
      acyclic,
      all_grants_present: allGrantsPresent,
      hop_status: hopStatus,
    };
  },
};

registerProvider(oidcTokenExchangeProvider);

export { oidcTokenExchangeProvider };
