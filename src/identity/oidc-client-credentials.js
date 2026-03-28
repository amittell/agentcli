/**
 * OIDC Client Credentials Grant identity provider.
 *
 * Implements OAuth 2.0 Client Credentials Grant (RFC 6749 Section 4.4)
 * for service-to-service authentication. Uses the global fetch() API
 * available in Node >= 22 (no external dependencies).
 */

import { readFileSync, writeFileSync, unlinkSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
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
  if (valueFrom.command) {
    try {
      const result = spawnSync('sh', ['-c', valueFrom.command], {
        encoding: 'utf8',
        timeout: 30000,
        stdio: ['pipe', 'pipe', 'pipe'],
        env,
      });
      if (result.status === 0 && result.stdout) {
        return result.stdout.trim();
      }
      return null;
    } catch {
      return null;
    }
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

const oidcClientCredentialsProvider = {
  name: 'oidc-client-credentials',

  capabilities: {
    auth_modes: ['service'],
    credential_types: ['access_token'],
    presentation_kinds: ['env', 'file'],
    handoff_modes: ['none'],
    refreshable: false,
    delegation: false,
    trust_levels: ['untrusted', 'restricted', 'supervised', 'autonomous'],
    approval_mechanisms: [],
  },

  /**
   * Validate a profile for the oidc-client-credentials provider.
   *
   * Checks that the profile declares a valid token_endpoint, client_id,
   * and has client_secret available through either provider_config or inputs.
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

    // Validate client_id
    if (typeof providerConfig.client_id !== 'string' || providerConfig.client_id.length === 0) {
      errors.push('auth.provider_config.client_id is required and must be a non-empty string');
    }

    // Validate client_secret availability
    const hasProviderConfigSecret =
      typeof providerConfig.client_secret === 'string' ||
      (providerConfig.client_secret && typeof providerConfig.client_secret === 'object' && providerConfig.client_secret.value_from);

    const hasInputsSecret =
      inputs.client_secret && inputs.client_secret.value_from;

    if (!hasProviderConfigSecret && !hasInputsSecret) {
      errors.push(
        'client_secret is required: provide auth.provider_config.client_secret (string or {value_from}) ' +
        'or auth.inputs.client_secret with a value_from object'
      );
    }

    if (errors.length > 0) {
      return { valid: false, errors };
    }

    return { valid: true };
  },

  /**
   * Resolve a credential session by performing an OAuth 2.0 Client Credentials
   * Grant against the configured token endpoint.
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
    const clientId = providerConfig.client_id;
    const clientSecret = resolveClientSecret(profile, env);

    const trustLevel = (profile.trust && profile.trust.level) || 'supervised';
    const subject = profile.subject || {};

    // Build empty session for non-required failure cases
    const buildEmptySession = () => ({
      provider: 'oidc-client-credentials',
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
        client_id: clientId,
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

    if (!clientSecret) {
      if (required) {
        throw Object.assign(
          new Error('Client secret could not be resolved from provider_config or inputs'),
          { code: 'token_request_failed' }
        );
      }
      return buildEmptySession();
    }

    // Build the token request body
    const params = new URLSearchParams();
    params.set('grant_type', 'client_credentials');
    params.set('client_id', clientId);
    params.set('client_secret', clientSecret);

    if (auth.scopes && auth.scopes.length > 0) {
      params.set('scope', auth.scopes.join(' '));
    }

    if (auth.audience) {
      params.set('audience', auth.audience);
    }

    if (auth.resource) {
      params.set('resource', auth.resource);
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

      tokenResponse = await response.json();
    } catch (fetchErr) {
      if (fetchErr.code === 'token_request_failed') {
        throw fetchErr;
      }

      const err = new Error(
        `Token request to ${tokenEndpoint} failed: ${fetchErr.message}`
      );
      err.code = 'token_request_failed';
      err.cause = fetchErr;

      if (required) {
        throw err;
      }
      return buildEmptySession();
    }

    return {
      provider: 'oidc-client-credentials',
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
      delegation_chain: [{
        kind: subject.kind || 'service',
        principal: subject.principal || clientId,
        grant: 'client-credentials',
        validated: true,
      }],
      delegation_validation: {
        valid: true,
        depth: 1,
        acyclic: true,
        all_grants_present: true,
      },
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
        token_endpoint: tokenEndpoint,
        client_id: clientId,
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
};

registerProvider(oidcClientCredentialsProvider);

export { oidcClientCredentialsProvider };
