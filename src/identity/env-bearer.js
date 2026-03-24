/**
 * Environment variable bearer token identity provider.
 *
 * Resolves a bearer token from an environment variable specified
 * in the identity profile's provider_config.token_env field.
 */

import { writeFileSync, unlinkSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { registerProvider } from './index.js';
import { resolveSourcePath, formatMaterializationValue, buildCredentialSummary } from './session.js';

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

const envBearerProvider = {
  name: 'env-bearer',

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
   * Validate a profile for the env-bearer provider.
   *
   * Checks that the profile declares either a token_env in provider_config
   * or has an appropriate entry in auth.inputs.
   *
   * @param {object} profile - The identity profile.
   * @param {object} _ctx    - Resolution context.
   * @returns {{ valid: boolean, errors?: string[] }}
   */
  validateProfile(profile, _ctx) {
    const errors = [];

    const providerConfig = profile.auth && profile.auth.provider_config;
    const inputs = profile.auth && profile.auth.inputs;

    const hasTokenEnv = providerConfig &&
      typeof providerConfig.token_env === 'string' &&
      providerConfig.token_env.length > 0;

    const hasTokenInput = inputs && (
      typeof inputs.token === 'string' ||
      typeof inputs.access_token === 'string' ||
      typeof inputs.bearer_token === 'string'
    );

    if (!hasTokenEnv && !hasTokenInput) {
      errors.push(
        'env-bearer provider requires auth.provider_config.token_env (non-empty string naming the environment variable) ' +
        'or an auth.inputs entry for token, access_token, or bearer_token'
      );
    }

    if (errors.length > 0) {
      return { valid: false, errors };
    }

    return { valid: true };
  },

  /**
   * Resolve a credential session by reading the bearer token from the
   * environment variable specified in the profile.
   *
   * @param {object} request - The session request containing the profile.
   * @param {object} [ctx]   - Resolution context. ctx.env defaults to process.env.
   * @returns {object} A credential session.
   */
  resolveSession(request, ctx) {
    const env = (ctx && ctx.env) || process.env;
    const profile = request.profile || {};
    const providerConfig = (profile.auth && profile.auth.provider_config) || {};
    const tokenEnv = providerConfig.token_env;

    const token = tokenEnv ? env[tokenEnv] : undefined;
    const required = profile.auth && profile.auth.required !== false;

    if (!token && required) {
      throw Object.assign(
        new Error(
          `Bearer token not found: environment variable "${tokenEnv || '(not specified)'}" is not set or is empty`
        ),
        { code: 'token_not_found' }
      );
    }

    const trustLevel = (profile.trust && profile.trust.level) || 'supervised';
    const subject = profile.subject || {};

    // If token is missing and not required, return session with empty credentials
    if (!token) {
      return {
        provider: 'env-bearer',
        subject: {
          principal: subject.principal || null,
          issuer: subject.issuer || null,
          run_as: subject.run_as || null,
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
    }

    const auth = profile.auth || {};

    return {
      provider: 'env-bearer',
      subject: {
        principal: subject.principal || null,
        issuer: subject.issuer || null,
        run_as: subject.run_as || null,
      },
      instance: null,
      trust: {
        declared_level: trustLevel,
        effective_level: trustLevel,
      },
      delegation_chain: [
        {
          kind: subject.kind || 'unknown',
          principal: subject.principal || null,
          grant: 'bearer-token',
          validated: true,
        },
      ],
      delegation_validation: {
        valid: true,
        depth: 1,
        acyclic: true,
        all_grants_present: true,
      },
      credentials: {
        access_token: {
          kind: 'bearer',
          value: token,
          audience: auth.audience || null,
          scopes: auth.scopes || [],
          expires_at: null,
        },
      },
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
   * Describe a session for audit purposes. Redacts the bearer token value
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
          // Skip bindings that target 'none' or have no recognized kind
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

registerProvider(envBearerProvider);

export { envBearerProvider };
