/**
 * File-based bearer token identity provider.
 *
 * Resolves a bearer token by reading from a file specified in the
 * identity profile's provider_config.token_file field. The file path
 * can also be provided indirectly via auth.inputs.token_file.value_from,
 * which resolves the path from an environment variable or another file.
 */

import { existsSync, readFileSync, statSync, writeFileSync, unlinkSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
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

/**
 * Resolve a value_from indirection to a string value.
 *
 * Supports reading from an environment variable (value_from.env) or
 * a file (value_from.file).
 *
 * @param {object} valueFrom - Object with env or file property.
 * @param {object} env       - Environment variables object.
 * @returns {string|undefined} The resolved value, or undefined.
 */
function resolveValueFrom(valueFrom, env) {
  if (!valueFrom || typeof valueFrom !== 'object') return undefined;
  if (valueFrom.env) {
    const val = env[valueFrom.env];
    return typeof val === 'string' ? val.trim() : undefined;
  }
  if (valueFrom.file) {
    try {
      return readFileSync(valueFrom.file, 'utf8').trim();
    } catch (_e) {
      return undefined;
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
      return undefined;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

/**
 * Check if a file's permissions indicate it is world-readable.
 * Returns a warning string if world-readable, or null otherwise.
 *
 * @param {string} filePath - Path to check.
 * @returns {string|null} Warning message, or null if permissions are acceptable.
 */
function checkWorldReadable(filePath) {
  try {
    const stats = statSync(filePath);
    const othersRead = stats.mode & 0o004;
    if (othersRead) {
      return `Token file "${filePath}" is world-readable (mode ${(stats.mode & 0o777).toString(8)}). Consider restricting permissions to 0600.`;
    }
  } catch (_e) {
    // If stat fails, skip the permission check; existence check handles missing files.
  }
  return null;
}

const fileBearerProvider = {
  name: 'file-bearer',

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
   * Validate a profile for the file-bearer provider.
   *
   * Checks that the profile declares either a token_file in provider_config
   * (a non-empty string file path) or has an appropriate value_from entry
   * in auth.inputs.token_file.
   *
   * @param {object} profile - The identity profile.
   * @param {object} _ctx    - Resolution context.
   * @returns {{ valid: boolean, errors?: string[] }}
   */
  validateProfile(profile, _ctx) {
    const errors = [];

    const providerConfig = profile.auth && profile.auth.provider_config;
    const inputs = profile.auth && profile.auth.inputs;

    const hasTokenFile = providerConfig &&
      typeof providerConfig.token_file === 'string' &&
      providerConfig.token_file.length > 0;

    const hasTokenFileInput = inputs &&
      inputs.token_file &&
      inputs.token_file.value_from &&
      typeof inputs.token_file.value_from === 'object' &&
      (typeof inputs.token_file.value_from.env === 'string' ||
       typeof inputs.token_file.value_from.file === 'string' ||
       typeof inputs.token_file.value_from.command === 'string');

    if (!hasTokenFile && !hasTokenFileInput) {
      errors.push(
        'file-bearer provider requires auth.provider_config.token_file (non-empty string path to the token file) ' +
        'or auth.inputs.token_file.value_from with env, file, or command source providing the file path'
      );
    }

    if (errors.length > 0) {
      return { valid: false, errors };
    }

    return { valid: true };
  },

  /**
   * Resolve a credential session by reading a bearer token from a file.
   *
   * Determines the token file path from provider_config.token_file or
   * by resolving auth.inputs.token_file.value_from indirection. Reads
   * the file contents, trims whitespace, and returns a credential session.
   *
   * Warns (via provider_assertions) if the token file is world-readable.
   *
   * @param {object} request - The session request containing the profile.
   * @param {object} [ctx]   - Resolution context. ctx.env defaults to process.env.
   * @returns {object} A credential session.
   */
  resolveSession(request, ctx) {
    const env = (ctx && ctx.env) || process.env;
    const profile = request.profile || {};
    const providerConfig = (profile.auth && profile.auth.provider_config) || {};
    const inputs = (profile.auth && profile.auth.inputs) || {};
    const required = profile.auth && profile.auth.required !== false;

    // Determine the file path: direct from provider_config, or indirect via value_from
    let tokenFilePath = providerConfig.token_file || undefined;

    if (!tokenFilePath && inputs.token_file && inputs.token_file.value_from) {
      tokenFilePath = resolveValueFrom(inputs.token_file.value_from, env);
    }

    if (!tokenFilePath || typeof tokenFilePath !== 'string' || tokenFilePath.length === 0) {
      if (required) {
        throw Object.assign(
          new Error(
            'Token file path not found: neither auth.provider_config.token_file nor auth.inputs.token_file.value_from resolved to a path'
          ),
          { code: 'token_file_not_found' }
        );
      }
      return buildEmptySession(profile);
    }

    // Check file existence
    if (!existsSync(tokenFilePath)) {
      if (required) {
        throw Object.assign(
          new Error(`Token file not found: "${tokenFilePath}" does not exist`),
          { code: 'token_file_not_found' }
        );
      }
      return buildEmptySession(profile);
    }

    // Check permissions and collect warnings
    const providerAssertions = {};
    const permWarning = checkWorldReadable(tokenFilePath);
    if (permWarning) {
      providerAssertions.permission_warning = permWarning;
    }

    // Read and trim the token
    const token = readFileSync(tokenFilePath, 'utf8').trim();

    if (token.length === 0) {
      if (required) {
        throw Object.assign(
          new Error(`Token file is empty: "${tokenFilePath}" contains no token after trimming whitespace`),
          { code: 'token_file_empty' }
        );
      }
      return buildEmptySession(profile);
    }

    const trustLevel = (profile.trust && profile.trust.level) || 'supervised';
    const subject = profile.subject || {};
    const auth = profile.auth || {};

    providerAssertions.token_file = tokenFilePath;

    return {
      provider: 'file-bearer',
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
      provider_assertions: providerAssertions,
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

/**
 * Build an empty session for cases where the token is not available
 * and authentication is not required.
 *
 * @param {object} profile - The identity profile.
 * @returns {object} A credential session with no credentials.
 */
function buildEmptySession(profile) {
  const trustLevel = (profile.trust && profile.trust.level) || 'supervised';
  const subject = profile.subject || {};

  return {
    provider: 'file-bearer',
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

registerProvider(fileBearerProvider);

export { fileBearerProvider };
