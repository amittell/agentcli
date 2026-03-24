/**
 * Azure Managed Identity provider.
 *
 * Acquires access tokens from the Azure Instance Metadata Service (IMDS)
 * endpoint at 169.254.169.254. Works with both system-assigned and
 * user-assigned managed identities on Azure VMs, App Services, and
 * other Azure compute resources. Uses the global fetch() API available
 * in Node >= 22 (no external dependencies).
 */

import { readFileSync, writeFileSync, unlinkSync, mkdirSync } from 'node:fs';
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

const azureManagedIdentityProvider = {
  name: 'azure-managed-identity',

  capabilities: {
    auth_modes: ['service'],
    credential_types: ['access_token'],
    presentation_kinds: ['env', 'file'],
    handoff_modes: ['none'],
    refreshable: true,
    delegation: false,
    trust_levels: ['untrusted', 'restricted', 'supervised', 'autonomous'],
    approval_mechanisms: [],
  },

  /**
   * Validate a profile for the azure-managed-identity provider.
   *
   * Checks that the profile declares a valid resource URI. The client_id
   * is optional and only required for user-assigned managed identities.
   *
   * @param {object} profile - The identity profile.
   * @param {object} [_ctx]  - Resolution context.
   * @returns {{ valid: boolean, errors?: string[] }}
   */
  validateProfile(profile, _ctx) {
    const errors = [];
    const providerConfig = (profile.auth && profile.auth.provider_config) || {};

    if (typeof providerConfig.resource !== 'string' || providerConfig.resource.length === 0) {
      errors.push(
        'auth.provider_config.resource is required and must be a non-empty string ' +
        '(e.g. "https://management.azure.com/")'
      );
    }

    if (providerConfig.client_id !== undefined && providerConfig.client_id !== null) {
      if (typeof providerConfig.client_id !== 'string' || providerConfig.client_id.length === 0) {
        errors.push(
          'auth.provider_config.client_id, when specified, must be a non-empty string ' +
          '(used for user-assigned managed identities)'
        );
      }
    }

    if (errors.length > 0) {
      return { valid: false, errors };
    }

    return { valid: true };
  },

  /**
   * Resolve a credential session by requesting an access token from the
   * Azure Instance Metadata Service (IMDS) endpoint.
   *
   * The IMDS endpoint is a link-local address (169.254.169.254) that is
   * only reachable from within Azure compute resources with managed identity
   * enabled.
   *
   * @param {object} request - The session request containing the profile and instanceId.
   * @param {object} [ctx]   - Resolution context.
   * @returns {Promise<object>} A credential session.
   */
  async resolveSession(request, ctx) {
    const profile = request.profile || {};
    const providerConfig = (profile.auth && profile.auth.provider_config) || {};
    const auth = profile.auth || {};
    const required = auth.required !== false;

    const resource = providerConfig.resource;
    const clientId = providerConfig.client_id || null;

    const trustLevel = (profile.trust && profile.trust.level) || 'supervised';
    const subject = profile.subject || {};

    const buildEmptySession = () => ({
      provider: 'azure-managed-identity',
      subject: {
        principal: subject.principal || null,
        issuer: subject.issuer || 'https://sts.windows.net/',
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
        resource,
        client_id: clientId,
      },
      refresh: {
        supported: true,
        expires_at: null,
      },
      handoff: {
        mode: 'none',
        prepared: false,
      },
    });

    // Build the IMDS token request URL
    const imdsUrl = new URL('http://169.254.169.254/metadata/identity/oauth2/token');
    imdsUrl.searchParams.set('api-version', '2018-02-01');
    imdsUrl.searchParams.set('resource', resource);
    if (clientId) {
      imdsUrl.searchParams.set('client_id', clientId);
    }

    let tokenResponse;
    try {
      const response = await fetch(imdsUrl.toString(), {
        method: 'GET',
        headers: { 'Metadata': 'true' },
        signal: AbortSignal.timeout(10000),
      });

      if (!response.ok) {
        let errorBody;
        try {
          errorBody = await response.text();
        } catch {
          errorBody = '(unable to read response body)';
        }

        const err = new Error(
          `Azure IMDS returned HTTP ${response.status}: ${errorBody}`
        );
        err.code = 'managed_identity_unavailable';
        err.status = response.status;
        err.body = errorBody;

        if (required) {
          throw err;
        }
        return buildEmptySession();
      }

      tokenResponse = await response.json();
    } catch (fetchErr) {
      if (fetchErr.code === 'managed_identity_unavailable') {
        throw fetchErr;
      }

      const err = new Error(
        'Azure IMDS endpoint not reachable. This provider requires an Azure environment with managed identity enabled.'
      );
      err.code = 'managed_identity_unavailable';
      err.cause = fetchErr;

      if (required) {
        throw err;
      }
      return buildEmptySession();
    }

    const expiresAt = tokenResponse.expires_on
      ? new Date(Number(tokenResponse.expires_on) * 1000).toISOString()
      : tokenResponse.expires_in
        ? new Date(Date.now() + Number(tokenResponse.expires_in) * 1000).toISOString()
        : null;

    return {
      provider: 'azure-managed-identity',
      subject: {
        principal: subject.principal || null,
        issuer: subject.issuer || 'https://sts.windows.net/',
        run_as: subject.run_as || null,
      },
      instance: request.instanceId ? { id: request.instanceId, source: 'operator' } : null,
      trust: {
        declared_level: trustLevel,
        effective_level: trustLevel,
      },
      delegation_chain: [{
        kind: subject.kind || 'service',
        principal: subject.principal || 'managed-identity',
        grant: 'managed-identity',
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
          audience: resource,
          scopes: auth.scopes || [],
          expires_at: expiresAt,
        },
      },
      provider_assertions: {
        token_type: tokenResponse.token_type || 'Bearer',
        resource: tokenResponse.resource || resource,
        client_id: clientId,
      },
      refresh: {
        supported: true,
        expires_at: expiresAt,
      },
      handoff: {
        mode: 'none',
        prepared: false,
      },
    };
  },

  /**
   * Refresh a credential session by re-requesting a token from IMDS.
   *
   * Azure managed identity tokens are short-lived and IMDS always returns
   * a fresh token, making this equivalent to a new resolveSession call.
   *
   * @param {object} session - The current credential session.
   * @param {object} [ctx]   - Resolution context.
   * @returns {Promise<object>} A refreshed credential session.
   */
  async refreshSession(session, ctx) {
    const resource = session.provider_assertions && session.provider_assertions.resource;
    const clientId = session.provider_assertions && session.provider_assertions.client_id;

    return azureManagedIdentityProvider.resolveSession({
      profile: {
        auth: {
          provider_config: { resource, client_id: clientId },
        },
        trust: session.trust ? { level: session.trust.declared_level } : undefined,
        subject: session.subject,
      },
      instanceId: session.instance && session.instance.id,
    }, ctx);
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
          const prefix = target.prefix || 'agentcli-azure-cred';
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

registerProvider(azureManagedIdentityProvider);

export { azureManagedIdentityProvider };
