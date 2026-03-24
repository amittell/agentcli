/**
 * GCP Workload Identity Federation provider.
 *
 * Acquires access tokens from the GCP metadata server at
 * metadata.google.internal. Works on GCE instances, GKE pods with
 * Workload Identity, Cloud Run services, and other GCP compute
 * resources. Supports service account impersonation via the
 * service_account_email configuration option. Uses the global fetch()
 * API available in Node >= 22 (no external dependencies).
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

const gcpWorkloadIdentityProvider = {
  name: 'gcp-workload-identity',

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
   * Validate a profile for the gcp-workload-identity provider.
   *
   * Checks that the profile declares scopes (either via
   * provider_config.scopes or auth.scopes). The service_account_email
   * is optional and used for impersonation.
   *
   * @param {object} profile - The identity profile.
   * @param {object} [_ctx]  - Resolution context.
   * @returns {{ valid: boolean, errors?: string[] }}
   */
  validateProfile(profile, _ctx) {
    const errors = [];
    const providerConfig = (profile.auth && profile.auth.provider_config) || {};
    const auth = profile.auth || {};

    const scopes = providerConfig.scopes || auth.scopes;
    if (!scopes || !Array.isArray(scopes) || scopes.length === 0) {
      errors.push(
        'Scopes are required: provide auth.provider_config.scopes or auth.scopes ' +
        'as a non-empty array (e.g. ["https://www.googleapis.com/auth/cloud-platform"])'
      );
    } else {
      for (let i = 0; i < scopes.length; i++) {
        if (typeof scopes[i] !== 'string' || scopes[i].length === 0) {
          errors.push(`scopes[${i}] must be a non-empty string`);
        }
      }
    }

    if (providerConfig.service_account_email !== undefined && providerConfig.service_account_email !== null) {
      if (typeof providerConfig.service_account_email !== 'string' || providerConfig.service_account_email.length === 0) {
        errors.push(
          'auth.provider_config.service_account_email, when specified, must be a non-empty string ' +
          '(e.g. "my-sa@my-project.iam.gserviceaccount.com")'
        );
      } else if (!providerConfig.service_account_email.includes('@')) {
        errors.push(
          'auth.provider_config.service_account_email must be a valid service account email address'
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
   * GCP metadata server.
   *
   * The GCP metadata server (metadata.google.internal) is only reachable
   * from within GCP compute resources with a service account attached.
   * When service_account_email is specified, requests the token for that
   * specific service account (impersonation).
   *
   * @param {object} request - The session request containing the profile and instanceId.
   * @param {object} [ctx]   - Resolution context.
   * @returns {Promise<object>} A credential session.
   */
  async resolveSession(request, _ctx) {
    const profile = request.profile || {};
    const providerConfig = (profile.auth && profile.auth.provider_config) || {};
    const auth = profile.auth || {};
    const required = auth.required !== false;

    const scopes = providerConfig.scopes || auth.scopes || [];
    const serviceAccountEmail = providerConfig.service_account_email || null;

    const trustLevel = (profile.trust && profile.trust.level) || 'supervised';
    const subject = profile.subject || {};

    const buildEmptySession = () => ({
      provider: 'gcp-workload-identity',
      subject: {
        principal: subject.principal || null,
        issuer: subject.issuer || 'https://accounts.google.com',
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
        scopes,
        service_account_email: serviceAccountEmail,
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

    // Build the metadata server token request URL
    // When a specific service account is requested, use its path; otherwise use default
    const accountIdentifier = serviceAccountEmail || 'default';
    const metadataUrl = new URL(
      `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/${accountIdentifier}/token`
    );

    // GCP metadata server accepts scopes as a query parameter for token requests
    if (scopes.length > 0) {
      metadataUrl.searchParams.set('scopes', scopes.join(','));
    }

    let tokenResponse;
    try {
      const response = await fetch(metadataUrl.toString(), {
        method: 'GET',
        headers: { 'Metadata-Flavor': 'Google' },
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
          `GCP metadata server returned HTTP ${response.status}: ${errorBody}`
        );
        err.code = 'gcp_metadata_unavailable';
        err.status = response.status;
        err.body = errorBody;

        if (required) {
          throw err;
        }
        return buildEmptySession();
      }

      tokenResponse = await response.json();
    } catch (fetchErr) {
      if (fetchErr.code === 'gcp_metadata_unavailable') {
        throw fetchErr;
      }

      const err = new Error(
        'GCP metadata server not reachable. This provider requires a GCP environment with workload identity enabled.'
      );
      err.code = 'gcp_metadata_unavailable';
      err.cause = fetchErr;

      if (required) {
        throw err;
      }
      return buildEmptySession();
    }

    const expiresAt = tokenResponse.expires_in
      ? new Date(Date.now() + Number(tokenResponse.expires_in) * 1000).toISOString()
      : null;

    return {
      provider: 'gcp-workload-identity',
      subject: {
        principal: subject.principal || serviceAccountEmail || null,
        issuer: subject.issuer || 'https://accounts.google.com',
        run_as: subject.run_as || null,
      },
      instance: request.instanceId ? { id: request.instanceId, source: 'operator' } : null,
      trust: {
        declared_level: trustLevel,
        effective_level: trustLevel,
      },
      delegation_chain: [{
        kind: subject.kind || 'service',
        principal: subject.principal || serviceAccountEmail || 'workload-identity',
        grant: 'workload-identity',
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
          audience: null,
          scopes,
          expires_at: expiresAt,
        },
      },
      provider_assertions: {
        token_type: tokenResponse.token_type || 'Bearer',
        scopes,
        service_account_email: serviceAccountEmail,
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
   * Refresh a credential session by re-requesting a token from the
   * GCP metadata server.
   *
   * GCP metadata server always returns a fresh token, so refresh is
   * equivalent to a new resolveSession call with the same parameters.
   *
   * @param {object} session - The current credential session.
   * @param {object} [ctx]   - Resolution context.
   * @returns {Promise<object>} A refreshed credential session.
   */
  async refreshSession(session, ctx) {
    const scopes = session.provider_assertions && session.provider_assertions.scopes;
    const serviceAccountEmail = session.provider_assertions && session.provider_assertions.service_account_email;

    return gcpWorkloadIdentityProvider.resolveSession({
      profile: {
        auth: {
          provider_config: { scopes, service_account_email: serviceAccountEmail },
          scopes,
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
          const prefix = target.prefix || 'agentcli-gcp-cred';
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

registerProvider(gcpWorkloadIdentityProvider);

export { gcpWorkloadIdentityProvider };
