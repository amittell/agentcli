/**
 * Microsoft Entra Agent ID identity provider.
 *
 * Acquires access tokens from the Entra token endpoint using agent identity
 * client credentials flow with a platform-issued JWT client assertion.
 * Entra Agent ID is distinct from standard Azure Managed Identity: agent
 * identities are registered in the Entra Agent Registry, authenticate via
 * platform-issued tokens rather than IMDS, and support agent-specific
 * Conditional Access policies and lifecycle governance.
 *
 * Uses the global fetch() API available in Node >= 22 (no external
 * dependencies).
 */

import { readFileSync, writeFileSync, unlinkSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import process from 'node:process';
import { resolveCommandValue } from '../command.js';
import { registerProvider } from './index.js';
import { resolveSourcePath, formatMaterializationValue, buildCredentialSummary } from './session.js';

/**
 * GUID format: 8-4-4-4-12 hex digits.
 */
const GUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Validate that a value looks like a GUID if it contains hyphens in the
 * expected positions (loose check: only validates format when the value
 * appears to be a GUID attempt).
 *
 * @param {string} value - The string to validate.
 * @returns {boolean} True if the value is a valid GUID or not GUID-shaped.
 */
function isValidGuidIfApplicable(value) {
  // If it contains hyphens at positions consistent with a GUID, enforce format
  if (value.length === 36 && value[8] === '-' && value[13] === '-') {
    return GUID_PATTERN.test(value);
  }
  return true;
}

/**
 * Resolve a value_from indirection object to its concrete value.
 *
 * Supports env (environment variable) and file (filesystem path) sources.
 *
 * @param {object} valueFrom - The value_from descriptor.
 * @param {object} [env]     - Environment variable map, defaults to process.env.
 * @returns {string|null} The resolved value, or null if unresolvable.
 */
function resolveValueFrom(valueFrom, env = process.env, { cwd = process.cwd(), commandEnv = env } = {}) {
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
    return resolveCommandValue(valueFrom.command, { env, commandEnv, cwd });
  }
  return null;
}

/**
 * Resolve the client assertion (platform token) for Entra Agent ID
 * authentication.
 *
 * Resolution order:
 *   1. AGENTCLI_ENTRA_CLIENT_ASSERTION environment variable
 *   2. auth.inputs.client_assertion.value_from (file or env indirection)
 *   3. auth.provider_config.client_assertion (direct string or value_from)
 *   4. IMDS fallback: acquire a managed identity token for the blueprint app
 *
 * @param {object} profile       - The identity profile.
 * @param {object} env           - Environment variable map.
 * @param {string} blueprintAppId - The blueprint application ID (used for IMDS resource).
 * @returns {Promise<string|null>} The resolved client assertion, or null.
 */
async function resolveClientAssertion(profile, env, blueprintAppId, cwd, commandEnv = env) {
  // 1. Environment variable
  const envAssertion = env.AGENTCLI_ENTRA_CLIENT_ASSERTION;
  if (typeof envAssertion === 'string' && envAssertion.length > 0) {
    return envAssertion;
  }

  const providerConfig = (profile.auth && profile.auth.provider_config) || {};
  const inputs = (profile.auth && profile.auth.inputs) || {};

  // 2. inputs.client_assertion.value_from
  if (inputs.client_assertion && inputs.client_assertion.value_from) {
    const resolved = resolveValueFrom(inputs.client_assertion.value_from, env, { cwd, commandEnv });
    if (resolved) return resolved;
  }

  // 3. provider_config.client_assertion (direct string or value_from)
  if (typeof providerConfig.client_assertion === 'string' && providerConfig.client_assertion.length > 0) {
    return providerConfig.client_assertion;
  }
  if (providerConfig.client_assertion && typeof providerConfig.client_assertion === 'object' && providerConfig.client_assertion.value_from) {
    const resolved = resolveValueFrom(providerConfig.client_assertion.value_from, env, { cwd, commandEnv });
    if (resolved) return resolved;
  }

  // 4. IMDS fallback: acquire a managed identity token for the blueprint app
  try {
    const imdsUrl = new URL('http://169.254.169.254/metadata/identity/oauth2/token');
    imdsUrl.searchParams.set('api-version', '2018-02-01');
    imdsUrl.searchParams.set('resource', `api://${blueprintAppId}`);

    const imdsResponse = await fetch(imdsUrl.toString(), {
      method: 'GET',
      headers: { 'Metadata': 'true' },
      signal: AbortSignal.timeout(5000),
    });

    if (imdsResponse.ok) {
      const imdsToken = await imdsResponse.json();
      if (imdsToken.access_token) {
        return imdsToken.access_token;
      }
    }
  } catch {
    // IMDS not reachable; fall through
  }

  return null;
}

/**
 * Acquire an access token from the Entra token endpoint using client
 * credentials flow with a JWT client assertion.
 *
 * @param {string} tokenEndpoint   - The Entra token endpoint URL.
 * @param {string} blueprintAppId  - The blueprint application ID (client_id).
 * @param {string} clientAssertion - The platform-issued JWT client assertion.
 * @param {string[]} scopes        - Requested token scopes.
 * @returns {Promise<object>} The parsed token response.
 */
async function acquireToken(tokenEndpoint, blueprintAppId, clientAssertion, scopes) {
  const params = new URLSearchParams();
  params.set('grant_type', 'client_credentials');
  params.set('client_id', blueprintAppId);
  params.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
  params.set('client_assertion', clientAssertion);

  if (scopes.length > 0) {
    params.set('scope', scopes.join(' '));
  }

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
      `Entra token endpoint returned HTTP ${response.status}: ${errorBody}`
    );
    err.code = 'entra_agent_id_token_failed';
    err.status = response.status;
    err.body = errorBody;
    throw err;
  }

  return response.json();
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

const entraAgentIdProvider = {
  name: 'entra-agent-id',

  capabilities: {
    auth_modes: ['service', 'on-behalf-of'],
    credential_types: ['access_token'],
    presentation_kinds: ['env', 'file'],
    handoff_modes: ['none', 'downscope'],
    refreshable: true,
    delegation: true,
    trust_levels: ['untrusted', 'restricted', 'supervised', 'autonomous'],
    approval_mechanisms: ['ciba'],
  },

  /**
   * Validate a profile for the entra-agent-id provider.
   *
   * Checks that the profile declares valid tenant_id, blueprint_app_id,
   * and agent_identity_id. All three must be non-empty strings and, when
   * they appear to be GUIDs, must match the standard 8-4-4-4-12 hex format.
   *
   * @param {object} profile - The identity profile.
   * @param {object} [_ctx]  - Resolution context.
   * @returns {{ valid: boolean, errors?: string[] }}
   */
  validateProfile(profile, _ctx) {
    const errors = [];
    const providerConfig = (profile.auth && profile.auth.provider_config) || {};

    // tenant_id
    if (typeof providerConfig.tenant_id !== 'string' || providerConfig.tenant_id.length === 0) {
      errors.push(
        'auth.provider_config.tenant_id is required and must be a non-empty string (Entra tenant GUID)'
      );
    } else if (!isValidGuidIfApplicable(providerConfig.tenant_id)) {
      errors.push(
        'auth.provider_config.tenant_id does not match GUID format (expected 8-4-4-4-12 hex pattern)'
      );
    }

    // blueprint_app_id
    if (typeof providerConfig.blueprint_app_id !== 'string' || providerConfig.blueprint_app_id.length === 0) {
      errors.push(
        'auth.provider_config.blueprint_app_id is required and must be a non-empty string (blueprint application GUID)'
      );
    } else if (!isValidGuidIfApplicable(providerConfig.blueprint_app_id)) {
      errors.push(
        'auth.provider_config.blueprint_app_id does not match GUID format (expected 8-4-4-4-12 hex pattern)'
      );
    }

    // agent_identity_id
    if (typeof providerConfig.agent_identity_id !== 'string' || providerConfig.agent_identity_id.length === 0) {
      errors.push(
        'auth.provider_config.agent_identity_id is required and must be a non-empty string (agent identity GUID)'
      );
    } else if (!isValidGuidIfApplicable(providerConfig.agent_identity_id)) {
      errors.push(
        'auth.provider_config.agent_identity_id does not match GUID format (expected 8-4-4-4-12 hex pattern)'
      );
    }

    if (errors.length > 0) {
      return { valid: false, errors };
    }

    return { valid: true };
  },

  /**
   * Resolve a credential session by acquiring an access token from the
   * Entra token endpoint using client credentials flow with a platform-
   * issued JWT client assertion.
   *
   * The client assertion is resolved from environment variables, profile
   * inputs, provider_config, or by falling back to IMDS on Azure.
   *
   * @param {object} request - The session request containing the profile and instanceId.
   * @param {object} [ctx]   - Resolution context. ctx.env defaults to process.env.
   * @returns {Promise<object>} A credential session.
   */
  async resolveSession(request, ctx) {
    const env = (ctx && ctx.env) || process.env;
    const cwd = (ctx && ctx.cwd) || process.cwd();
    const commandEnv = (ctx && ctx.commandEnv) || env;
    const profile = request.profile || {};
    const providerConfig = (profile.auth && profile.auth.provider_config) || {};
    const auth = profile.auth || {};

    const tenantId = providerConfig.tenant_id;
    const blueprintAppId = providerConfig.blueprint_app_id;
    const agentIdentityId = providerConfig.agent_identity_id;

    const authority = providerConfig.authority || `https://login.microsoftonline.com/${tenantId}`;
    const tokenEndpoint = `${authority}/oauth2/v2.0/token`;
    const scopes = auth.scopes || providerConfig.scopes || [];

    const trustLevel = (profile.trust && profile.trust.level) || 'supervised';
    const subject = profile.subject || {};

    // 1. Resolve client assertion
    const clientAssertion = await resolveClientAssertion(profile, env, blueprintAppId, cwd, commandEnv);

    if (!clientAssertion) {
      const err = new Error(
        'Entra Agent ID client assertion not available. Set AGENTCLI_ENTRA_CLIENT_ASSERTION, ' +
        'provide client_assertion via inputs, or run on Azure with managed identity enabled.'
      );
      err.code = 'entra_agent_id_unavailable';
      throw err;
    }

    // 2. Acquire token
    let tokenResponse;
    try {
      tokenResponse = await acquireToken(tokenEndpoint, blueprintAppId, clientAssertion, scopes);
    } catch (fetchErr) {
      if (fetchErr.code === 'entra_agent_id_token_failed') {
        throw fetchErr;
      }

      const err = new Error(
        `Entra Agent ID token request to ${tokenEndpoint} failed: ${fetchErr.message}`
      );
      err.code = 'entra_agent_id_unavailable';
      err.cause = fetchErr;
      throw err;
    }

    // 3. Build credential session
    const expiresAt = new Date(Date.now() + (tokenResponse.expires_in || 3600) * 1000).toISOString();

    return {
      provider: 'entra-agent-id',
      subject: {
        principal: subject.principal || `agent://entra/${tenantId}/${agentIdentityId}`,
        issuer: `https://login.microsoftonline.com/${tenantId}`,
        run_as: subject.run_as || null,
      },
      instance: request.instanceId ? { id: request.instanceId, source: 'operator' } : null,
      trust: {
        declared_level: trustLevel,
        effective_level: trustLevel,
      },
      delegation_chain: [{
        kind: 'agent',
        principal: `agent://entra/${tenantId}/${agentIdentityId}`,
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
          audience: scopes[0] || null,
          scopes,
          expires_at: expiresAt,
        },
      },
      provider_assertions: {
        tenant_id: tenantId,
        blueprint_app_id: blueprintAppId,
        agent_identity_id: agentIdentityId,
        token_type: tokenResponse.token_type || 'bearer',
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
   * Refresh a credential session by re-acquiring a token using the same
   * Entra Agent ID flow.
   *
   * @param {object} session - The current credential session.
   * @param {object} [ctx]   - Resolution context.
   * @returns {Promise<object>} A refreshed credential session.
   */
  async refreshSession(session, ctx) {
    const assertions = session.provider_assertions || {};

    return entraAgentIdProvider.resolveSession({
      profile: {
        auth: {
          provider_config: {
            tenant_id: assertions.tenant_id,
            blueprint_app_id: assertions.blueprint_app_id,
            agent_identity_id: assertions.agent_identity_id,
          },
          scopes: session.credentials && session.credentials.access_token
            ? session.credentials.access_token.scopes
            : [],
        },
        trust: session.trust ? { level: session.trust.declared_level } : undefined,
        subject: session.subject,
      },
      instanceId: session.instance && session.instance.id,
    }, ctx);
  },

  /**
   * Prepare a handoff by downscoping the current access token.
   *
   * For 'downscope' mode, requests a new token from the Entra token
   * endpoint with reduced scopes using the existing client assertion flow.
   *
   * @param {object} session - The credential session from resolveSession.
   * @param {object} handoff - Handoff descriptor with mode and optional scopes/audience.
   * @param {object} [ctx]   - Resolution context.
   * @returns {Promise<object>} Handoff result with the downscoped credential or failure reason.
   */
  async prepareHandoff(session, handoff, ctx) {
    if (!handoff || handoff.mode !== 'downscope') {
      return { prepared: false, reason: `unsupported handoff mode: ${handoff && handoff.mode}` };
    }

    const assertions = session.provider_assertions || {};
    const tenantId = assertions.tenant_id;
    const blueprintAppId = assertions.blueprint_app_id;

    if (!tenantId || !blueprintAppId) {
      return { prepared: false, reason: 'tenant_id or blueprint_app_id not available in session provider_assertions' };
    }

    const env = (ctx && ctx.env) || process.env;
    const cwd = (ctx && ctx.cwd) || process.cwd();
    const commandEnv = (ctx && ctx.commandEnv) || env;

    // Resolve client assertion for the downscope request
    const clientAssertion = await resolveClientAssertion({
      auth: { provider_config: assertions },
    }, env, blueprintAppId, cwd, commandEnv);

    if (!clientAssertion) {
      return { prepared: false, reason: 'client assertion not available for downscope token request' };
    }

    const authority = `https://login.microsoftonline.com/${tenantId}`;
    const tokenEndpoint = `${authority}/oauth2/v2.0/token`;
    const downscopeScopes = handoff.scopes || (session.credentials && session.credentials.access_token
      ? session.credentials.access_token.scopes
      : []);

    let tokenResponse;
    try {
      tokenResponse = await acquireToken(tokenEndpoint, blueprintAppId, clientAssertion, downscopeScopes);
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
          audience: handoff.audience || (session.credentials && session.credentials.access_token
            ? session.credentials.access_token.audience
            : null),
          scopes: downscopeScopes,
          expires_at: tokenResponse.expires_in
            ? new Date(Date.now() + tokenResponse.expires_in * 1000).toISOString()
            : null,
        },
      },
      provider_assertions: {
        token_type: tokenResponse.token_type || 'bearer',
        downscoped_from: 'parent-session',
      },
    };
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
          const prefix = target.prefix || 'agentcli-entra-cred';
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

registerProvider(entraAgentIdProvider);

export { entraAgentIdProvider };
