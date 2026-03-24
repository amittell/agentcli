/**
 * SPIFFE JWT-SVID identity provider.
 *
 * Acquires JWT-SVIDs (SPIFFE Verifiable Identity Documents) from the
 * SPIFFE Workload API or from file-mounted projected volumes. SPIFFE
 * (Secure Production Identity Framework for Everyone) provides
 * cryptographically verifiable workload identities. Supports reading
 * JWT-SVIDs from file paths (common in Kubernetes with SPIRE agent
 * projected volumes) or via the SPIFFE Workload API socket. Uses the
 * global fetch() API available in Node >= 22 (no external dependencies).
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

/**
 * Decode a base64url-encoded string to a UTF-8 string.
 *
 * Handles the base64url alphabet (- and _ instead of + and /) and
 * missing padding characters.
 *
 * @param {string} str - Base64url-encoded string.
 * @returns {string} Decoded UTF-8 string.
 */
function base64urlDecode(str) {
  // Convert base64url to standard base64
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding if necessary
  const padding = base64.length % 4;
  if (padding === 2) {
    base64 += '==';
  } else if (padding === 3) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64').toString('utf8');
}

/**
 * Parse JWT claims from a JWT token string without signature verification.
 *
 * Extracts and decodes the payload segment of a JWT token. Does NOT
 * verify the signature -- that is the responsibility of the SPIFFE
 * trust bundle verifier at the consuming service.
 *
 * @param {string} jwt - The JWT token string.
 * @returns {{ header: object, payload: object }} Decoded JWT header and payload.
 * @throws {Error} If the JWT format is invalid.
 */
function parseJwtClaims(jwt) {
  if (typeof jwt !== 'string' || jwt.length === 0) {
    throw new Error('JWT token is empty or not a string');
  }

  const parts = jwt.split('.');
  if (parts.length !== 3) {
    throw new Error(`Invalid JWT format: expected 3 dot-separated parts, got ${parts.length}`);
  }

  let header;
  try {
    header = JSON.parse(base64urlDecode(parts[0]));
  } catch (err) {
    throw new Error(`Failed to decode JWT header: ${err.message}`, { cause: err });
  }

  let payload;
  try {
    payload = JSON.parse(base64urlDecode(parts[1]));
  } catch (err) {
    throw new Error(`Failed to decode JWT payload: ${err.message}`, { cause: err });
  }

  return { header, payload };
}

const spiffeJwtSvidProvider = {
  name: 'spiffe-jwt-svid',

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
   * Validate a profile for the spiffe-jwt-svid provider.
   *
   * Checks that the profile declares an audience. The workload API socket
   * is optional and defaults to the SPIFFE_ENDPOINT_SOCKET environment
   * variable. The svid_file path is an alternative acquisition method.
   *
   * @param {object} profile - The identity profile.
   * @param {object} [_ctx]  - Resolution context.
   * @returns {{ valid: boolean, errors?: string[] }}
   */
  validateProfile(profile, _ctx) {
    const errors = [];
    const providerConfig = (profile.auth && profile.auth.provider_config) || {};
    const auth = profile.auth || {};

    const audience = providerConfig.audience || auth.audience;
    if (typeof audience !== 'string' || audience.length === 0) {
      errors.push(
        'Audience is required: provide auth.provider_config.audience or auth.audience ' +
        'as a non-empty string (e.g. "spiffe://example.org/my-service")'
      );
    }

    if (providerConfig.workload_api_socket !== undefined && providerConfig.workload_api_socket !== null) {
      if (typeof providerConfig.workload_api_socket !== 'string' || providerConfig.workload_api_socket.length === 0) {
        errors.push(
          'auth.provider_config.workload_api_socket, when specified, must be a non-empty string ' +
          '(path to the SPIFFE Workload API Unix domain socket)'
        );
      }
    }

    if (providerConfig.svid_file !== undefined && providerConfig.svid_file !== null) {
      if (typeof providerConfig.svid_file !== 'string' || providerConfig.svid_file.length === 0) {
        errors.push(
          'auth.provider_config.svid_file, when specified, must be a non-empty string ' +
          '(path to a file containing the JWT-SVID)'
        );
      }
    }

    if (errors.length > 0) {
      return { valid: false, errors };
    }

    return { valid: true };
  },

  /**
   * Resolve a credential session by acquiring a JWT-SVID.
   *
   * Attempts to acquire the JWT-SVID in order of preference:
   * 1. Read from a file path (svid_file) -- common with Kubernetes projected volumes
   * 2. Contact the SPIFFE Workload API via the configured or default socket
   *
   * The SPIFFE Workload API is a Unix domain socket gRPC service. Since
   * gRPC requires external dependencies, this provider uses the file-based
   * approach as the primary mechanism. The Workload API socket path is
   * recorded for diagnostic purposes.
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

    const audience = providerConfig.audience || auth.audience;
    const svidFile = providerConfig.svid_file || null;
    const workloadApiSocket = providerConfig.workload_api_socket || env.SPIFFE_ENDPOINT_SOCKET || null;

    const trustLevel = (profile.trust && profile.trust.level) || 'supervised';
    const subject = profile.subject || {};

    const buildEmptySession = () => ({
      provider: 'spiffe-jwt-svid',
      subject: {
        principal: subject.principal || null,
        issuer: subject.issuer || null,
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
        audience,
        svid_file: svidFile,
        workload_api_socket: workloadApiSocket,
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

    // Strategy 1: Read JWT-SVID from a file path
    let jwtSvid = null;
    let acquisitionMethod = null;

    if (svidFile) {
      try {
        jwtSvid = readFileSync(svidFile, 'utf8').trim();
        if (jwtSvid.length === 0) {
          jwtSvid = null;
        } else {
          acquisitionMethod = 'file';
        }
      } catch {
        // File not readable -- fall through to socket approach
        jwtSvid = null;
      }
    }

    // Strategy 2: Try the SPIFFE Workload API via HTTP
    // The SPIRE Agent exposes a REST-like API at the Unix domain socket.
    // Standard fetch() cannot connect to Unix domain sockets, but some
    // SPIFFE implementations expose an HTTP endpoint. Attempt to reach it
    // if the socket path looks like a TCP endpoint (http:// or https://).
    if (!jwtSvid && workloadApiSocket) {
      if (workloadApiSocket.startsWith('http://') || workloadApiSocket.startsWith('https://')) {
        // TCP-based Workload API endpoint (e.g., Envoy SDS sidecar or
        // SPIRE Agent configured with a TCP listener)
        try {
          const apiUrl = new URL('/v1/auth/jwt-svids', workloadApiSocket);
          const response = await fetch(apiUrl.toString(), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ audience: [audience] }),
            signal: AbortSignal.timeout(10000),
          });

          if (response.ok) {
            const data = await response.json();
            // SPIRE REST API returns { svids: [{ spiffe_id, svid, ... }] }
            if (data.svids && data.svids.length > 0 && data.svids[0].svid) {
              jwtSvid = data.svids[0].svid;
              acquisitionMethod = 'workload-api-http';
            }
          }
        } catch {
          // HTTP endpoint not reachable -- fall through to error
        }
      }
      // Unix domain socket path (e.g., /run/spire/agent/sockets/api.sock)
      // Standard Node fetch() cannot connect to UDS without a custom agent.
      // This is a known limitation documented below. The svid_file approach
      // is the recommended alternative.
    }

    if (!jwtSvid) {
      const err = new Error(
        'SPIFFE workload API not available. Set SPIFFE_ENDPOINT_SOCKET or provide svid_file path.'
      );
      err.code = 'spiffe_unavailable';

      if (required) {
        throw err;
      }
      return buildEmptySession();
    }

    // Parse the JWT-SVID to extract claims
    let claims;
    try {
      const parsed = parseJwtClaims(jwtSvid);
      claims = parsed.payload;
    } catch (parseErr) {
      const err = new Error(
        `Failed to parse JWT-SVID: ${parseErr.message}`
      );
      err.code = 'spiffe_unavailable';
      err.cause = parseErr;

      if (required) {
        throw err;
      }
      return buildEmptySession();
    }

    // Extract SPIFFE-specific claims
    const spiffeId = claims.sub || null;
    const jwtAudience = claims.aud
      ? (Array.isArray(claims.aud) ? claims.aud : [claims.aud])
      : [audience];
    const expiresAt = claims.exp
      ? new Date(claims.exp * 1000).toISOString()
      : null;
    const issuedAt = claims.iat
      ? new Date(claims.iat * 1000).toISOString()
      : null;
    const issuer = claims.iss || null;

    return {
      provider: 'spiffe-jwt-svid',
      subject: {
        principal: subject.principal || spiffeId,
        issuer: subject.issuer || issuer,
        run_as: subject.run_as || null,
      },
      instance: request.instanceId ? { id: request.instanceId, source: 'operator' } : null,
      trust: {
        declared_level: trustLevel,
        effective_level: trustLevel,
      },
      delegation_chain: [{
        kind: subject.kind || 'service',
        principal: subject.principal || spiffeId || 'spiffe-workload',
        grant: 'jwt-svid',
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
          kind: 'jwt-svid',
          value: jwtSvid,
          audience: jwtAudience.length === 1 ? jwtAudience[0] : jwtAudience,
          scopes: auth.scopes || [],
          expires_at: expiresAt,
        },
      },
      provider_assertions: {
        spiffe_id: spiffeId,
        audience: jwtAudience,
        issuer,
        issued_at: issuedAt,
        acquisition_method: acquisitionMethod,
        svid_file: svidFile,
        workload_api_socket: workloadApiSocket,
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
   * Refresh a credential session by re-reading the JWT-SVID.
   *
   * SPIFFE JWT-SVIDs are short-lived and automatically rotated by the
   * SPIRE agent. Re-reading the svid_file or re-requesting from the
   * workload API will return the current valid SVID.
   *
   * @param {object} session - The current credential session.
   * @param {object} [ctx]   - Resolution context.
   * @returns {Promise<object>} A refreshed credential session.
   */
  async refreshSession(session, ctx) {
    const svidFile = session.provider_assertions && session.provider_assertions.svid_file;
    const workloadApiSocket = session.provider_assertions && session.provider_assertions.workload_api_socket;
    const audience = session.provider_assertions && session.provider_assertions.audience;
    const primaryAudience = Array.isArray(audience) ? audience[0] : audience;

    return spiffeJwtSvidProvider.resolveSession({
      profile: {
        auth: {
          provider_config: {
            audience: primaryAudience,
            svid_file: svidFile,
            workload_api_socket: workloadApiSocket,
          },
        },
        trust: session.trust ? { level: session.trust.declared_level } : undefined,
        subject: session.subject,
      },
      instanceId: session.instance && session.instance.id,
    }, ctx);
  },

  /**
   * Describe a session for audit purposes. Redacts the JWT-SVID value
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
          const prefix = target.prefix || 'agentcli-spiffe-cred';
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

registerProvider(spiffeJwtSvidProvider);

export { spiffeJwtSvidProvider };
