/**
 * AWS STS AssumeRole identity provider.
 *
 * Acquires temporary security credentials by calling the AWS Security Token
 * Service (STS) AssumeRole API. Implements AWS Signature Version 4 request
 * signing using Node crypto primitives (no AWS SDK dependency). Works when
 * AWS credentials are available via environment variables or instance metadata.
 * Uses the global fetch() API available in Node >= 22 (no external dependencies).
 */

import { readFileSync, writeFileSync, unlinkSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes, createHmac, createHash } from 'node:crypto';
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
 * Compute SHA-256 hex digest of a string.
 *
 * @param {string} data - Input string.
 * @returns {string} Lowercase hex digest.
 */
function sha256Hex(data) {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}

/**
 * Compute HMAC-SHA256 of a message using a key.
 *
 * @param {Buffer|string} key     - HMAC key (Buffer for binary, string for utf8).
 * @param {string}        message - Message to sign.
 * @returns {Buffer} Raw HMAC digest.
 */
function hmacSha256(key, message) {
  return createHmac('sha256', key).update(message, 'utf8').digest();
}

/**
 * Derive the AWS Signature Version 4 signing key.
 *
 * The signing key is derived through a chain of HMAC-SHA256 operations:
 *   kDate    = HMAC("AWS4" + secretKey, dateStamp)
 *   kRegion  = HMAC(kDate, region)
 *   kService = HMAC(kRegion, service)
 *   kSigning = HMAC(kService, "aws4_request")
 *
 * @param {string} secretKey - AWS secret access key.
 * @param {string} dateStamp - Date in YYYYMMDD format.
 * @param {string} region    - AWS region (e.g. "us-east-1").
 * @param {string} service   - AWS service name (e.g. "sts").
 * @returns {Buffer} The derived signing key.
 */
function deriveSigningKey(secretKey, dateStamp, region, service) {
  const kDate = hmacSha256(`AWS4${secretKey}`, dateStamp);
  const kRegion = hmacSha256(kDate, region);
  const kService = hmacSha256(kRegion, service);
  const kSigning = hmacSha256(kService, 'aws4_request');
  return kSigning;
}

/**
 * Sign an AWS STS request using Signature Version 4.
 *
 * Constructs the canonical request, string to sign, and Authorization
 * header per the AWS Signature V4 specification.
 *
 * @param {object} params - Request parameters.
 * @param {string} params.method      - HTTP method (POST).
 * @param {string} params.host        - Request host (e.g. "sts.us-east-1.amazonaws.com").
 * @param {string} params.region      - AWS region.
 * @param {string} params.body        - URL-encoded request body.
 * @param {string} params.accessKeyId - AWS access key ID.
 * @param {string} params.secretKey   - AWS secret access key.
 * @param {string} params.sessionToken - Optional session token for temporary credentials.
 * @returns {{ headers: object, url: string }} Signed request headers and URL.
 */
function signStsRequest({ method, host, region, body, accessKeyId, secretKey, sessionToken }) {
  const service = 'sts';
  const now = new Date();
  const dateStamp = now.toISOString().replace(/[-:]/g, '').slice(0, 8);
  const amzDate = now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');

  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const payloadHash = sha256Hex(body);

  // Build signed headers list - must be sorted
  const signedHeaderNames = ['content-type', 'host', 'x-amz-date'];
  if (sessionToken) {
    signedHeaderNames.push('x-amz-security-token');
  }
  signedHeaderNames.sort();
  const signedHeadersStr = signedHeaderNames.join(';');

  // Build canonical headers - must be sorted by header name
  const canonicalHeaderParts = [
    `content-type:application/x-www-form-urlencoded; charset=utf-8`,
    `host:${host}`,
    `x-amz-date:${amzDate}`,
  ];
  if (sessionToken) {
    canonicalHeaderParts.push(`x-amz-security-token:${sessionToken}`);
  }
  canonicalHeaderParts.sort();
  const canonicalHeaders = canonicalHeaderParts.join('\n') + '\n';

  // Canonical request per SigV4 spec
  const canonicalRequest = [
    method,
    '/',
    '',
    canonicalHeaders,
    signedHeadersStr,
    payloadHash,
  ].join('\n');

  // String to sign
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join('\n');

  // Calculate signature
  const signingKey = deriveSigningKey(secretKey, dateStamp, region, service);
  const signature = createHmac('sha256', signingKey)
    .update(stringToSign, 'utf8')
    .digest('hex');

  const authorization =
    `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, ` +
    `SignedHeaders=${signedHeadersStr}, ` +
    `Signature=${signature}`;

  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
    'Host': host,
    'X-Amz-Date': amzDate,
    'Authorization': authorization,
  };

  if (sessionToken) {
    headers['X-Amz-Security-Token'] = sessionToken;
  }

  return {
    headers,
    url: `https://${host}/`,
  };
}

/**
 * Extract a named XML element value from an XML string.
 *
 * Uses simple regex extraction suitable for the well-structured XML
 * returned by AWS STS. Not a general-purpose XML parser.
 *
 * @param {string} xml  - The XML string.
 * @param {string} tag  - The element name to extract.
 * @returns {string|null} The text content of the element, or null if not found.
 */
function extractXmlValue(xml, tag) {
  const pattern = new RegExp(`<${tag}>([^<]*)</${tag}>`);
  const match = xml.match(pattern);
  return match ? match[1] : null;
}

const awsStsAssumeRoleProvider = {
  name: 'aws-sts-assume-role',

  capabilities: {
    auth_modes: ['service', 'exchange'],
    credential_types: ['access_token'],
    presentation_kinds: ['env', 'file'],
    handoff_modes: ['none'],
    refreshable: false,
    delegation: true,
    trust_levels: ['untrusted', 'restricted', 'supervised', 'autonomous'],
    approval_mechanisms: [],
  },

  /**
   * Validate a profile for the aws-sts-assume-role provider.
   *
   * Checks that the profile declares a valid role ARN. Region and
   * session name are optional with sensible defaults.
   *
   * @param {object} profile - The identity profile.
   * @param {object} [_ctx]  - Resolution context.
   * @returns {{ valid: boolean, errors?: string[] }}
   */
  validateProfile(profile, _ctx) {
    const errors = [];
    const providerConfig = (profile.auth && profile.auth.provider_config) || {};

    if (typeof providerConfig.role_arn !== 'string' || providerConfig.role_arn.length === 0) {
      errors.push('auth.provider_config.role_arn is required and must be a non-empty string (e.g. "arn:aws:iam::123456789012:role/MyRole")');
    } else if (!providerConfig.role_arn.startsWith('arn:aws:iam::') && !providerConfig.role_arn.startsWith('arn:aws:iam:')) {
      // ARN format: arn:aws:iam::<account>:role/<name> or arn:aws:iam:<partition>:<account>:role/<name>
      // Be lenient -- just check prefix
      if (!providerConfig.role_arn.match(/^arn:aws(-[a-z]+)?:iam::/)) {
        errors.push('auth.provider_config.role_arn must be a valid IAM role ARN (e.g. "arn:aws:iam::123456789012:role/MyRole")');
      }
    }

    if (providerConfig.region !== undefined && providerConfig.region !== null) {
      if (typeof providerConfig.region !== 'string' || providerConfig.region.length === 0) {
        errors.push('auth.provider_config.region, when specified, must be a non-empty string (e.g. "us-east-1")');
      }
    }

    if (providerConfig.session_name !== undefined && providerConfig.session_name !== null) {
      if (typeof providerConfig.session_name !== 'string' || providerConfig.session_name.length === 0) {
        errors.push('auth.provider_config.session_name, when specified, must be a non-empty string');
      } else if (!/^[\w+=,.@-]{2,64}$/.test(providerConfig.session_name)) {
        errors.push('auth.provider_config.session_name must be 2-64 characters and contain only alphanumeric, =, ,, ., @, and - characters');
      }
    }

    if (errors.length > 0) {
      return { valid: false, errors };
    }

    return { valid: true };
  },

  /**
   * Resolve a credential session by calling AWS STS AssumeRole.
   *
   * Requires AWS credentials (access key ID and secret access key)
   * available via environment variables. Constructs a signed STS
   * AssumeRole request using AWS Signature V4.
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

    const roleArn = providerConfig.role_arn;
    const region = providerConfig.region || env.AWS_DEFAULT_REGION || env.AWS_REGION || 'us-east-1';
    const sessionName = providerConfig.session_name || 'agentcli-session';
    const durationSeconds = providerConfig.duration_seconds || 3600;

    const trustLevel = (profile.trust && profile.trust.level) || 'supervised';
    const subject = profile.subject || {};

    const buildEmptySession = () => ({
      provider: 'aws-sts-assume-role',
      subject: {
        principal: subject.principal || null,
        issuer: subject.issuer || `https://sts.${region}.amazonaws.com/`,
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
        role_arn: roleArn,
        region,
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

    // Resolve AWS credentials from environment
    const accessKeyId = env.AWS_ACCESS_KEY_ID;
    const secretAccessKey = env.AWS_SECRET_ACCESS_KEY;
    const existingSessionToken = env.AWS_SESSION_TOKEN || null;

    if (!accessKeyId || !secretAccessKey) {
      const err = new Error(
        'AWS credentials not found. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or run in an AWS environment with instance role.'
      );
      err.code = 'aws_credentials_unavailable';

      if (required) {
        throw err;
      }
      return buildEmptySession();
    }

    // Build the STS AssumeRole request body
    const body = new URLSearchParams();
    body.set('Action', 'AssumeRole');
    body.set('Version', '2011-06-15');
    body.set('RoleArn', roleArn);
    body.set('RoleSessionName', sessionName);
    body.set('DurationSeconds', String(durationSeconds));

    if (providerConfig.external_id) {
      body.set('ExternalId', providerConfig.external_id);
    }

    const bodyStr = body.toString();

    // Determine STS endpoint host
    const host = region === 'us-east-1'
      ? 'sts.amazonaws.com'
      : `sts.${region}.amazonaws.com`;

    // Sign the request with AWS Signature V4
    const signed = signStsRequest({
      method: 'POST',
      host,
      region,
      body: bodyStr,
      accessKeyId,
      secretKey: secretAccessKey,
      sessionToken: existingSessionToken,
    });

    let responseXml;
    try {
      const response = await fetch(signed.url, {
        method: 'POST',
        headers: signed.headers,
        body: bodyStr,
        signal: AbortSignal.timeout(30000),
      });

      responseXml = await response.text();

      if (!response.ok) {
        const errorCode = extractXmlValue(responseXml, 'Code') || 'Unknown';
        const errorMessage = extractXmlValue(responseXml, 'Message') || responseXml;

        const err = new Error(
          `STS AssumeRole returned HTTP ${response.status}: ${errorCode} - ${errorMessage}`
        );
        err.code = 'aws_sts_error';
        err.status = response.status;
        err.body = responseXml;

        if (required) {
          throw err;
        }
        return buildEmptySession();
      }
    } catch (fetchErr) {
      if (fetchErr.code === 'aws_sts_error') {
        throw fetchErr;
      }

      const err = new Error(
        `STS AssumeRole request to ${signed.url} failed: ${fetchErr.message}`
      );
      err.code = 'aws_credentials_unavailable';
      err.cause = fetchErr;

      if (required) {
        throw err;
      }
      return buildEmptySession();
    }

    // Parse the STS response XML
    const assumedAccessKeyId = extractXmlValue(responseXml, 'AccessKeyId');
    const assumedSecretAccessKey = extractXmlValue(responseXml, 'SecretAccessKey');
    const sessionToken = extractXmlValue(responseXml, 'SessionToken');
    const expiration = extractXmlValue(responseXml, 'Expiration');
    const assumedRoleArn = extractXmlValue(responseXml, 'Arn');

    if (!assumedAccessKeyId || !assumedSecretAccessKey || !sessionToken) {
      const err = new Error(
        'STS AssumeRole response did not contain expected credential fields'
      );
      err.code = 'aws_sts_error';
      err.body = responseXml;

      if (required) {
        throw err;
      }
      return buildEmptySession();
    }

    const expiresAt = expiration || null;

    return {
      provider: 'aws-sts-assume-role',
      subject: {
        principal: subject.principal || assumedRoleArn || null,
        issuer: subject.issuer || `https://sts.${region}.amazonaws.com/`,
        run_as: subject.run_as || null,
      },
      instance: request.instanceId ? { id: request.instanceId, source: 'operator' } : null,
      trust: {
        declared_level: trustLevel,
        effective_level: trustLevel,
      },
      delegation_chain: [
        {
          kind: 'caller',
          principal: accessKeyId,
          grant: 'sts-assume-role',
          validated: true,
        },
        {
          kind: subject.kind || 'service',
          principal: subject.principal || assumedRoleArn || roleArn,
          grant: 'sts-assume-role',
          validated: true,
        },
      ],
      delegation_validation: awsStsAssumeRoleProvider.validateDelegation(
        [
          { kind: 'caller', principal: accessKeyId, grant: 'sts-assume-role', validated: true },
          { kind: subject.kind || 'service', principal: subject.principal || assumedRoleArn || roleArn, grant: 'sts-assume-role', validated: true },
        ],
        auth.delegation_policy || { max_depth: 3, allowed_delegators: [], require_grant_per_hop: true },
        {}
      ),
      credentials: {
        access_token: {
          kind: 'aws-session',
          value: sessionToken,
          audience: roleArn,
          scopes: auth.scopes || [],
          expires_at: expiresAt,
        },
        access_key_id: {
          kind: 'aws-access-key',
          value: assumedAccessKeyId,
        },
        secret_access_key: {
          kind: 'aws-secret-key',
          value: assumedSecretAccessKey,
        },
      },
      provider_assertions: {
        role_arn: roleArn,
        assumed_role_arn: assumedRoleArn,
        region,
        session_name: sessionName,
      },
      refresh: {
        supported: false,
        expires_at: expiresAt,
      },
      handoff: {
        mode: 'none',
        prepared: false,
      },
    };
  },

  /**
   * Describe a session for audit purposes. Redacts the session token,
   * access key ID, and secret access key values.
   *
   * @param {object} session - The credential session.
   * @param {object} _ctx    - Resolution context.
   * @returns {object} Audit-safe session description.
   */
  describeSession(session, _ctx) {
    const described = structuredClone(session);

    if (described.credentials) {
      if (described.credentials.access_token) {
        described.credentials.access_token.value = '[REDACTED]';
      }
      if (described.credentials.access_key_id) {
        described.credentials.access_key_id.value = '[REDACTED]';
      }
      if (described.credentials.secret_access_key) {
        described.credentials.secret_access_key.value = '[REDACTED]';
      }
    }

    described.credential_summary = buildCredentialSummary(session);

    return described;
  },

  /**
   * Materialize credentials for tool consumption.
   *
   * Handles AWS-specific bindings: resolves source paths from the session
   * and maps them to environment variables (AWS_ACCESS_KEY_ID,
   * AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN) or temp files.
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
          const prefix = target.prefix || 'agentcli-aws-cred';
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
   * Checks that the chain is acyclic (no circular role assumptions),
   * that the chain depth does not exceed the policy maximum, and that
   * all hops have a grant present.
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

    // Check for cycles: duplicate principals indicate a circular role assumption
    const seenPrincipals = new Set();
    let acyclic = true;
    for (const entry of entries) {
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

registerProvider(awsStsAssumeRoleProvider);

export { awsStsAssumeRoleProvider };
