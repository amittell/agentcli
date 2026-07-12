/**
 * SPIFFE JWT-SVID identity provider.
 *
 * This provider deliberately supports only file-mounted JWT-SVIDs. The SPIFFE
 * Workload API is a gRPC Unix-socket protocol and must be integrated through a
 * conforming client, not an ad-hoc HTTP endpoint. File-mounted tokens are
 * accepted only after audience, lifetime, subject, and signature verification.
 */

import { readFileSync } from 'node:fs';
import { createPublicKey, verify as verifySignature } from 'node:crypto';
import { registerProvider } from './index.js';
import {
  buildCredentialSummary,
  cleanupMaterializedCredentials,
  materializeCredentialBindings,
  redactSession,
} from './session.js';

const SUPPORTED_ALGORITHMS = new Map([
  ['RS256', 'RSA-SHA256'],
  ['RS384', 'RSA-SHA384'],
  ['RS512', 'RSA-SHA512'],
]);
const sessionContexts = new WeakMap();

function providerError(code, message) {
  return Object.assign(new Error(message), { code });
}

function decodeJsonSegment(segment, label) {
  if (typeof segment !== 'string' || segment.length === 0 || !/^[A-Za-z0-9_-]+$/.test(segment)) {
    throw providerError('spiffe_svid_invalid', `JWT-SVID ${label} is malformed`);
  }
  try {
    const decoded = Buffer.from(segment, 'base64url').toString('utf8');
    const value = JSON.parse(decoded);
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('not an object');
    return value;
  } catch {
    throw providerError('spiffe_svid_invalid', `JWT-SVID ${label} is not valid JSON`);
  }
}

function parseJwtSvid(token) {
  if (typeof token !== 'string') throw providerError('spiffe_svid_invalid', 'JWT-SVID must be a string');
  const segments = token.split('.');
  if (segments.length !== 3 || segments.some(segment => segment.length === 0)) {
    throw providerError('spiffe_svid_invalid', 'JWT-SVID must contain three non-empty segments');
  }
  const [encodedHeader, encodedClaims, encodedSignature] = segments;
  if (!/^[A-Za-z0-9_-]+$/.test(encodedSignature)) {
    throw providerError('spiffe_svid_invalid', 'JWT-SVID signature is malformed');
  }
  const signature = Buffer.from(encodedSignature, 'base64url');
  if (signature.length === 0) throw providerError('spiffe_svid_invalid', 'JWT-SVID signature is empty');
  return {
    header: decodeJsonSegment(encodedHeader, 'header'),
    claims: decodeJsonSegment(encodedClaims, 'claims'),
    signature,
    signingInput: `${encodedHeader}.${encodedClaims}`,
  };
}

function parseTrustDocument(value, label) {
  if (value && typeof value === 'object') return value;
  if (typeof value !== 'string' || value.trim() === '') {
    throw providerError('spiffe_trust_invalid', `${label} is empty`);
  }
  try {
    return JSON.parse(value);
  } catch {
    throw providerError('spiffe_trust_invalid', `${label} is not valid JSON`);
  }
}

function assertStrongRsaKey(key) {
  if (key.asymmetricKeyType !== 'rsa' || (key.asymmetricKeyDetails?.modulusLength || 0) < 2048) {
    throw providerError('spiffe_trust_invalid', 'JWT-SVID trust key must be an RSA public key of at least 2048 bits');
  }
  return key;
}

function selectJwk(document, header) {
  const keys = Array.isArray(document?.keys) ? document.keys : [document];
  const candidates = keys.filter(key => key && typeof key === 'object' && key.kty === 'RSA');
  const key = header.kid
    ? candidates.find(candidate => candidate.kid === header.kid)
    : candidates.length === 1 ? candidates[0] : null;
  if (!key) {
    throw providerError(
      'spiffe_trust_invalid',
      header.kid ? 'No trusted JWT-SVID key matches the token key id' : 'JWT-SVID trust set is ambiguous without a key id'
    );
  }
  if (key.use != null && key.use !== 'sig') {
    throw providerError('spiffe_trust_invalid', 'Selected JWT-SVID key is not authorized for signatures');
  }
  if (key.alg != null && key.alg !== header.alg) {
    throw providerError('spiffe_trust_invalid', 'Selected JWT-SVID key does not permit the token algorithm');
  }
  if (key.d != null || (Array.isArray(key.key_ops) && !key.key_ops.includes('verify'))) {
    throw providerError('spiffe_trust_invalid', 'Selected JWT-SVID key must be a public verification key');
  }
  return assertStrongRsaKey(createPublicKey({ key, format: 'jwk' }));
}

function validateJwksStructure(value) {
  const document = parseTrustDocument(value, 'JWT-SVID JWKS');
  const keys = Array.isArray(document?.keys) ? document.keys : [document];
  if (keys.length === 0) throw providerError('spiffe_trust_invalid', 'JWT-SVID JWKS contains no keys');
  for (const key of keys) {
    if (!key || typeof key !== 'object' || key.kty !== 'RSA') {
      throw providerError('spiffe_trust_invalid', 'JWT-SVID JWKS supports RSA signing keys only');
    }
    if (key.d != null || (Array.isArray(key.key_ops) && !key.key_ops.includes('verify'))) {
      throw providerError('spiffe_trust_invalid', 'JWT-SVID JWKS must contain public verification keys only');
    }
    assertStrongRsaKey(createPublicKey({ key, format: 'jwk' }));
  }
}

function resolveTrustKey(config, header) {
  if (typeof config.public_key_pem === 'string' && config.public_key_pem.trim()) {
    if (/BEGIN (?:RSA )?PRIVATE KEY/.test(config.public_key_pem)) {
      throw providerError('spiffe_trust_invalid', 'JWT-SVID trust material must not contain a private key');
    }
    return { key: assertStrongRsaKey(createPublicKey(config.public_key_pem)), source: 'public_key_pem' };
  }
  if (typeof config.public_key_file === 'string' && config.public_key_file.trim()) {
    const pem = readFileSync(config.public_key_file, 'utf8');
    if (/BEGIN (?:RSA )?PRIVATE KEY/.test(pem)) {
      throw providerError('spiffe_trust_invalid', 'JWT-SVID trust material must not contain a private key');
    }
    return {
      key: assertStrongRsaKey(createPublicKey(pem)),
      source: 'public_key_file',
    };
  }
  if (config.jwks != null) {
    return { key: selectJwk(parseTrustDocument(config.jwks, 'JWT-SVID JWKS'), header), source: 'jwks' };
  }
  if (typeof config.jwks_file === 'string' && config.jwks_file.trim()) {
    const document = parseTrustDocument(readFileSync(config.jwks_file, 'utf8'), 'JWT-SVID JWKS file');
    return { key: selectJwk(document, header), source: 'jwks_file' };
  }
  throw providerError('spiffe_trust_required', 'JWT-SVID cryptographic trust material is required');
}

function validateAudience(claim, expected) {
  const audiences = Array.isArray(claim) ? claim : [claim];
  return audiences.some(value => typeof value === 'string' && value === expected);
}

function validateSpiffeId(value) {
  if (typeof value !== 'string' || !value.startsWith('spiffe://')) return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'spiffe:' && parsed.hostname.length > 0 &&
      parsed.username === '' && parsed.password === '' && parsed.search === '' && parsed.hash === '';
  } catch {
    return false;
  }
}

function verifyJwtSvid(token, config, expectedAudience, { clockToleranceS = 30 } = {}) {
  const parsed = parseJwtSvid(token);
  const algorithm = SUPPORTED_ALGORITHMS.get(parsed.header.alg);
  if (!algorithm) {
    throw providerError('spiffe_algorithm_unsupported', 'JWT-SVID uses an unsupported signature algorithm');
  }
  if (parsed.header.typ != null && parsed.header.typ !== 'JWT') {
    throw providerError('spiffe_svid_invalid', 'JWT-SVID typ header must be JWT when present');
  }

  const now = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(parsed.claims.exp) || parsed.claims.exp <= now - clockToleranceS) {
    throw providerError('spiffe_svid_expired', 'JWT-SVID is expired or has no valid expiration');
  }
  if (parsed.claims.nbf != null &&
      (!Number.isFinite(parsed.claims.nbf) || parsed.claims.nbf > now + clockToleranceS)) {
    throw providerError('spiffe_svid_not_active', 'JWT-SVID is not active yet');
  }
  if (parsed.claims.iat != null &&
      (!Number.isFinite(parsed.claims.iat) || parsed.claims.iat > now + clockToleranceS)) {
    throw providerError('spiffe_svid_invalid', 'JWT-SVID issuance time is in the future');
  }
  if (!validateAudience(parsed.claims.aud, expectedAudience)) {
    throw providerError('spiffe_audience_mismatch', 'JWT-SVID audience does not match the requested audience');
  }
  if (!validateSpiffeId(parsed.claims.sub)) {
    throw providerError('spiffe_svid_invalid', 'JWT-SVID subject is not a valid SPIFFE ID');
  }
  if (!validateSpiffeId(parsed.claims.iss)) {
    throw providerError('spiffe_svid_invalid', 'JWT-SVID issuer is not a valid SPIFFE trust-domain URI');
  }
  if (config.expected_issuer != null && parsed.claims.iss !== config.expected_issuer) {
    throw providerError('spiffe_issuer_mismatch', 'JWT-SVID issuer does not match the configured issuer');
  }

  let trust;
  try {
    trust = resolveTrustKey(config, parsed.header);
  } catch (error) {
    if (error?.code) throw error;
    throw providerError('spiffe_trust_invalid', 'JWT-SVID trust material could not be loaded');
  }
  let verified;
  try {
    verified = verifySignature(
      algorithm,
      Buffer.from(parsed.signingInput, 'ascii'),
      trust.key,
      parsed.signature
    );
  } catch {
    throw providerError('spiffe_signature_invalid', 'JWT-SVID signature verification failed');
  }
  if (!verified) throw providerError('spiffe_signature_invalid', 'JWT-SVID signature verification failed');
  return { ...parsed, trustSource: trust.source };
}

function emptySession(profile) {
  const trustLevel = profile?.trust?.level || 'supervised';
  return {
    provider: 'spiffe-jwt-svid',
    subject: {
      principal: profile?.subject?.principal || null,
      issuer: profile?.subject?.issuer || null,
      run_as: profile?.subject?.run_as || null,
    },
    instance: null,
    trust: { declared_level: trustLevel, effective_level: trustLevel },
    delegation_chain: [],
    delegation_validation: {
      valid: true,
      depth: 0,
      acyclic: true,
      all_grants_present: true,
    },
    credentials: {},
    provider_assertions: { acquisition_method: 'file', signature_verified: false },
    refresh: { supported: true, expires_at: null },
    handoff: { mode: 'none', prepared: false },
  };
}

const spiffeJwtSvidProvider = {
  name: 'spiffe-jwt-svid',

  capabilities: {
    auth_modes: ['service', 'delegated'],
    credential_types: ['jwt_svid'],
    presentation_kinds: ['env', 'file', 'stdin'],
    handoff_modes: ['none'],
    refreshable: true,
    delegation: true,
    trust_levels: ['restricted', 'supervised', 'autonomous'],
    approval_mechanisms: [],
  },

  validateProfile(profile) {
    const errors = [];
    const auth = profile?.auth || {};
    const config = auth.provider_config || {};
    const required = auth.required !== false;
    const audience = auth.audience || config.audience;
    const declaredPrincipal = profile?.subject?.principal;

    if (declaredPrincipal != null && !validateSpiffeId(declaredPrincipal)) {
      errors.push('subject.principal must be a valid SPIFFE ID when declared');
    }

    if (config.workload_api_socket != null) {
      errors.push('auth.provider_config.workload_api_socket is unsupported; mount a JWT-SVID file instead');
    }
    if (config.jwks_uri != null) {
      errors.push('auth.provider_config.jwks_uri is unsupported; provide local trust material instead');
    }
    if (required && (typeof config.svid_file !== 'string' || config.svid_file.trim() === '')) {
      errors.push('auth.provider_config.svid_file is required for file-mounted JWT-SVID acquisition');
    } else if (config.svid_file != null && typeof config.svid_file !== 'string') {
      errors.push('auth.provider_config.svid_file must be a string');
    }
    if (required && (typeof audience !== 'string' || audience.trim() === '')) {
      errors.push('auth.audience or auth.provider_config.audience is required for JWT-SVID verification');
    }

    const trustSources = ['public_key_pem', 'public_key_file', 'jwks', 'jwks_file']
      .filter(key => config[key] != null);
    if (required && trustSources.length !== 1) {
      errors.push('exactly one local JWT-SVID trust source is required');
    } else if (trustSources.length > 1) {
      errors.push('configure only one JWT-SVID trust source');
    }
    if (config.public_key_pem != null) {
      if (typeof config.public_key_pem !== 'string' || config.public_key_pem.trim() === '') {
        errors.push('auth.provider_config.public_key_pem must be a non-empty PEM string');
      } else {
        try {
          if (/BEGIN (?:RSA )?PRIVATE KEY/.test(config.public_key_pem)) throw new Error('private key');
          assertStrongRsaKey(createPublicKey(config.public_key_pem));
        } catch {
          errors.push('auth.provider_config.public_key_pem must be a public RSA key of at least 2048 bits');
        }
      }
    }
    if (config.public_key_file != null &&
        (typeof config.public_key_file !== 'string' || config.public_key_file.trim() === '')) {
      errors.push('auth.provider_config.public_key_file must be a non-empty file path');
    }
    if (config.jwks != null) {
      try {
        validateJwksStructure(config.jwks);
      } catch (error) {
        errors.push(error.message);
      }
    }
    if (config.jwks_file != null &&
        (typeof config.jwks_file !== 'string' || config.jwks_file.trim() === '')) {
      errors.push('auth.provider_config.jwks_file must be a non-empty file path');
    }
    if (config.clock_tolerance_s != null &&
        (!Number.isInteger(config.clock_tolerance_s) || config.clock_tolerance_s < 0 || config.clock_tolerance_s > 300)) {
      errors.push('auth.provider_config.clock_tolerance_s must be an integer from 0 through 300');
    }
    return errors.length === 0 ? { valid: true } : { valid: false, errors };
  },

  resolveSession(request, ctx = {}) {
    const profile = request?.profile || {};
    const auth = profile.auth || {};
    const config = auth.provider_config || {};
    const required = auth.required !== false;
    const audience = auth.audience || config.audience;

    const trustConfigured = ['public_key_pem', 'public_key_file', 'jwks', 'jwks_file']
      .some(key => config[key] != null);
    if (!config.svid_file || (!required && (!audience || !trustConfigured))) return emptySession(profile);
    let token;
    try {
      token = readFileSync(config.svid_file, 'utf8').trim();
    } catch {
      if (!required) return emptySession(profile);
      throw providerError('spiffe_svid_unavailable', 'File-mounted JWT-SVID could not be read');
    }
    if (!token) {
      if (!required) return emptySession(profile);
      throw providerError('spiffe_svid_unavailable', 'File-mounted JWT-SVID is empty');
    }

    let verified;
    try {
      verified = verifyJwtSvid(token, {
        ...config,
        expected_issuer: profile?.subject?.issuer || config.issuer || null,
      }, audience, {
        clockToleranceS: config.clock_tolerance_s ?? 30,
      });
    } catch (error) {
      if (!required) return emptySession(profile);
      throw error;
    }
    const claims = verified.claims;
    const trustLevel = profile?.trust?.level || 'supervised';
    const declaredPrincipal = profile?.subject?.principal ?? null;
    if (declaredPrincipal != null && declaredPrincipal !== claims.sub) {
      throw providerError(
        'identity_resolution_failed',
        'Declared SPIFFE principal does not match the verified JWT-SVID subject'
      );
    }
    const principal = claims.sub;
    const session = {
      provider: 'spiffe-jwt-svid',
      subject: {
        principal,
        issuer: profile?.subject?.issuer || claims.iss || null,
        run_as: profile?.subject?.run_as || null,
      },
      instance: request?.instanceId ? { id: request.instanceId, source: 'operator' } : null,
      trust: { declared_level: trustLevel, effective_level: trustLevel },
      delegation_chain: [{
        kind: 'workload',
        principal,
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
        jwt_svid: {
          kind: 'jwt-svid',
          value: token,
          audience,
          expires_at: new Date(claims.exp * 1000).toISOString(),
        },
      },
      provider_assertions: {
        spiffe_id: claims.sub,
        issuer: claims.iss || null,
        audience,
        issued_at: Number.isFinite(claims.iat) ? new Date(claims.iat * 1000).toISOString() : null,
        acquisition_method: 'file',
        signature_verified: true,
        jwt_alg: verified.header.alg,
        jwt_kid: verified.header.kid || null,
        trust_source: verified.trustSource,
      },
      refresh: {
        supported: true,
        expires_at: new Date(claims.exp * 1000).toISOString(),
      },
      handoff: { mode: 'none', prepared: false },
    };
    sessionContexts.set(session, { request, ctx });
    return session;
  },

  refreshSession(session, ctx = {}) {
    const prior = sessionContexts.get(session);
    if (!prior) {
      throw providerError('spiffe_refresh_unavailable', 'JWT-SVID refresh requires the original in-process profile context');
    }
    return this.resolveSession(prior.request, { ...prior.ctx, ...ctx });
  },

  describeSession(session) {
    const described = redactSession(session);
    described.credential_summary = buildCredentialSummary(session);
    return described;
  },

  materialize(session, presentation) {
    return materializeCredentialBindings(session, presentation, {
      allowedTargetKinds: this.capabilities.presentation_kinds,
      tempPrefix: 'agentcli-spiffe-jwt-svid',
    });
  },

  cleanup(materialization) {
    return cleanupMaterializedCredentials(materialization);
  },

  validateDelegation(chain, policy = {}) {
    const entries = Array.isArray(chain) ? chain : [];
    const maxDepth = Number.isInteger(policy.max_depth) ? policy.max_depth : 1;
    return {
      valid: entries.length <= maxDepth && entries.every(entry => entry?.validated === true),
      depth: entries.length,
      acyclic: true,
      all_grants_present: entries.every(entry => typeof entry?.grant === 'string' && entry.grant.length > 0),
    };
  },
};

registerProvider(spiffeJwtSvidProvider);

export { spiffeJwtSvidProvider, verifyJwtSvid };
