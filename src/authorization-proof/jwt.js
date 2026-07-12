/**
 * JWT-based authorization proof verifier.
 *
 * Handles JWT verification for manifest authorization proofs using
 * pure Node.js built-in crypto -- no external dependencies.
 *
 * Supports RS256 and ES256 signature verification. Structural and claims
 * validation is reported separately, but a JWT is never marked verified
 * unless its cryptographic signature is verified by a trusted key.
 */

import { createPublicKey, createVerify } from 'node:crypto';
import { canonicalDigest } from '../canonical.js';
import { registerVerifier } from './index.js';

const DEFAULT_JWKS_CACHE_TTL_MS = 5 * 60 * 1000;
const AUDIT_SAFE_CLAIMS = [
  'org_id',
  'on_behalf_of_user_id',
  'delegation_grant_id',
  'run_id',
  'agent_id',
  'verification_ref',
  'verification_level',
  'verification_verified_at',
  'step_up_policy',
  'session_id',
  'request_id',
  'manifest_digest',
];
const jwksCache = new Map();
const PRIVATE_KEY_PEM = /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/;

// -- JWT Helpers --

/**
 * Decode a base64url-encoded string to a Buffer.
 *
 * Replaces URL-safe characters with standard base64 equivalents
 * and adds padding as needed before decoding.
 *
 * @param {string} str - Base64url-encoded string.
 * @returns {Buffer} Decoded bytes.
 */
function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padLength = (4 - (base64.length % 4)) % 4;
  base64 += '='.repeat(padLength);
  return Buffer.from(base64, 'base64');
}

/**
 * Split and decode a JWT token into its constituent parts.
 *
 * @param {string} token - The raw JWT string.
 * @returns {{ header: object, payload: object, signatureRaw: Buffer, parts: string[] }}
 */
function decodeJwtParts(token) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error(`Invalid JWT structure: expected 3 parts, got ${parts.length}`);
  }

  let header;
  try {
    header = JSON.parse(base64UrlDecode(parts[0]).toString('utf8'));
  } catch (err) {
    throw new Error(`Failed to decode JWT header: ${err.message}`, { cause: err });
  }

  let payload;
  try {
    payload = JSON.parse(base64UrlDecode(parts[1]).toString('utf8'));
  } catch (err) {
    throw new Error(`Failed to decode JWT payload: ${err.message}`, { cause: err });
  }

  const signatureRaw = base64UrlDecode(parts[2]);

  return { header, payload, signatureRaw, parts };
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim() !== '';
}

function normalizeAudience(value) {
  if (Array.isArray(value)) return value;
  if (value === undefined || value === null) return [];
  return [value];
}

function audienceIncludes(actualValue, expectedValue) {
  return normalizeAudience(actualValue).includes(expectedValue);
}

function normalizeVerificationKey(publicKey) {
  if (!publicKey) {
    throw new Error('public key is required');
  }

  if (typeof publicKey === 'string' || Buffer.isBuffer(publicKey)) {
    if (PRIVATE_KEY_PEM.test(String(publicKey))) {
      throw new Error('private key material is forbidden in public_key');
    }
    return createPublicKey(publicKey);
  }

  if (typeof publicKey === 'object' && publicKey !== null) {
    if ('kty' in publicKey) {
      if ('d' in publicKey) throw new Error('private JWK material is forbidden in public_key');
      return createPublicKey({ key: publicKey, format: 'jwk' });
    }
    return createPublicKey(publicKey);
  }

  throw new Error('unsupported public key format');
}

function inferKeyTypeFromAlg(alg) {
  if (typeof alg !== 'string') return null;
  if (alg.startsWith('RS')) return 'RSA';
  if (alg.startsWith('ES')) return 'EC';
  return null;
}

function parseMaxAgeMs(cacheControl) {
  if (!isNonEmptyString(cacheControl)) return null;
  const match = cacheControl.match(/max-age=(\d+)/i);
  if (!match) return null;
  const seconds = Number.parseInt(match[1], 10);
  if (!Number.isFinite(seconds) || seconds < 0) return null;
  return seconds * 1000;
}

async function fetchJsonWebKeySet(jwksUri, ctx = {}) {
  const now = Date.now();
  const cached = jwksCache.get(jwksUri);
  if (cached && cached.expiresAt > now) {
    return cached.body;
  }

  if (typeof fetch !== 'function') {
    throw new Error('global fetch is not available for JWKS resolution');
  }

  let response;
  try {
    response = await fetch(jwksUri, {
      method: 'GET',
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(5000),
    });
  } catch (err) {
    throw new Error(`failed to fetch JWKS: ${err.message}`, { cause: err });
  }

  if (!response.ok) {
    throw new Error(`failed to fetch JWKS: HTTP ${response.status} ${response.statusText}`);
  }

  let body;
  try {
    body = await response.json();
  } catch (err) {
    throw new Error(`failed to parse JWKS response: ${err.message}`, { cause: err });
  }

  if (!body || !Array.isArray(body.keys)) {
    throw new Error('JWKS response must contain a keys array');
  }

  const cacheTtlMs =
    parseMaxAgeMs(response.headers.get('cache-control'))
    ?? ctx.jwksCacheTtlMs
    ?? DEFAULT_JWKS_CACHE_TTL_MS;
  jwksCache.set(jwksUri, {
    body,
    expiresAt: now + cacheTtlMs,
  });

  return body;
}

function selectJwkForHeader(keys, header) {
  if (!Array.isArray(keys) || keys.length === 0) {
    return { ok: false, error: 'JWKS did not contain any keys' };
  }

  let candidates = keys.filter(key =>
    key &&
    (!key.use || key.use === 'sig') &&
    (!Array.isArray(key.key_ops) || key.key_ops.includes('verify'))
  );

  const expectedKeyType = inferKeyTypeFromAlg(header?.alg);
  if (expectedKeyType) {
    const typed = candidates.filter(key => !key.kty || key.kty === expectedKeyType);
    if (typed.length > 0) {
      candidates = typed;
    }
  }

  if (isNonEmptyString(header?.alg)) {
    const algMatched = candidates.filter(key => !key.alg || key.alg === header.alg);
    if (algMatched.length > 0) {
      candidates = algMatched;
    }
  }

  if (isNonEmptyString(header?.kid)) {
    candidates = candidates.filter(key => key.kid === header.kid);
    if (candidates.length === 0) {
      return { ok: false, error: `JWKS did not contain a key for kid "${header.kid}"` };
    }
  }

  if (candidates.length === 1) {
    return { ok: true, key: candidates[0] };
  }

  if (candidates.length === 0) {
    return { ok: false, error: 'no JWKS keys matched the JWT header' };
  }

  return {
    ok: false,
    error: 'multiple JWKS keys matched the JWT header; include a kid to disambiguate',
  };
}

async function resolveJwtTrustedKey(proof, profile, ctx = {}) {
  if (ctx.trustedKey) {
    return {
      trustedKey: ctx.trustedKey,
      trustedKeySource: ctx.trustedKeySource || 'context',
      trustedKeyId: ctx.trustedKeyId || null,
      trustedKeyError: null,
    };
  }

  if (isNonEmptyString(profile?.public_key)) {
    return {
      trustedKey: profile.public_key,
      trustedKeySource: 'public_key',
      trustedKeyId: null,
      trustedKeyError: null,
    };
  }

  if (!isNonEmptyString(profile?.jwks_uri)) {
    return {
      trustedKey: null,
      trustedKeySource: null,
      trustedKeyId: null,
      trustedKeyError: null,
    };
  }

  let decoded;
  try {
    decoded = decodeJwtParts(proof.trim());
  } catch (err) {
    return {
      trustedKey: null,
      trustedKeySource: null,
      trustedKeyId: null,
      trustedKeyError: `failed to decode JWT for JWKS lookup: ${err.message}`,
    };
  }

  let jwks;
  try {
    jwks = await fetchJsonWebKeySet(profile.jwks_uri, ctx);
  } catch (err) {
    return {
      trustedKey: null,
      trustedKeySource: 'jwks_uri',
      trustedKeyId: null,
      trustedKeyError: err.message,
    };
  }

  const selected = selectJwkForHeader(jwks.keys, decoded.header);
  if (!selected.ok) {
    return {
      trustedKey: null,
      trustedKeySource: 'jwks_uri',
      trustedKeyId: decoded.header?.kid || null,
      trustedKeyError: selected.error,
    };
  }

  return {
    trustedKey: selected.key,
    trustedKeySource: 'jwks_uri',
    trustedKeyId: selected.key.kid || decoded.header?.kid || null,
    trustedKeyError: null,
  };
}

export async function resolveJwtVerificationContext(proof, profile, ctx = {}) {
  const context = {
    ...ctx,
    manifestDigest: ctx.manifestDigest ?? (
      ctx.manifest == null ? null : canonicalDigest(ctx.manifest)
    ),
    requireSignature: ctx.requireSignature ?? true,
    requireManifestBinding: ctx.requireManifestBinding ?? true,
  };
  const resolved = await resolveJwtTrustedKey(proof, profile, context);
  return {
    ...context,
    trustedKey: resolved.trustedKey,
    trustedKeySource: resolved.trustedKeySource,
    trustedKeyId: resolved.trustedKeyId,
    trustedKeyError: resolved.trustedKeyError,
  };
}

/**
 * Verify a JWT signature using Node.js built-in crypto.
 *
 * Supports RS256 (RSA-SHA256) and ES256 (ECDSA P-256 with SHA-256).
 *
 * @param {{ header: object, signatureRaw: Buffer, parts: string[] }} decoded - Decoded JWT parts.
 * @param {string|object} publicKey - PEM string or JWK object for the public key.
 * @returns {{ verified: boolean, reason?: string }}
 */
function verifyJwtSignature(decoded, publicKey) {
  const { header, signatureRaw, parts } = decoded;
  const alg = header.alg;
  const signingInput = `${parts[0]}.${parts[1]}`;
  let verificationKey;

  try {
    verificationKey = normalizeVerificationKey(publicKey);
  } catch (err) {
    return { verified: false, reason: `invalid verification key: ${err.message}` };
  }

  if (alg === 'RS256') {
    try {
      const verifier = createVerify('RSA-SHA256');
      verifier.update(signingInput);
      const valid = verifier.verify(verificationKey, signatureRaw);
      return valid
        ? { verified: true }
        : { verified: false, reason: 'RS256 signature verification failed' };
    } catch (err) {
      return { verified: false, reason: `RS256 verification error: ${err.message}` };
    }
  }

  if (alg === 'ES256') {
    try {
      const verifier = createVerify('SHA256');
      verifier.update(signingInput);
      const valid = verifier.verify(
        { key: verificationKey, dsaEncoding: 'ieee-p1363' },
        signatureRaw
      );
      return valid
        ? { verified: true }
        : { verified: false, reason: 'ES256 signature verification failed' };
    } catch (err) {
      return { verified: false, reason: `ES256 verification error: ${err.message}` };
    }
  }

  return { verified: false, reason: `Unsupported JWT algorithm: ${alg}` };
}

/**
 * Standard claim name mappings from profile claim names to JWT registered claim names.
 */
const CLAIM_MAPPINGS = {
  subject: 'sub',
  audience: 'aud',
  issuer: 'iss',
};

/**
 * Validate declared claims from a profile against decoded JWT payload claims.
 *
 * Maps profile-level claim names (subject, audience, issuer) to their
 * standard JWT claim names (sub, aud, iss). Custom claims are checked
 * directly by key.
 *
 * @param {object} declaredClaims - Claims declared in the profile.
 * @param {object} payload - Decoded JWT payload.
 * @returns {{ valid: boolean, errors: Array<{ field: string, message: string }> }}
 */
function validateDeclaredClaims(declaredClaims, payload) {
  const errors = [];

  for (const [key, expectedValue] of Object.entries(declaredClaims)) {
    const jwtKey = CLAIM_MAPPINGS[key] || key;
    const actualValue = payload[jwtKey];

    if (actualValue === undefined) {
      errors.push({
        field: `claims.${key}`,
        message: `Expected claim "${jwtKey}" not present in JWT payload`,
      });
    } else if (Array.isArray(actualValue)) {
      // For array claims (e.g. aud), check if expected value is included
      if (!actualValue.includes(expectedValue)) {
        errors.push({
          field: `claims.${key}`,
          message: `Claim "${jwtKey}" does not satisfy the declared value`,
        });
      }
    } else if (actualValue !== expectedValue) {
      errors.push({
        field: `claims.${key}`,
        message: `Claim "${jwtKey}" does not satisfy the declared value`,
      });
    }
  }

  return { valid: errors.length === 0, errors };
}

// -- Verifier implementation --

const jwtVerifier = {
  name: 'jwt',

  /**
   * Validate a JWT authorization proof profile without resolving the proof value.
   *
   * Checks that issuer is a non-empty string when present, that proof uses
   * value_from with env, file, or literal source, and that claims is an object
   * when present.
   *
   * @param {object} profile - The authorization proof profile.
   * @param {object} _ctx    - Validation context.
   * @returns {{ valid: boolean, errors?: Array<{ field: string, message: string }> }}
   */
  validateProfile(profile, ctx = {}) {
    const errors = [];

    if (profile.issuer !== undefined && profile.issuer !== null) {
      if (typeof profile.issuer !== 'string' || profile.issuer === '') {
        errors.push({
          field: 'issuer',
          message: 'issuer must be a non-empty string when present',
        });
      }
    }

    if (!profile.proof || !profile.proof.value_from) {
      errors.push({
        field: 'proof',
        message: 'proof must use value_from with env, file, literal, or command source',
      });
    } else {
      const vf = profile.proof.value_from;
      const sources = ['env', 'file', 'literal', 'command']
        .filter(source => vf[source] !== undefined);
      if (sources.length !== 1) {
        errors.push({
          field: 'proof.value_from',
          message: 'value_from must specify exactly one of env, file, literal, or command',
        });
      } else if (sources[0] === 'literal') {
        errors.push({
          field: 'proof.value_from.literal',
          message: 'JWT proofs must be stored outside the manifest to bind its canonical digest',
        });
      }
    }

    if (profile.claims !== undefined && profile.claims !== null) {
      if (typeof profile.claims !== 'object' || Array.isArray(profile.claims)) {
        errors.push({
          field: 'claims',
          message: 'claims must be an object when present',
        });
      }
    }

    if (profile.jwks_uri !== undefined && profile.jwks_uri !== null) {
      if (typeof profile.jwks_uri !== 'string' || profile.jwks_uri.trim() === '') {
        errors.push({
          field: 'jwks_uri',
          message: 'jwks_uri must be a non-empty string when present',
        });
      } else {
        try {
          const uri = new URL(profile.jwks_uri);
          if (uri.protocol !== 'https:' && ctx.allowInsecureJwks !== true) {
            errors.push({
              field: 'jwks_uri',
              message: 'jwks_uri must use HTTPS',
            });
          }
        } catch {
          errors.push({
            field: 'jwks_uri',
            message: 'jwks_uri must be a valid URL',
          });
        }
      }
    }

    if (profile.public_key !== undefined && profile.public_key !== null) {
      if (typeof profile.public_key !== 'string' || profile.public_key.trim() === '') {
        errors.push({
          field: 'public_key',
          message: 'public_key must be a non-empty string when present',
        });
      } else {
        try {
          normalizeVerificationKey(profile.public_key);
        } catch (error) {
          errors.push({
            field: 'public_key',
            message: `public_key is not a valid verification key: ${error.message}`,
          });
        }
      }
    }

    if (
      !isNonEmptyString(profile.public_key) &&
      !isNonEmptyString(profile.jwks_uri) &&
      !ctx.trustedKey
    ) {
      errors.push({
        field: 'verify',
        message: 'jwt proof verification requires public_key or jwks_uri',
      });
    }

    return errors.length === 0
      ? { valid: true }
      : { valid: false, errors };
  },

  /**
   * Verify a resolved JWT proof against the declared profile.
   *
   * Parses and validates JWT structure, checks expiry and not-before claims,
   * validates declared claims and the canonical manifest binding, then
   * verifies the cryptographic signature with configured trust material.
   *
   * @param {string} proof   - The resolved JWT string.
   * @param {object} profile - The authorization proof profile.
   * @param {object} ctx     - Verification context (may contain trustedKey, manifestDigest).
   * @returns {object} Verification result.
   */
  verifyProof(proof, profile, ctx) {
    const context = ctx || {};
    const signatureRequired = Boolean(context.requireSignature);
    const manifestBindingRequired = context.requireManifestBinding !== false;

    // Validate proof is a non-empty string
    if (!proof || typeof proof !== 'string') {
      return {
        verified: false,
        method: 'jwt',
        reason: 'proof value is missing or not a string',
        claims_validated: false,
        signature_verified: false,
      };
    }

    // Parse JWT structure
    let decoded;
    try {
      decoded = decodeJwtParts(proof.trim());
    } catch (err) {
      return {
        verified: false,
        method: 'jwt',
        reason: err.message,
        claims_validated: false,
        signature_verified: false,
      };
    }

    const { header, payload } = decoded;

    // Validate header has alg
    if (!header.alg) {
      return {
        verified: false,
        method: 'jwt',
        reason: 'JWT header missing "alg" field',
        claims_validated: false,
        signature_verified: false,
      };
    }

    if (profile.issuer !== undefined && profile.issuer !== null && payload.iss !== profile.issuer) {
      return {
        verified: false,
        method: 'jwt',
        reason: 'JWT issuer does not match the declared issuer',
        claims_validated: false,
        signature_verified: false,
      };
    }

    if (profile.audience !== undefined && profile.audience !== null) {
      if (!audienceIncludes(payload.aud, profile.audience)) {
        return {
          verified: false,
          method: 'jwt',
          reason: 'JWT audience does not satisfy the declared audience',
          claims_validated: false,
          signature_verified: false,
        };
      }
    }

    // Check expiry (exp claim)
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp !== undefined) {
      if (typeof payload.exp !== 'number') {
        return {
          verified: false,
          method: 'jwt',
          reason: 'JWT "exp" claim is not a number',
          claims_validated: false,
          signature_verified: false,
        };
      }
      if (now >= payload.exp) {
        return {
          verified: false,
          method: 'jwt',
          reason: `JWT has expired (exp: ${payload.exp}, now: ${now})`,
          claims_validated: false,
          signature_verified: false,
        };
      }
    }

    // Check not-before (nbf claim)
    if (payload.nbf !== undefined) {
      if (typeof payload.nbf !== 'number') {
        return {
          verified: false,
          method: 'jwt',
          reason: 'JWT "nbf" claim is not a number',
          claims_validated: false,
          signature_verified: false,
        };
      }
      if (now < payload.nbf) {
        return {
          verified: false,
          method: 'jwt',
          reason: `JWT is not yet valid (nbf: ${payload.nbf}, now: ${now})`,
          claims_validated: false,
          signature_verified: false,
        };
      }
    }

    // Validate declared claims from profile
    if (profile.claims && typeof profile.claims === 'object' && !Array.isArray(profile.claims)) {
      const claimsResult = validateDeclaredClaims(profile.claims, payload);
      if (!claimsResult.valid) {
        const reasons = claimsResult.errors.map(e => e.message).join('; ');
        return {
          verified: false,
          method: 'jwt',
          reason: `Claims validation failed: ${reasons}`,
          claims_validated: false,
          signature_verified: false,
        };
      }
    }

    let manifestBound = !manifestBindingRequired;
    let manifestBindingReason = null;
    if (manifestBindingRequired) {
      if (typeof context.manifestDigest !== 'string' || context.manifestDigest.length === 0) {
        manifestBindingReason = 'trusted manifest digest is required for JWT authorization proof verification';
      } else if (typeof payload.manifest_digest !== 'string') {
        manifestBindingReason = 'JWT is missing required manifest_digest claim';
      } else if (
        payload.manifest_digest.replace(/^sha256:/, '') !==
        context.manifestDigest.replace(/^sha256:/, '')
      ) {
        manifestBindingReason = 'JWT manifest_digest claim does not match the canonical manifest';
      } else {
        manifestBound = true;
      }
    }

    // Attempt signature verification
    let signatureVerified = false;
    let signatureReason = context.trustedKeyError || 'no trusted key available for signature verification';

    if (context.trustedKey) {
      const sigResult = verifyJwtSignature(decoded, context.trustedKey);
      signatureVerified = sigResult.verified;
      signatureReason = sigResult.verified ? undefined : sigResult.reason;
    } else if (signatureRequired) {
      signatureReason = signatureReason || 'signature required but no trusted key available';
    }

    // Build audit-safe subset of decoded claims
    const decodedClaims = {};
    if (payload.sub !== undefined) decodedClaims.sub = payload.sub;
    if (payload.aud !== undefined) decodedClaims.aud = payload.aud;
    if (payload.iss !== undefined) decodedClaims.iss = payload.iss;
    if (payload.exp !== undefined) decodedClaims.exp = payload.exp;
    if (payload.nbf !== undefined) decodedClaims.nbf = payload.nbf;
    for (const claim of AUDIT_SAFE_CLAIMS) {
      if (payload[claim] !== undefined && decodedClaims[claim] === undefined) {
        decodedClaims[claim] = payload[claim];
      }
    }
    // Arbitrary claims may be validated, but only the explicit audit-safe
    // allowlist above is retained. A manifest author cannot opt a credential
    // or other sensitive custom claim into audit output by naming it here.

    // Claims-only parsing is useful diagnostics, not authorization. A JWT is
    // verified only after cryptographic verification by a trusted key.
    const verified = signatureVerified && manifestBound;

    const result = {
      verified,
      method: 'jwt',
      issuer: payload.iss || profile.issuer || null,
      audience: payload.aud || profile.audience || null,
      claims_validated: true,
      signature_verified: signatureVerified,
      signature_required: signatureRequired,
      manifest_binding_required: manifestBindingRequired,
      manifest_bound: manifestBound,
      decoded_claims: decodedClaims,
      key_id: context.trustedKeyId || header.kid || null,
      key_source: context.trustedKeySource || null,
      manifest_digest: context.manifestDigest || null,
      verified_at: new Date().toISOString(),
    };

    if (!signatureVerified) {
      result.signature_verification_reason = signatureReason;
    }
    if (!verified) {
      result.reason = [
        !signatureVerified ? signatureReason : null,
        !manifestBound ? manifestBindingReason : null,
      ].filter(Boolean).join('; ') || 'JWT verification failed';
    }

    return result;
  },

  /**
   * Describe a JWT verification result for audit purposes.
   *
   * Returns an audit-safe summary with no raw JWT values.
   *
   * @param {object} result - The verification result from verifyProof.
   * @param {object} _ctx   - Description context.
   * @returns {object} Audit-safe verification summary.
   */
  describeVerification(result, _ctx) {
    return {
      method: 'jwt',
      issuer: result.issuer,
      audience: result.audience || null,
      verified: result.verified,
      verified_at: result.verified_at || null,
      manifest_digest: result.manifest_digest || null,
      verifier: 'jwt',
      claims_validated: result.claims_validated,
      signature_verified: result.signature_verified,
      signature_required: result.signature_required,
      manifest_binding_required: result.manifest_binding_required,
      manifest_bound: result.manifest_bound,
      decoded_claims: result.decoded_claims || null,
      key_id: result.key_id || null,
      key_source: result.key_source || null,
      reason: result.reason || result.signature_verification_reason || null,
    };
  },
};

registerVerifier(jwtVerifier);

export { jwtVerifier, base64UrlDecode, decodeJwtParts, verifyJwtSignature };
