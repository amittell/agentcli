/**
 * JWT-based authorization proof verifier.
 *
 * Handles JWT verification for manifest authorization proofs using
 * pure Node.js built-in crypto -- no external dependencies.
 *
 * Supports RS256 and ES256 signature verification when a trusted
 * public key is provided. Without a trusted key, structural and
 * claims validation is still performed but cryptographic signature
 * verification is skipped.
 */

import { createVerify } from 'node:crypto';
import { registerVerifier } from './index.js';

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

  if (alg === 'RS256') {
    try {
      const verifier = createVerify('RSA-SHA256');
      verifier.update(signingInput);
      const valid = verifier.verify(publicKey, signatureRaw);
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
        { key: publicKey, dsaEncoding: 'ieee-p1363' },
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
          message: `Claim "${jwtKey}" value does not include expected "${expectedValue}"`,
        });
      }
    } else if (actualValue !== expectedValue) {
      errors.push({
        field: `claims.${key}`,
        message: `Claim "${jwtKey}" expected "${expectedValue}", got "${actualValue}"`,
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
   * value_from with env or file source, and that claims is an object when present.
   *
   * @param {object} profile - The authorization proof profile.
   * @param {object} _ctx    - Validation context.
   * @returns {{ valid: boolean, errors?: Array<{ field: string, message: string }> }}
   */
  validateProfile(profile, _ctx) {
    const errors = [];

    if (profile.issuer !== undefined && profile.issuer !== null) {
      if (typeof profile.issuer !== 'string' || profile.issuer === '') {
        errors.push({
          field: 'issuer',
          message: 'issuer must be a non-empty string when present',
        });
      }
    }

    if (profile.proof) {
      if (!profile.proof.value_from) {
        errors.push({
          field: 'proof',
          message: 'proof must use value_from with env or file source',
        });
      } else {
        const vf = profile.proof.value_from;
        if (!vf.env && !vf.file) {
          errors.push({
            field: 'proof.value_from',
            message: 'value_from must specify env or file source',
          });
        }
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

    return errors.length === 0
      ? { valid: true }
      : { valid: false, errors };
  },

  /**
   * Verify a resolved JWT proof against the declared profile.
   *
   * Parses and validates JWT structure, checks expiry and not-before claims,
   * validates declared claims, and optionally verifies the cryptographic
   * signature when a trusted key is available.
   *
   * @param {string} proof   - The resolved JWT string.
   * @param {object} profile - The authorization proof profile.
   * @param {object} ctx     - Verification context (may contain trustedKey, manifestDigest).
   * @returns {object} Verification result.
   */
  verifyProof(proof, profile, ctx) {
    const context = ctx || {};

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

    // Attempt signature verification
    let signatureVerified = false;
    let signatureReason = 'no trusted key available for signature verification';

    if (context.trustedKey) {
      const sigResult = verifyJwtSignature(decoded, context.trustedKey);
      signatureVerified = sigResult.verified;
      signatureReason = sigResult.verified ? undefined : sigResult.reason;
    }

    // Build audit-safe subset of decoded claims
    const decodedClaims = {};
    if (payload.sub !== undefined) decodedClaims.sub = payload.sub;
    if (payload.aud !== undefined) decodedClaims.aud = payload.aud;
    if (payload.iss !== undefined) decodedClaims.iss = payload.iss;
    if (payload.exp !== undefined) decodedClaims.exp = payload.exp;
    if (payload.nbf !== undefined) decodedClaims.nbf = payload.nbf;
    // Include custom claims declared in the profile
    if (profile.claims && typeof profile.claims === 'object') {
      for (const key of Object.keys(profile.claims)) {
        const jwtKey = CLAIM_MAPPINGS[key] || key;
        if (payload[jwtKey] !== undefined && decodedClaims[jwtKey] === undefined) {
          decodedClaims[jwtKey] = payload[jwtKey];
        }
      }
    }

    // Determine overall verification: all checks must pass
    // Structure and claims are validated at this point.
    // If a trusted key was provided, signature must also verify.
    // If no trusted key, claims-only validation counts as verified (signature_verified remains false).
    // If a trusted key was provided, signature must also pass.
    const verified = context.trustedKey ? signatureVerified : true;

    const result = {
      verified,
      method: 'jwt',
      issuer: payload.iss || profile.issuer || null,
      claims_validated: true,
      signature_verified: signatureVerified,
      decoded_claims: decodedClaims,
      manifest_digest: context.manifestDigest || null,
      verified_at: new Date().toISOString(),
    };

    if (!signatureVerified) {
      result.signature_verification_reason = signatureReason;
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
      verified: result.verified,
      verified_at: result.verified_at || null,
      manifest_digest: result.manifest_digest || null,
      verifier: 'jwt',
      claims_validated: result.claims_validated,
      signature_verified: result.signature_verified,
    };
  },
};

registerVerifier(jwtVerifier);

export { jwtVerifier, base64UrlDecode, decodeJwtParts, verifyJwtSignature };
