/**
 * X.509 certificate-based authorization proof verifier.
 *
 * Verifies authorization proofs backed by X.509 certificates using
 * Node.js built-in crypto.X509Certificate (available since Node 15).
 * Validates certificate validity period, subject/issuer claims, and
 * optionally verifies the certificate chain against a CA certificate.
 */

import { X509Certificate } from 'node:crypto';
import { registerVerifier } from './index.js';

/**
 * Check whether a certificate subject or subjectAltName matches an expected value.
 *
 * The expected value is compared against the certificate's subject DN string
 * and, if present, the subjectAltName string. Matching is case-insensitive
 * and supports substring matching within the DN components.
 *
 * @param {crypto.X509Certificate} cert - The parsed X.509 certificate.
 * @param {string} expected - The expected subject value (DN or SAN entry).
 * @returns {boolean} True if the expected value matches.
 */
function subjectMatches(cert, expected) {
  const normalizedExpected = expected.toLowerCase();

  // Check the subject DN
  const subject = cert.subject || '';
  if (subject.toLowerCase().includes(normalizedExpected)) {
    return true;
  }

  // Check individual DN components for exact value match
  // Subject DN format is like "CN=example\nO=Org\nOU=Unit"
  const subjectLines = subject.split('\n');
  for (const line of subjectLines) {
    const eqIdx = line.indexOf('=');
    if (eqIdx !== -1) {
      const value = line.slice(eqIdx + 1).trim();
      if (value.toLowerCase() === normalizedExpected) {
        return true;
      }
    }
  }

  // Check subjectAltName
  const san = cert.subjectAltName || '';
  if (san && san.toLowerCase().includes(normalizedExpected)) {
    return true;
  }

  return false;
}

/**
 * Check whether a certificate issuer DN matches an expected value.
 *
 * @param {crypto.X509Certificate} cert - The parsed X.509 certificate.
 * @param {string} expected - The expected issuer value (DN or partial).
 * @returns {boolean} True if the expected value matches.
 */
function issuerMatches(cert, expected) {
  const normalizedExpected = expected.toLowerCase();

  const issuer = cert.issuer || '';
  if (issuer.toLowerCase().includes(normalizedExpected)) {
    return true;
  }

  // Check individual DN components
  const issuerLines = issuer.split('\n');
  for (const line of issuerLines) {
    const eqIdx = line.indexOf('=');
    if (eqIdx !== -1) {
      const value = line.slice(eqIdx + 1).trim();
      if (value.toLowerCase() === normalizedExpected) {
        return true;
      }
    }
  }

  return false;
}

const certificateVerifier = {
  name: 'certificate',

  /**
   * Validate a certificate authorization proof profile.
   *
   * Checks that proof.value_from is present (the certificate or certificate chain).
   * Issuer is optional (expected CA DN). Claims may contain subject and issuer
   * fields to validate against the certificate.
   *
   * @param {object} profile - The authorization proof profile.
   * @param {object} _ctx    - Validation context.
   * @returns {{ valid: boolean, errors?: Array<{ field: string, message: string }> }}
   */
  validateProfile(profile, _ctx) {
    const errors = [];

    if (profile.proof) {
      if (!profile.proof.value_from) {
        errors.push({
          field: 'proof',
          message: 'proof must use value_from to reference the certificate',
        });
      } else {
        const vf = profile.proof.value_from;
        if (!vf.env && !vf.file && !vf.literal) {
          errors.push({
            field: 'proof.value_from',
            message: 'value_from must specify env, file, or literal source',
          });
        }
      }
    } else {
      errors.push({
        field: 'proof',
        message: 'proof is required for certificate verification',
      });
    }

    if (profile.issuer !== undefined && profile.issuer !== null) {
      if (typeof profile.issuer !== 'string' || profile.issuer === '') {
        errors.push({
          field: 'issuer',
          message: 'issuer must be a non-empty string when present',
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

    return errors.length === 0
      ? { valid: true }
      : { valid: false, errors };
  },

  /**
   * Verify a resolved certificate proof against the declared profile.
   *
   * Parses the PEM-encoded certificate, validates its validity period,
   * checks subject/issuer claims, and optionally verifies the certificate
   * chain against a CA certificate.
   *
   * @param {string} proof   - The resolved PEM-encoded certificate string.
   * @param {object} profile - The authorization proof profile.
   * @param {object} ctx     - Verification context (may contain caCert, manifestDigest).
   * @returns {object} Verification result.
   */
  verifyProof(proof, profile, ctx) {
    const context = ctx || {};
    const claims = (profile && profile.claims) || {};

    // Parse the certificate
    let cert;
    try {
      cert = new X509Certificate(proof);
    } catch (err) {
      return {
        verified: false,
        method: 'certificate',
        issuer: null,
        subject: null,
        subject_alt_name: null,
        claims_validated: false,
        signature_verified: false,
        signature_verification_reason: `failed to parse certificate: ${err.message}`,
        not_before: null,
        not_after: null,
        serial_number: null,
        fingerprint: null,
        manifest_digest: context.manifestDigest || null,
        verified_at: new Date().toISOString(),
      };
    }

    // Check certificate validity period
    const now = new Date();
    const validFrom = new Date(cert.validFrom);
    const validTo = new Date(cert.validTo);
    let expired = false;
    let notYetValid = false;
    const validityErrors = [];

    if (now > validTo) {
      expired = true;
      validityErrors.push(`certificate expired at ${cert.validTo}`);
    }

    if (now < validFrom) {
      notYetValid = true;
      validityErrors.push(`certificate not valid until ${cert.validFrom}`);
    }

    // Validate claims against certificate fields
    let claimsValid = true;
    const claimsErrors = [];

    if (claims.subject) {
      if (!subjectMatches(cert, claims.subject)) {
        claimsValid = false;
        claimsErrors.push(
          `subject claim "${claims.subject}" does not match certificate subject "${cert.subject}" or SAN "${cert.subjectAltName || '(none)'}"`
        );
      }
    }

    if (claims.issuer) {
      if (!issuerMatches(cert, claims.issuer)) {
        claimsValid = false;
        claimsErrors.push(
          `issuer claim "${claims.issuer}" does not match certificate issuer "${cert.issuer}"`
        );
      }
    }

    // Verify the certificate chain if a CA certificate is provided
    let signatureValid = false;
    let signatureReason = 'no CA certificate provided for chain verification';

    if (context.caCert) {
      let caCertObj;
      try {
        caCertObj = new X509Certificate(context.caCert);
      } catch (err) {
        signatureReason = `failed to parse CA certificate: ${err.message}`;
      }

      if (caCertObj) {
        try {
          const issuedBy = cert.checkIssued(caCertObj);
          if (!issuedBy) {
            signatureReason = 'certificate was not issued by the provided CA';
          } else {
            // Verify the cryptographic signature
            const sigValid = cert.verify(caCertObj.publicKey);
            if (sigValid) {
              signatureValid = true;
              signatureReason = null;
            } else {
              signatureReason = 'certificate signature verification against CA public key failed';
            }
          }
        } catch (err) {
          signatureReason = `chain verification error: ${err.message}`;
        }
      }
    }

    // Overall verification: claims valid, not expired, not yet valid, and signature valid
    const timeValid = !expired && !notYetValid;
    const verified = claimsValid && timeValid && signatureValid;

    // Build composite reason if not verified
    let reason = null;
    if (!verified) {
      const reasons = [];
      if (!claimsValid) reasons.push(...claimsErrors);
      if (!timeValid) reasons.push(...validityErrors);
      if (!signatureValid && signatureReason) reasons.push(signatureReason);
      reason = reasons.join('; ');
    }

    const result = {
      verified,
      method: 'certificate',
      issuer: cert.issuer,
      subject: cert.subject,
      subject_alt_name: cert.subjectAltName || null,
      claims_validated: claimsValid,
      signature_verified: signatureValid,
      signature_verification_reason: reason,
      not_before: cert.validFrom,
      not_after: cert.validTo,
      serial_number: cert.serialNumber,
      fingerprint: cert.fingerprint256,
      manifest_digest: context.manifestDigest || null,
      verified_at: new Date().toISOString(),
    };

    return result;
  },

  /**
   * Describe a certificate verification result for audit purposes.
   *
   * Returns an audit-safe summary with no raw certificate data.
   *
   * @param {object} result - The verification result from verifyProof.
   * @param {object} _ctx   - Description context.
   * @returns {object} Audit-safe verification summary.
   */
  describeVerification(result, _ctx) {
    return {
      method: 'certificate',
      issuer: result.issuer,
      verified: result.verified,
      verified_at: result.verified_at || null,
      manifest_digest: result.manifest_digest || null,
      verifier: 'certificate',
      claims_validated: result.claims_validated,
      signature_verified: result.signature_verified,
      fingerprint: result.fingerprint,
      serial_number: result.serial_number,
    };
  },
};

registerVerifier(certificateVerifier);

export { certificateVerifier };
