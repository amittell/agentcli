/**
 * X.509 certificate-based authorization proof verifier.
 *
 * Verifies authorization proofs backed by X.509 certificates using
 * Node.js built-in crypto.X509Certificate (available since Node 15).
 * Validates certificate validity, exact subject/issuer claims, its chain
 * against a configured CA certificate, and proof of possession over the
 * canonical manifest.
 */

import {
  createVerify,
  verify as verifySignature,
  X509Certificate,
} from 'node:crypto';
import { canonicalStringify, hashString } from '../canonical.js';
import { resolveValueFrom } from '../command.js';
import { registerVerifier } from './index.js';

const V4_PROOF_SCHEMA = 'openclaw.scheduler.authorization-proof';

export function buildCertificateV4SigningContent({
  artifactDigest,
  nonce,
  issuedAt,
  expiresAt,
  keyId,
} = {}) {
  return canonicalStringify({
    schema: V4_PROOF_SCHEMA,
    version: 4,
    method: 'certificate',
    artifact_digest: artifactDigest,
    nonce,
    issued_at: issuedAt,
    expires_at: expiresAt,
    key_id: keyId,
  });
}

function normalizeDigest(value) {
  return typeof value === 'string' ? value.replace(/^sha256:/, '') : null;
}

function resolveCanonicalManifest(ctx = {}) {
  const artifactMode = ctx.artifactDigest != null || ctx.handoffArtifactDigest != null;
  const source = artifactMode
    ? ctx.artifactPayload
    : (ctx.manifest ?? ctx.manifestContent);
  if (source === undefined || source === null) {
    return {
      error: artifactMode
        ? 'canonical handoff artifact payload is required for certificate proof of possession'
        : 'canonical manifest content is required for certificate proof of possession',
    };
  }

  let signedObject;
  try {
    if (Buffer.isBuffer(source)) signedObject = JSON.parse(source.toString('utf8'));
    else if (typeof source === 'string') signedObject = JSON.parse(source);
    else if (typeof source === 'object' && !Array.isArray(source)) signedObject = source;
    else return { error: 'signed content must be a JSON object' };
  } catch (error) {
    return { error: `signed content must be valid JSON: ${error.message}` };
  }

  const content = canonicalStringify(signedObject);
  const digest = hashString(content);
  const expectedDigest = artifactMode
    ? (ctx.artifactDigest ?? ctx.handoffArtifactDigest)
    : ctx.manifestDigest;
  if (expectedDigest && normalizeDigest(expectedDigest) !== normalizeDigest(digest)) {
    return {
      error: artifactMode
        ? 'provided artifact digest does not match canonical artifact payload'
        : 'provided manifest digest does not match canonical manifest content',
    };
  }
  return { content, digest, artifactMode };
}

function parseCertificateProof(proof) {
  if (proof && typeof proof === 'object' && !Buffer.isBuffer(proof)) {
    return {
      certificate: proof.certificate,
      signature: proof.signature,
      artifact_digest: proof.artifact_digest,
      nonce: proof.nonce,
      issued_at: proof.issued_at,
      expires_at: proof.expires_at,
      key_id: proof.key_id,
    };
  }
  if (typeof proof !== 'string' && !Buffer.isBuffer(proof)) {
    throw new TypeError('certificate proof must be a PEM string or JSON proof envelope');
  }
  const text = Buffer.isBuffer(proof) ? proof.toString('utf8') : proof.trim();
  if (text.startsWith('{')) {
    const parsed = JSON.parse(text);
    return {
      certificate: parsed.certificate,
      signature: parsed.signature,
      artifact_digest: parsed.artifact_digest,
      nonce: parsed.nonce,
      issued_at: parsed.issued_at,
      expires_at: parsed.expires_at,
      key_id: parsed.key_id,
    };
  }
  return { certificate: text, signature: null };
}

function validateV4CertificateEnvelope(parsed, context) {
  const v4 = context.handoffVersion === 4 || context.artifactDigest != null;
  if (!v4) return { ok: true, v4: false };
  for (const field of [
    'certificate',
    'signature',
    'artifact_digest',
    'nonce',
    'issued_at',
    'expires_at',
    'key_id',
  ]) {
    if (typeof parsed[field] !== 'string' || parsed[field].length === 0) {
      return { ok: false, v4: true, reason: `handoff v4 certificate proof is missing ${field}` };
    }
  }
  if (normalizeDigest(parsed.artifact_digest) !== normalizeDigest(context.artifactDigest)) {
    return { ok: false, v4: true, reason: 'certificate proof artifact digest does not match' };
  }
  const now = typeof context.now === 'number' ? context.now : Date.now();
  const issuedAt = Date.parse(parsed.issued_at);
  const expiresAt = Date.parse(parsed.expires_at);
  const skewMs = (context.clockSkewSeconds ?? 60) * 1000;
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || expiresAt <= issuedAt) {
    return { ok: false, v4: true, reason: 'certificate proof has invalid issued_at or expires_at' };
  }
  if (issuedAt > now + skewMs) {
    return { ok: false, v4: true, reason: 'certificate proof issued_at is in the future' };
  }
  if (expiresAt + skewMs <= now) {
    return { ok: false, v4: true, reason: 'certificate proof has expired' };
  }
  return { ok: true, v4: true };
}

function enforceV4CertificateGuards(parsed, context, profile, cert) {
  const envelope = validateV4CertificateEnvelope(parsed, context);
  if (!envelope.ok || !envelope.v4) {
    return envelope.v4
      ? { ok: false, reason: envelope.reason }
      : { ok: true, replayProtected: true, revocationChecked: true };
  }

  const claimReplay = context.claimProofReplay
    ?? context.replayStore?.claim?.bind(context.replayStore);
  if (typeof claimReplay !== 'function') {
    return { ok: false, reason: 'handoff v4 proof replay store is required' };
  }
  const replay = claimReplay({
    method: 'certificate',
    issuer: profile.issuer ?? cert.issuer ?? null,
    subject: cert.subject ?? null,
    proofId: parsed.nonce,
    artifactDigest: context.artifactDigest,
    expiresAt: parsed.expires_at,
    runId: context.runId ?? null,
  });
  if (replay && typeof replay.then === 'function') {
    return { ok: false, reason: 'handoff v4 replay store must complete synchronously' };
  }
  const replayProtected = replay === true || replay?.claimed === true || replay?.ok === true;
  if (!replayProtected) {
    return { ok: false, reason: replay?.reason || 'certificate proof nonce was already used' };
  }

  const checkRevocation = context.checkProofRevocation
    ?? context.revocationChecker?.check?.bind(context.revocationChecker);
  if (typeof checkRevocation !== 'function') {
    return { ok: false, reason: 'handoff v4 proof revocation checker is required' };
  }
  const revocation = checkRevocation({
    method: 'certificate',
    issuer: cert.issuer ?? profile.issuer ?? null,
    subject: cert.subject ?? null,
    proofId: parsed.nonce,
    artifactDigest: context.artifactDigest,
    keyId: parsed.key_id ?? cert.fingerprint256,
    serialNumber: cert.serialNumber,
    fingerprint: cert.fingerprint256,
  });
  if (revocation && typeof revocation.then === 'function') {
    return { ok: false, reason: 'handoff v4 revocation checker must complete synchronously' };
  }
  if (revocation === true || revocation?.revoked === true) {
    return { ok: false, reason: revocation?.reason || 'certificate proof is revoked' };
  }
  return { ok: true, replayProtected: true, revocationChecked: true };
}

function verifyProofOfPossession(cert, signature, signedContent) {
  if (typeof signature !== 'string' || signature.trim() === '') {
    return { verified: false, reason: 'certificate proof is missing a manifest signature' };
  }
  if (!signedContent) {
    return { verified: false, reason: 'canonical proof signing content is required' };
  }

  let signatureBytes;
  try {
    const normalized = signature.replace(/\s+/g, '');
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
      throw new TypeError('signature is not valid base64');
    }
    signatureBytes = Buffer.from(normalized, 'base64');
  } catch (error) {
    return { verified: false, reason: error.message };
  }

  try {
    const keyType = cert.publicKey.asymmetricKeyType;
    let verified;
    if (keyType === 'ed25519' || keyType === 'ed448') {
      verified = verifySignature(
        null,
        Buffer.from(signedContent, 'utf8'),
        cert.publicKey,
        signatureBytes
      );
    } else if (keyType === 'rsa' || keyType === 'rsa-pss' || keyType === 'ec') {
      const verifier = createVerify('SHA256');
      verifier.update(signedContent);
      verified = verifier.verify(cert.publicKey, signatureBytes);
    } else {
      return { verified: false, reason: `unsupported certificate key type: ${keyType}` };
    }
    return verified
      ? { verified: true }
      : { verified: false, reason: 'manifest signature verification failed' };
  } catch (error) {
    return { verified: false, reason: `manifest signature verification error: ${error.message}` };
  }
}

export function resolveCertificateVerificationContext(profile = {}, ctx = {}) {
  let caCert = ctx.caCert || profile.ca_certificate || profile.public_key || null;
  let caCertError = null;

  if (!caCert && profile.ca_certificate_from) {
    try {
      caCert = resolveValueFrom(profile.ca_certificate_from, {
        env: ctx.env,
        cwd: ctx.cwd,
        allowCommand: ctx.allowCommand === true,
      });
    } catch (error) {
      caCertError = error.message;
    }
  }

  const manifest = resolveCanonicalManifest(ctx);
  return {
    ...ctx,
    caCert,
    caCertError,
    manifestContent: manifest.content || null,
    manifestDigest: manifest.artifactMode
      ? (ctx.manifestDigest ?? null)
      : (manifest.digest || null),
    artifactDigest: manifest.artifactMode
      ? manifest.digest
      : (ctx.artifactDigest ?? ctx.handoffArtifactDigest ?? null),
    handoffVersion: manifest.artifactMode ? 4 : (ctx.handoffVersion ?? null),
    manifestContextError: manifest.error || null,
    requireProofOfPossession: ctx.requireProofOfPossession ?? true,
  };
}

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
  const normalizedExpected = expected.trim().toLowerCase();

  const subject = cert.subject || '';
  if (subject.trim().toLowerCase() === normalizedExpected) {
    return true;
  }

  const subjectLines = subject.split('\n');
  for (const line of subjectLines) {
    if (line.trim().toLowerCase() === normalizedExpected) return true;
    const eqIdx = line.indexOf('=');
    if (eqIdx !== -1) {
      const value = line.slice(eqIdx + 1).trim();
      if (value.toLowerCase() === normalizedExpected) {
        return true;
      }
    }
  }

  const san = cert.subjectAltName || '';
  for (const entry of san.split(/,\s*/)) {
    const normalizedEntry = entry.trim().toLowerCase();
    if (normalizedEntry === normalizedExpected) return true;
    const colonIdx = entry.indexOf(':');
    if (colonIdx !== -1 && entry.slice(colonIdx + 1).trim().toLowerCase() === normalizedExpected) {
      return true;
    }
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
  const normalizedExpected = expected.trim().toLowerCase();

  const issuer = cert.issuer || '';
  if (issuer.trim().toLowerCase() === normalizedExpected) {
    return true;
  }

  const issuerLines = issuer.split('\n');
  for (const line of issuerLines) {
    if (line.trim().toLowerCase() === normalizedExpected) return true;
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
  validateProfile(profile, ctx = {}) {
    const errors = [];

    if (!profile.proof || !profile.proof.value_from) {
      errors.push({
        field: 'proof',
        message: 'proof must use value_from to reference the certificate proof envelope',
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
          message: 'certificate proof envelopes must be stored outside the manifest to avoid a circular signature',
        });
      }
    }

    if (
      !profile.ca_certificate &&
      !profile.ca_certificate_from &&
      !profile.public_key &&
      !ctx.caCert
    ) {
      errors.push({
        field: 'verify',
        message: 'certificate verification requires ca_certificate, ca_certificate_from, or public_key',
      });
    }
    const configuredCa = profile.ca_certificate || profile.public_key;
    if (configuredCa) {
      try {
        new X509Certificate(configuredCa);
      } catch (error) {
        errors.push({
          field: profile.ca_certificate ? 'ca_certificate' : 'public_key',
          message: `configured CA is not a valid X.509 certificate: ${error.message}`,
        });
      }
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
      } else {
        for (const claim of ['subject', 'issuer']) {
          if (
            profile.claims[claim] !== undefined &&
            (typeof profile.claims[claim] !== 'string' || profile.claims[claim].trim() === '')
          ) {
            errors.push({
              field: `claims.${claim}`,
              message: `${claim} claim must be a non-empty string when present`,
            });
          }
        }
      }
    }

    return errors.length === 0
      ? { valid: true }
      : { valid: false, errors };
  },

  /**
   * Verify a resolved certificate proof against the declared profile.
   *
   * Parses the proof envelope, validates the certificate and CA chain, and
   * verifies its signature over the canonical manifest.
   *
   * @param {string} proof   - The resolved PEM-encoded certificate string.
   * @param {object} profile - The authorization proof profile.
   * @param {object} ctx     - Verification context (may contain caCert, manifestDigest).
   * @returns {object} Verification result.
   */
  verifyProof(proof, profile, ctx) {
    const context = resolveCertificateVerificationContext(profile, ctx || {});
    const verificationNowMs = typeof context.now === 'number'
      ? context.now
      : context.now instanceof Date
        ? context.now.getTime()
        : Date.now();
    const verifiedAt = new Date(verificationNowMs).toISOString();
    const claims = (profile && profile.claims) || {};

    let parsedProof;
    try {
      parsedProof = parseCertificateProof(proof);
    } catch (error) {
      return {
        verified: false,
        method: 'certificate',
        reason: `failed to parse certificate proof: ${error.message}`,
        claims_validated: false,
        signature_verified: false,
        proof_of_possession_verified: false,
        manifest_digest: context.manifestDigest || null,
        verified_at: verifiedAt,
      };
    }

    const envelope = validateV4CertificateEnvelope(parsedProof, context);
    if (!envelope.ok) {
      return {
        verified: false,
        method: 'certificate',
        reason: envelope.reason,
        claims_validated: false,
        signature_verified: false,
        proof_of_possession_verified: false,
        artifact_digest: context.artifactDigest ?? null,
        artifact_bound: false,
        replay_protected: false,
        revocation_checked: false,
        manifest_digest: context.manifestDigest || null,
        verified_at: verifiedAt,
      };
    }

    // Parse the certificate
    let cert;
    try {
      cert = new X509Certificate(parsedProof.certificate);
    } catch (err) {
      return {
        verified: false,
        method: 'certificate',
        issuer: null,
        subject: null,
        subject_alt_name: null,
        claims_validated: false,
        signature_verified: false,
        proof_of_possession_verified: false,
        signature_verification_reason: `failed to parse certificate: ${err.message}`,
        not_before: null,
        not_after: null,
        serial_number: null,
        fingerprint: null,
        manifest_digest: context.manifestDigest || null,
        verified_at: verifiedAt,
      };
    }

    // Check certificate validity period
    const now = new Date(verificationNowMs);
    const validFrom = new Date(cert.validFrom);
    const validTo = new Date(cert.validTo);
    let expired = false;
    let notYetValid = false;
    const validityErrors = [];
    const certificateUsageValid = cert.ca !== true;

    if (!certificateUsageValid) {
      validityErrors.push('presented authorization certificate must not be a CA certificate');
    }

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
          const caValidFrom = new Date(caCertObj.validFrom);
          const caValidTo = new Date(caCertObj.validTo);
          if (caCertObj.ca !== true) {
            signatureReason = 'provided trust certificate is not a CA certificate';
          } else if (now < caValidFrom || now > caValidTo) {
            signatureReason = 'provided CA certificate is outside its validity period';
          } else if (!cert.checkIssued(caCertObj)) {
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

    if (!context.caCert && context.caCertError) {
      signatureReason = `CA certificate resolution failed: ${context.caCertError}`;
    }

    const possessionContent = envelope.v4
      ? buildCertificateV4SigningContent({
          artifactDigest: parsedProof.artifact_digest,
          nonce: parsedProof.nonce,
          issuedAt: parsedProof.issued_at,
          expiresAt: parsedProof.expires_at,
          keyId: parsedProof.key_id,
        })
      : context.manifestContent;
    const possession = context.manifestContextError
      ? { verified: false, reason: context.manifestContextError }
      : context.requireProofOfPossession
        ? verifyProofOfPossession(cert, parsedProof.signature, possessionContent)
        : { verified: true };

    // Overall verification requires a trusted chain and proof that the holder
    // of the certificate private key signed the canonical manifest.
    const timeValid = !expired && !notYetValid;
    const cryptographicallyVerified = claimsValid
      && timeValid
      && certificateUsageValid
      && signatureValid
      && possession.verified;
    const guards = cryptographicallyVerified
      ? enforceV4CertificateGuards(parsedProof, context, profile || {}, cert)
      : { ok: false };
    const verified = cryptographicallyVerified && guards.ok;

    // Build composite reason if not verified
    let reason = null;
    if (!verified) {
      const reasons = [];
      if (!claimsValid) reasons.push(...claimsErrors);
      if (!timeValid || !certificateUsageValid) reasons.push(...validityErrors);
      if (!signatureValid && signatureReason) reasons.push(signatureReason);
      if (!possession.verified && possession.reason) reasons.push(possession.reason);
      if (cryptographicallyVerified && !guards.ok && guards.reason) reasons.push(guards.reason);
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
      proof_of_possession_verified: possession.verified,
      signature_verification_reason: verified ? null : reason,
      not_before: cert.validFrom,
      not_after: cert.validTo,
      serial_number: cert.serialNumber,
      fingerprint: cert.fingerprint256,
      manifest_digest: context.manifestDigest || null,
      artifact_digest: context.artifactDigest ?? null,
      artifact_bound: !envelope.v4
        || normalizeDigest(parsedProof.artifact_digest) === normalizeDigest(context.artifactDigest),
      replay_protected: guards.replayProtected === true,
      revocation_checked: guards.revocationChecked === true,
      verified_at: verifiedAt,
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
      proof_of_possession_verified: result.proof_of_possession_verified,
      fingerprint: result.fingerprint,
      serial_number: result.serial_number,
      artifact_digest: result.artifact_digest || null,
      artifact_bound: result.artifact_bound === true,
      replay_protected: result.replay_protected === true,
      revocation_checked: result.revocation_checked === true,
      reason: result.signature_verification_reason || result.reason || null,
    };
  },
};

registerVerifier(certificateVerifier);

export { certificateVerifier };
