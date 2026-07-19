/**
 * Detached-signature authorization proof verifier.
 *
 * Verifies detached cryptographic signatures over the manifest payload
 * using Node.js built-in crypto. Supports RSA, ECDSA, and EdDSA key-based
 * verification, and optionally delegates to ssh-keygen for SSH-style
 * allowed-signers verification.
 */

import { createVerify, createPublicKey, randomUUID, verify as verifySignature } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, writeFileSync, unlinkSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import process from 'node:process';
import { canonicalStringify, hashString } from '../canonical.js';
import { registerVerifier } from './index.js';
import { publicKeyId } from './key-identity.js';

const PRIVATE_KEY_PEM = /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/;
const V4_PROOF_SCHEMA = 'openclaw.scheduler.authorization-proof';

export function detachedSignatureKeyId(publicKey) {
  return publicKeyId(publicKey);
}

export function buildDetachedSignatureV4SigningContent({
  artifactDigest,
  nonce,
  issuedAt,
  expiresAt,
  keyId,
} = {}) {
  return canonicalStringify({
    schema: V4_PROOF_SCHEMA,
    version: 4,
    method: 'detached-signature',
    artifact_digest: artifactDigest,
    nonce,
    issued_at: issuedAt,
    expires_at: expiresAt,
    key_id: keyId,
  });
}

/**
 * Attempt to auto-detect a suitable verification algorithm from a PEM public key.
 *
 * Parses the key to determine its asymmetric type and returns the corresponding
 * OpenSSL algorithm string for use with crypto.createVerify.
 *
 * @param {string} pem - PEM-encoded public key.
 * @returns {string|null|undefined} Algorithm identifier, null for EdDSA, or undefined for unsupported keys.
 */
function detectAlgorithm(pem) {
  if (PRIVATE_KEY_PEM.test(String(pem))) return undefined;
  try {
    const keyObj = createPublicKey(pem);
    const type = keyObj.asymmetricKeyType;
    if (type === 'rsa' || type === 'rsa-pss') {
      return 'RSA-SHA256';
    }
    if (type === 'ec') {
      return 'SHA256';
    }
    if (type === 'ed25519' || type === 'ed448') {
      return null; // Ed25519/Ed448 use sign/verify directly, not createVerify
    }
    return undefined;
  } catch (_err) {
    return undefined;
  }
}

function normalizeDigest(value) {
  return typeof value === 'string' ? value.replace(/^sha256:/, '') : null;
}

function canonicalManifestContext(ctx = {}) {
  const artifactMode = ctx.artifactDigest != null || ctx.handoffArtifactDigest != null;
  const sourceValue = artifactMode
    ? ctx.artifactPayload
    : (ctx.manifest ?? ctx.manifestContent);
  if (sourceValue === undefined || sourceValue === null) {
    return {
      error: artifactMode
        ? 'canonical handoff artifact payload is required'
        : 'canonical manifest content is required',
    };
  }

  let source;
  if (Buffer.isBuffer(sourceValue)) {
    try {
      source = JSON.parse(sourceValue.toString('utf8'));
    } catch (error) {
      return { error: `signed content must be valid JSON: ${error.message}` };
    }
  } else if (typeof sourceValue === 'string') {
    try {
      source = JSON.parse(sourceValue);
    } catch (error) {
      return { error: `signed content must be valid JSON: ${error.message}` };
    }
  } else if (typeof sourceValue === 'object' && !Array.isArray(sourceValue)) {
    source = sourceValue;
  } else {
    return { error: 'signed content must be a JSON object' };
  }

  const content = canonicalStringify(source);
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

export function resolveDetachedSignatureVerificationContext(profile = {}, ctx = {}) {
  const canonical = canonicalManifestContext(ctx);
  const configuredAllowedSigners = ctx.allowedSignersPath || profile.allowed_signers || null;
  const allowedSignersPath = configuredAllowedSigners && !isAbsolute(configuredAllowedSigners)
    ? resolve(ctx.cwd || process.cwd(), configuredAllowedSigners)
    : configuredAllowedSigners;
  return {
    ...ctx,
    manifestContent: canonical.content || null,
    manifestDigest: canonical.artifactMode
      ? (ctx.manifestDigest ?? null)
      : (canonical.digest || null),
    artifactDigest: canonical.artifactMode
      ? canonical.digest
      : (ctx.artifactDigest ?? ctx.handoffArtifactDigest ?? null),
    handoffVersion: canonical.artifactMode
      ? 4
      : (ctx.handoffVersion ?? ctx.handoff_version ?? null),
    manifestContextError: canonical.error || null,
    trustedKey: ctx.trustedKey || profile.public_key || null,
    allowedSignersPath,
    principal: ctx.principal || profile.principal || 'agentcli',
    namespace: ctx.namespace || profile.namespace || 'agentcli',
  };
}

function decodeBase64Signature(proof) {
  if (Buffer.isBuffer(proof)) return proof;
  if (typeof proof !== 'string' || proof.trim() === '') {
    throw new TypeError('detached signature must be a non-empty base64 string or Buffer');
  }
  const normalized = proof.replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
    throw new TypeError('detached signature is not valid base64');
  }
  return Buffer.from(normalized, 'base64');
}

function parseV4Envelope(proof, context) {
  const v4 = Number(context.handoffVersion ?? context.handoff_version) === 4
    || context.artifactDigest != null;
  if (!v4) return { signature: proof, v4: false };

  let envelope = proof;
  if (Buffer.isBuffer(envelope)) envelope = envelope.toString('utf8');
  if (typeof envelope === 'string') {
    try {
      envelope = JSON.parse(envelope);
    } catch {
      return { error: 'handoff v4 detached proof must be a JSON envelope', v4: true };
    }
  }
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
    return { error: 'handoff v4 detached proof must be an object', v4: true };
  }

  for (const field of ['signature', 'artifact_digest', 'nonce', 'issued_at', 'expires_at', 'key_id']) {
    if (typeof envelope[field] !== 'string' || envelope[field].length === 0) {
      return { error: `handoff v4 detached proof is missing ${field}`, v4: true };
    }
  }
  if (normalizeDigest(envelope.artifact_digest) !== normalizeDigest(context.artifactDigest)) {
    return { error: 'detached proof artifact digest does not match', v4: true };
  }

  const now = typeof context.now === 'number'
    ? context.now
    : context.now instanceof Date
      ? context.now.getTime()
      : Date.now();
  const issuedAt = Date.parse(envelope.issued_at);
  const expiresAt = Date.parse(envelope.expires_at);
  const skewMs = (context.clockSkewSeconds ?? 60) * 1000;
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || expiresAt <= issuedAt) {
    return { error: 'detached proof has invalid issued_at or expires_at', v4: true };
  }
  if (issuedAt > now + skewMs) {
    return { error: 'detached proof issued_at is in the future', v4: true };
  }
  if (expiresAt + skewMs <= now) {
    return { error: 'detached proof has expired', v4: true };
  }
  return { signature: envelope.signature, envelope, v4: true };
}

function enforceV4RuntimeGuards(parsed, context, profile, verifiedKeyId) {
  if (!parsed.v4) {
    return { ok: true, replayProtected: true, revocationChecked: true };
  }
  if (typeof verifiedKeyId !== 'string' || verifiedKeyId.length === 0) {
    return { ok: false, reason: 'handoff v4 requires a verified detached-signature key identity' };
  }
  if (parsed.envelope.key_id !== verifiedKeyId) {
    return { ok: false, reason: 'detached proof key_id does not match the verified signing key' };
  }

  const checkRevocation = context.checkProofRevocation
    ?? context.revocationChecker?.check?.bind(context.revocationChecker);
  if (typeof checkRevocation !== 'function') {
    return { ok: false, reason: 'handoff v4 proof revocation checker is required' };
  }
  const revocation = checkRevocation({
    method: 'detached-signature',
    issuer: profile.issuer ?? null,
    proofId: parsed.envelope.nonce,
    artifactDigest: context.artifactDigest,
    keyId: verifiedKeyId,
  });
  if (revocation && typeof revocation.then === 'function') {
    return { ok: false, reason: 'handoff v4 revocation checker must complete synchronously' };
  }
  if (revocation === true || revocation?.revoked === true) {
    return { ok: false, reason: revocation?.reason || 'detached proof key is revoked' };
  }
  if (revocation?.revoked !== false) {
    return {
      ok: false,
      reason: revocation?.reason
        || 'handoff v4 revocation checker did not explicitly confirm the detached proof key is not revoked',
    };
  }

  const claimReplay = context.claimProofReplay
    ?? context.replayStore?.claim?.bind(context.replayStore);
  if (typeof claimReplay !== 'function') {
    return { ok: false, reason: 'handoff v4 proof replay store is required' };
  }
  const replay = claimReplay({
    method: 'detached-signature',
    issuer: profile.issuer ?? null,
    proofId: parsed.envelope.nonce,
    artifactDigest: context.artifactDigest,
    expiresAt: parsed.envelope.expires_at,
    runId: context.runId ?? null,
  });
  if (replay && typeof replay.then === 'function') {
    return { ok: false, reason: 'handoff v4 replay store must complete synchronously' };
  }
  const replayProtected = replay === true || replay?.claimed === true || replay?.ok === true;
  if (!replayProtected) {
    return { ok: false, reason: replay?.reason || 'detached proof nonce was already used' };
  }
  return { ok: true, replayProtected: true, revocationChecked: true };
}

function signedContent(parsed, context) {
  if (!parsed.v4) return context.manifestContent;
  return buildDetachedSignatureV4SigningContent({
    artifactDigest: parsed.envelope.artifact_digest,
    nonce: parsed.envelope.nonce,
    issuedAt: parsed.envelope.issued_at,
    expiresAt: parsed.envelope.expires_at,
    keyId: parsed.envelope.key_id,
  });
}

function verifiedAt(context) {
  const now = typeof context.now === 'number'
    ? context.now
    : context.now instanceof Date
      ? context.now.getTime()
      : Date.now();
  return new Date(now).toISOString();
}

/**
 * Verify a detached signature using ssh-keygen -Y verify.
 *
 * Writes the signature to a temporary file, invokes ssh-keygen, and
 * cleans up afterward. Requires an allowed_signers file and a principal.
 *
 * @param {Buffer|string} signature - The detached signature bytes.
 * @param {Buffer|string} content - The content that was signed.
 * @param {{ allowedSignersPath: string, principal?: string, namespace?: string }} options
 * @returns {{ verified: boolean, reason?: string }}
 */
function verifySshSignature(signature, content, options) {
  const { allowedSignersPath, principal = 'agentcli', namespace = 'agentcli' } = options;

  if (!allowedSignersPath || !existsSync(allowedSignersPath)) {
    return { verified: false, reason: 'allowed_signers file not found for SSH verification' };
  }

  const tmpSigPath = join(
    tmpdir(),
    `agentcli-detached-verify-${randomUUID()}.sig`
  );

  try {
    const sigStr = Buffer.isBuffer(signature) ? signature.toString('utf8') : signature;
    writeFileSync(tmpSigPath, sigStr, 'utf8');

    const contentStr = Buffer.isBuffer(content) ? content.toString('utf8') : content;

    const result = spawnSync('ssh-keygen', [
      '-Y', 'verify',
      '-f', allowedSignersPath,
      '-I', principal,
      '-n', namespace,
      '-s', tmpSigPath,
    ], {
      input: contentStr,
      encoding: 'utf8',
      timeout: 10000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    if (result.status === 0) {
      const output = `${result.stdout || ''}\n${result.stderr || ''}`;
      const fingerprint = output.match(/SHA256:[A-Za-z0-9+/]+={0,2}/)?.[0] ?? null;
      return { verified: true, keyId: fingerprint };
    }

    return {
      verified: false,
      reason: (result.stderr || '').trim() || 'SSH signature verification failed',
    };
  } finally {
    try { unlinkSync(tmpSigPath); } catch (_e) { /* cleanup best-effort */ }
  }
}

const detachedSignatureVerifier = {
  name: 'detached-signature',

  /**
   * Validate a detached-signature authorization proof profile.
   *
   * Checks that proof.value_from is present. Issuer is optional.
   * Claims are not applicable for detached signatures and are ignored
   * per spec.
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
        message: 'proof must use value_from to reference the detached signature',
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
          message: 'detached signatures must be stored outside the manifest to avoid a circular signature',
        });
      }
    }

    if (
      !profile.public_key &&
      !profile.allowed_signers &&
      !ctx.trustedKey &&
      !ctx.allowedSignersPath
    ) {
      errors.push({
        field: 'verify',
        message: 'detached-signature verification requires public_key or allowed_signers',
      });
    }
    if (profile.public_key && detectAlgorithm(profile.public_key) === undefined) {
      errors.push({
        field: 'public_key',
        message: 'public_key is not a supported RSA, ECDSA, Ed25519, or Ed448 key',
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

    // claims are not applicable for detached signatures; if present, they are ignored

    return errors.length === 0
      ? { valid: true }
      : { valid: false, errors };
  },

  /**
   * Verify a resolved detached signature proof against the manifest content.
   *
   * The proof is the raw signature bytes (already resolved from value_from by
   * the caller). Verification requires either a trusted PEM public key or an
   * SSH allowed-signers path in the context.
   *
   * @param {string|Buffer} proof   - The resolved detached signature.
   * @param {object} profile        - The authorization proof profile.
   * @param {object} ctx            - Verification context.
   * @returns {object} Verification result.
   */
  verifyProof(proof, profile, ctx) {
    const context = resolveDetachedSignatureVerificationContext(profile, ctx || {});
    const digest = context.manifestDigest;
    const parsed = parseV4Envelope(proof, context);

    if (parsed.error) {
      return {
        verified: false,
        method: 'detached-signature',
        issuer: profile?.issuer ?? null,
        signature_verified: false,
        signature_verification_reason: parsed.error,
        manifest_digest: digest,
        artifact_digest: context.artifactDigest ?? null,
        artifact_bound: false,
        replay_protected: false,
        revocation_checked: false,
        verified_at: verifiedAt(context),
      };
    }

    if (context.manifestContextError || !context.manifestContent) {
      return {
        verified: false,
        method: 'detached-signature',
        issuer: (profile && profile.issuer) || null,
        signature_verified: false,
        signature_verification_reason: context.manifestContextError || 'canonical manifest content is required',
        manifest_digest: digest,
        verified_at: verifiedAt(context),
      };
    }

    // SSH-style verification path
    if (context.allowedSignersPath) {
      const sshResult = verifySshSignature(
        parsed.signature,
        signedContent(parsed, context),
        {
          allowedSignersPath: context.allowedSignersPath,
          principal: context.principal || 'agentcli',
          namespace: context.namespace || 'agentcli',
        }
      );

      const guards = sshResult.verified
        ? enforceV4RuntimeGuards(parsed, context, profile || {}, sshResult.keyId)
        : { ok: false, reason: sshResult.reason };
      return {
        verified: sshResult.verified && guards.ok,
        method: 'detached-signature',
        issuer: (profile && profile.issuer) || null,
        signature_verified: sshResult.verified,
        signature_verification_reason: sshResult.verified && guards.ok
          ? null
          : (guards.reason || sshResult.reason),
        manifest_digest: digest,
        artifact_digest: context.artifactDigest ?? null,
        artifact_bound: !parsed.v4
          || normalizeDigest(parsed.envelope?.artifact_digest) === normalizeDigest(context.artifactDigest),
        replay_protected: guards.replayProtected === true,
        revocation_checked: guards.revocationChecked === true,
        key_id: sshResult.keyId ?? null,
        verified_at: verifiedAt(context),
      };
    }

    // PEM public key verification path
    if (context.trustedKey) {
      const algorithm = context.algorithm ?? detectAlgorithm(context.trustedKey);

      let verificationReason = null;
      let signatureValid;

      try {
        const signature = decodeBase64Signature(parsed.signature);
        if (algorithm === null) {
          signatureValid = verifySignature(
            null,
            Buffer.from(signedContent(parsed, context), 'utf8'),
            context.trustedKey,
            signature
          );
        } else if (algorithm) {
          const verifier = createVerify(algorithm);
          verifier.update(signedContent(parsed, context));
          signatureValid = verifier.verify(context.trustedKey, signature);
        } else {
          signatureValid = false;
          verificationReason = 'unsupported trusted public key type';
        }

        if (!signatureValid && !verificationReason) {
          verificationReason = 'signature verification failed';
        }
      } catch (err) {
        signatureValid = false;
        verificationReason = `signature verification error: ${err.message}`;
      }

      let verifiedKeyId = null;
      if (signatureValid) {
        try {
          verifiedKeyId = detachedSignatureKeyId(context.trustedKey);
          if (context.trustedKeyId && context.trustedKeyId !== verifiedKeyId) {
            signatureValid = false;
            verificationReason = 'trusted detached-signature key ID does not match the verified signing key';
          }
        } catch (error) {
          signatureValid = false;
          verificationReason = `could not derive verified detached-signature key identity: ${error.message}`;
        }
      }
      const guards = signatureValid
        ? enforceV4RuntimeGuards(parsed, context, profile || {}, verifiedKeyId)
        : { ok: false, reason: verificationReason };
      return {
        verified: signatureValid && guards.ok,
        method: 'detached-signature',
        issuer: (profile && profile.issuer) || null,
        signature_verified: signatureValid,
        signature_verification_reason: signatureValid && guards.ok
          ? null
          : (guards.reason || verificationReason),
        manifest_digest: digest,
        artifact_digest: context.artifactDigest ?? null,
        artifact_bound: !parsed.v4
          || normalizeDigest(parsed.envelope?.artifact_digest) === normalizeDigest(context.artifactDigest),
        replay_protected: guards.replayProtected === true,
        revocation_checked: guards.revocationChecked === true,
        key_id: verifiedKeyId,
        verified_at: verifiedAt(context),
      };
    }

    // No key available -- structural only
    return {
      verified: false,
      method: 'detached-signature',
      issuer: (profile && profile.issuer) || null,
      signature_verified: false,
      signature_verification_reason: 'no trusted key available for detached signature verification',
      manifest_digest: digest,
      verified_at: verifiedAt(context),
    };
  },

  /**
   * Describe a detached-signature verification result for audit purposes.
   *
   * Returns an audit-safe summary with no raw signature data.
   *
   * @param {object} result - The verification result from verifyProof.
   * @param {object} _ctx   - Description context.
   * @returns {object} Audit-safe verification summary.
   */
  describeVerification(result, _ctx) {
    return {
      method: 'detached-signature',
      issuer: result.issuer,
      verified: result.verified,
      verified_at: result.verified_at || null,
      manifest_digest: result.manifest_digest || null,
      verifier: 'detached-signature',
      signature_verified: result.signature_verified,
      artifact_digest: result.artifact_digest || null,
      artifact_bound: result.artifact_bound === true,
      replay_protected: result.replay_protected === true,
      revocation_checked: result.revocation_checked === true,
      key_id: result.key_id || null,
      reason: result.signature_verification_reason || result.reason || null,
    };
  },
};

registerVerifier(detachedSignatureVerifier);

export { detachedSignatureVerifier };
