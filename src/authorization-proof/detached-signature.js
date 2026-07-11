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

const PRIVATE_KEY_PEM = /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/;

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
  const manifestValue = ctx.manifest ?? ctx.manifestContent;
  if (manifestValue === undefined || manifestValue === null) {
    return { error: 'canonical manifest content is required' };
  }

  let manifest;
  if (Buffer.isBuffer(manifestValue)) {
    try {
      manifest = JSON.parse(manifestValue.toString('utf8'));
    } catch (error) {
      return { error: `manifest content must be valid JSON: ${error.message}` };
    }
  } else if (typeof manifestValue === 'string') {
    try {
      manifest = JSON.parse(manifestValue);
    } catch (error) {
      return { error: `manifest content must be valid JSON: ${error.message}` };
    }
  } else if (typeof manifestValue === 'object' && !Array.isArray(manifestValue)) {
    manifest = manifestValue;
  } else {
    return { error: 'manifest content must be a JSON object' };
  }

  const content = canonicalStringify(manifest);
  const digest = hashString(content);
  if (
    ctx.manifestDigest &&
    normalizeDigest(ctx.manifestDigest) !== normalizeDigest(digest)
  ) {
    return { error: 'provided manifest digest does not match canonical manifest content' };
  }
  return { content, digest };
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
    manifestDigest: canonical.digest || null,
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
      return { verified: true };
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

    if (context.manifestContextError || !context.manifestContent) {
      return {
        verified: false,
        method: 'detached-signature',
        issuer: (profile && profile.issuer) || null,
        signature_verified: false,
        signature_verification_reason: context.manifestContextError || 'canonical manifest content is required',
        manifest_digest: digest,
        verified_at: new Date().toISOString(),
      };
    }

    // SSH-style verification path
    if (context.allowedSignersPath) {
      const sshResult = verifySshSignature(
        proof,
        context.manifestContent,
        {
          allowedSignersPath: context.allowedSignersPath,
          principal: context.principal || 'agentcli',
          namespace: context.namespace || 'agentcli',
        }
      );

      return {
        verified: sshResult.verified,
        method: 'detached-signature',
        issuer: (profile && profile.issuer) || null,
        signature_verified: sshResult.verified,
        signature_verification_reason: sshResult.verified ? null : sshResult.reason,
        manifest_digest: digest,
        verified_at: new Date().toISOString(),
      };
    }

    // PEM public key verification path
    if (context.trustedKey) {
      const algorithm = context.algorithm ?? detectAlgorithm(context.trustedKey);

      let verificationReason = null;
      let signatureValid;

      try {
        const signature = decodeBase64Signature(proof);
        if (algorithm === null) {
          signatureValid = verifySignature(
            null,
            Buffer.from(context.manifestContent, 'utf8'),
            context.trustedKey,
            signature
          );
        } else if (algorithm) {
          const verifier = createVerify(algorithm);
          verifier.update(context.manifestContent);
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

      return {
        verified: signatureValid,
        method: 'detached-signature',
        issuer: (profile && profile.issuer) || null,
        signature_verified: signatureValid,
        signature_verification_reason: signatureValid ? null : verificationReason,
        manifest_digest: digest,
        verified_at: new Date().toISOString(),
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
      verified_at: new Date().toISOString(),
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
      reason: result.signature_verification_reason || result.reason || null,
    };
  },
};

registerVerifier(detachedSignatureVerifier);

export { detachedSignatureVerifier };
