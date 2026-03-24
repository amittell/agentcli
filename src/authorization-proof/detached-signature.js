/**
 * Detached-signature authorization proof verifier.
 *
 * Verifies detached cryptographic signatures over the manifest payload
 * using Node.js built-in crypto. Supports RSA and ECDSA key-based
 * verification, and optionally delegates to ssh-keygen for SSH-style
 * allowed-signers verification.
 */

import { createHash, createVerify, createPublicKey } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, writeFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { registerVerifier } from './index.js';

/**
 * Attempt to auto-detect a suitable verification algorithm from a PEM public key.
 *
 * Parses the key to determine its asymmetric type and returns the corresponding
 * OpenSSL algorithm string for use with crypto.createVerify.
 *
 * @param {string} pem - PEM-encoded public key.
 * @returns {string|null} Algorithm identifier (e.g. 'RSA-SHA256', 'SHA256'), or null for EdDSA keys.
 */
function detectAlgorithm(pem) {
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
    return 'RSA-SHA256'; // fallback
  } catch (_err) {
    return 'RSA-SHA256'; // conservative default
  }
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
    `agentcli-detached-verify-${Date.now()}-${Math.random().toString(36).slice(2)}.sig`
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
  validateProfile(profile, _ctx) {
    const errors = [];

    if (profile.proof) {
      if (!profile.proof.value_from) {
        errors.push({
          field: 'proof',
          message: 'proof must use value_from to reference the detached signature',
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
    } else {
      errors.push({
        field: 'proof',
        message: 'proof is required for detached-signature verification',
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
    const context = ctx || {};

    // Compute or use pre-computed manifest digest
    let digest = context.manifestDigest || null;

    // Manifest content is required for detached signature verification
    if (!context.manifestContent && !digest) {
      return {
        verified: false,
        method: 'detached-signature',
        issuer: (profile && profile.issuer) || null,
        signature_verified: false,
        signature_verification_reason: 'manifest content required for detached signature verification',
        manifest_digest: null,
        verified_at: new Date().toISOString(),
      };
    }

    if (!digest && context.manifestContent) {
      digest = createHash('sha256')
        .update(context.manifestContent)
        .digest('hex');
    }

    // SSH-style verification path
    if (context.sshVerify && context.allowedSignersPath) {
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
      const algorithm = context.algorithm || detectAlgorithm(context.trustedKey);

      if (!algorithm) {
        // Ed25519/Ed448 keys use a different verification API (crypto.verify)
        // that does not go through createVerify. Return informative result.
        return {
          verified: false,
          method: 'detached-signature',
          issuer: (profile && profile.issuer) || null,
          signature_verified: false,
          signature_verification_reason: 'Ed25519/Ed448 detached signature verification requires SSH verification path',
          manifest_digest: digest,
          verified_at: new Date().toISOString(),
        };
      }

      let verificationReason = null;
      let signatureValid;

      try {
        const verifier = createVerify(algorithm);
        verifier.update(context.manifestContent);

        const proofData = Buffer.isBuffer(proof) ? proof.toString('base64') : proof;
        signatureValid = verifier.verify(context.trustedKey, proofData, 'base64');

        if (!signatureValid) {
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
    };
  },
};

registerVerifier(detachedSignatureVerifier);

export { detachedSignatureVerifier };
