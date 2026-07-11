/**
 * SSH evidence provider.
 *
 * Implements the evidence provider interface for SSH key-based attestation.
 * Reimplements SSH signing logic cleanly for the evidence architecture
 * without importing from src/signing/.
 */

import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { canonicalStringify, hashString } from '../canonical.js';
import { registerEvidenceProvider } from './index.js';
import { validateCompleteEvidencePayload } from './payload.js';

const SSH_KEY_CANDIDATES = ['id_ed25519', 'id_ecdsa', 'id_rsa'];
const NAMESPACE = 'agentcli';
export const EVIDENCE_ENVELOPE_SCHEMA = 'agentcli.evidence.envelope';
export const EVIDENCE_ENVELOPE_VERSION = 1;

function signatureDocumentForEnvelope(envelope) {
  return canonicalStringify({
    schema: envelope.schema,
    version: envelope.version,
    method: envelope.method,
    key_fingerprint: envelope.key_fingerprint,
    principal: envelope.principal,
    namespace: envelope.namespace,
    payload_format: envelope.payload_format,
    payload_digest: envelope.payload_digest,
    signed_payload: envelope.signed_payload,
  });
}

// -- Key discovery --

/**
 * Resolve an SSH signing key path.
 *
 * Precedence: explicit signingKey arg > AGENTCLI_SIGNING_KEY env > default SSH key discovery.
 *
 * @param {{ env?: object, homeDir?: string, signingKey?: string }} options
 * @returns {string|null} Resolved key path, or null if none found.
 */
export function resolveSigningKey({ env = process.env, homeDir = homedir(), signingKey } = {}) {
  if (signingKey) {
    return existsSync(signingKey) ? signingKey : null;
  }

  const explicit = env.AGENTCLI_SIGNING_KEY;
  if (explicit) {
    return existsSync(explicit) ? explicit : null;
  }

  const sshDir = join(homeDir, '.ssh');
  for (const candidate of SSH_KEY_CANDIDATES) {
    const keyPath = join(sshDir, candidate);
    if (existsSync(keyPath)) return keyPath;
  }

  return null;
}

/**
 * Get the SHA256 fingerprint of an SSH key.
 *
 * @param {string} keyPath - Path to the private or public key file.
 * @returns {string|null} Fingerprint string (e.g. 'SHA256:...'), or null on failure.
 */
export function getKeyFingerprint(keyPath) {
  const pubKeyPath = keyPath.endsWith('.pub') ? keyPath : `${keyPath}.pub`;
  if (!existsSync(pubKeyPath)) return null;

  const result = spawnSync('ssh-keygen', ['-lf', pubKeyPath], {
    encoding: 'utf8',
    timeout: 5000,
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  if (result.status !== 0) return null;

  const match = result.stdout.match(/SHA256:[A-Za-z0-9+/=]+/);
  return match ? match[0] : null;
}

// -- Allowed signers --

/**
 * Resolve the path to an allowed_signers file.
 *
 * @param {{ env?: object, statePath?: string }} options
 * @returns {string|null} Path to allowed_signers file, or null if not found.
 */
export function resolveAllowedSigners({ env = process.env, statePath } = {}) {
  const explicit = env.AGENTCLI_ALLOWED_SIGNERS;
  if (explicit && existsSync(explicit) && lstatSync(explicit).isFile()) return explicit;

  if (statePath && existsSync(statePath) && lstatSync(statePath).isFile()) return statePath;

  return null;
}

/**
 * Generate an allowed_signers file from public keys in ~/.ssh/.
 *
 * @param {{ principal: string, homeDir?: string, outputPath: string }} options
 * @returns {string|null} The output path on success, or null if no public keys found.
 */
export function generateAllowedSigners({ principal, homeDir = homedir(), outputPath }) {
  const sshDir = join(homeDir, '.ssh');
  const lines = [];

  for (const candidate of SSH_KEY_CANDIDATES) {
    const pubPath = join(sshDir, `${candidate}.pub`);
    if (existsSync(pubPath)) {
      const pubKey = readFileSync(pubPath, 'utf8').trim();
      lines.push(`${principal} ${pubKey}`);
    }
  }

  if (lines.length === 0) return null;

  const outputDirectory = dirname(outputPath);
  mkdirSync(outputDirectory, { recursive: true, mode: 0o700 });
  if (process.platform !== 'win32') chmodSync(outputDirectory, 0o700);
  let descriptor;
  try {
    descriptor = openSync(
      outputPath,
      fsConstants.O_WRONLY |
        fsConstants.O_CREAT |
        fsConstants.O_TRUNC |
        (fsConstants.O_NOFOLLOW || 0),
      0o600
    );
    writeFileSync(descriptor, lines.join('\n') + '\n', 'utf8');
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
  if (process.platform !== 'win32') chmodSync(outputPath, 0o600);
  return outputPath;
}

// -- Evidence provider implementation --

const sshEvidenceProvider = {
  name: 'ssh',
  methods: ['ssh-signature'],

  validateProfile(profile = {}) {
    const format = profile.payload?.format;
    if (format != null && format !== 'canonical-json') {
      return {
        valid: false,
        errors: ['payload.format must be "canonical-json" for the SSH evidence provider'],
      };
    }
    return { valid: true };
  },

  /**
   * Resolve signing credentials from config and context.
   *
   * @param {object} config - Provider configuration (may contain key_path from value_from resolution).
   * @param {object} ctx    - Execution context (may contain env, homeDir).
   * @returns {{ keyPath: string, principal: string }|null} Resolved credentials, or null if no key found.
   */
  resolve(config = {}, ctx = {}) {
    const env = ctx.env || process.env;
    const homeDir = ctx.homeDir || homedir();
    const signingKey = config.key_path || undefined;

    const keyPath = resolveSigningKey({ env, homeDir, signingKey });
    return keyPath
      ? {
          keyPath,
          principal: config.principal || ctx.principal || 'agentcli',
        }
      : null;
  },

  /**
   * Sign/attest a canonical evidence payload using SSH key.
   *
   * @param {string} payload - JSON string of the canonical evidence payload.
   * @param {object} config  - Resolved credentials (must contain keyPath).
   * @param {object} ctx     - Execution context.
   * @returns {{ attested: boolean, envelope?: object, reason?: string }}
   */
  attest(payload, config = {}, _ctx = {}) {
    const keyPath = config.keyPath;
    if (!keyPath || !existsSync(keyPath)) {
      return { attested: false, reason: 'no signing key available' };
    }

    let parsedPayload;
    try {
      parsedPayload = JSON.parse(payload);
    } catch (error) {
      return { attested: false, reason: `evidence payload must be valid JSON: ${error.message}` };
    }
    const payloadValidation = validateCompleteEvidencePayload(parsedPayload);
    if (!payloadValidation.valid) {
      return {
        attested: false,
        reason: `incomplete evidence payload: ${payloadValidation.errors.join('; ')}`,
      };
    }
    if (canonicalStringify(parsedPayload) !== payload) {
      return { attested: false, reason: 'evidence payload must use canonical JSON serialization' };
    }

    const fingerprint = getKeyFingerprint(keyPath);
    const envelope = {
      schema: EVIDENCE_ENVELOPE_SCHEMA,
      version: EVIDENCE_ENVELOPE_VERSION,
      method: 'ssh-signature',
      key_fingerprint: fingerprint,
      principal: config.principal || 'agentcli',
      namespace: NAMESPACE,
      payload_format: 'canonical-json',
      payload_digest: hashString(payload),
      signed_payload: payload,
    };
    const signatureDocument = signatureDocumentForEnvelope(envelope);

    const result = spawnSync('ssh-keygen', [
      '-Y', 'sign',
      '-f', keyPath,
      '-n', NAMESPACE,
    ], {
      input: signatureDocument,
      encoding: 'utf8',
      timeout: 10000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    if (result.status !== 0) {
      const stderr = (result.stderr || '').trim();
      if (stderr.includes('passphrase')) {
        return { attested: false, reason: 'key requires passphrase and is not loaded in ssh-agent' };
      }
      return { attested: false, reason: stderr || `ssh-keygen exited with status ${result.status}` };
    }

    const signature = result.stdout.trim();
    if (!signature.includes('BEGIN SSH SIGNATURE')) {
      return { attested: false, reason: 'ssh-keygen produced no signature' };
    }

    return {
      attested: true,
      envelope: {
        ...envelope,
        signature,
      },
    };
  },

  /**
   * Verify an evidence envelope.
   *
   * @param {object} envelope - The evidence envelope to verify.
   * @param {object} options  - Must contain allowedSignersPath and principal.
   * @param {object} ctx      - Execution context.
   * @returns {{ verified: boolean, principal?: string, key_fingerprint?: string, reason?: string }}
   */
  verify(envelope, options = {}, _ctx = {}) {
    if (!envelope || !envelope.signature || !envelope.signed_payload) {
      return { verified: false, reason: 'missing evidence envelope data' };
    }

    if (
      envelope.schema !== EVIDENCE_ENVELOPE_SCHEMA ||
      envelope.version !== EVIDENCE_ENVELOPE_VERSION ||
      envelope.method !== 'ssh-signature'
    ) {
      return { verified: false, reason: 'unsupported evidence envelope schema or version' };
    }

    if (envelope.payload_format !== 'canonical-json') {
      return { verified: false, reason: 'unsupported evidence payload format' };
    }

    const payloadDigest = hashString(envelope.signed_payload);
    if (envelope.payload_digest !== payloadDigest) {
      return { verified: false, reason: 'evidence payload digest mismatch' };
    }

    let parsedPayload;
    try {
      parsedPayload = JSON.parse(envelope.signed_payload);
    } catch (error) {
      return { verified: false, reason: `invalid evidence payload JSON: ${error.message}` };
    }

    const payloadValidation = validateCompleteEvidencePayload(parsedPayload);
    if (!payloadValidation.valid) {
      return {
        verified: false,
        reason: `invalid signed evidence payload: ${payloadValidation.errors.join('; ')}`,
      };
    }
    if (canonicalStringify(parsedPayload) !== envelope.signed_payload) {
      return { verified: false, reason: 'signed evidence payload is not canonical JSON' };
    }

    const { allowedSignersPath } = options;
    const principal = options.principal || envelope.principal;

    if (!allowedSignersPath || !existsSync(allowedSignersPath)) {
      return { verified: false, reason: 'allowed_signers file not found' };
    }

    if (!principal) {
      return { verified: false, reason: 'no principal specified for verification' };
    }

    if (options.principal && envelope.principal && options.principal !== envelope.principal) {
      return { verified: false, reason: 'evidence principal does not match expected principal' };
    }

    if (envelope.namespace !== NAMESPACE) {
      return { verified: false, reason: 'evidence namespace does not match agentcli' };
    }

    const tmpSigPath = join(tmpdir(), `agentcli-evidence-verify-${randomUUID()}.sig`);
    try {
      writeFileSync(tmpSigPath, envelope.signature, 'utf8');

      const result = spawnSync('ssh-keygen', [
        '-Y', 'verify',
        '-f', allowedSignersPath,
        '-I', principal,
        '-n', envelope.namespace || NAMESPACE,
        '-s', tmpSigPath,
      ], {
        input: signatureDocumentForEnvelope(envelope),
        encoding: 'utf8',
        timeout: 10000,
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      if (result.status === 0) {
        const fingerprintMatch = `${result.stdout || ''}\n${result.stderr || ''}`
          .match(/SHA256:[A-Za-z0-9+/=]+/);
        const verifiedFingerprint = fingerprintMatch ? fingerprintMatch[0] : null;
        if (
          envelope.key_fingerprint &&
          verifiedFingerprint &&
          envelope.key_fingerprint !== verifiedFingerprint
        ) {
          return { verified: false, reason: 'evidence key fingerprint does not match verified signer' };
        }
        return {
          verified: true,
          principal,
          key_fingerprint: verifiedFingerprint || envelope.key_fingerprint || null,
          payload_digest: payloadDigest,
          envelope_version: envelope.version,
          payload: parsedPayload,
        };
      }

      return {
        verified: false,
        reason: (result.stderr || '').trim() || 'verification failed',
      };
    } finally {
      try { unlinkSync(tmpSigPath); } catch (_e) { /* cleanup best-effort */ }
    }
  },

  /**
   * Produce audit-safe metadata about an evidence envelope.
   *
   * @param {object} envelope - The evidence envelope.
   * @param {object} ctx      - Execution context.
   * @returns {object} Audit-safe metadata.
   */
  describe(envelope, _ctx = {}) {
    return {
      provider: 'ssh',
      method: envelope.method,
      attested: envelope.attested !== false,
      envelope_schema: envelope.schema || null,
      envelope_version: envelope.version || null,
      payload_digest: envelope.payload_digest || null,
      key_fingerprint: envelope.key_fingerprint,
      principal: envelope.principal || null,
      namespace: envelope.namespace,
    };
  },
};

registerEvidenceProvider(sshEvidenceProvider);

export { sshEvidenceProvider };
