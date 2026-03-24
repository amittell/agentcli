/**
 * SSH evidence provider.
 *
 * Implements the evidence provider interface for SSH key-based attestation.
 * Reimplements SSH signing logic cleanly for the evidence architecture
 * without importing from src/signing/.
 */

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync, unlinkSync, mkdirSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { registerEvidenceProvider } from './index.js';

const SSH_KEY_CANDIDATES = ['id_ed25519', 'id_ecdsa', 'id_rsa'];
const NAMESPACE = 'agentcli';

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
  if (explicit && existsSync(explicit)) return explicit;

  if (statePath && existsSync(statePath)) return statePath;

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

  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, lines.join('\n') + '\n', 'utf8');
  return outputPath;
}

// -- Evidence provider implementation --

const sshEvidenceProvider = {
  name: 'ssh',
  methods: ['ssh-signature'],

  /**
   * Resolve signing credentials from config and context.
   *
   * @param {object} config - Provider configuration (may contain key_path from value_from resolution).
   * @param {object} ctx    - Execution context (may contain env, homeDir).
   * @returns {{ keyPath: string }|null} Resolved credentials, or null if no key found.
   */
  resolve(config = {}, ctx = {}) {
    const env = ctx.env || process.env;
    const homeDir = ctx.homeDir || homedir();
    const signingKey = config.key_path || undefined;

    const keyPath = resolveSigningKey({ env, homeDir, signingKey });
    return keyPath ? { keyPath } : null;
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

    const result = spawnSync('ssh-keygen', [
      '-Y', 'sign',
      '-f', keyPath,
      '-n', NAMESPACE,
    ], {
      input: payload,
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

    const fingerprint = getKeyFingerprint(keyPath);

    return {
      attested: true,
      envelope: {
        method: 'ssh-signature',
        key_fingerprint: fingerprint,
        namespace: NAMESPACE,
        signed_payload: payload,
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

    const { allowedSignersPath, principal } = options;

    if (!allowedSignersPath || !existsSync(allowedSignersPath)) {
      return { verified: false, reason: 'allowed_signers file not found' };
    }

    if (!principal) {
      return { verified: false, reason: 'no principal specified for verification' };
    }

    const tmpSigPath = join(tmpdir(), `agentcli-evidence-verify-${Date.now()}-${Math.random().toString(36).slice(2)}.sig`);
    try {
      writeFileSync(tmpSigPath, envelope.signature, 'utf8');

      const result = spawnSync('ssh-keygen', [
        '-Y', 'verify',
        '-f', allowedSignersPath,
        '-I', principal,
        '-n', envelope.namespace || NAMESPACE,
        '-s', tmpSigPath,
      ], {
        input: envelope.signed_payload,
        encoding: 'utf8',
        timeout: 10000,
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      if (result.status === 0) {
        const fingerprint = envelope.key_fingerprint || null;
        return { verified: true, principal, key_fingerprint: fingerprint };
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
      key_fingerprint: envelope.key_fingerprint,
      namespace: envelope.namespace,
    };
  },
};

registerEvidenceProvider(sshEvidenceProvider);

export { sshEvidenceProvider };
