import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync, unlinkSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { registerProvider } from './index.js';

const SSH_KEY_CANDIDATES = ['id_ed25519', 'id_ecdsa', 'id_rsa'];
const NAMESPACE = 'agentcli';

// -- Key discovery --

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

// -- Signing --

export function signPayload(payload, { keyPath }) {
  if (!keyPath || !existsSync(keyPath)) {
    return { signed: false, reason: 'no signing key available' };
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
    return {
      signed: false,
      reason: stderr.includes('passphrase')
        ? 'key requires passphrase and is not loaded in ssh-agent'
        : stderr || `ssh-keygen exited with status ${result.status}`,
    };
  }

  const signature = result.stdout.trim();
  if (!signature.includes('BEGIN SSH SIGNATURE')) {
    return { signed: false, reason: 'ssh-keygen produced no signature' };
  }

  const fingerprint = getKeyFingerprint(keyPath);

  return {
    signed: true,
    attestation: {
      method: 'ssh-signature',
      key_fingerprint: fingerprint,
      namespace: NAMESPACE,
      signed_payload: payload,
      signature,
    },
  };
}

// -- Verification --

export function resolveAllowedSigners({ env = process.env, statePath } = {}) {
  const explicit = env.AGENTCLI_ALLOWED_SIGNERS;
  if (explicit && existsSync(explicit)) return explicit;

  if (statePath && existsSync(statePath)) return statePath;

  return null;
}

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

export function verifySignature(attestation, { allowedSignersPath, principal }) {
  if (!attestation || !attestation.signature || !attestation.signed_payload) {
    return { verified: false, reason: 'missing attestation data' };
  }

  if (!allowedSignersPath || !existsSync(allowedSignersPath)) {
    return { verified: false, reason: 'allowed_signers file not found' };
  }

  if (!principal) {
    return { verified: false, reason: 'no principal specified for verification' };
  }

  const tmpSigPath = join(tmpdir(), `agentcli-verify-${Date.now()}-${Math.random().toString(36).slice(2)}.sig`);
  try {
    writeFileSync(tmpSigPath, attestation.signature, 'utf8');

    const result = spawnSync('ssh-keygen', [
      '-Y', 'verify',
      '-f', allowedSignersPath,
      '-I', principal,
      '-n', attestation.namespace || NAMESPACE,
      '-s', tmpSigPath,
    ], {
      input: attestation.signed_payload,
      encoding: 'utf8',
      timeout: 10000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    if (result.status === 0) {
      const fingerprint = attestation.key_fingerprint || null;
      return { verified: true, principal, key_fingerprint: fingerprint };
    }

    return {
      verified: false,
      reason: (result.stderr || '').trim() || 'verification failed',
    };
  } finally {
    try { unlinkSync(tmpSigPath); } catch (_e) { /* cleanup best-effort */ }
  }
}

// -- Provider registration --

const sshProvider = {
  name: 'ssh',
  methods: ['ssh-signature'],

  resolve(options = {}) {
    const keyPath = resolveSigningKey(options);
    return keyPath ? { keyPath } : null;
  },

  sign(payload, config) {
    if (!config || !config.keyPath) {
      return { signed: false, reason: 'no signing key available' };
    }
    return signPayload(payload, config);
  },

  verify(attestation, options) {
    return verifySignature(attestation, options);
  },
};

registerProvider(sshProvider);

export { sshProvider };
