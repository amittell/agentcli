import { createHash, createPublicKey } from 'node:crypto';

export function publicKeyId(publicKey) {
  const normalized = publicKey?.type === 'public' && typeof publicKey.export === 'function'
    ? publicKey
    : createPublicKey(publicKey);
  const spki = normalized.export({ type: 'spki', format: 'der' });
  const digest = createHash('sha256').update(spki).digest('hex');
  return `spki-sha256:${digest}`;
}
