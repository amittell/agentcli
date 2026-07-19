import { createHash, createPublicKey } from 'node:crypto';

export function publicKeyId(publicKey) {
  if (publicKey && typeof publicKey === 'object' && 'kty' in publicKey && 'd' in publicKey) {
    throw new Error('private JWK material is forbidden when deriving a public key ID');
  }
  const normalized = publicKey?.type === 'public' && typeof publicKey.export === 'function'
    ? publicKey
    : publicKey && typeof publicKey === 'object' && !Array.isArray(publicKey) && 'kty' in publicKey
      ? createPublicKey({ key: publicKey, format: 'jwk' })
      : createPublicKey(publicKey);
  const spki = normalized.export({ type: 'spki', format: 'der' });
  const digest = createHash('sha256').update(spki).digest('hex');
  return `spki-sha256:${digest}`;
}
