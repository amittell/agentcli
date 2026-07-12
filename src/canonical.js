import { createHash } from 'node:crypto';

function normalizePrimitive(value) {
  if (value === undefined) return null;
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new TypeError('Canonical values must contain only finite numbers');
  }
  return value;
}

export function sortKeysDeep(value) {
  if (value === null || typeof value !== 'object') {
    return normalizePrimitive(value);
  }

  if (Array.isArray(value)) {
    return value.map(item => sortKeysDeep(item));
  }

  const sorted = {};
  for (const key of Object.keys(value).sort()) {
    sorted[key] = sortKeysDeep(value[key]);
  }
  return sorted;
}

export function canonicalStringify(value) {
  return JSON.stringify(sortKeysDeep(value));
}

export function hashString(value, { prefix = true } = {}) {
  const digest = createHash('sha256').update(String(value), 'utf8').digest('hex');
  return prefix ? `sha256:${digest}` : digest;
}

export function hashNullableString(value, options) {
  return value == null ? null : hashString(value, options);
}

export function canonicalDigest(value, { prefix = true } = {}) {
  return hashString(canonicalStringify(value), { prefix });
}
