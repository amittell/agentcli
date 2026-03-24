/**
 * Credential session utilities.
 *
 * Helpers for navigating, redacting, summarizing, and formatting
 * credential sessions produced by identity providers.
 */

/**
 * Canonical trust level ordering, from least to most privileged.
 */
export const TRUST_LEVELS = ['untrusted', 'restricted', 'supervised', 'autonomous'];

/**
 * Navigate a session object using a dot-delimited path.
 *
 * Returns the value at the path, or undefined if any segment does not resolve.
 * Paths are case-sensitive. Array indexing is not supported.
 *
 * @param {object} session - The session object to navigate.
 * @param {string} path    - Dot-delimited path (e.g. 'credentials.access_token.value').
 * @returns {*} The resolved value, or undefined.
 */
export function resolveSourcePath(session, path) {
  if (!session || typeof path !== 'string' || path === '') return undefined;

  const segments = path.split('.');
  let current = session;

  for (const segment of segments) {
    if (current === null || current === undefined || typeof current !== 'object') {
      return undefined;
    }
    current = current[segment];
  }

  return current;
}

/**
 * Return a deep copy of the session with all leaf values under `credentials`
 * replaced with '[REDACTED]'. Structure is preserved.
 *
 * @param {object} session - The credential session.
 * @returns {object} Redacted copy.
 */
export function redactSession(session) {
  const copy = structuredClone(session);
  if (copy.credentials && typeof copy.credentials === 'object') {
    redactObject(copy.credentials);
  }
  return copy;
}

/**
 * Recursively replace all leaf values in an object with '[REDACTED]'.
 * @param {object} obj
 */
function redactObject(obj) {
  for (const key of Object.keys(obj)) {
    const val = obj[key];
    if (val !== null && typeof val === 'object' && !Array.isArray(val)) {
      redactObject(val);
    } else if (Array.isArray(val)) {
      obj[key] = val.map(item => {
        if (item !== null && typeof item === 'object') {
          const clone = structuredClone(item);
          redactObject(clone);
          return clone;
        }
        return '[REDACTED]';
      });
    } else {
      obj[key] = '[REDACTED]';
    }
  }
}

/**
 * Build a summary of credential types and earliest expiration from a session.
 *
 * @param {object} session - The credential session.
 * @returns {{ credential_types: string[], expires_at: string|null }}
 */
export function buildCredentialSummary(session) {
  const types = [];
  let earliestExpiry = null;

  if (session.credentials && typeof session.credentials === 'object') {
    for (const [key, cred] of Object.entries(session.credentials)) {
      types.push(cred.kind || key);
      if (cred.expires_at) {
        if (earliestExpiry === null || new Date(cred.expires_at) < new Date(earliestExpiry)) {
          earliestExpiry = cred.expires_at;
        }
      }
    }
  }

  return { credential_types: types, expires_at: earliestExpiry };
}

/**
 * Check whether any credential in the session has expired.
 *
 * @param {object} session - The credential session.
 * @returns {boolean} True if at least one credential has an expires_at in the past.
 */
export function isSessionExpired(session) {
  if (!session.credentials || typeof session.credentials !== 'object') return false;

  const now = Date.now();
  for (const cred of Object.values(session.credentials)) {
    if (cred.expires_at && new Date(cred.expires_at).getTime() <= now) {
      return true;
    }
  }

  return false;
}

/**
 * Format a value according to a materialization binding format.
 *
 * @param {*}      value  - The value to format.
 * @param {string} format - One of 'raw', 'json', 'base64'.
 * @returns {string} The formatted value.
 */
export function formatMaterializationValue(value, format) {
  switch (format) {
    case 'json':
      return JSON.stringify(value);
    case 'base64':
      return Buffer.from(String(value)).toString('base64');
    case 'raw':
    default:
      return String(value);
  }
}

/**
 * Validate that a trust level string is one of the canonical values.
 *
 * @param {string} level - The trust level to validate.
 * @returns {{ valid: boolean, error?: string }}
 */
export function validateTrustLevel(level) {
  if (TRUST_LEVELS.includes(level)) {
    return { valid: true };
  }
  return { valid: false, error: `Invalid trust level "${level}". Must be one of: ${TRUST_LEVELS.join(', ')}` };
}

/**
 * Compare two trust levels using canonical ordering.
 *
 * @param {string} a - First trust level.
 * @param {string} b - Second trust level.
 * @returns {number} -1 if a < b, 0 if a === b, 1 if a > b.
 */
export function compareTrustLevels(a, b) {
  const indexA = TRUST_LEVELS.indexOf(a);
  const indexB = TRUST_LEVELS.indexOf(b);

  if (indexA === -1) throw new Error(`Unknown trust level: "${a}"`);
  if (indexB === -1) throw new Error(`Unknown trust level: "${b}"`);

  if (indexA < indexB) return -1;
  if (indexA > indexB) return 1;
  return 0;
}
