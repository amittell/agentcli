/**
 * Signing provider registry and resolution.
 *
 * A signing provider implements:
 *   name     - string identifier (e.g. 'ssh', 'oidc', 'x509', 'kms', 'none')
 *   resolve  - (options) => config | null  -- find credentials/configuration
 *   sign     - (payload, config) => { signed, attestation?, reason? }
 *   verify   - (attestation, options) => { verified, reason?, principal?, key_fingerprint? }
 */

const providers = new Map();

export function registerProvider(provider) {
  if (!provider || typeof provider.name !== 'string') {
    throw new Error('Provider must have a string name');
  }
  if (typeof provider.resolve !== 'function') {
    throw new Error(`Provider "${provider.name}" must implement resolve(options)`);
  }
  if (typeof provider.sign !== 'function') {
    throw new Error(`Provider "${provider.name}" must implement sign(payload, config)`);
  }
  if (typeof provider.verify !== 'function') {
    throw new Error(`Provider "${provider.name}" must implement verify(attestation, options)`);
  }
  providers.set(provider.name, provider);
}

export function getProvider(name) {
  return providers.get(name) ?? null;
}

export function listProviders() {
  return [...providers.keys()];
}

/**
 * Resolve which provider to use based on explicit signer choice, env, or default.
 * Precedence: explicit signer arg > AGENTCLI_SIGNER env > 'ssh'
 */
export function resolveProvider({ signer, env = process.env } = {}) {
  const name = signer || env.AGENTCLI_SIGNER || 'ssh';
  const provider = providers.get(name);
  if (!provider) {
    const available = listProviders().join(', ');
    throw Object.assign(
      new Error(`Unknown signing provider: "${name}". Available: ${available}`),
      { code: 'invalid_argument' }
    );
  }
  return provider;
}

/**
 * Resolve provider by attestation method string (for verification dispatch).
 * Maps attestation.method values back to their provider.
 */
export function resolveProviderForMethod(method) {
  if (!method) return null;
  for (const provider of providers.values()) {
    if (provider.methods && provider.methods.includes(method)) {
      return provider;
    }
  }
  return null;
}

// -- Built-in 'none' provider (explicit opt-out) --

const noneProvider = {
  name: 'none',
  methods: [],

  resolve() {
    return {};
  },

  sign() {
    return { signed: false, reason: 'signing disabled (provider: none)' };
  },

  verify() {
    return { verified: false, reason: 'no signing was performed (provider: none)' };
  },
};

registerProvider(noneProvider);
