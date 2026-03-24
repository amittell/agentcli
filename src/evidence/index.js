/**
 * Evidence provider registry and resolution.
 *
 * An evidence provider implements:
 *   name     - string identifier (e.g. 'ssh', 'none', 'sigstore')
 *   methods  - array of method strings this provider handles (e.g. ['ssh-signature'])
 *   resolve  - (config, ctx) => credentials/configuration for evidence generation
 *   attest   - (payload, config, ctx) => sign/attest a canonical evidence payload
 *   verify   - (envelope, options, ctx) => verify evidence, return machine-readable verdict
 *   describe - (envelope, ctx) => produce audit-safe metadata about the evidence
 */

const providers = new Map();

export function registerEvidenceProvider(provider) {
  if (!provider || typeof provider.name !== 'string') {
    throw new Error('Evidence provider must have a string name');
  }
  if (typeof provider.resolve !== 'function') {
    throw new Error(`Evidence provider "${provider.name}" must implement resolve(config, ctx)`);
  }
  if (typeof provider.attest !== 'function') {
    throw new Error(`Evidence provider "${provider.name}" must implement attest(payload, config, ctx)`);
  }
  if (typeof provider.verify !== 'function') {
    throw new Error(`Evidence provider "${provider.name}" must implement verify(envelope, options, ctx)`);
  }
  if (typeof provider.describe !== 'function') {
    throw new Error(`Evidence provider "${provider.name}" must implement describe(envelope, ctx)`);
  }
  providers.set(provider.name, provider);
}

export function getEvidenceProvider(name) {
  return providers.get(name) ?? null;
}

export function listEvidenceProviders() {
  return [...providers.keys()];
}

/**
 * Resolve which provider to use based on explicit choice, env, or default.
 * Precedence: explicit evidenceProvider arg > AGENTCLI_EVIDENCE_PROVIDER env > 'ssh'
 */
export function resolveEvidenceProvider({ evidenceProvider, env = process.env } = {}) {
  const name = evidenceProvider || env.AGENTCLI_EVIDENCE_PROVIDER || 'ssh';
  const provider = providers.get(name);
  if (!provider) {
    const available = listEvidenceProviders().join(', ');
    throw Object.assign(
      new Error(`Unknown evidence provider: "${name}". Available: ${available}`),
      { code: 'invalid_argument' }
    );
  }
  return provider;
}

/**
 * Resolve provider by evidence method string (for verification dispatch).
 * Finds a provider whose methods array includes the given method.
 */
export function resolveEvidenceProviderForMethod(method) {
  if (!method) return null;
  for (const provider of providers.values()) {
    if (provider.methods && provider.methods.includes(method)) {
      return provider;
    }
  }
  return null;
}
