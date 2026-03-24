/**
 * Identity provider registry and resolution.
 *
 * An identity provider implements:
 *   name                 - string identifier (e.g. 'none', 'env-bearer', 'oidc')
 *   capabilities         - object describing provider capabilities
 *   validateProfile      - (profile, ctx) => validation result (MUST NOT resolve credentials)
 *   resolveSession       - (request, ctx) => credential session
 *   describeSession      - (session, ctx) => audit-safe summary (MUST NOT include raw secrets)
 *   materialize          - (session, presentation, ctx) => materialization result with cleanup metadata
 *   cleanup              - (materialization, ctx) => cleanup result
 *
 * Optional methods (gated by capabilities):
 *   refreshSession       - (session, ctx) => refreshed session (when capabilities.refreshable is true)
 *   prepareHandoff       - (session, handoff, ctx) => handoff result (when handoff_modes includes non-"none")
 *   validateDelegation   - (chain, policy, ctx) => validation result (when capabilities.delegation is true)
 */

const providers = new Map();

const REQUIRED_METHODS = [
  'validateProfile',
  'resolveSession',
  'describeSession',
  'materialize',
  'cleanup',
];

/**
 * Register an identity provider.
 *
 * Validates that the provider has a string name, a capabilities object,
 * and all required methods. Optional methods are validated against
 * declared capabilities.
 *
 * @param {object} provider - The identity provider to register.
 */
export function registerProvider(provider) {
  if (!provider || typeof provider.name !== 'string' || provider.name === '') {
    throw new Error('Identity provider must have a non-empty string name');
  }

  if (!provider.capabilities || typeof provider.capabilities !== 'object') {
    throw new Error(`Identity provider "${provider.name}" must have a capabilities object`);
  }

  for (const method of REQUIRED_METHODS) {
    if (typeof provider[method] !== 'function') {
      throw new Error(`Identity provider "${provider.name}" must implement ${method}()`);
    }
  }

  // Validate optional method presence matches declared capabilities
  if (provider.capabilities.refreshable && typeof provider.refreshSession !== 'function') {
    throw new Error(
      `Identity provider "${provider.name}" declares refreshable capability but does not implement refreshSession()`
    );
  }

  const handoffModes = provider.capabilities.handoff_modes || [];
  const hasNonNoneHandoff = handoffModes.some(m => m !== 'none');
  if (hasNonNoneHandoff && typeof provider.prepareHandoff !== 'function') {
    throw new Error(
      `Identity provider "${provider.name}" declares non-none handoff modes but does not implement prepareHandoff()`
    );
  }

  if (provider.capabilities.delegation && typeof provider.validateDelegation !== 'function') {
    throw new Error(
      `Identity provider "${provider.name}" declares delegation capability but does not implement validateDelegation()`
    );
  }

  providers.set(provider.name, provider);
}

/**
 * Get a registered identity provider by name.
 *
 * @param {string} name - Provider name.
 * @returns {object|null} The provider, or null if not found.
 */
export function getProvider(name) {
  return providers.get(name) ?? null;
}

/**
 * List the names of all registered identity providers.
 *
 * @returns {string[]}
 */
export function listProviders() {
  return [...providers.keys()];
}

/**
 * Resolve an identity provider by explicit name. Throws if not found.
 *
 * @param {string} providerName - The provider name to resolve.
 * @returns {object} The resolved provider.
 */
export function resolveProvider(providerName) {
  const provider = providers.get(providerName);
  if (!provider) {
    const available = listProviders().join(', ');
    throw Object.assign(
      new Error(`Unknown identity provider: "${providerName}". Available: ${available || '(none)'}`),
      { code: 'unknown_identity_provider' }
    );
  }
  return provider;
}

/**
 * Return a map of provider name to capabilities for all registered providers.
 *
 * @returns {Map<string, object>}
 */
export function listProviderCapabilities() {
  const result = new Map();
  for (const [name, provider] of providers) {
    result.set(name, provider.capabilities);
  }
  return result;
}
