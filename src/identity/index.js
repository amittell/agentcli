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

import { stripeApiKeyProvider } from './stripe-api-key.js';
import {
  cleanupMaterializedCredentials,
  combineValidationResults,
  describeCredentialSession,
  enforceDelegationPolicy,
  materializeCredentialBindings,
  sanitizeProviderError,
  validateCommonIdentityProfile,
  validateSecureEndpoint,
} from './session.js';

const providers = new Map();

const REQUIRED_METHODS = [
  'validateProfile',
  'resolveSession',
  'describeSession',
  'materialize',
  'cleanup',
];

const REQUIRED_CAPABILITY_ARRAYS = [
  'auth_modes',
  'credential_types',
  'presentation_kinds',
  'handoff_modes',
  'trust_levels',
  'approval_mechanisms',
];
const HARDENED_PROVIDER = Symbol('agentcli.hardenedIdentityProvider');
const cleanupResults = new WeakMap();

function isThenable(value) {
  return value !== null && typeof value === 'object' && typeof value.then === 'function';
}

function endpointValidation(provider, profile) {
  const config = profile?.auth?.provider_config || {};
  const errors = [];
  for (const [key, path] of [
    ['token_endpoint', 'auth.provider_config.token_endpoint'],
    ['api_base', 'auth.provider_config.api_base'],
    ['authority', 'auth.provider_config.authority'],
  ]) {
    if (config[key] != null) errors.push(...validateSecureEndpoint(config[key], path));
  }
  return errors.length === 0 ? { valid: true } : { valid: false, errors };
}

function sanitizeValidationResult(result, profile, ctx) {
  if (result?.valid !== false) return { valid: true };
  const errors = (result.errors || [result.error || 'profile validation failed']).map(error =>
    sanitizeProviderError(
      { message: typeof error === 'string' ? error : error?.message },
      { profile, env: ctx?.env }
    ).message
  );
  return { valid: false, errors };
}

function finalizeResolvedSession(provider, result, profile, ctx) {
  if (result?.ok === false) {
    const safe = sanitizeProviderError(
      { message: result.error, code: 'identity_resolution_failed', transient: result.transient },
      { profile, env: ctx?.env }
    );
    return { ...result, error: safe.message };
  }

  const session = result?.ok === true && result.session ? result.session : result;
  if (!session || typeof session !== 'object') {
    throw Object.assign(
      new Error(`Identity provider "${provider.name}" returned an invalid credential session`),
      { code: 'identity_resolution_failed' }
    );
  }

  const policy = profile?.auth?.delegation_policy || {};
  const delegation = provider.validateDelegation
    ? provider.validateDelegation(session.delegation_chain || [], policy, ctx)
    : enforceDelegationPolicy(session, policy);
  if (delegation?.valid === false) {
    const safeDelegation = describeCredentialSession({
      credentials: {},
      delegation_validation: delegation,
    }).delegation_validation;
    throw Object.assign(
      new Error(`Identity provider "${provider.name}" returned a delegation chain that violates policy`),
      { code: 'identity_delegation_invalid', delegation_validation: safeDelegation }
    );
  }
  session.delegation_validation = {
    ...(session.delegation_validation || {}),
    ...(delegation || {}),
    valid: true,
  };

  return result?.ok === true && result.session ? { ...result, session } : session;
}

function wrapProviderSecurity(provider) {
  if (provider[HARDENED_PROVIDER]) return provider;

  const originalValidate = provider.validateProfile.bind(provider);
  const originalResolve = provider.resolveSession.bind(provider);
  const originalCleanup = provider.cleanup.bind(provider);
  const originalDelegation = typeof provider.validateDelegation === 'function'
    ? provider.validateDelegation.bind(provider)
    : null;
  const originalRefresh = typeof provider.refreshSession === 'function'
    ? provider.refreshSession.bind(provider)
    : null;
  const originalHandoff = typeof provider.prepareHandoff === 'function'
    ? provider.prepareHandoff.bind(provider)
    : null;

  // Shared materialization supports stdin for providers that already support
  // generic env/file presentation. Stripe intentionally remains env-only.
  if (provider.name !== 'stripe-api-key' &&
      provider.capabilities.presentation_kinds.some(kind => kind === 'env' || kind === 'file') &&
      !provider.capabilities.presentation_kinds.includes('stdin')) {
    provider.capabilities.presentation_kinds.push('stdin');
  }

  provider.validateProfile = function validateHardenedProfile(profile, ctx = {}) {
    const common = validateCommonIdentityProfile(provider, profile, ctx);
    const endpoints = endpointValidation(provider, profile);
    let own;
    try {
      // Existing OIDC validators use allowInsecure for local mock servers.
      // The common endpoint validation above still rejects every non-loopback
      // HTTP endpoint, so this cannot enable remote plaintext transport.
      own = originalValidate(profile, { ...ctx, allowInsecure: true });
    } catch (error) {
      own = { valid: false, errors: [sanitizeProviderError(error, { profile, env: ctx?.env }).message] };
    }
    if (isThenable(own)) {
      return own
        .then(result => sanitizeValidationResult(combineValidationResults(common, endpoints, result), profile, ctx))
        .catch(error => ({
          valid: false,
          errors: [sanitizeProviderError(error, { profile, env: ctx?.env }).message],
        }));
    }
    return sanitizeValidationResult(combineValidationResults(common, endpoints, own), profile, ctx);
  };

  if (originalDelegation) {
    provider.validateDelegation = function validateHardenedDelegation(chain, policy, ctx) {
      let providerResult;
      try {
        providerResult = originalDelegation(chain, policy, ctx);
      } catch (error) {
        return {
          valid: false,
          errors: [sanitizeProviderError(error, { env: ctx?.env }).message],
        };
      }
      const common = enforceDelegationPolicy({ delegation_chain: chain }, policy);
      if (isThenable(providerResult)) {
        return providerResult.then(result => ({
          ...common,
          ...result,
          valid: common.valid && result?.valid !== false,
          errors: [...(common.errors || []), ...(result?.errors || [])],
        }));
      }
      return {
        ...common,
        ...(providerResult || {}),
        valid: common.valid && providerResult?.valid !== false,
        errors: [...(common.errors || []), ...(providerResult?.errors || [])],
      };
    };
  }

  provider.resolveSession = function resolveHardenedSession(request, ctx = {}) {
    const profile = request?.profile || {};
    const validation = provider.validateProfile(profile, ctx);

    const resolveAfterValidation = validated => {
      if (validated?.valid === false) {
        throw Object.assign(
          new Error(`Identity profile for provider "${provider.name}" is invalid: ${(validated.errors || []).join('; ')}`),
          { code: 'identity_profile_invalid', validation: validated }
        );
      }
      let result;
      try {
        result = originalResolve(request, ctx);
      } catch (error) {
        throw sanitizeProviderError(error, { profile, env: ctx?.env });
      }
      if (isThenable(result)) {
        return result
          .then(value => finalizeResolvedSession(provider, value, profile, ctx))
          .catch(error => { throw sanitizeProviderError(error, { profile, env: ctx?.env }); });
      }
      return finalizeResolvedSession(provider, result, profile, ctx);
    };

    return isThenable(validation)
      ? validation.then(resolveAfterValidation)
      : resolveAfterValidation(validation);
  };

  provider.describeSession = function describeHardenedSession(session) {
    return describeCredentialSession(session);
  };

  provider.materialize = function materializeHardenedSession(session, presentation = {}, _ctx = {}) {
    const stripeDefault = provider.name === 'stripe-api-key'
      ? [{
          source: 'credentials.api_key.value',
          target: { kind: 'env', name: 'STRIPE_API_KEY' },
          required: true,
          redact: true,
        }]
      : [];
    const explicit = Array.isArray(presentation?.bindings) ? presentation.bindings : [];
    const effectivePresentation = provider.name === 'stripe-api-key'
      ? { ...presentation, bindings: [...stripeDefault, ...explicit] }
      : presentation;
    const result = materializeCredentialBindings(session, effectivePresentation, {
      allowedTargetKinds: provider.capabilities.presentation_kinds,
      tempPrefix: `agentcli-${provider.name}`,
    });

    if (provider.name === 'stripe-api-key' && session?.provider_assertions?.key_strategy === 'dynamic') {
      result.cleanup_required = true;
      Object.defineProperty(result, 'session', {
        value: session,
        enumerable: false,
        configurable: false,
        writable: false,
      });
    }
    return result;
  };

  provider.cleanup = function cleanupHardenedSession(materialization, ctx = {}) {
    if (materialization && typeof materialization === 'object') {
      const existing = cleanupResults.get(materialization);
      if (existing) return existing;
    }

    const localResult = cleanupMaterializedCredentials(materialization);
    if (provider.name !== 'stripe-api-key') {
      if ((localResult.warnings || []).length === 0 && materialization && typeof materialization === 'object') {
        cleanupResults.set(materialization, localResult);
      }
      return localResult;
    }

    let providerResult;
    try {
      providerResult = originalCleanup(materialization, ctx);
    } catch (error) {
      providerResult = {
        cleaned: true,
        warnings: [sanitizeProviderError(error, { env: ctx?.env }).message],
      };
    }
    const combine = result => {
      const warnings = [
        ...(localResult.warnings || []),
        ...(result?.warnings || []).map(warning =>
          sanitizeProviderError({ message: warning }, { env: ctx?.env }).message
        ),
      ];
      return warnings.length > 0 ? { cleaned: true, warnings } : { cleaned: true };
    };
    if (isThenable(providerResult)) {
      const operation = providerResult
        .then(combine)
        .then(result => {
          if ((result.warnings || []).length > 0) cleanupResults.delete(materialization);
          else cleanupResults.set(materialization, result);
          return result;
        })
        .catch(error => {
          cleanupResults.delete(materialization);
          throw error;
        });
      if (materialization && typeof materialization === 'object') cleanupResults.set(materialization, operation);
      return operation;
    }
    const result = combine(providerResult);
    if ((result.warnings || []).length === 0 && materialization && typeof materialization === 'object') {
      cleanupResults.set(materialization, result);
    }
    return result;
  };

  if (originalRefresh) {
    provider.refreshSession = function refreshHardenedSession(session, ctx = {}) {
      let result;
      try {
        result = originalRefresh(session, ctx);
      } catch (error) {
        throw sanitizeProviderError(error, { env: ctx?.env });
      }
      const finalize = value => finalizeResolvedSession(
        provider,
        value,
        ctx.profile || { auth: { delegation_policy: ctx.delegation_policy || {} } },
        ctx
      );
      return isThenable(result)
        ? result.then(finalize).catch(error => { throw sanitizeProviderError(error, { env: ctx?.env }); })
        : finalize(result);
    };
  }

  if (originalHandoff) {
    provider.prepareHandoff = function prepareHardenedHandoff(session, handoff, ctx = {}) {
      let result;
      try {
        result = originalHandoff(session, handoff, ctx);
      } catch (error) {
        throw sanitizeProviderError(error, { profile: handoff?.parent_profile, env: ctx?.env });
      }
      const finalize = value => {
        if (value && typeof value === 'object' && value.prepared !== true) {
          const safe = { ...value };
          if (typeof safe.error === 'string') {
            safe.error = sanitizeProviderError(
              { message: safe.error },
              { profile: handoff?.parent_profile, env: ctx?.env }
            ).message;
          }
          if (typeof safe.reason === 'string') {
            safe.reason = sanitizeProviderError(
              { message: safe.reason },
              { profile: handoff?.parent_profile, env: ctx?.env }
            ).message;
          }
          return safe;
        }
        if (value?.prepared && value.session) {
          const delegationPolicy = handoff?.parent_profile?.auth?.delegation_policy || {};
          const providerPolicy = {
            ...delegationPolicy,
            scope_hierarchy: handoff?.parent_profile?.auth?.provider_config?.scope_hierarchy || {},
          };
          const validation = provider.validateDelegation
            ? provider.validateDelegation(
                value.session.delegation_chain || [],
                providerPolicy,
                ctx
              )
            : enforceDelegationPolicy(value.session, delegationPolicy);
          if (validation?.valid === false) {
            throw Object.assign(new Error('Prepared credential handoff violates delegation policy'), {
              code: 'identity_delegation_invalid',
              delegation_validation: validation,
            });
          }
        }
        return value;
      };
      return isThenable(result)
        ? result.then(finalize).catch(error => { throw sanitizeProviderError(error, { env: ctx?.env }); })
        : finalize(result);
    };
  }

  Object.defineProperty(provider, HARDENED_PROVIDER, { value: true });
  return provider;
}

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

  for (const capability of REQUIRED_CAPABILITY_ARRAYS) {
    if (!Array.isArray(provider.capabilities[capability])) {
      throw new Error(`Identity provider "${provider.name}" capability ${capability} must be an array`);
    }
  }
  if (typeof provider.capabilities.refreshable !== 'boolean') {
    throw new Error(`Identity provider "${provider.name}" capability refreshable must be a boolean`);
  }
  if (typeof provider.capabilities.delegation !== 'boolean') {
    throw new Error(`Identity provider "${provider.name}" capability delegation must be a boolean`);
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

  providers.set(provider.name, wrapProviderSecurity(provider));
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

registerProvider(stripeApiKeyProvider);
