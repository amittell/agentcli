/**
 * Authorization provider registry and resolution.
 *
 * An authorization provider implements:
 *   name                 - string identifier (e.g. 'none', 'opa', 'cedar', 'topaz')
 *   capabilities         - { decision_kinds, escalation, batch, dry_run }
 *   validateProfile      - (profile, ctx) => validation result
 *   authorize            - (request, profile, ctx) => normalized authorization decision
 *   describeDecision     - (decision, ctx) => audit-safe decision description
 */

const providers = new Map();

const REQUIRED_METHODS = [
  'validateProfile',
  'authorize',
  'describeDecision',
];

/**
 * Register an authorization provider.
 *
 * Validates that the provider has a string name, a capabilities object
 * with at least a decision_kinds array, and all required methods.
 *
 * @param {object} provider - The authorization provider to register.
 */
export function registerAuthorizationProvider(provider) {
  if (!provider || typeof provider.name !== 'string' || provider.name === '') {
    throw new Error('Authorization provider must have a non-empty string name');
  }

  if (!provider.capabilities || typeof provider.capabilities !== 'object') {
    throw new Error(`Authorization provider "${provider.name}" must have a capabilities object`);
  }

  if (!Array.isArray(provider.capabilities.decision_kinds)) {
    throw new Error(
      `Authorization provider "${provider.name}" capabilities must include a decision_kinds array`
    );
  }

  for (const method of REQUIRED_METHODS) {
    if (typeof provider[method] !== 'function') {
      throw new Error(`Authorization provider "${provider.name}" must implement ${method}()`);
    }
  }

  providers.set(provider.name, provider);
}

/**
 * Get a registered authorization provider by name.
 *
 * @param {string} name - Provider name.
 * @returns {object|null} The provider, or null if not found.
 */
export function getAuthorizationProvider(name) {
  return providers.get(name) ?? null;
}

/**
 * List the names of all registered authorization providers.
 *
 * @returns {string[]}
 */
export function listAuthorizationProviders() {
  return [...providers.keys()];
}

/**
 * Resolve an authorization provider by explicit name. Throws if not found.
 *
 * @param {string} providerName - The provider name to resolve.
 * @returns {object} The resolved provider.
 */
export function resolveAuthorizationProvider(providerName) {
  const provider = providers.get(providerName);
  if (!provider) {
    const available = listAuthorizationProviders().join(', ');
    throw Object.assign(
      new Error(
        `Unknown authorization provider: "${providerName}". Available: ${available || '(none)'}`
      ),
      { code: 'unknown_authorization_provider' }
    );
  }
  return provider;
}

/**
 * Build a normalized authorization request from the execution context.
 *
 * Only top-level sections that appear in includeFields are added to the
 * result. The source section is always included regardless of includeFields.
 *
 * @param {object} params
 * @param {object} params.source   - { workflow_id, task_id }
 * @param {object} params.identity - { principal, trust_level }
 * @param {object} params.contract - { required_trust_level, allowed_paths }
 * @param {object} params.command  - { program, args }
 * @param {object} params.actor    - { actor, org_id, on_behalf_of_user_id, delegation_grant_id, run_id, agent_id }
 * @param {object} params.stepUp   - { verified, method, issuer, verified_at, step_up_policy, verification_ref, verification_level, claims, reason }
 * @param {object} params.resource - Resource object or null
 * @param {object} params.trust    - { declared_level, effective_level }
 * @param {string[]} params.includeFields - The request.include array from the authorization profile
 * @returns {object} The normalized authorization request.
 */
export function normalizeAuthorizationRequest({
  source,
  identity,
  contract,
  command,
  actor,
  stepUp,
  resource,
  trust,
  includeFields,
}) {
  const fields = Array.isArray(includeFields) ? includeFields : [];

  const request = {
    source: source
      ? { workflow_id: source.workflow_id, task_id: source.task_id }
      : { workflow_id: null, task_id: null },
  };

  if (fields.includes('identity')) {
    request.identity = identity
      ? { principal: identity.principal, trust_level: identity.trust_level }
      : { principal: null, trust_level: null };
  }

  if (fields.includes('contract')) {
    request.contract = contract
      ? { required_trust_level: contract.required_trust_level, allowed_paths: contract.allowed_paths }
      : { required_trust_level: null, allowed_paths: null };
  }

  if (fields.includes('command')) {
    request.command = command
      ? { program: command.program, args: command.args }
      : { program: null, args: null };
  }

  if (fields.includes('actor')) {
    request.actor = actor
      ? {
          actor: actor.actor
            ? {
                principal: actor.actor.principal ?? null,
                kind: actor.actor.kind ?? null,
                display_name: actor.actor.display_name ?? null,
              }
            : {
                principal: null,
                kind: null,
                display_name: null,
              },
          org_id: actor.org_id ?? null,
          on_behalf_of_user_id: actor.on_behalf_of_user_id ?? null,
          delegation_grant_id: actor.delegation_grant_id ?? null,
          run_id: actor.run_id ?? null,
          agent_id: actor.agent_id ?? null,
        }
      : {
          actor: {
            principal: null,
            kind: null,
            display_name: null,
          },
          org_id: null,
          on_behalf_of_user_id: null,
          delegation_grant_id: null,
          run_id: null,
          agent_id: null,
        };
  }

  if (fields.includes('step_up')) {
    request.step_up = stepUp
      ? {
          verified: stepUp.verified ?? null,
          method: stepUp.method ?? null,
          issuer: stepUp.issuer ?? null,
          verified_at: stepUp.verified_at ?? null,
          step_up_policy: stepUp.step_up_policy ?? null,
          verification_ref: stepUp.verification_ref ?? null,
          verification_level: stepUp.verification_level ?? null,
          claims: stepUp.claims ?? null,
          reason: stepUp.reason ?? null,
        }
      : {
          verified: null,
          method: null,
          issuer: null,
          verified_at: null,
          step_up_policy: null,
          verification_ref: null,
          verification_level: null,
          claims: null,
          reason: null,
        };
  }

  if (fields.includes('resource')) {
    request.resource = resource ?? null;
  }

  if (fields.includes('trust')) {
    request.trust = trust
      ? { declared_level: trust.declared_level, effective_level: trust.effective_level }
      : { declared_level: null, effective_level: null };
  }

  return request;
}

/**
 * Map a provider-specific response value to the normalized decision set.
 *
 * Checks the provider's response value against the configured allow, deny, and
 * escalate value lists. Unmapped values default to 'deny' per spec.
 *
 * @param {string} providerResponse - The raw decision value from the provider.
 * @param {object} decisionConfig   - The decision block from the authorization profile.
 * @param {string[]} decisionConfig.allow_values    - Values that map to 'permit'.
 * @param {string[]} decisionConfig.deny_values     - Values that map to 'deny'.
 * @param {string[]} decisionConfig.escalate_values - Values that map to 'require-escalation'.
 * @returns {{ decision: string, original_value: string, mapped: boolean }}
 */
export function normalizeDecision(providerResponse, decisionConfig) {
  const config = decisionConfig || {};
  const allowValues = Array.isArray(config.allow_values) ? config.allow_values : [];
  const denyValues = Array.isArray(config.deny_values) ? config.deny_values : [];
  const escalateValues = Array.isArray(config.escalate_values) ? config.escalate_values : [];

  if (allowValues.includes(providerResponse)) {
    return { decision: 'permit', original_value: providerResponse, mapped: true };
  }

  if (denyValues.includes(providerResponse)) {
    return { decision: 'deny', original_value: providerResponse, mapped: true };
  }

  if (escalateValues.includes(providerResponse)) {
    return { decision: 'require-escalation', original_value: providerResponse, mapped: true };
  }

  return { decision: 'deny', original_value: providerResponse, mapped: false };
}
