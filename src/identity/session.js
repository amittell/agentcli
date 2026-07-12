/**
 * Shared identity-provider security primitives.
 *
 * Provider implementations intentionally keep credential acquisition details
 * local, while this module owns the invariants that must be identical across
 * providers: structural validation, audit redaction, presentation, cleanup,
 * and delegation-policy enforcement.
 */

import {
  chmodSync,
  closeSync,
  fchmodSync,
  mkdtempSync,
  openSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';

export const TRUST_LEVELS = ['untrusted', 'restricted', 'supervised', 'autonomous'];

const VALID_AUTH_MODES = ['none', 'service', 'delegated', 'on-behalf-of', 'impersonation', 'exchange'];
const VALID_CACHE_MODES = ['none', 'memory', 'state'];
const VALID_REFRESH_MODES = ['never', 'manual', 'auto'];
const VALID_HANDOFF_MODES = ['none', 'downscope', 'transaction-token'];
const VALID_PRESENTATION_KINDS = ['env', 'file', 'stdin', 'none'];
const VALID_FORMATS = ['raw', 'json', 'base64'];
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const SENSITIVE_KEY = /(?:^|_)(?:access_token|refresh_token|subject_token|id_token|secret|password|passphrase|api_key|access_key|private_key|client_assertion|credential)(?:_|$)/i;
const SENSITIVE_PATH_KEY = /^(?:token_file|svid_file|private_key_file|client_secret_file|assertion_file)$/i;
const JWT_LIKE = /\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
const STRIPE_KEY_LIKE = /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9_-]+\b/g;
const AWS_ACCESS_KEY_LIKE = /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g;

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function containsControlCharacter(value) {
  return [...String(value)].some(character => {
    const code = character.codePointAt(0);
    return code <= 0x1f || code === 0x7f;
  });
}

function identityError(code, message, details = {}) {
  return Object.assign(new Error(message), { code, ...details });
}

function pushTypeError(errors, path, value, type) {
  if (value != null && typeof value !== type) {
    errors.push(`${path} must be ${type === 'object' ? 'an object' : `a ${type}`}`);
  }
}

function runtimeCapability(ctx, name) {
  return ctx?.runtimeCapabilities?.[name] === true || ctx?.runtime_capabilities?.[name] === true;
}

/**
 * Validate provider-independent profile semantics against advertised provider
 * and runtime capabilities. No credential source is read by this function.
 */
export function validateCommonIdentityProfile(provider, profile, ctx = {}) {
  const errors = [];
  if (!isObject(profile)) {
    return { valid: false, errors: ['identity profile must be an object'] };
  }

  const capabilities = provider?.capabilities || {};
  const auth = profile.auth == null ? {} : profile.auth;
  const subject = profile.subject == null ? {} : profile.subject;
  const trust = profile.trust == null ? {} : profile.trust;
  const presentation = profile.presentation == null ? {} : profile.presentation;

  if (profile.provider != null && profile.provider !== provider?.name) {
    errors.push(`profile.provider must be "${provider?.name}"`);
  }

  if (!isObject(auth)) errors.push('auth must be an object');
  if (!isObject(subject)) errors.push('subject must be an object');
  if (!isObject(trust)) errors.push('trust must be an object');
  if (!isObject(presentation)) errors.push('presentation must be an object');
  if (errors.length > 0) return { valid: false, errors };

  const authMode = auth.mode ?? null;
  if (authMode != null && !VALID_AUTH_MODES.includes(authMode)) {
    errors.push(`auth.mode must be one of: ${VALID_AUTH_MODES.join(', ')}`);
  } else if (authMode != null && !(capabilities.auth_modes || []).includes(authMode)) {
    errors.push(`auth.mode "${authMode}" is not supported by provider "${provider.name}"`);
  }

  if (auth.required != null && typeof auth.required !== 'boolean') {
    errors.push('auth.required must be a boolean');
  }
  if (auth.scopes != null && !Array.isArray(auth.scopes)) {
    errors.push('auth.scopes must be an array');
  } else if (Array.isArray(auth.scopes) &&
             auth.scopes.some(scope => typeof scope !== 'string' || scope.length === 0)) {
    errors.push('auth.scopes must contain only non-empty strings');
  }
  pushTypeError(errors, 'auth.audience', auth.audience, 'string');
  pushTypeError(errors, 'auth.resource', auth.resource, 'string');
  if (auth.inputs != null && !isObject(auth.inputs)) errors.push('auth.inputs must be an object');
  if (auth.provider_config != null && !isObject(auth.provider_config)) {
    errors.push('auth.provider_config must be an object');
  }

  const cacheMode = auth.cache ?? 'none';
  if (!VALID_CACHE_MODES.includes(cacheMode)) {
    errors.push(`auth.cache must be one of: ${VALID_CACHE_MODES.join(', ')}`);
  } else if (cacheMode !== 'none') {
    const providerSupportsCache = (capabilities.cache_modes || []).includes(cacheMode);
    if (!providerSupportsCache || (!ctx?.structural && !runtimeCapability(ctx, 'credentialCache'))) {
      errors.push(`auth.cache "${cacheMode}" is unsupported by the active provider/runtime`);
    }
  }

  const refreshMode = auth.refresh ?? 'never';
  if (!VALID_REFRESH_MODES.includes(refreshMode)) {
    errors.push(`auth.refresh must be one of: ${VALID_REFRESH_MODES.join(', ')}`);
  } else if (refreshMode !== 'never') {
    if (capabilities.refreshable !== true ||
        (!ctx?.structural && !runtimeCapability(ctx, 'credentialRefresh'))) {
      errors.push(`auth.refresh "${refreshMode}" is unsupported by the active provider/runtime`);
    }
  }

  const trustLevel = trust.level ?? null;
  if (trustLevel != null && !TRUST_LEVELS.includes(trustLevel)) {
    errors.push(`trust.level must be one of: ${TRUST_LEVELS.join(', ')}`);
  } else if (trustLevel != null && !(capabilities.trust_levels || []).includes(trustLevel)) {
    errors.push(`trust.level "${trustLevel}" is not supported by provider "${provider.name}"`);
  }

  const delegationMode = subject.delegation_mode ?? 'none';
  if (!['none', 'on-behalf-of', 'impersonation'].includes(delegationMode)) {
    errors.push('subject.delegation_mode must be one of: none, on-behalf-of, impersonation');
  }
  const delegationPolicy = auth.delegation_policy ?? null;
  const delegationPolicyDeclared = isObject(delegationPolicy) && Object.values(delegationPolicy)
    .some(value => value != null && (!Array.isArray(value) || value.length > 0));
  const delegationRequested = delegationMode !== 'none' || delegationPolicyDeclared ||
    ['delegated', 'on-behalf-of', 'impersonation', 'exchange'].includes(authMode);
  if (delegationRequested && capabilities.delegation !== true) {
    errors.push(`delegation is not supported by provider "${provider.name}"`);
  }
  if (delegationPolicy != null) {
    if (!isObject(delegationPolicy)) {
      errors.push('auth.delegation_policy must be an object');
    } else {
      if (delegationPolicy.max_depth != null &&
          (!Number.isInteger(delegationPolicy.max_depth) || delegationPolicy.max_depth < 1)) {
        errors.push('auth.delegation_policy.max_depth must be an integer greater than zero');
      }
      if (delegationPolicy.allowed_delegators != null &&
          (!Array.isArray(delegationPolicy.allowed_delegators) ||
           delegationPolicy.allowed_delegators.some(value => typeof value !== 'string' || value.length === 0))) {
        errors.push('auth.delegation_policy.allowed_delegators must be an array of non-empty strings');
      }
      if (delegationPolicy.require_grant_per_hop != null &&
          typeof delegationPolicy.require_grant_per_hop !== 'boolean') {
        errors.push('auth.delegation_policy.require_grant_per_hop must be a boolean');
      }
    }
  }

  const handoffMode = presentation.handoff ?? 'none';
  if (!VALID_HANDOFF_MODES.includes(handoffMode)) {
    errors.push(`presentation.handoff must be one of: ${VALID_HANDOFF_MODES.join(', ')}`);
  } else if (!(capabilities.handoff_modes || []).includes(handoffMode)) {
    errors.push(`presentation.handoff "${handoffMode}" is not supported by provider "${provider.name}"`);
  } else if (handoffMode !== 'none' &&
             !ctx?.structural &&
             !runtimeCapability(ctx, 'credentialHandoff')) {
    errors.push(`presentation.handoff "${handoffMode}" is unsupported by the active runtime`);
  }

  if (presentation.default_redaction != null && typeof presentation.default_redaction !== 'boolean') {
    errors.push('presentation.default_redaction must be a boolean');
  }
  if (presentation.cleanup != null && !['always', 'on-success', 'on-failure', 'never'].includes(presentation.cleanup)) {
    errors.push('presentation.cleanup must be one of: always, on-success, on-failure, never');
  }

  if (presentation.bindings != null && !Array.isArray(presentation.bindings)) {
    errors.push('presentation.bindings must be an array');
  } else {
    let stdinBindings = 0;
    for (const [index, binding] of (presentation.bindings || []).entries()) {
      const path = `presentation.bindings[${index}]`;
      if (!isObject(binding)) {
        errors.push(`${path} must be an object`);
        continue;
      }
      if (typeof binding.source !== 'string' || binding.source.length === 0) {
        errors.push(`${path}.source must be a non-empty string`);
      } else if (binding.source === 'provider_assertions' ||
                 binding.source.startsWith('provider_assertions.') ||
                 binding.source === 'delegation_chain' ||
                 binding.source.startsWith('delegation_chain.')) {
        errors.push(`${path}.source cannot reference audit-only session data`);
      }
      if (!isObject(binding.target)) {
        errors.push(`${path}.target must be an object`);
        continue;
      }
      const kind = binding.target.kind;
      if (!VALID_PRESENTATION_KINDS.includes(kind)) {
        errors.push(`${path}.target.kind must be one of: ${VALID_PRESENTATION_KINDS.join(', ')}`);
      } else if (kind !== 'none' && !(capabilities.presentation_kinds || []).includes(kind)) {
        errors.push(`${path}.target.kind "${kind}" is not supported by provider "${provider.name}"`);
      }
      if (kind === 'env' && !ENV_NAME.test(binding.target.name || '')) {
        errors.push(`${path}.target.name must be a valid environment variable name`);
      }
      if (kind === 'file' && binding.target.name != null && !isSafeCredentialFilename(binding.target.name)) {
        errors.push(`${path}.target.name must be a safe filename without path components`);
      }
      if (kind === 'file' && binding.target.expose_as != null && !ENV_NAME.test(binding.target.expose_as)) {
        errors.push(`${path}.target.expose_as must be a valid environment variable name`);
      }
      if (kind === 'stdin') stdinBindings += 1;
      if (binding.required != null && typeof binding.required !== 'boolean') {
        errors.push(`${path}.required must be a boolean`);
      }
      if (binding.redact != null && typeof binding.redact !== 'boolean') {
        errors.push(`${path}.redact must be a boolean`);
      }
      if (binding.format != null && !VALID_FORMATS.includes(binding.format)) {
        errors.push(`${path}.format must be one of: ${VALID_FORMATS.join(', ')}`);
      }
    }
    if (stdinBindings > 1) errors.push('presentation.bindings may contain at most one stdin target');
  }

  return errors.length === 0 ? { valid: true } : { valid: false, errors };
}

export function combineValidationResults(...results) {
  const errors = [];
  for (const result of results) {
    if (result?.valid === false) {
      for (const error of result.errors || [result.error || 'profile validation failed']) {
        errors.push(typeof error === 'string' ? error : (error?.message || 'profile validation failed'));
      }
    }
  }
  return errors.length === 0 ? { valid: true } : { valid: false, errors };
}

export function assertValidIdentityProfile(provider, profile, validation) {
  if (validation?.valid !== false) return;
  throw identityError(
    'identity_profile_invalid',
    `Identity profile for provider "${provider.name}" is invalid: ${(validation.errors || []).join('; ')}`,
    { validation }
  );
}

/** Return true only for local loopback host names and addresses. */
export function isLoopbackHostname(hostname) {
  const normalized = String(hostname || '').replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  if (normalized === 'localhost' || normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') return true;
  const octets = normalized.split('.');
  return octets.length === 4 && octets.every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255) && Number(octets[0]) === 127;
}

/** Validate a user-configurable network endpoint without permitting fail-open HTTP. */
export function validateSecureEndpoint(value, path = 'endpoint', { allowLoopbackHttp = true } = {}) {
  if (typeof value !== 'string' || value.trim() === '') {
    return [`${path} must be a non-empty URL`];
  }
  try {
    const parsed = new URL(value);
    if (parsed.username || parsed.password) return [`${path} must not contain URL credentials`];
    if (parsed.protocol === 'https:') return [];
    if (parsed.protocol === 'http:' && allowLoopbackHttp && isLoopbackHostname(parsed.hostname)) return [];
    return [`${path} must use HTTPS; HTTP is allowed only for loopback endpoints`];
  } catch {
    return [`${path} must be a valid URL`];
  }
}

export function resolveSourcePath(session, path) {
  if (!session || typeof path !== 'string' || path === '') return undefined;
  const segments = path.split('.');
  let current = session;
  for (const segment of segments) {
    if (current === null || current === undefined || typeof current !== 'object') return undefined;
    current = current[segment];
  }
  return current;
}

function sanitizeNonSecretString(value) {
  return String(value)
    .replace(JWT_LIKE, '[REDACTED]')
    .replace(STRIPE_KEY_LIKE, '[REDACTED]')
    .replace(AWS_ACCESS_KEY_LIKE, '[REDACTED]');
}

function redactRecursively(value, { force = false } = {}) {
  if (force) {
    if (Array.isArray(value)) return value.map(item => redactRecursively(item, { force: true }));
    if (isObject(value)) {
      const result = {};
      for (const [childKey, childValue] of Object.entries(value)) {
        result[childKey] = redactRecursively(childValue, { force: true, key: childKey });
      }
      return result;
    }
    return '[REDACTED]';
  }
  if (Array.isArray(value)) return value.map(item => redactRecursively(item));
  if (!isObject(value)) return typeof value === 'string' ? sanitizeNonSecretString(value) : value;

  const result = {};
  for (const [childKey, childValue] of Object.entries(value)) {
    const childForce = childKey === 'credentials' || childKey === 'derived_credentials' ||
      childKey === 'child_credentials' || SENSITIVE_KEY.test(childKey) || SENSITIVE_PATH_KEY.test(childKey);
    if (!childForce && typeof childValue === 'string' && /(?:endpoint|api_base|authority|url|uri)$/i.test(childKey)) {
      try {
        const parsed = new URL(childValue);
        parsed.username = '';
        parsed.password = '';
        parsed.search = '';
        parsed.hash = '';
        result[childKey] = parsed.toString();
        continue;
      } catch {
        // Preserve non-URL identifiers after credential-pattern scrubbing.
      }
    }
    result[childKey] = redactRecursively(childValue, { force: childForce });
  }
  return result;
}

/** Return a deep audit-safe representation of a credential session. */
export function redactSession(session) {
  return redactRecursively(structuredClone(session || {}));
}

export function describeCredentialSession(session) {
  const described = redactSession(session);
  described.credential_summary = buildCredentialSummary(session || {});
  return described;
}

export function buildCredentialSummary(session) {
  const types = [];
  let earliestExpiry = null;
  if (isObject(session?.credentials)) {
    for (const [key, credential] of Object.entries(session.credentials)) {
      types.push(credential?.kind || key);
      if (credential?.expires_at) {
        if (earliestExpiry === null || new Date(credential.expires_at) < new Date(earliestExpiry)) {
          earliestExpiry = credential.expires_at;
        }
      }
    }
  }
  return { credential_types: types, expires_at: earliestExpiry };
}

export function isSessionExpired(session) {
  if (!isObject(session?.credentials)) return false;
  const now = Date.now();
  return Object.values(session.credentials).some(credential =>
    credential?.expires_at && new Date(credential.expires_at).getTime() <= now
  );
}

export function formatMaterializationValue(value, format) {
  const effectiveFormat = format || ((value !== null && typeof value === 'object') ? 'json' : 'raw');
  switch (effectiveFormat) {
    case 'json':
      return JSON.stringify(value);
    case 'base64':
      return Buffer.from(String(value)).toString('base64');
    case 'raw':
      return String(value);
    default:
      throw identityError('presentation_format_unsupported', 'Unsupported credential presentation format');
  }
}

function isSafeCredentialFilename(name) {
  return typeof name === 'string' && name.length > 0 && name.length <= 255 &&
    name !== '.' && name !== '..' && basename(name) === name &&
    !name.includes('/') && !name.includes('\\') && !containsControlCharacter(name);
}

function secureWriteCredentialFile(directory, name, contents) {
  const path = join(directory, name);
  let descriptor = null;
  let failure = null;
  try {
    descriptor = openSync(path, 'wx', 0o600);
    fchmodSync(descriptor, 0o600);
    writeFileSync(descriptor, contents, { encoding: 'utf8' });
  } catch (error) {
    failure = error;
  } finally {
    if (descriptor !== null) {
      try {
        closeSync(descriptor);
      } catch (error) {
        failure ||= error;
      }
    }
  }
  if (failure) {
    try {
      unlinkSync(path);
    } catch {
      // The file may never have been created. The private parent directory is
      // still removed by the caller's failure cleanup.
    }
    throw failure;
  }
  return path;
}

/**
 * Materialize explicit credential bindings using private temp directories and
 * strict target validation. This function never reads outside the session.
 */
export function materializeCredentialBindings(session, presentation = {}, {
  allowedTargetKinds = ['env', 'file', 'stdin'],
  defaultBindings = [],
  tempPrefix = 'agentcli-credential',
} = {}) {
  const bindings = Array.isArray(presentation?.bindings) && presentation.bindings.length > 0
    ? presentation.bindings
    : defaultBindings;
  const envVars = {};
  const tempFiles = [];
  const tempDirectories = [];
  let stdin = null;

  try {
    for (const [index, binding] of bindings.entries()) {
      if (!isObject(binding) || typeof binding.source !== 'string' || !isObject(binding.target)) {
        throw identityError('presentation_binding_invalid', `Credential presentation binding ${index} is invalid`);
      }
      const source = binding.source;
      if (source === 'provider_assertions' || source.startsWith('provider_assertions.') ||
          source === 'delegation_chain' || source.startsWith('delegation_chain.')) {
        throw identityError('presentation_source_forbidden', 'Credential presentation cannot use audit-only session data');
      }

      const rawValue = resolveSourcePath(session, source);
      if (rawValue === undefined || rawValue === null) {
        if (binding.required === true) {
          throw identityError('presentation_binding_missing', `Required credential presentation binding ${index} is unavailable`);
        }
        continue;
      }

      const kind = binding.target.kind;
      if (kind === 'none') continue;
      if (!allowedTargetKinds.includes(kind)) {
        throw identityError('presentation_target_unsupported', `Credential presentation target "${kind || 'unspecified'}" is unsupported`);
      }
      const formatted = formatMaterializationValue(rawValue, binding.format);

      if (kind === 'env') {
        if (!ENV_NAME.test(binding.target.name || '')) {
          throw identityError('presentation_target_invalid', 'Credential environment target name is invalid');
        }
        envVars[binding.target.name] = formatted;
      } else if (kind === 'stdin') {
        if (stdin !== null) {
          throw identityError('presentation_stdin_conflict', 'Only one credential binding may target stdin');
        }
        stdin = formatted;
      } else if (kind === 'file') {
        const requestedName = binding.target.name ?? `credential-${index}`;
        if (!isSafeCredentialFilename(requestedName)) {
          throw identityError('presentation_target_invalid', 'Credential file target name is invalid');
        }
        const prefix = String(binding.target.prefix || tempPrefix).replace(/[^A-Za-z0-9._-]/g, '-').slice(0, 80) || tempPrefix;
        const directory = mkdtempSync(join(tmpdir(), `${prefix}-`));
        chmodSync(directory, 0o700);
        tempDirectories.push(directory);
        const path = secureWriteCredentialFile(directory, requestedName, formatted);
        tempFiles.push({ path, directory, binding_source: source, name: requestedName });
        if (binding.target.expose_as != null) {
          if (!ENV_NAME.test(binding.target.expose_as)) {
            throw identityError('presentation_target_invalid', 'Credential file exposure environment name is invalid');
          }
          envVars[binding.target.expose_as] = path;
        }
      }
    }
  } catch (error) {
    cleanupMaterializedCredentials({ temp_files: tempFiles, temp_directories: tempDirectories });
    throw error;
  }

  return {
    materialized: bindings.length > 0,
    cleanup_required: tempFiles.length > 0,
    env_vars: envVars,
    temp_files: tempFiles,
    temp_directories: tempDirectories,
    stdin,
  };
}

/** Remove provider-created files and directories. Repeated calls are safe. */
export function cleanupMaterializedCredentials(materialization) {
  const warnings = [];
  const directories = new Set(materialization?.temp_directories || []);
  for (const entry of materialization?.temp_files || []) {
    const path = typeof entry === 'string' ? entry : entry?.path;
    if (entry?.directory) directories.add(entry.directory);
    if (!path) continue;
    try {
      unlinkSync(path);
    } catch (error) {
      if (error?.code !== 'ENOENT') warnings.push('Failed to delete a temporary credential file');
    }
  }
  for (const directory of [...directories].reverse()) {
    try {
      rmdirSync(directory);
    } catch (error) {
      if (error?.code !== 'ENOENT') warnings.push('Failed to delete a temporary credential directory');
    }
  }
  return { cleaned: true, warnings };
}

/** Enforce provider-independent delegation constraints on a resolved chain. */
export function enforceDelegationPolicy(session, policy = {}) {
  const chain = Array.isArray(session?.delegation_chain) ? session.delegation_chain : [];
  const maxDepth = Number.isInteger(policy?.max_depth) ? policy.max_depth : null;
  const allowed = Array.isArray(policy?.allowed_delegators) ? new Set(policy.allowed_delegators) : null;
  const requireGrant = policy?.require_grant_per_hop !== false;
  const failures = [];
  const seen = new Set();

  if (maxDepth !== null && chain.length > maxDepth) failures.push('delegation chain exceeds max_depth');
  for (const [index, hop] of chain.entries()) {
    const principal = hop?.principal;
    const transition = `${principal || '(unknown)'}\u0000${hop?.grant || '(none)'}`;
    if (seen.has(transition)) failures.push(`delegation chain contains a repeated hop at index ${index}`);
    seen.add(transition);
    if (allowed && allowed.size > 0 && (!principal || !allowed.has(principal))) {
      failures.push(`delegator at index ${index} is not allowed`);
    }
    if (requireGrant && (typeof hop?.grant !== 'string' || hop.grant.length === 0 || hop.validated === false)) {
      failures.push(`delegation hop ${index} lacks a validated grant`);
    }
  }

  return {
    valid: failures.length === 0,
    depth: chain.length,
    acyclic: !failures.some(failure => failure.includes('repeated hop')),
    all_grants_present: !failures.some(failure => failure.includes('grant')),
    errors: failures,
  };
}

function collectKnownSecrets(value, env, secrets, parentKey = '') {
  if (Array.isArray(value)) {
    for (const item of value) collectKnownSecrets(item, env, secrets, parentKey);
    return;
  }
  if (!isObject(value)) return;
  for (const [key, child] of Object.entries(value)) {
    if (key === 'value_from' && isObject(child)) {
      if (typeof child.env === 'string' && typeof env?.[child.env] === 'string') secrets.add(env[child.env]);
      if (typeof child.env === 'string') secrets.add(child.env);
      if (typeof child.file === 'string') secrets.add(child.file);
      if (typeof child.command === 'string') secrets.add(child.command);
      if (typeof child.literal === 'string') secrets.add(child.literal);
      continue;
    }
    if ((key.endsWith('_env') || key === 'env') && typeof child === 'string') {
      secrets.add(child);
      if (typeof env?.[child] === 'string') secrets.add(env[child]);
    }
    if ((key.endsWith('_file') || key === 'file' || key.endsWith('_command') || key === 'command') &&
        typeof child === 'string') {
      secrets.add(child);
    }
    if (/(?:endpoint|api_base|authority|url|uri)$/i.test(key) && typeof child === 'string') {
      try {
        const parsed = new URL(child);
        if (parsed.username || parsed.password || parsed.search || parsed.hash) secrets.add(child);
      } catch {
        secrets.add(child);
      }
    }
    if ((SENSITIVE_KEY.test(key) && !/(?:strategy|id|file|env|command|endpoint|uri|url)$/i.test(key)) && typeof child === 'string') {
      secrets.add(child);
    }
    collectKnownSecrets(child, env, secrets, key || parentKey);
  }
}

/** Return a runtime error with credential values removed from its message. */
export function sanitizeProviderError(error, { profile, env } = {}) {
  const secrets = new Set();
  collectKnownSecrets(profile, env, secrets);
  let message = String(error?.message || 'Identity provider operation failed');
  for (const secret of secrets) {
    if (secret && secret.length > 2) message = message.split(secret).join('[REDACTED]');
  }
  message = message
    .replace(JWT_LIKE, '[REDACTED]')
    .replace(STRIPE_KEY_LIKE, '[REDACTED]')
    .replace(AWS_ACCESS_KEY_LIKE, '[REDACTED]')
    .replace(/((?:token|secret|password|assertion|api[_-]?key)\s*[=:]\s*)[^\s,;]+/gi, '$1[REDACTED]')
    .replace(/(returned HTTP \d+)(?::[\s\S]*)/i, '$1')
    .replace(/(failed \(HTTP \d+\))(?::[\s\S]*)/i, '$1');
  return identityError(error?.code || 'identity_provider_error', message, {
    transient: error?.transient === true,
  });
}

export function validateTrustLevel(level) {
  return TRUST_LEVELS.includes(level)
    ? { valid: true }
    : { valid: false, error: `Invalid trust level "${level}". Must be one of: ${TRUST_LEVELS.join(', ')}` };
}

export function compareTrustLevels(a, b) {
  const indexA = TRUST_LEVELS.indexOf(a);
  const indexB = TRUST_LEVELS.indexOf(b);
  if (indexA === -1) throw new Error(`Unknown trust level: "${a}"`);
  if (indexB === -1) throw new Error(`Unknown trust level: "${b}"`);
  return Math.sign(indexA - indexB);
}
