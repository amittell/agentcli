/**
 * Stripe API key identity provider.
 *
 * Resolves Stripe API keys from environment variables, files, or shell
 * commands (e.g. Vault) based on a scope-aware permission set model.
 * Supports two key strategies:
 *   - precreated: Resolve existing keys (restricted or secret) by scope name.
 *   - dynamic: Mint restricted keys via Stripe API (not yet implemented).
 *
 * This file is self-contained with no imports from agentcli internals.
 * It can be copied to the scheduler's plugin directory and loaded as-is.
 * When running inside agentcli, it conditionally registers itself with
 * the provider registry.
 */

import { execSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

// ---------------------------------------------------------------------------
// Command-source cache: Map<cacheKey, { value, expiresAt }>
// ---------------------------------------------------------------------------
const commandCache = new Map();

/**
 * Purge expired entries from the command cache. Called before reads
 * to keep the cache bounded without a background timer.
 */
function purgeExpiredCache() {
  const now = Date.now();
  for (const [key, entry] of commandCache) {
    if (entry.expiresAt <= now) {
      commandCache.delete(key);
    }
  }
}

/**
 * Stable fingerprint of an explicit env object for cache keys (order-independent).
 * @param {object} env
 * @returns {string}
 */
function envFingerprint(env) {
  const keys = Object.keys(env).sort();
  const h = createHash('sha256');
  for (const k of keys) {
    const v = env[k];
    h.update(k);
    h.update('\0');
    h.update(v == null ? '' : String(v));
    h.update('\0');
  }
  return h.digest('hex');
}

/**
 * Build a cache key for command-based key resolution.
 * Includes cwd and (when env is not process.env) a fingerprint of env entries so the
 * same shell snippet cannot return a stale key across different contexts.
 * @param {string} command
 * @param {object} [opts]
 * @returns {string}
 */
function commandSourceCacheKey(command, opts) {
  const cwdPart = opts && opts.cwd != null ? String(opts.cwd) : '';
  let envPart = '@inherit';
  if (opts && opts.env != null && typeof opts.env === 'object' && opts.env !== process.env) {
    envPart = envFingerprint(opts.env);
  }
  return `${command}\0${cwdPart}\0${envPart}`;
}

/**
 * Resolve a key value from a command source, with TTL-based caching.
 *
 * The command string comes from the operator's manifest provider_config
 * (e.g. "vault kv get -field=api_key secret/apps/stripe/payments") and
 * requires shell interpretation for pipes, redirects, and subshells.
 * This is not user-supplied input -- it is operator-controlled config.
 *
 * @param {string} command  - Shell command to execute.
 * @param {number} ttlMs    - Cache TTL in milliseconds.
 * @param {object} [opts]   - Options: { cwd, env }. Cached per command+cwd; if env is not
 *                            `process.env`, entries are fingerprinted so values cannot bleed across contexts.
 * @returns {{ ok: boolean, value?: string, error?: string, transient?: boolean }}
 */
function resolveCommandSource(command, ttlMs, opts) {
  purgeExpiredCache();

  const cacheKey = commandSourceCacheKey(command, opts);
  const cached = commandCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) {
    return { ok: true, value: cached.value };
  }

  try {
    const result = execSync(command, {
      timeout: 30000,
      maxBuffer: 1024 * 1024,
      shell: true,
      cwd: opts && opts.cwd,
      env: opts && opts.env,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const value = (result || '').trim();
    if (!value) {
      return {
        ok: false,
        transient: false,
        error: `Command returned empty output: ${command}`,
      };
    }
    commandCache.set(cacheKey, { value, expiresAt: Date.now() + ttlMs });
    return { ok: true, value };
  } catch (err) {
    const isTimeout = err.killed || (err.signal === 'SIGTERM');
    return {
      ok: false,
      transient: isTimeout,
      error: `Command failed (exit ${err.status || 'unknown'}): ${command}`,
    };
  }
}

/**
 * Resolve a key value from a file source.
 *
 * @param {string} filePath - Absolute or relative file path.
 * @returns {{ ok: boolean, value?: string, error?: string, transient?: boolean }}
 */
function resolveFileSource(filePath) {
  try {
    const content = readFileSync(filePath, 'utf8').trim();
    if (!content) {
      return {
        ok: false,
        transient: false,
        error: `Key file is empty: ${filePath}`,
      };
    }
    return { ok: true, value: content };
  } catch (err) {
    const isTransient = err.code === 'EACCES' || err.code === 'EMFILE' || err.code === 'ENFILE';
    return {
      ok: false,
      transient: isTransient,
      error: `Failed to read key file "${filePath}": ${err.message}`,
    };
  }
}

/**
 * Resolve a key value from an environment variable.
 *
 * @param {string} envVar - Environment variable name.
 * @param {object} env    - Environment object (defaults to process.env).
 * @returns {{ ok: boolean, value?: string, error?: string, transient?: boolean }}
 */
function resolveEnvSource(envVar, env) {
  const value = env[envVar];
  if (!value || typeof value !== 'string' || value.trim() === '') {
    return {
      ok: false,
      transient: false,
      error: `Environment variable "${envVar}" is not set or is empty`,
    };
  }
  return { ok: true, value: value.trim() };
}

// ---------------------------------------------------------------------------
// Key format validation
// ---------------------------------------------------------------------------

/**
 * Valid Stripe key prefixes. Secret keys start with sk_, restricted keys
 * with rk_. Each is followed by live_ or test_ indicating the mode.
 */
const VALID_KEY_PREFIXES = ['sk_live_', 'sk_test_', 'rk_live_', 'rk_test_'];

/**
 * Validate that a string looks like a Stripe API key.
 *
 * @param {string} key         - The key value to validate.
 * @param {string} accountMode - Expected account mode: "live" or "test".
 * @returns {{ valid: boolean, error?: string }}
 */
function validateKeyFormat(key, accountMode) {
  if (typeof key !== 'string' || key.length < 12) {
    return { valid: false, error: 'Key value is too short to be a valid Stripe API key' };
  }

  const hasValidPrefix = VALID_KEY_PREFIXES.some(prefix => key.startsWith(prefix));
  if (!hasValidPrefix) {
    return {
      valid: false,
      error: `Key does not match expected Stripe format (expected prefix: sk_live_, sk_test_, rk_live_, or rk_test_)`,
    };
  }

  const keyMode = key.startsWith('sk_live_') || key.startsWith('rk_live_') ? 'live' : 'test';
  if (keyMode !== accountMode) {
    return {
      valid: false,
      error: `Key mode mismatch: key is "${keyMode}" but profile declares account_mode "${accountMode}"`,
    };
  }

  return { valid: true };
}

// ---------------------------------------------------------------------------
// Scope hierarchy utilities
// ---------------------------------------------------------------------------

/**
 * Check whether a scope hierarchy contains cycles using iterative DFS.
 *
 * @param {object} hierarchy - Map of parent scope to array of child scopes.
 * @returns {{ acyclic: boolean, cycle_path?: string[] }}
 */
function checkScopeHierarchyCycles(hierarchy) {
  if (!hierarchy || typeof hierarchy !== 'object') {
    return { acyclic: true };
  }

  const allNodes = Object.keys(hierarchy);

  for (const startNode of allNodes) {
    // DFS with explicit path tracking for each starting node
    const visited = new Set();
    const inStack = new Set();
    const stack = [{ node: startNode, path: [startNode], childIndex: 0 }];
    inStack.add(startNode);

    while (stack.length > 0) {
      const frame = stack[stack.length - 1];
      const children = hierarchy[frame.node] || [];

      if (frame.childIndex >= children.length) {
        // All children processed, backtrack
        inStack.delete(frame.node);
        visited.add(frame.node);
        stack.pop();
        continue;
      }

      const child = children[frame.childIndex];
      frame.childIndex++;

      if (inStack.has(child)) {
        // Found a cycle -- build the cycle path
        const cyclePath = [...frame.path, child];
        return { acyclic: false, cycle_path: cyclePath };
      }

      if (!visited.has(child)) {
        inStack.add(child);
        stack.push({ node: child, path: [...frame.path, child], childIndex: 0 });
      }
    }
  }

  return { acyclic: true };
}

/**
 * Check whether target_scope is reachable from parent_scope via the
 * scope hierarchy (BFS reachability).
 *
 * @param {object} hierarchy    - Scope hierarchy map.
 * @param {string} parentScope  - The scope the parent holds.
 * @param {string} targetScope  - The scope the child requests.
 * @returns {boolean} True if target is reachable from parent (i.e. is a downscope).
 */
function isScopeReachable(hierarchy, parentScope, targetScope) {
  if (parentScope === targetScope) return true;
  if (!hierarchy || typeof hierarchy !== 'object') return false;

  const visited = new Set();
  const queue = [parentScope];
  visited.add(parentScope);

  while (queue.length > 0) {
    const current = queue.shift();
    const children = hierarchy[current];
    if (!Array.isArray(children)) continue;

    for (const child of children) {
      if (child === targetScope) return true;
      if (!visited.has(child)) {
        visited.add(child);
        queue.push(child);
      }
    }
  }

  return false;
}

/**
 * Mask a key value for safe display: show prefix and last 4 characters.
 *
 * @param {string} key - The Stripe API key.
 * @returns {string} Masked representation (e.g. "rk_live_...ab1c").
 */
function maskKeyValue(key) {
  if (typeof key !== 'string' || key.length < 12) return '[INVALID_KEY]';
  const prefixMatch = key.match(/^(sk_live_|sk_test_|rk_live_|rk_test_)/);
  if (!prefixMatch) return '[UNKNOWN_FORMAT]';
  const suffix = key.slice(-4);
  return `${prefixMatch[1]}...${suffix}`;
}

// ---------------------------------------------------------------------------
// Session path resolution (self-contained, mirrors session.js resolveSourcePath)
// ---------------------------------------------------------------------------

/**
 * Navigate a session object using a dot-delimited path.
 *
 * @param {object} session - The session object.
 * @param {string} path    - Dot-delimited path (e.g. 'credentials.api_key.value').
 * @returns {*} The resolved value, or undefined.
 */
function resolveSessionPath(session, path) {
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

// ---------------------------------------------------------------------------
// Provider implementation
// ---------------------------------------------------------------------------

const stripeApiKeyProvider = {
  name: 'stripe-api-key',
  type: 'identity',

  capabilities: {
    auth_modes: ['service'],
    credential_types: ['api_key'],
    presentation_kinds: ['env'],
    handoff_modes: ['none', 'downscope'],
    refreshable: false,
    delegation: true,
    trust_levels: ['untrusted', 'restricted', 'supervised', 'autonomous'],
    approval_mechanisms: [],
  },

  /**
   * Validate an identity profile for the stripe-api-key provider.
   *
   * Checks key_strategy, account_mode, permission_sets (for precreated),
   * scope_hierarchy acyclicity (DFS), and master_key_source (for dynamic).
   *
   * @param {object} profile - The identity profile.
   * @param {object} _ctx    - Resolution context (unused).
   * @returns {{ valid: boolean, errors?: string[] }}
   */
  validateProfile(profile, _ctx) {
    const errors = [];
    const config = (profile.auth && profile.auth.provider_config) || {};

    // key_strategy
    const validStrategies = ['precreated', 'dynamic'];
    if (!config.key_strategy || !validStrategies.includes(config.key_strategy)) {
      errors.push(
        `provider_config.key_strategy is required and must be one of: ${validStrategies.join(', ')}`
      );
    }

    // account_mode
    const validModes = ['live', 'test'];
    if (!config.account_mode || !validModes.includes(config.account_mode)) {
      errors.push(
        `provider_config.account_mode is required and must be one of: ${validModes.join(', ')}`
      );
    }

    if (config.key_strategy === 'precreated') {
      // permission_sets: must have at least one entry
      if (!config.permission_sets || typeof config.permission_sets !== 'object') {
        errors.push('provider_config.permission_sets is required for precreated strategy and must be an object');
      } else {
        const scopeNames = Object.keys(config.permission_sets);
        if (scopeNames.length === 0) {
          errors.push('provider_config.permission_sets must contain at least one scope entry');
        }

        for (const scopeName of scopeNames) {
          const entry = config.permission_sets[scopeName];
          if (!entry || typeof entry !== 'object') {
            errors.push(`permission_sets["${scopeName}"] must be an object`);
            continue;
          }
          const hasSource = (
            (typeof entry.key_env === 'string' && entry.key_env.length > 0) ||
            (typeof entry.key_file === 'string' && entry.key_file.length > 0) ||
            (typeof entry.key_command === 'string' && entry.key_command.length > 0)
          );
          if (!hasSource) {
            errors.push(
              `permission_sets["${scopeName}"] must declare at least one key source: key_env, key_file, or key_command`
            );
          }
        }
      }

      // scope_hierarchy: optional but if present must be acyclic
      if (config.scope_hierarchy !== undefined && config.scope_hierarchy !== null) {
        if (typeof config.scope_hierarchy !== 'object') {
          errors.push('provider_config.scope_hierarchy must be an object mapping scope names to arrays of child scopes');
        } else {
          // Validate structure
          for (const [parent, children] of Object.entries(config.scope_hierarchy)) {
            if (!Array.isArray(children)) {
              errors.push(`scope_hierarchy["${parent}"] must be an array of child scope names`);
              continue;
            }
            for (const child of children) {
              if (typeof child !== 'string' || child.length === 0) {
                errors.push(`scope_hierarchy["${parent}"] contains an invalid child scope (must be non-empty string)`);
              }
            }
          }

          // DFS cycle check
          const cycleResult = checkScopeHierarchyCycles(config.scope_hierarchy);
          if (!cycleResult.acyclic) {
            const path = cycleResult.cycle_path ? cycleResult.cycle_path.join(' -> ') : '(unknown)';
            errors.push(`scope_hierarchy contains a cycle: ${path}`);
          }
        }
      }
    }

    if (config.key_strategy === 'dynamic') {
      // master_key_source is required for dynamic strategy
      if (!config.master_key_source || typeof config.master_key_source !== 'object') {
        errors.push('provider_config.master_key_source is required for dynamic strategy');
      } else {
        const src = config.master_key_source;
        const hasSource = (
          (typeof src.env === 'string' && src.env.length > 0) ||
          (typeof src.file === 'string' && src.file.length > 0) ||
          (typeof src.command === 'string' && src.command.length > 0)
        );
        if (!hasSource) {
          errors.push('master_key_source must declare at least one source: env, file, or command');
        }
      }
    }

    // cache_ttl_s: optional, must be a positive number if present
    if (config.cache_ttl_s !== undefined && config.cache_ttl_s !== null) {
      if (typeof config.cache_ttl_s !== 'number' || config.cache_ttl_s <= 0) {
        errors.push('provider_config.cache_ttl_s must be a positive number');
      }
    }

    if (errors.length > 0) {
      return { valid: false, errors };
    }

    return { valid: true };
  },

  /**
   * Resolve a credential session by reading a Stripe API key from the
   * configured source for the requested scope.
   *
   * For precreated strategy: resolves the key from the permission set entry
   * matching request.scope (env var, file, or shell command).
   *
   * For dynamic strategy: not yet implemented; returns a permanent error.
   *
   * @param {object} request - Session request: { profile, instanceId, scope }.
   * @param {object} [ctx]   - Resolution context: { env, cwd }.
   * @returns {{ ok: boolean, session?: object, transient?: boolean, error?: string }}
   */
  resolveSession(request, ctx) {
    const env = (ctx && ctx.env) || process.env;
    const cwd = (ctx && ctx.cwd) || process.cwd();
    const profile = request.profile || {};
    const config = (profile.auth && profile.auth.provider_config) || {};
    const scope = request.scope || null;
    const trustLevel = (profile.trust && profile.trust.level) || 'supervised';

    if (config.key_strategy === 'dynamic') {
      return {
        ok: false,
        transient: false,
        error: 'Dynamic key strategy not yet implemented',
      };
    }

    // Precreated strategy
    if (!config.permission_sets || typeof config.permission_sets !== 'object') {
      return {
        ok: false,
        transient: false,
        error: 'No permission_sets configured in provider_config',
      };
    }

    // Determine which scope to resolve
    const effectiveScope = scope || Object.keys(config.permission_sets)[0];
    const permSet = config.permission_sets[effectiveScope];
    if (!permSet) {
      const available = Object.keys(config.permission_sets).join(', ');
      return {
        ok: false,
        transient: false,
        error: `Unknown scope "${effectiveScope}". Available scopes: ${available}`,
      };
    }

    // Resolve the key value from the appropriate source
    let keyResult;
    const cacheTtlMs = ((config.cache_ttl_s != null ? config.cache_ttl_s : 300)) * 1000;

    if (typeof permSet.key_env === 'string' && permSet.key_env.length > 0) {
      keyResult = resolveEnvSource(permSet.key_env, env);
    } else if (typeof permSet.key_file === 'string' && permSet.key_file.length > 0) {
      keyResult = resolveFileSource(permSet.key_file);
    } else if (typeof permSet.key_command === 'string' && permSet.key_command.length > 0) {
      keyResult = resolveCommandSource(permSet.key_command, cacheTtlMs, { cwd, env });
    } else {
      return {
        ok: false,
        transient: false,
        error: `Permission set "${effectiveScope}" has no valid key source (key_env, key_file, or key_command)`,
      };
    }

    if (!keyResult.ok) {
      return {
        ok: false,
        transient: keyResult.transient,
        error: keyResult.error,
      };
    }

    // Validate key format against account_mode
    const accountMode = config.account_mode || 'test';
    const formatCheck = validateKeyFormat(keyResult.value, accountMode);
    if (!formatCheck.valid) {
      return {
        ok: false,
        transient: false,
        error: formatCheck.error,
      };
    }

    const session = {
      provider: 'stripe-api-key',
      subject: {
        kind: 'service',
        principal: `stripe:${accountMode}`,
      },
      instance: request.instanceId ? { id: request.instanceId, source: 'operator' } : null,
      trust: {
        declared_level: trustLevel,
        effective_level: trustLevel,
      },
      credentials: {
        api_key: {
          kind: 'bearer',
          value: keyResult.value,
          scope: effectiveScope,
        },
      },
      provider_assertions: {
        key_strategy: config.key_strategy,
        account_mode: accountMode,
        scope: effectiveScope,
      },
      delegation_chain: [
        {
          kind: 'service',
          principal: `stripe:${accountMode}`,
          grant: `scope:${effectiveScope}`,
          validated: true,
        },
      ],
      delegation_validation: {
        valid: true,
        depth: 1,
        acyclic: true,
        escalation_detected: false,
      },
      refresh: {
        supported: false,
        expires_at: null,
      },
      handoff: {
        mode: config.scope_hierarchy ? 'downscope' : 'none',
        prepared: false,
      },
    };

    return { ok: true, session };
  },

  /**
   * Materialize session credentials into environment variables for
   * subprocess injection.
   *
   * Default binding: STRIPE_API_KEY = session.credentials.api_key.value.
   * Additional bindings can be specified in the presentation object.
   *
   * @param {object} session      - The credential session.
   * @param {object} presentation - Presentation descriptor with optional bindings.
   * @param {object} _ctx         - Resolution context.
   * @returns {{ materialized: boolean, env_vars: object, cleanup_required: boolean }}
   */
  materialize(session, presentation, _ctx) {
    const envVars = {};
    const config = session.provider_assertions || {};

    // Default binding
    if (session.credentials && session.credentials.api_key && session.credentials.api_key.value) {
      envVars['STRIPE_API_KEY'] = session.credentials.api_key.value;
    }

    // Additional bindings from presentation
    const bindings = (presentation && presentation.bindings) || [];
    for (const binding of bindings) {
      const target = binding.target || {};
      if (target.kind !== 'env' || !target.name) continue;

      const value = resolveSessionPath(session, binding.source);
      if (value !== undefined && value !== null) {
        envVars[target.name] = String(value);
      }
    }

    return {
      materialized: true,
      env_vars: envVars,
      cleanup_required: config.key_strategy === 'dynamic',
    };
  },

  /**
   * Clean up materialized credentials.
   *
   * For precreated strategy: no-op (keys are long-lived).
   * For dynamic strategy: placeholder for future key revocation.
   *
   * @param {object} _materialization - The materialization result.
   * @param {object} _ctx             - Resolution context.
   * @returns {{ cleaned: boolean, warnings?: string[] }}
   */
  cleanup(_materialization, _ctx) {
    // Precreated keys need no cleanup -- they are long-lived and not minted per-job
    return { cleaned: true };
  },

  /**
   * Prepare a credential handoff for a child task that requests a
   * narrower scope than its parent.
   *
   * Reads the parent's identity profile from handoff.parent_profile to
   * look up permission_sets and scope_hierarchy, then validates the
   * target_scope is reachable from the parent's scope and resolves
   * the narrower key.
   *
   * @param {object} session  - The parent's credential session.
   * @param {object} handoff  - Handoff descriptor: { target_scope, parent_profile }.
   * @param {object} [ctx]    - Resolution context: { env, cwd }.
   * @returns {{ prepared: boolean, session?: object, error?: string }}
   */
  prepareHandoff(session, handoff, ctx) {
    const env = (ctx && ctx.env) || process.env;
    const cwd = (ctx && ctx.cwd) || process.cwd();
    const targetScope = handoff && handoff.target_scope;
    const parentProfile = handoff && handoff.parent_profile;

    if (!targetScope) {
      return { prepared: false, error: 'handoff.target_scope is required' };
    }

    if (!parentProfile) {
      return { prepared: false, error: 'handoff.parent_profile is required' };
    }

    const config = (parentProfile.auth && parentProfile.auth.provider_config) || {};

    if (config.key_strategy === 'dynamic') {
      return { prepared: false, error: 'Dynamic key strategy not yet implemented for handoff' };
    }

    // Determine parent scope from the current session
    const parentScope = (session.credentials && session.credentials.api_key &&
      session.credentials.api_key.scope) || null;

    if (!parentScope) {
      return { prepared: false, error: 'Parent session has no scope in credentials' };
    }

    // Validate that target_scope is reachable from parent scope via hierarchy
    const hierarchy = config.scope_hierarchy || {};
    if (!isScopeReachable(hierarchy, parentScope, targetScope)) {
      return {
        prepared: false,
        error: `Scope "${targetScope}" is not reachable from parent scope "${parentScope}" via scope_hierarchy`,
      };
    }

    // Look up the target scope's permission set
    const permSets = config.permission_sets || {};
    const targetPermSet = permSets[targetScope];
    if (!targetPermSet) {
      const available = Object.keys(permSets).join(', ');
      return {
        prepared: false,
        error: `No permission_set defined for scope "${targetScope}". Available: ${available}`,
      };
    }

    // Resolve the narrower key
    const cacheTtlMs = ((config.cache_ttl_s != null ? config.cache_ttl_s : 300)) * 1000;
    let keyResult;

    if (typeof targetPermSet.key_env === 'string' && targetPermSet.key_env.length > 0) {
      keyResult = resolveEnvSource(targetPermSet.key_env, env);
    } else if (typeof targetPermSet.key_file === 'string' && targetPermSet.key_file.length > 0) {
      keyResult = resolveFileSource(targetPermSet.key_file);
    } else if (typeof targetPermSet.key_command === 'string' && targetPermSet.key_command.length > 0) {
      keyResult = resolveCommandSource(targetPermSet.key_command, cacheTtlMs, { cwd, env });
    } else {
      return {
        prepared: false,
        error: `Permission set "${targetScope}" has no valid key source`,
      };
    }

    if (!keyResult.ok) {
      return { prepared: false, error: keyResult.error };
    }

    // Validate key format
    const accountMode = config.account_mode || 'test';
    const formatCheck = validateKeyFormat(keyResult.value, accountMode);
    if (!formatCheck.valid) {
      return { prepared: false, error: formatCheck.error };
    }

    // Build the narrower session
    const trustLevel = session.trust ? session.trust.effective_level : 'supervised';
    const childSession = {
      provider: 'stripe-api-key',
      subject: {
        kind: 'service',
        principal: `stripe:${accountMode}`,
      },
      instance: session.instance,
      trust: {
        declared_level: trustLevel,
        effective_level: trustLevel,
      },
      credentials: {
        api_key: {
          kind: 'bearer',
          value: keyResult.value,
          scope: targetScope,
        },
      },
      provider_assertions: {
        key_strategy: config.key_strategy,
        account_mode: accountMode,
        scope: targetScope,
        parent_scope: parentScope,
      },
      delegation_chain: [
        ...(session.delegation_chain || []),
        {
          kind: 'service',
          principal: `stripe:${accountMode}`,
          grant: `downscope:${parentScope}->${targetScope}`,
          validated: true,
        },
      ],
      delegation_validation: {
        valid: true,
        depth: (session.delegation_chain || []).length + 1,
        acyclic: true,
        escalation_detected: false,
      },
      refresh: {
        supported: false,
        expires_at: null,
      },
      handoff: {
        mode: 'downscope',
        prepared: true,
      },
    };

    return { prepared: true, session: childSession };
  },

  /**
   * Validate a delegation chain for scope escalation and depth.
   *
   * Checks:
   *   - Chain depth does not exceed policy.max_depth (default 5).
   *   - No scope escalation (each hop's scope must be reachable from
   *     its predecessor via the scope_hierarchy).
   *   - Chain is acyclic (no repeated scope transitions).
   *
   * @param {Array<object>} chain  - Delegation chain entries.
   * @param {object}        policy - Delegation policy: { max_depth, scope_hierarchy }.
   * @param {object}        [_ctx] - Resolution context.
   * @returns {{ valid: boolean, depth: number, acyclic: boolean, escalation_detected: boolean, hop_status: Array<object> }}
   */
  validateDelegation(chain, policy, _ctx) {
    const maxDepth = (policy && typeof policy.max_depth === 'number') ? policy.max_depth : 5;
    const hierarchy = (policy && policy.scope_hierarchy) || {};
    const entries = Array.isArray(chain) ? chain : [];
    const depth = entries.length;

    let escalationDetected = false;
    const seenTransitions = new Set();
    let acyclic = true;

    const hopStatus = entries.map((entry, index) => {
      const grant = entry.grant || '';
      const status = {
        index,
        kind: entry.kind || null,
        principal: entry.principal || null,
        grant: grant || null,
        valid: true,
      };

      // Check for escalation via downscope grants
      if (grant.startsWith('downscope:')) {
        const transitionPart = grant.slice('downscope:'.length);
        const arrowIndex = transitionPart.indexOf('->');
        if (arrowIndex !== -1) {
          const fromScope = transitionPart.slice(0, arrowIndex);
          const toScope = transitionPart.slice(arrowIndex + 2);

          // Verify the transition is valid (toScope reachable from fromScope)
          if (!isScopeReachable(hierarchy, fromScope, toScope)) {
            escalationDetected = true;
            status.valid = false;
            status.escalation = `${fromScope} -> ${toScope}`;
          }

          // Check for duplicate transitions (cycle detection in chain)
          const transitionKey = `${fromScope}->${toScope}`;
          if (seenTransitions.has(transitionKey)) {
            acyclic = false;
            status.cycle = true;
          }
          seenTransitions.add(transitionKey);
        }
      }

      return status;
    });

    const depthOk = depth <= maxDepth;
    const valid = depthOk && acyclic && !escalationDetected;

    return {
      valid,
      depth,
      acyclic,
      escalation_detected: escalationDetected,
      hop_status: hopStatus,
    };
  },

  /**
   * Describe a session for audit purposes. Redacts all key values;
   * shows only prefix and last 4 characters.
   *
   * @param {object} session - The credential session.
   * @param {object} _ctx    - Resolution context.
   * @returns {object} Audit-safe session description.
   */
  describeSession(session, _ctx) {
    const described = structuredClone(session);

    if (described.credentials && described.credentials.api_key) {
      const original = described.credentials.api_key.value;
      described.credentials.api_key.value = maskKeyValue(original);
    }

    return described;
  },
};

export default stripeApiKeyProvider;
export { stripeApiKeyProvider };
