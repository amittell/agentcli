/**
 * Stripe API key identity provider.
 *
 * Resolves Stripe API keys from environment variables, files, or shell
 * commands (e.g. Vault) based on a scope-aware permission set model.
 * Supports two key strategies:
 *   - precreated: Resolve existing keys (restricted or secret) by scope name.
 *   - dynamic: Mint restricted keys via the Stripe API at runtime.
 *
 * This file is self-contained with no imports from agentcli internals.
 * It can be copied to the scheduler's plugin directory and loaded as-is.
 * When running inside agentcli, it conditionally registers itself with
 * the provider registry.
 */

import { execSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import https from 'node:https';
import http from 'node:http';
import { URL } from 'node:url';

// ---------------------------------------------------------------------------
// Command-source cache: Map<cacheKey, { value, expiresAt }>
// Expected cardinality: low (one entry per distinct command+cwd+env tuple;
// typically 1-5 entries for a Stripe profile's permission_sets). No LRU
// eviction -- purgeExpiredCache removes entries after TTL. If command-source
// usage grows beyond a handful of scopes, add a max-entries cap.
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
// Dynamic key minting: Stripe restricted-key API helpers
// ---------------------------------------------------------------------------

/**
 * Default Stripe API base URL.
 */
const DEFAULT_API_BASE = 'https://api.stripe.com';

/**
 * Default buffer (in seconds) added to task timeout when computing key expiry.
 */
const DEFAULT_EXPIRY_BUFFER_S = 300;

/**
 * Default scope-to-permission mapping for Stripe restricted keys.
 *
 * Each scope name maps to an object of Stripe resource permissions.
 * The keys follow the Stripe restricted key permission format:
 *   permissions[<resource>][<action>] = "read" | "write" | "none"
 *
 * These mappings produce the least-privilege set for common scope names.
 * Operators can override this via config.scope_permissions.
 */
const DEFAULT_SCOPE_PERMISSIONS = {
  full: {
    'charges': 'write',
    'customers': 'write',
    'payment_intents': 'write',
    'subscriptions': 'write',
    'invoices': 'write',
    'refunds': 'write',
    'balance': 'read',
    'events': 'read',
  },
  payments: {
    'charges': 'write',
    'payment_intents': 'write',
    'refunds': 'write',
    'customers': 'read',
  },
  readonly: {
    'charges': 'read',
    'customers': 'read',
    'payment_intents': 'read',
    'subscriptions': 'read',
    'invoices': 'read',
    'balance': 'read',
    'events': 'read',
  },
};

/**
 * Encode an object of scope permissions into x-www-form-urlencoded body params
 * for the Stripe restricted key API.
 *
 * Input: { charges: 'write', customers: 'read' }
 * Output: 'permissions[charges][write]=true&permissions[customers][read]=true'
 *
 * @param {object} permissions - Map of resource to permission level.
 * @returns {string} URL-encoded body string.
 */
function encodePermissionsBody(permissions) {
  const parts = [];
  for (const [resource, level] of Object.entries(permissions)) {
    parts.push(`permissions[${encodeURIComponent(resource)}][${encodeURIComponent(level)}]=true`);
  }
  return parts.join('&');
}

/**
 * Resolve the permission set for a scope, checking config overrides first,
 * then falling back to DEFAULT_SCOPE_PERMISSIONS.
 *
 * @param {string} scope - The scope name.
 * @param {object} config - Provider config.
 * @returns {object|null} Permission map, or null if no mapping exists.
 */
function resolvePermissionsForScope(scope, config) {
  if (config.scope_permissions && config.scope_permissions[scope]) {
    return config.scope_permissions[scope];
  }
  return DEFAULT_SCOPE_PERMISSIONS[scope] || null;
}

/**
 * Make an HTTPS (or HTTP for testing) request and return the parsed JSON response.
 *
 * @param {object} opts
 * @param {string} opts.method - HTTP method.
 * @param {string} opts.url - Full URL string.
 * @param {object} opts.headers - Request headers.
 * @param {string} [opts.body] - Request body.
 * @param {number} [opts.timeout] - Request timeout in ms (default 30000).
 * @returns {Promise<{ statusCode: number, body: object }>}
 */
function stripeRequest(opts) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(opts.url);
    const transport = parsed.protocol === 'http:' ? http : https;

    const reqOpts = {
      method: opts.method,
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'http:' ? 80 : 443),
      path: parsed.pathname + parsed.search,
      headers: {
        ...opts.headers,
      },
      timeout: opts.timeout || 30000,
    };

    if (opts.body) {
      reqOpts.headers['Content-Length'] = Buffer.byteLength(opts.body, 'utf8');
    }

    const req = transport.request(reqOpts, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let body;
        try {
          body = JSON.parse(raw);
        } catch (_parseErr) {
          body = { raw_body: raw };
        }
        resolve({ statusCode: res.statusCode, body });
      });
    });

    req.on('error', (err) => reject(err));
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Stripe API request timed out'));
    });

    if (opts.body) {
      req.write(opts.body);
    }
    req.end();
  });
}

/**
 * Create a restricted API key via the Stripe API.
 *
 * POST /v1/api_keys
 * Authorization: Bearer <master_key>
 * Content-Type: application/x-www-form-urlencoded
 *
 * Expected response (success):
 *   { "id": "rk_...", "object": "api_key", "secret": "rk_test_...", ... }
 *
 * @param {string} masterKey - The secret key with permission to create restricted keys.
 * @param {object} permissions - Resource-to-level permission map.
 * @param {string} apiBase - Stripe API base URL.
 * @returns {Promise<{ ok: boolean, key_id?: string, key_secret?: string, error?: string, transient?: boolean }>}
 */
async function createRestrictedKey(masterKey, permissions, apiBase) {
  const body = encodePermissionsBody(permissions);
  const url = `${apiBase}/v1/api_keys`;

  try {
    const res = await stripeRequest({
      method: 'POST',
      url,
      headers: {
        'Authorization': `Bearer ${masterKey}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body,
    });

    if (res.statusCode >= 200 && res.statusCode < 300) {
      const keyId = res.body.id;
      const keySecret = res.body.secret || res.body.key;
      if (!keyId || !keySecret) {
        return {
          ok: false,
          transient: false,
          error: `Stripe API returned success but missing id or secret in response: ${JSON.stringify(res.body)}`,
        };
      }
      return { ok: true, key_id: keyId, key_secret: keySecret };
    }

    const isTransient = res.statusCode === 429 || res.statusCode >= 500;
    const errorMsg = (res.body && res.body.error && res.body.error.message)
      ? res.body.error.message
      : `HTTP ${res.statusCode}`;
    return {
      ok: false,
      transient: isTransient,
      error: `Stripe API error creating restricted key: ${errorMsg}`,
    };
  } catch (err) {
    return {
      ok: false,
      transient: true,
      error: `Stripe API request failed: ${err.message}`,
    };
  }
}

/**
 * Delete a restricted API key via the Stripe API.
 *
 * DELETE /v1/api_keys/{key_id}
 * Authorization: Bearer <master_key>
 *
 * @param {string} masterKey - The secret key with permission to manage restricted keys.
 * @param {string} keyId - The restricted key ID to delete.
 * @param {string} apiBase - Stripe API base URL.
 * @returns {Promise<{ ok: boolean, error?: string }>}
 */
async function deleteRestrictedKey(masterKey, keyId, apiBase) {
  const url = `${apiBase}/v1/api_keys/${encodeURIComponent(keyId)}`;

  try {
    const res = await stripeRequest({
      method: 'DELETE',
      url,
      headers: {
        'Authorization': `Bearer ${masterKey}`,
      },
    });

    if (res.statusCode >= 200 && res.statusCode < 300) {
      return { ok: true };
    }

    const errorMsg = (res.body && res.body.error && res.body.error.message)
      ? res.body.error.message
      : `HTTP ${res.statusCode}`;
    return { ok: false, error: `Stripe API error deleting key ${keyId}: ${errorMsg}` };
  } catch (err) {
    return { ok: false, error: `Stripe API request failed during key deletion: ${err.message}` };
  }
}

/**
 * Resolve the master key from the configured source (env, file, or command).
 *
 * @param {object} masterKeySource - { env?, file?, command? }
 * @param {object} env - Environment object.
 * @param {string} cwd - Working directory.
 * @returns {{ ok: boolean, value?: string, error?: string, transient?: boolean }}
 */
function resolveMasterKey(masterKeySource, env, cwd) {
  if (!masterKeySource || typeof masterKeySource !== 'object') {
    return { ok: false, transient: false, error: 'master_key_source is missing or not an object' };
  }
  if (typeof masterKeySource.env === 'string' && masterKeySource.env.length > 0) {
    return resolveEnvSource(masterKeySource.env, env);
  }
  if (typeof masterKeySource.file === 'string' && masterKeySource.file.length > 0) {
    return resolveFileSource(masterKeySource.file);
  }
  if (typeof masterKeySource.command === 'string' && masterKeySource.command.length > 0) {
    return resolveCommandSource(masterKeySource.command, 60000, { cwd, env });
  }
  return {
    ok: false,
    transient: false,
    error: 'master_key_source has no valid source (env, file, or command)',
  };
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

      // api_base: optional, must be a valid URL if present
      if (config.api_base !== undefined && config.api_base !== null) {
        if (typeof config.api_base !== 'string' || config.api_base.length === 0) {
          errors.push('provider_config.api_base must be a non-empty string URL');
        } else {
          try {
            const parsed = new URL(config.api_base);
            if (parsed.protocol === 'https:') {
              // OK: HTTPS is always allowed
            } else if (parsed.protocol === 'http:') {
              const isLocalhost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
              if (!isLocalhost && config.allow_insecure_http !== true) {
                errors.push(
                  'provider_config.api_base using http: is only allowed for localhost or when provider_config.allow_insecure_http is true'
                );
              }
            } else {
              errors.push('provider_config.api_base must use https: protocol');
            }
          } catch (_urlErr) {
            errors.push(`provider_config.api_base is not a valid URL: ${config.api_base}`);
          }
        }
      }

      // default_expiry_buffer_s: optional, must be a positive number if present
      if (config.default_expiry_buffer_s !== undefined && config.default_expiry_buffer_s !== null) {
        if (typeof config.default_expiry_buffer_s !== 'number' || config.default_expiry_buffer_s <= 0) {
          errors.push('provider_config.default_expiry_buffer_s must be a positive number');
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
      return this._resolveDynamicSession(request, config, env, cwd, trustLevel);
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
   * Internal: resolve a dynamic session by minting a restricted key via Stripe API.
   *
   * @param {object} request - Session request.
   * @param {object} config - Provider config.
   * @param {object} env - Environment object.
   * @param {string} cwd - Working directory.
   * @param {string} trustLevel - Effective trust level.
   * @returns {Promise<{ ok: boolean, session?: object, transient?: boolean, error?: string }>}
   */
  async _resolveDynamicSession(request, config, env, cwd, trustLevel) {
    const scope = request.scope || 'full';
    const accountMode = config.account_mode || 'test';
    const apiBase = config.api_base || DEFAULT_API_BASE;
    const expiryBufferS = (typeof config.default_expiry_buffer_s === 'number' && config.default_expiry_buffer_s > 0)
      ? config.default_expiry_buffer_s
      : DEFAULT_EXPIRY_BUFFER_S;

    // Resolve the master key
    const masterKeyResult = resolveMasterKey(config.master_key_source, env, cwd);
    if (!masterKeyResult.ok) {
      return {
        ok: false,
        transient: masterKeyResult.transient,
        error: `Failed to resolve master key: ${masterKeyResult.error}`,
      };
    }

    // Validate master key format
    const masterKeyCheck = validateKeyFormat(masterKeyResult.value, accountMode);
    if (!masterKeyCheck.valid) {
      return {
        ok: false,
        transient: false,
        error: `Master key format invalid: ${masterKeyCheck.error}`,
      };
    }

    // Resolve permissions for the requested scope
    const permissions = resolvePermissionsForScope(scope, config);
    if (!permissions || Object.keys(permissions).length === 0) {
      return {
        ok: false,
        transient: false,
        error: `No permission mapping found for scope "${scope}". Define scope_permissions["${scope}"] in provider_config or use a built-in scope (full, payments, readonly).`,
      };
    }

    // Create the restricted key via Stripe API
    const createResult = await createRestrictedKey(masterKeyResult.value, permissions, apiBase);
    if (!createResult.ok) {
      return {
        ok: false,
        transient: createResult.transient,
        error: createResult.error,
      };
    }

    // Compute expiry: task timeout (if known) + buffer, or just buffer from now
    const taskTimeoutS = (request.task_timeout_s && typeof request.task_timeout_s === 'number')
      ? request.task_timeout_s
      : 0;
    const expiresAt = new Date(Date.now() + ((taskTimeoutS + expiryBufferS) * 1000)).toISOString();

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
          value: createResult.key_secret,
          scope,
        },
      },
      provider_assertions: {
        key_strategy: 'dynamic',
        account_mode: accountMode,
        scope,
        stripe_key_id: createResult.key_id,
        api_base: apiBase,
      },
      delegation_chain: [
        {
          kind: 'service',
          principal: `stripe:${accountMode}`,
          grant: `scope:${scope}`,
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
        expires_at: expiresAt,
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

    const result = {
      materialized: true,
      env_vars: envVars,
      cleanup_required: config.key_strategy === 'dynamic',
    };

    // Embed session reference so cleanup() can access stripe_key_id and
    // provider_config without callers needing to thread the session through ctx.
    if (config.key_strategy === 'dynamic') {
      result.session = session;
    }

    return result;
  },

  /**
   * Clean up materialized credentials.
   *
   * For precreated strategy: no-op (keys are long-lived).
   * For dynamic strategy: revokes the minted restricted key via Stripe API.
   * Revocation is best-effort: failures are reported as warnings but
   * do not cause the cleanup to fail overall.
   *
   * @param {object} materialization - The materialization result (includes session reference).
   * @param {object} ctx             - Resolution context: { session, env, cwd }.
   * @returns {Promise<{ cleaned: boolean, warnings?: string[] }>|{ cleaned: boolean, warnings?: string[] }}
   */
  cleanup(materialization, ctx) {
    const session = (ctx && ctx.session) || (materialization && materialization.session) || null;
    if (!session) {
      return { cleaned: true };
    }

    const assertions = session.provider_assertions || {};
    if (assertions.key_strategy !== 'dynamic') {
      // Precreated keys need no cleanup -- they are long-lived and not minted per-job
      return { cleaned: true };
    }

    const keyId = assertions.stripe_key_id;
    if (!keyId) {
      return { cleaned: true, warnings: ['Dynamic session has no stripe_key_id; nothing to revoke'] };
    }

    // Resolve master key for deletion
    const env = (ctx && ctx.env) || process.env;
    const cwd = (ctx && ctx.cwd) || process.cwd();
    const config = (ctx && ctx.provider_config) || {};
    const masterKeySource = config.master_key_source || {};
    const apiBase = assertions.api_base || config.api_base || DEFAULT_API_BASE;

    const masterKeyResult = resolveMasterKey(masterKeySource, env, cwd);
    if (!masterKeyResult.ok) {
      return {
        cleaned: true,
        warnings: [`Could not resolve master key for cleanup: ${masterKeyResult.error}`],
      };
    }

    // Async deletion, best-effort
    return deleteRestrictedKey(masterKeyResult.value, keyId, apiBase).then((delResult) => {
      if (!delResult.ok) {
        return { cleaned: true, warnings: [delResult.error] };
      }
      return { cleaned: true };
    }).catch((err) => {
      return { cleaned: true, warnings: [`Key revocation failed: ${err.message}`] };
    });
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

    if (config.key_strategy === 'dynamic') {
      return this._prepareDynamicHandoff(session, targetScope, parentScope, config, env, cwd);
    }

    // Look up the target scope's permission set (precreated strategy)
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
   * Internal: prepare a dynamic handoff by minting a new restricted key
   * with narrower permissions for the target scope.
   *
   * @param {object} session - Parent session.
   * @param {string} targetScope - Target scope for the child.
   * @param {string} parentScope - Parent's current scope.
   * @param {object} config - Provider config from parent profile.
   * @param {object} env - Environment object.
   * @param {string} cwd - Working directory.
   * @returns {Promise<{ prepared: boolean, session?: object, error?: string }>}
   */
  async _prepareDynamicHandoff(session, targetScope, parentScope, config, env, cwd) {
    const accountMode = config.account_mode || 'test';
    const apiBase = config.api_base || DEFAULT_API_BASE;
    const expiryBufferS = (typeof config.default_expiry_buffer_s === 'number' && config.default_expiry_buffer_s > 0)
      ? config.default_expiry_buffer_s
      : DEFAULT_EXPIRY_BUFFER_S;

    // Resolve the master key for minting the child key
    const masterKeyResult = resolveMasterKey(config.master_key_source, env, cwd);
    if (!masterKeyResult.ok) {
      return { prepared: false, error: `Failed to resolve master key for handoff: ${masterKeyResult.error}` };
    }

    // Resolve narrower permissions for the target scope
    const permissions = resolvePermissionsForScope(targetScope, config);
    if (!permissions || Object.keys(permissions).length === 0) {
      return {
        prepared: false,
        error: `No permission mapping for handoff scope "${targetScope}". Define scope_permissions["${targetScope}"] in provider_config.`,
      };
    }

    // Mint a new restricted key with the narrower permissions
    const createResult = await createRestrictedKey(masterKeyResult.value, permissions, apiBase);
    if (!createResult.ok) {
      return { prepared: false, error: createResult.error };
    }

    const expiresAt = new Date(Date.now() + (expiryBufferS * 1000)).toISOString();
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
          value: createResult.key_secret,
          scope: targetScope,
        },
      },
      provider_assertions: {
        key_strategy: 'dynamic',
        account_mode: accountMode,
        scope: targetScope,
        parent_scope: parentScope,
        stripe_key_id: createResult.key_id,
        api_base: apiBase,
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
        expires_at: expiresAt,
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

// Exported for unit testing of internal helpers
export {
  encodePermissionsBody,
  resolvePermissionsForScope,
  stripeRequest,
  createRestrictedKey,
  deleteRestrictedKey,
  resolveMasterKey,
  DEFAULT_API_BASE,
  DEFAULT_EXPIRY_BUFFER_S,
  DEFAULT_SCOPE_PERMISSIONS,
};
