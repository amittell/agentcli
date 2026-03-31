# Design: Stripe Identity Provider, Sub-Agent Credential Flow, and Real Provider Calls

Date: 2026-03-29
Status: Draft

## Problem

Three connected gaps prevent the scheduler from executing tasks that require real credentials:

1. The scheduler stores v0.2 identity/authorization declarations but evaluates them structurally (no real provider calls). A Stripe task gets its trust level checked, but no API key is resolved or materialized.
2. Sub-agents spawned by the scheduler receive zero identity context. A parent task with Stripe credentials spawns children that run credential-less.
3. The scheduler has no mechanism to inject per-job environment variables into shell task subprocesses.

## Decisions Made During Design

- Stripe key resolution supports two strategies: `precreated` (resolve existing keys from Vault/env by scope name) and `dynamic` (mint restricted keys via Stripe API when available). Both use the same manifest syntax.
- Sub-agent credential flow is controlled per-task via a new `child_credential_policy` field (separate from the existing `delegation_mode` which describes identity acquisition method).
- Four child credential policies: `none`, `inherit`, `downscope`, `independent`.
- Child policy defaults to parent's when not declared on the child task.
- Provider calls classify errors as transient (retry-eligible) or permanent (no retry).
- Agent task credentials use auth-profile forwarding only. No credential injection via prompt. Full agent credential injection deferred until OpenClaw supports an env-inject header.
- Providers are loaded via a plugin directory, not imported from agentcli.
- Provider exports include a `type` field (`identity`, `authorization`, or `proof-verifier`) so the same file satisfies both agentcli's registry and the scheduler's plugin loader. agentcli's registry ignores the field; the scheduler uses it for categorization.
- Provider files are self-contained (no imports from agentcli internals). Deployment to the scheduler's plugin directory is an operational concern (copy, symlink, or shared package).
- The `prepareHandoff` method receives the parent's full profile (including `provider_config`) via `handoff.parent_profile`, so it can look up permission sets for the target scope without requiring provider statefulness.
- Compile-time validation: if a child task's effective `child_credential_policy` is `downscope` (declared or inherited) and the child declares no identity scope, compilation fails with an actionable error.
- Vault access uses the `command` value source (shells out to `vault kv get`) or pre-loaded env vars. No Vault SDK dependency.

## Architecture

### Credential Flow for a Stripe Task With Sub-Agents

```
Manifest:
  identity_profiles:
    - id: stripe-live
      provider: stripe-api-key
      provider_config:
        key_strategy: precreated
        account_mode: live
        key_source: env              # or vault via command
        permission_sets:
          full:      { key_env: STRIPE_KEY_FULL }
          payments:  { key_env: STRIPE_KEY_PAYMENTS }
          readonly:  { key_env: STRIPE_KEY_READONLY }
        scope_hierarchy:
          full: [payments, readonly]
          payments: []
          readonly: []

  workflows:
    - id: stripe-ops
      identity: { ref: stripe-live, scope: full }
      child_credential_policy: downscope
      tasks:
        - id: process-charges        # parent, gets full key
          shell: { program: node, args: [charge.js] }
          schedule: { cron: "0 9 * * *" }
        - id: send-receipts           # child, gets readonly key
          shell: { program: node, args: [receipts.js] }
          trigger: { parent: process-charges, on: success }
          identity: { ref: stripe-live, scope: readonly }
        - id: issue-refunds           # child, gets payments key
          shell: { program: node, args: [refunds.js] }
          trigger: { parent: process-charges, on: failure }
          identity: { ref: stripe-live, scope: payments }
```

At dispatch of process-charges:
1. Provider resolves `STRIPE_KEY_FULL` from env
2. Trust evaluation passes
3. Materialization produces `{ env_vars: { STRIPE_API_KEY: "rk_live_..." } }`
4. Shell subprocess spawned with `STRIPE_API_KEY` in environment
5. On completion, cleanup runs (no-op for precreated keys)

At dispatch of send-receipts (child):
1. Scheduler reads parent job's `child_credential_policy: downscope`
2. Child declares `scope: readonly`
3. Scheduler validates `readonly` is in parent's `scope_hierarchy.full` (no escalation)
4. Provider resolves `STRIPE_KEY_READONLY` from env
5. Shell subprocess spawned with narrower `STRIPE_API_KEY`

### Error Flow

```
Provider returns: { ok: false, transient: true, error: "Vault timeout" }
  -> Run marked as error with message "Identity resolution failed (transient): Vault timeout"
  -> Retry system retries if max_retries > 0

Provider returns: { ok: false, transient: false, error: "Invalid key format" }
  -> Run marked as error with message "Identity resolution failed (permanent): Invalid key format"
  -> No retry regardless of max_retries
  -> Delivery system alerts operator
```

## Components

### 1. Stripe Identity Provider

New file: `agentcli/src/identity/stripe-api-key.js`

Implements the standard identity provider interface with two key resolution strategies. Exports include `type: "identity"` for compatibility with the scheduler's plugin registry.

**Provider config schema:**

```javascript
{
  key_strategy: "precreated" | "dynamic",
  account_mode: "live" | "test",

  // For precreated strategy:
  permission_sets: {
    "<scope_name>": {
      key_env: "<env var name>",           // key_source: env
      // OR
      key_file: "<file path>",             // key_source: file
      // OR
      key_command: "<shell command>",       // key_source: command (e.g., vault kv get)
    }
  },
  scope_hierarchy: {
    "<parent_scope>": ["<child_scope>", ...],  // declares valid downscope paths
  },
  cache_ttl_s: 300,  // optional, default 300s for command source

  // For dynamic strategy (future):
  master_key_source: { env: "..." } | { command: "..." } | { file: "..." },
  api_base: "https://api.stripe.com",     // override for testing
  default_expiry_buffer_s: 300,           // added to task timeout for key expiry
  fallback_to_precreated: false,          // opt-in, NOT automatic
}
```

**Interface methods:**

`validateProfile(profile, ctx)`:
- Validates key_strategy, account_mode
- For precreated: validates permission_sets has at least one entry, scope_hierarchy is acyclic
- For dynamic: validates master_key_source is present
- Returns `{ valid, errors }`

`resolveSession(request, ctx)`:
- `request.scope` identifies which permission set to use
- For precreated: resolves key via the permission set's source (env/file/command)
- For dynamic: resolves master key, calls Stripe API to mint restricted key
- Validates key format: `sk_live_*`, `sk_test_*`, `rk_live_*`, `rk_test_*`
- Caches command-source results for `cache_ttl_s`
- Returns `{ ok: true, session }` or `{ ok: false, transient, error }`

Session structure:
```javascript
{
  subject: { kind: "service", principal: "stripe:<account_mode>" },
  trust: { declared_level: profile.trust.level, effective_level: profile.trust.level },
  credentials: {
    api_key: {
      kind: "bearer",
      value: "rk_live_...",
      scope: "payments",
    }
  },
  // For dynamic strategy only:
  stripe_key_id: "ak_...",    // for cleanup/revocation
  expires_at: "...",           // ISO 8601
}
```

`materialize(session, presentation, ctx)`:
- Binds credentials to env vars per presentation bindings
- Default: `{ STRIPE_API_KEY: session.credentials.api_key.value }`
- Additional bindings from profile (STRIPE_ACCOUNT_ID, etc.)
- Returns `{ materialized: true, env_vars, cleanup_required: strategy === "dynamic" }`

`cleanup(materialization, ctx)`:
- For precreated: no-op
- For dynamic: `DELETE https://api.stripe.com/v1/api_keys/{id}` best-effort, log warning on failure

`prepareHandoff(session, handoff, ctx)`:
- Called for `downscope` child credential policy
- `handoff.target_scope` identifies the child's scope
- `handoff.parent_profile` carries the parent's full identity profile (including `provider_config` with `permission_sets` and `scope_hierarchy`). The scheduler populates this from the parent job's `identity` column.
- Validates target_scope is reachable from parent scope via `handoff.parent_profile.provider_config.scope_hierarchy`
- For precreated: reads the target scope's key source from `handoff.parent_profile.provider_config.permission_sets[target_scope]` and resolves the narrower key
- For dynamic: mints a new restricted key with narrower permissions using the master key from parent profile
- Returns `{ prepared: true, session: <narrower session> }` or `{ prepared: false, error }`

`validateDelegation(chain, policy, ctx)`:
- Validates chain depth does not exceed `policy.max_depth` (default: 5)
- Validates no scope escalation using scope_hierarchy
- Returns `{ valid, depth, acyclic, escalation_detected, hop_status }`

### 2. Provider Plugin System

New file: `openclaw-scheduler/provider-registry.js`

Loads identity, authorization, and proof verification providers from a configurable directory.

**Configuration:**
```
SCHEDULER_PROVIDER_PATH=/path/to/providers
```

**Startup behavior:**
- If `SCHEDULER_PROVIDER_PATH` is not set, no providers are loaded (structural-only mode, backward compatible)
- If set, scans directory for `*.js` files
- Each file must `export default` a provider object with at minimum `{ name, type }` where type is `identity`, `authorization`, or `proof-verifier`
- Registers providers by name
- Logs registered providers at startup

**API:**
```javascript
export async function loadProviders(dirPath)
export function getIdentityProvider(name)
export function getAuthorizationProvider(name)
export function getProofVerifier(name)
export function hasProvider(name)
export function listProviders()
```

**Provider object requirements:**
```javascript
// Identity provider
{ name: "stripe-api-key", type: "identity", validateProfile, resolveSession, materialize, cleanup, prepareHandoff?, validateDelegation? }

// Authorization provider
{ name: "opa", type: "authorization", validateProfile, authorize, describeDecision? }

// Proof verifier
{ name: "jwt", type: "proof-verifier", validateProfile, verifyProof, describeVerification? }
```

**Trust boundary:** The scheduler trusts all code in the provider directory. This is equivalent to trusting npm dependencies -- the operator controls what goes in the directory. Provider files are self-contained with no imports from agentcli internals, so they can be copied or symlinked from agentcli's `src/identity/` directory or installed as a separate package.

### 3. Async v02-runtime.js

All provider-calling functions become async. The `ctx` parameter is optional with a default of `{}` for backward compatibility.

**Changed signatures:**
```javascript
export async function resolveIdentity(job, ctx = {})
export function evaluateTrust(job, resolvedIdentity)          // stays sync
export async function verifyAuthorizationProof(job, ctx = {})
export async function evaluateAuthorization(job, identityResult, trustResult, ctx = {})
export function generateEvidence(job, runResult, outcomes)     // stays sync
export function summarizeCredentialHandoff(job)                // stays sync
```

**Resolution logic (resolveIdentity as example):**
```javascript
export async function resolveIdentity(job, ctx = {}) {
  const profile = parseIdentityProfile(job);
  if (!profile) return null;

  const provider = ctx.getIdentityProvider?.(profile.provider);
  if (provider) {
    try {
      const result = await provider.resolveSession(
        { profile, instanceId: job.id, scope: profile.scope },
        { env: ctx.env || process.env, cwd: ctx.cwd || process.cwd() }
      );
      if (!result.ok) {
        return {
          provider: profile.provider,
          error: result.error,
          transient: result.transient ?? true,
          source: "provider-error",
        };
      }
      return { provider: profile.provider, session: result.session, source: "provider" };
    } catch (err) {
      return {
        provider: profile.provider,
        error: err.message,
        transient: true,
        source: "provider-error",
      };
    }
  }

  // Fallback: structural resolution (current behavior)
  return resolveIdentityStructural(job);
}
```

Same pattern for `verifyAuthorizationProof` and `evaluateAuthorization`.

### 4. Shell Env Var Injection

**`dispatcher-shell.js`:** Add `env` parameter:
```javascript
export function runShellCommand(cmd, timeoutMs = 300000, env = null) {
  if (!cmd || typeof cmd !== "string") throw new Error("Shell command must be a non-empty string");
  const safeTimeout = (Number.isFinite(timeoutMs) && timeoutMs > 0) ? timeoutMs : 300_000;
  return new Promise((resolve) => {
    execCb(cmd, {
      timeout: safeTimeout,
      maxBuffer: 64 * 1024 * 1024,
      shell: DEFAULT_SHELL,
      env: env ? { ...process.env, ...env } : undefined,
    }, (err, stdout, stderr) => {
      resolve({ stdout: stdout || "", stderr: stderr || "", exitCode: ..., signal: ..., error: ... });
    });
  });
}
```

**`dispatcher-strategies.js` (executeShell):** Read materialized env from DispatchContext:
```javascript
export async function executeShell(job, ctx, deps) {
  const { runShellCommand, normalizeShellResult, log } = deps;
  const result = makeDefaultResult();
  const shellExec = await runShellCommand(job.payload_message, job.run_timeout_ms, ctx.materializedEnv || null);
  // ... normalize result
}
```

### 5. Agent Task Credentials

For agent tasks (isolated/main sessions via gateway), the scheduler uses **auth-profile forwarding only**:

- The scheduler sets `x-openclaw-auth-profile` on the gateway call (already implemented)
- If OpenClaw has a matching auth profile configured that resolves to Stripe credentials, the agent gets them
- If not, the agent runs without credentials and the task fails with a clear error

**No credential injection via prompt.** Putting credentials in message history is insecure (visible in session exports, other agents, logs) and fragile (agent may not parse correctly).

**Future path (requires OpenClaw PR):** Add `x-openclaw-env-inject` header support to the gateway. The scheduler sends JSON-encoded env vars, the gateway injects them into the agent's environment. Until then, agent tasks requiring credentials must have a matching OpenClaw auth profile.

**Practical impact:** Shell tasks get full credential injection now. Agent tasks work if OpenClaw has the right profile. This covers the `stripe-ops.json` and `stripe-projects.json` examples (which use shell targets).

### 6. Materialization in the Dispatch Pipeline

Materialization happens at the end of `prepareDispatch`, after all trust/auth gates pass, before returning the DispatchContext.

**Updated prepareDispatch flow:**
```
1. Claim idempotency key
2. Create run record
3. v0.2 identity resolution (now async, may call providers)
4. Trust evaluation gate (sync comparison, deny -> fail run)
5. Authorization proof verification (now async, may call verifiers)
6. Authorization evaluation gate (now async, may call OPA, deny -> fail run)
7. Credential handoff summary
8. ** NEW: Materialization phase **
   - If identity resolved successfully and provider supports materialize:
     - Call provider.materialize(session, presentation, ctx)
     - Store env_vars on DispatchContext as ctx.materializedEnv
     - Store cleanup metadata on ctx for finalizeDispatch
9. Return DispatchContext with materializedEnv
```

**Updated finalizeDispatch flow:**
```
1. Finish run (existing)
1b. Evidence generation (existing)
1c. Persist v0.2 outcomes (existing)
2. ** NEW: Provider cleanup **
   - If ctx has cleanup metadata and provider supports cleanup:
     - Call provider.cleanup(ctx.materialization, ctx)
     - Best-effort: log warning on failure, do not fail the run
3. Idempotency key management (existing)
4. Delivery, retry, children, dequeue (existing)
```

### 7. Child Credential Policy Enforcement

New field on jobs: `child_credential_policy` (TEXT, nullable, DEFAULT NULL).

Valid values: `none`, `inherit`, `downscope`, `independent`.

**Schema change:** Add column to jobs table, validation in validateJobSpec, include in PATCHABLE_COLUMNS and createJob INSERT.

**In prepareDispatch, when job has parent_id:**

```
1. Fetch parent job (SELECT id, child_credential_policy, identity, auth_profile FROM jobs WHERE id = ?)
2. Determine effective policy:
   - If child declares child_credential_policy: use it
   - Else if parent declares child_credential_policy: use parent's
   - Else: "none" (backward compatible default)
3. Apply policy:
   - "none": no credentials, skip identity resolution for parent context
   - "inherit": set child's auth_profile to parent job's auth_profile value
   - "downscope":
     a. Read parent's identity profile (from parent job's `identity` column) and scope
     b. Read child's declared scope
     c. Validate child scope is reachable from parent scope via scope_hierarchy
     d. Call provider.prepareHandoff(parentSession, { target_scope: childScope, parent_profile: parentIdentityProfile })
     e. Materialize the narrower session
   - "independent": resolve child's own identity profile (no parent involvement, existing behavior)
```

**For downscope, the parent's resolved identity is needed.** Two options:
- Re-resolve the parent's identity (another provider call)
- Read the parent's last run's `identity_resolved` column

Use option 2 when available (avoids redundant Vault/API calls). Fall back to option 1 if the parent has no completed runs yet (first dispatch of a triggered child where the parent is still running -- edge case, but possible with `trigger_on: complete`).

### 8. Vault Integration Pattern

**Recommended primary pattern:** Pre-load keys into env vars at scheduler startup.

```bash
# In scheduler startup script or systemd unit:
# (source your Vault auth helper if needed, e.g. vault login or env setup)
export STRIPE_KEY_FULL=$(vault kv get -field=api_key secret/apps/stripe/full)
export STRIPE_KEY_PAYMENTS=$(vault kv get -field=api_key secret/apps/stripe/payments)
export STRIPE_KEY_READONLY=$(vault kv get -field=api_key secret/apps/stripe/readonly)
exec node dispatcher.js
```

The provider reads env vars at dispatch time -- zero latency, zero subprocess overhead.

**Alternative for environments where env pre-loading is not possible:** Use `command` source in provider_config:
```json
{ "key_command": "vault kv get -field=api_key secret/apps/stripe/payments" }
```
The provider shells out, caches the result for `cache_ttl_s` (default 300s) to avoid hammering Vault.

## Files Changed

### New files (3):
- `agentcli/src/identity/stripe-api-key.js` -- Stripe identity provider
- `openclaw-scheduler/provider-registry.js` -- Plugin loader for identity/auth/proof providers
- `openclaw-scheduler/test-providers/mock-stripe.js` -- Mock Stripe provider for testing

### Modified files -- openclaw-scheduler (7):
- `schema.sql` -- Add `child_credential_policy` column to jobs table (v23)
- `migrate-consolidate.js` -- Add ALTER TABLE for new column
- `jobs.js` -- Validate `child_credential_policy` enum, add to createJob/updateJob/PATCHABLE_COLUMNS
- `v02-runtime.js` -- Make resolveIdentity/verifyAuthorizationProof/evaluateAuthorization async, add ctx parameter with fallback
- `dispatcher-strategies.js` -- Materialization phase in prepareDispatch, cleanup in finalizeDispatch, child credential policy enforcement, pass materializedEnv on DispatchContext
- `dispatcher-shell.js` -- Add env parameter to runShellCommand
- `dispatcher.js` -- Load providers at startup, pass provider registry in buildDispatchDeps ctx

### Modified files -- agentcli (4):
- `src/identity/index.js` -- Register stripe-api-key provider
- `src/compiler/openclaw-scheduler.js` -- Compile child_credential_policy field, validate downscope+scope consistency
- `src/compiler/shared.js` -- Resolve child_credential_policy from workflow/task declarations
- `src/scheduler-fields.js` -- Add child_credential_policy to SCHEDULER_FIELDS_V02

### Modified test files (3):
- `openclaw-scheduler/test.js` -- Async v02-runtime tests, child_credential_policy validation, materialization tests
- `openclaw-scheduler/test-integration-agentcli.js` -- Add v0.2 with child_credential_policy fixtures
- `agentcli/test/agentcli.test.js` -- Stripe provider validation, child_credential_policy compilation

## Testing Strategy

**Unit tests (no network):**
- Stripe provider with mock env vars (precreated strategy)
- Stripe provider validation (missing fields, invalid formats, invalid scope hierarchy)
- Scope hierarchy validation and escalation detection
- Provider plugin loading from test directory
- Async v02-runtime with mock providers in ctx
- Shell env var injection (verify env dict merges correctly)
- Child credential policy validation and compilation
- Compile-time error when child inherits downscope but declares no identity scope

**Integration tests (scheduler + agentcli, no network):**
- Compile manifest with child_credential_policy, apply to scheduler, verify field stored
- Dispatch shell task with mock Stripe provider, verify env vars reach subprocess
- Dispatch child task with downscope policy, verify narrower key resolved
- Dispatch child task with inherit policy, verify parent's auth_profile used
- Error classification: transient failure triggers retry, permanent failure skips retry

**Manual verification:**
- Pre-create Stripe test mode restricted keys in Dashboard
- Store in env vars, configure provider with precreated strategy
- Run a shell task that calls `curl https://api.stripe.com/v1/charges -u $STRIPE_API_KEY:`
- Verify the task succeeds with the restricted key's permissions
- Verify a child task with readonly scope cannot write charges

## Out of Scope

- Dynamic key minting via Stripe API (provider_config supports it, implementation deferred until API is available)
- Agent task credential injection beyond auth-profile forwarding (requires OpenClaw PR)
- Automatic Vault token refresh (use existing vault-env.sh or systemd timer)
- Provider hot-reload (restart scheduler to pick up provider changes)
- Multi-account Stripe support (single account_mode per profile; use separate profiles for multi-account)
