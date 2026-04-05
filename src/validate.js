import { MANIFEST_VERSION } from './schema.js';
import { onFailureTaskId } from './shorthand.js';

const SUPPORTED_VERSIONS = ['0.1', MANIFEST_VERSION];
const TRUST_LEVELS = ['untrusted', 'restricted', 'supervised', 'autonomous'];
const CHILD_CREDENTIAL_POLICIES = ['none', 'inherit', 'downscope', 'independent'];

const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const TOKEN_RE = /^[A-Za-z0-9@:_./-]+$/;
const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

const KNOWN_MANIFEST_KEYS = new Set([
  'version', 'workflows',
  'identity_profiles', 'authorization_proof_profiles', 'authorization_profiles', 'evidence_profiles'
]);

const KNOWN_WORKFLOW_KEYS = new Set([
  'id', 'name', 'model_policy', 'identity', 'contract', 'tasks',
  'authorization_proof', 'authorization', 'evidence', 'child_credential_policy',
  'verify'
]);

const KNOWN_TASK_KEYS = new Set([
  'id', 'name', 'enabled', 'prompt', 'command', 'shell', 'target',
  'model_policy', 'intent', 'output', 'budgets', 'schedule', 'trigger',
  'delivery', 'reliability', 'runtime', 'approval', 'context', 'session',
  'identity', 'contract', 'on_failure', 'auth_profile', 'delete_after_run',
  'authorization_proof', 'authorization', 'evidence', 'child_credential_policy',
  'verify'
]);

const KNOWN_ON_FAILURE_KEYS = new Set([
  'id', 'name', 'enabled', 'prompt', 'command', 'shell', 'target',
  'delay_s', 'condition', 'model_policy', 'intent', 'output', 'budgets',
  'delivery', 'reliability', 'runtime', 'approval', 'context', 'session',
  'identity', 'contract', 'delete_after_run',
  'authorization_proof', 'authorization', 'evidence'
]);

function isObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

function addError(errors, path, message) {
  errors.push({ path, message });
}

function checkUnknownKeys(warnings, path, value, knownKeys) {
  if (!isObject(value)) return;
  for (const key of Object.keys(value)) {
    if (!knownKeys.has(key)) {
      warnings.push({ path: `${path}.${key}`, message: `unknown key "${key}"` });
    }
  }
}

function hasUnsupportedControlChars(value) {
  for (const char of value) {
    const code = char.charCodeAt(0);
    if (
      (code >= 0x00 && code <= 0x08) ||
      code === 0x0B ||
      code === 0x0C ||
      (code >= 0x0E && code <= 0x1F) ||
      code === 0x7F
    ) {
      return true;
    }
  }
  return false;
}

function checkString(errors, path, value, { required = true } = {}) {
  if (value == null) {
    if (required) addError(errors, path, 'is required');
    return;
  }
  if (typeof value !== 'string') {
    addError(errors, path, 'must be a string');
    return;
  }
  if (value.trim() === '') {
    addError(errors, path, 'cannot be empty');
    return;
  }
  if (hasUnsupportedControlChars(value)) {
    addError(errors, path, 'contains unsupported control characters');
  }
}

function checkIdentifier(errors, path, value, { required = true } = {}) {
  checkString(errors, path, value, { required });
  if (value == null || typeof value !== 'string' || value.trim() === '') return;
  if (!IDENTIFIER_RE.test(value)) {
    addError(errors, path, 'must match /^[A-Za-z0-9][A-Za-z0-9._-]*$/');
  }
}

function checkToken(errors, path, value, { required = true } = {}) {
  checkString(errors, path, value, { required });
  if (value == null || typeof value !== 'string' || value.trim() === '') return;
  if (!TOKEN_RE.test(value)) {
    addError(errors, path, 'contains unsupported path or token characters');
  }
}

function checkInteger(errors, path, value, min = 0) {
  if (value == null) return;
  if (!Number.isInteger(value) || value < min) {
    addError(errors, path, `must be an integer >= ${min}`);
  }
}

function checkBoolean(errors, path, value) {
  if (value == null) return;
  if (typeof value !== 'boolean') {
    addError(errors, path, 'must be a boolean');
  }
}

function checkEnum(errors, path, value, allowed) {
  if (value == null) return;
  if (!allowed.includes(value)) {
    addError(errors, path, `must be one of: ${allowed.join(', ')}`);
  }
}

function checkLegacyCommand(errors, path, value) {
  if (value !== undefined) {
    addError(errors, path, 'is not supported; use shell.program and shell.args');
  }
}

function validateTriggerCondition(errors, path, value) {
  if (value == null) return;
  checkString(errors, path, value);
  if (typeof value !== 'string') return;
  if (value.startsWith('regex:')) {
    if (!value.slice('regex:'.length).trim()) {
      addError(errors, path, 'regex trigger condition cannot be empty');
      return;
    }
    try {
      new RegExp(value.slice('regex:'.length));
    } catch (err) {
      addError(errors, path, `invalid regex: ${err.message}`);
    }
    return;
  }
  if (value.startsWith('contains:')) {
    if (!value.slice('contains:'.length).trim()) {
      addError(errors, path, 'contains trigger condition cannot be empty');
    }
    return;
  }
  addError(errors, path, 'must start with contains: or regex:');
}

function validateTargetLike(errors, path, target) {
  if (!isObject(target)) {
    addError(errors, path, 'must be an object');
    return;
  }
  if (target.session_target == null) {
    addError(errors, `${path}.session_target`, 'is required');
  } else {
    checkEnum(errors, `${path}.session_target`, target.session_target, ['main', 'isolated', 'shell']);
  }
  checkEnum(errors, `${path}.payload_kind`, target.payload_kind, ['systemEvent', 'agentTurn', 'shellCommand']);
  checkToken(errors, `${path}.agent_id`, target.agent_id, { required: false });
}

function validateShellExecution(errors, path, value) {
  if (!isObject(value)) {
    addError(errors, path, 'must be an object');
    return;
  }

  checkToken(errors, `${path}.program`, value.program);

  if (value.args != null) {
    if (!Array.isArray(value.args)) {
      addError(errors, `${path}.args`, 'must be an array');
    } else {
      for (const [index, arg] of value.args.entries()) {
        checkString(errors, `${path}.args[${index}]`, arg);
      }
    }
  }

  if (value.env != null) {
    if (!isObject(value.env)) {
      addError(errors, `${path}.env`, 'must be an object');
    } else {
      for (const [name, envValue] of Object.entries(value.env)) {
        if (!ENV_NAME_RE.test(name)) {
          addError(errors, `${path}.env.${name}`, 'must match /^[A-Za-z_][A-Za-z0-9_]*$/');
        }
        checkString(errors, `${path}.env.${name}`, envValue);
      }
    }
  }

  checkString(errors, `${path}.cwd`, value.cwd, { required: false });

  if (value.stdin != null && typeof value.stdin !== 'string') {
    addError(errors, `${path}.stdin`, 'must be a string');
  }
}

function validateExecutionSurface(errors, path, value, sessionTarget) {
  checkLegacyCommand(errors, `${path}.command`, value.command);

  if (sessionTarget === 'shell') {
    if (value.prompt != null) {
      addError(errors, `${path}.prompt`, 'must not be present for shell targets');
    }
    if (value.target?.payload_kind != null && value.target.payload_kind !== 'shellCommand') {
      addError(errors, `${path}.target.payload_kind`, 'must be shellCommand for shell targets');
    }
    if (value.shell == null) {
      addError(errors, `${path}.shell`, 'is required');
    } else {
      validateShellExecution(errors, `${path}.shell`, value.shell);
    }
    return;
  }

  if (value.shell != null) {
    addError(errors, `${path}.shell`, 'must not be present unless target.session_target is shell');
  }
  checkString(errors, `${path}.prompt`, value.prompt);
}

function validateModelPolicy(errors, path, value) {
  if (!isObject(value)) {
    addError(errors, path, 'must be an object');
    return;
  }
  checkToken(errors, `${path}.provider`, value.provider, { required: false });
  checkToken(errors, `${path}.model`, value.model, { required: false });
  checkToken(errors, `${path}.thinking`, value.thinking, { required: false });
}

function validateIntent(errors, path, value) {
  if (!isObject(value)) {
    addError(errors, path, 'must be an object');
    return;
  }
  checkEnum(errors, `${path}.mode`, value.mode, ['execute', 'plan']);
  checkBoolean(errors, `${path}.read_only`, value.read_only);
}

function validateOutput(errors, path, value) {
  if (!isObject(value)) {
    addError(errors, path, 'must be an object');
    return;
  }
  checkInteger(errors, `${path}.preview_bytes`, value.preview_bytes, 64);
  checkEnum(errors, `${path}.offload`, value.offload, ['auto', 'always', 'never']);
  checkEnum(errors, `${path}.retrieve`, value.retrieve, ['inline', 'on-demand']);
  checkEnum(errors, `${path}.format`, value.format, ['json', 'ndjson', 'text']);
}

function validateBudgets(errors, path, value) {
  if (!isObject(value)) {
    addError(errors, path, 'must be an object');
    return;
  }
  checkInteger(errors, `${path}.max_iterations`, value.max_iterations, 1);
  checkInteger(errors, `${path}.max_fanout`, value.max_fanout, 1);
  checkInteger(errors, `${path}.max_context_items`, value.max_context_items, 1);
  checkInteger(errors, `${path}.max_pending_approvals`, value.max_pending_approvals, 1);
  checkInteger(errors, `${path}.max_queued_dispatches`, value.max_queued_dispatches, 1);
}

function validateSubject(errors, path, value) {
  if (!isObject(value)) { addError(errors, path, 'must be an object'); return; }
  checkEnum(errors, `${path}.kind`, value.kind, ['agent', 'service', 'workload', 'user', 'composite', 'delegated-agent', 'unknown']);
  checkString(errors, `${path}.principal`, value.principal, { required: false });
  checkString(errors, `${path}.display_name`, value.display_name, { required: false });
  checkToken(errors, `${path}.run_as`, value.run_as, { required: false });
  checkString(errors, `${path}.issuer`, value.issuer, { required: false });
  checkEnum(errors, `${path}.delegation_mode`, value.delegation_mode, ['none', 'on-behalf-of', 'impersonation']);
}

function validateDelegationPolicy(errors, path, value) {
  if (!isObject(value)) { addError(errors, path, 'must be an object'); return; }
  checkInteger(errors, `${path}.max_depth`, value.max_depth, 1);
  if (value.allowed_delegators != null && !Array.isArray(value.allowed_delegators)) {
    addError(errors, `${path}.allowed_delegators`, 'must be an array');
  }
  checkBoolean(errors, `${path}.require_grant_per_hop`, value.require_grant_per_hop);
}

function validateAuth(errors, path, value) {
  if (!isObject(value)) { addError(errors, path, 'must be an object'); return; }
  checkEnum(errors, `${path}.mode`, value.mode, ['none', 'service', 'delegated', 'on-behalf-of', 'impersonation', 'exchange']);
  if (value.scopes != null && !Array.isArray(value.scopes)) {
    addError(errors, `${path}.scopes`, 'must be an array');
  }
  checkString(errors, `${path}.audience`, value.audience, { required: false });
  checkString(errors, `${path}.resource`, value.resource, { required: false });
  checkEnum(errors, `${path}.cache`, value.cache, ['none', 'memory', 'state']);
  checkEnum(errors, `${path}.refresh`, value.refresh, ['never', 'manual', 'auto']);
  checkBoolean(errors, `${path}.required`, value.required);
  if (checkOptionalObject(errors, `${path}.delegation_policy`, value.delegation_policy)) {
    validateDelegationPolicy(errors, `${path}.delegation_policy`, value.delegation_policy);
  }
}

function validateTrust(errors, path, value) {
  if (!isObject(value)) { addError(errors, path, 'must be an object'); return; }
  checkEnum(errors, `${path}.level`, value.level, ['untrusted', 'restricted', 'supervised', 'autonomous']);
  if (checkOptionalObject(errors, `${path}.constraints`, value.constraints)) {
    checkEnum(errors, `${path}.constraints.escalation`, value.constraints.escalation, ['fail', 'human-approval', 'log-and-proceed']);
    checkEnum(errors, `${path}.constraints.max_autonomy`, value.constraints.max_autonomy, ['untrusted', 'restricted', 'supervised', 'autonomous']);
    checkString(errors, `${path}.constraints.escalation_timeout`, value.constraints.escalation_timeout, { required: false });
    checkBoolean(errors, `${path}.constraints.require_justification`, value.constraints.require_justification);
  }
}

function validatePresentation(errors, path, value) {
  if (!isObject(value)) { addError(errors, path, 'must be an object'); return; }
  checkEnum(errors, `${path}.handoff`, value.handoff, ['none', 'downscope', 'transaction-token']);
  checkEnum(errors, `${path}.cleanup`, value.cleanup, ['always', 'on-success', 'on-failure', 'never']);
  checkBoolean(errors, `${path}.default_redaction`, value.default_redaction);
  if (value.bindings != null) {
    if (!Array.isArray(value.bindings)) {
      addError(errors, `${path}.bindings`, 'must be an array');
    } else {
      for (const [i, binding] of value.bindings.entries()) {
        const bp = `${path}.bindings[${i}]`;
        if (!isObject(binding)) { addError(errors, bp, 'must be an object'); continue; }
        checkString(errors, `${bp}.source`, binding.source);
        if (checkOptionalObject(errors, `${bp}.target`, binding.target)) {
          checkEnum(errors, `${bp}.target.kind`, binding.target.kind, ['env', 'file', 'stdin', 'none']);
          checkString(errors, `${bp}.target.name`, binding.target.name, { required: false });
        }
        checkBoolean(errors, `${bp}.required`, binding.required);
        checkBoolean(errors, `${bp}.redact`, binding.redact);
        checkEnum(errors, `${bp}.format`, binding.format, ['raw', 'json', 'base64']);
      }
    }
  }
}

function validateIdentity(errors, path, value) {
  if (!isObject(value)) {
    addError(errors, path, 'must be an object');
    return;
  }

  // v0.2 identity (has ref or subject)
  if (
    value.ref != null ||
    value.scope != null ||
    value.subject != null ||
    value.auth != null ||
    value.trust != null ||
    value.presentation != null
  ) {
    checkString(errors, `${path}.ref`, value.ref, { required: false });
    checkString(errors, `${path}.scope`, value.scope, { required: false });
    if (checkOptionalObject(errors, `${path}.subject`, value.subject)) {
      validateSubject(errors, `${path}.subject`, value.subject);
    }
    if (checkOptionalObject(errors, `${path}.auth`, value.auth)) {
      validateAuth(errors, `${path}.auth`, value.auth);
    }
    if (checkOptionalObject(errors, `${path}.trust`, value.trust)) {
      validateTrust(errors, `${path}.trust`, value.trust);
    }
    if (checkOptionalObject(errors, `${path}.presentation`, value.presentation)) {
      validatePresentation(errors, `${path}.presentation`, value.presentation);
    }
    return;
  }

  // v0.1 identity (flat fields)
  checkToken(errors, `${path}.principal`, value.principal, { required: false });
  checkToken(errors, `${path}.run_as`, value.run_as, { required: false });
  checkString(errors, `${path}.attestation`, value.attestation, { required: false });
}

function validateAuthorizationProofRef(errors, path, value) {
  if (!isObject(value)) { addError(errors, path, 'must be an object'); return; }
  checkString(errors, `${path}.ref`, value.ref);
  if (value.claims != null && !isObject(value.claims)) {
    addError(errors, `${path}.claims`, 'must be an object');
  }
  if (checkOptionalObject(errors, `${path}.verify`, value.verify)) {
    checkBoolean(errors, `${path}.verify.required`, value.verify.required);
  }
}

function validateAuthorizationRequest(errors, path, value) {
  if (!isObject(value)) { addError(errors, path, 'must be an object'); return; }
  if (value.include != null) {
    if (!Array.isArray(value.include)) {
      addError(errors, `${path}.include`, 'must be an array');
    } else {
      for (const [index, item] of value.include.entries()) {
        checkString(errors, `${path}.include[${index}]`, item);
      }
    }
  }
}

function validateAuthorizationDecision(errors, path, value) {
  if (!isObject(value)) { addError(errors, path, 'must be an object'); return; }
  for (const field of ['allow_values', 'deny_values', 'escalate_values']) {
    if (value[field] != null) {
      if (!Array.isArray(value[field])) {
        addError(errors, `${path}.${field}`, 'must be an array');
      } else {
        for (const [index, item] of value[field].entries()) {
          checkString(errors, `${path}.${field}[${index}]`, item);
        }
      }
    }
  }
}

function validateAuthorizationRef(errors, path, value) {
  if (!isObject(value)) { addError(errors, path, 'must be an object'); return; }
  checkString(errors, `${path}.ref`, value.ref);
  checkEnum(errors, `${path}.on_error`, value.on_error, ['deny', 'warn']);
  if (value.provider_config != null && !isObject(value.provider_config)) {
    addError(errors, `${path}.provider_config`, 'must be an object');
  }
  if (checkOptionalObject(errors, `${path}.request`, value.request)) {
    validateAuthorizationRequest(errors, `${path}.request`, value.request);
  }
  if (checkOptionalObject(errors, `${path}.decision`, value.decision)) {
    validateAuthorizationDecision(errors, `${path}.decision`, value.decision);
  }
}

function validateEvidenceRef(errors, path, value) {
  if (!isObject(value)) { addError(errors, path, 'must be an object'); return; }
  checkString(errors, `${path}.ref`, value.ref, { required: false });
  if (checkOptionalObject(errors, `${path}.payload`, value.payload)) {
    if (value.payload.bind != null && !Array.isArray(value.payload.bind)) {
      addError(errors, `${path}.payload.bind`, 'must be an array');
    }
    if (value.payload.context != null && !isObject(value.payload.context)) {
      addError(errors, `${path}.payload.context`, 'must be an object');
    }
    checkEnum(errors, `${path}.payload.format`, value.payload.format, ['canonical-json', 'json']);
  }
  if (checkOptionalObject(errors, `${path}.verify`, value.verify)) {
    checkBoolean(errors, `${path}.verify.required`, value.verify.required);
  }
}

function validateContract(errors, path, value) {
  if (!isObject(value)) {
    addError(errors, path, 'must be an object');
    return;
  }
  checkEnum(errors, `${path}.sandbox`, value.sandbox, ['none', 'permissive', 'strict']);
  if (value.allowed_paths != null) {
    if (!Array.isArray(value.allowed_paths)) {
      addError(errors, `${path}.allowed_paths`, 'must be an array');
    } else {
      for (const [index, p] of value.allowed_paths.entries()) {
        checkString(errors, `${path}.allowed_paths[${index}]`, p);
      }
    }
  }
  checkEnum(errors, `${path}.network`, value.network, ['unrestricted', 'restricted', 'none']);
  if (value.max_cost_usd != null) {
    if (typeof value.max_cost_usd !== 'number' || value.max_cost_usd < 0) {
      addError(errors, `${path}.max_cost_usd`, 'must be a number >= 0');
    }
  }
  checkEnum(errors, `${path}.audit`, value.audit, ['none', 'on-failure', 'always']);
  checkEnum(errors, `${path}.required_trust_level`, value.required_trust_level, ['untrusted', 'restricted', 'supervised', 'autonomous']);
  checkEnum(errors, `${path}.trust_enforcement`, value.trust_enforcement, ['none', 'advisory', 'strict']);
}

function validateChildCredentialPolicy(errors, path, value) {
  checkEnum(errors, path, value, CHILD_CREDENTIAL_POLICIES);
}

function checkOptionalObject(errors, path, value) {
  if (value == null) return false;
  if (!isObject(value)) {
    addError(errors, path, 'must be an object');
    return false;
  }
  return true;
}

function validateValueFrom(errors, path, value, { allowLiteral = true } = {}) {
  if (!isObject(value)) {
    addError(errors, path, 'must be an object');
    return;
  }

  checkString(errors, `${path}.env`, value.env, { required: false });
  checkString(errors, `${path}.file`, value.file, { required: false });
  if (allowLiteral) {
    checkString(errors, `${path}.literal`, value.literal, { required: false });
  } else if (value.literal != null) {
    addError(errors, `${path}.literal`, 'is not supported here');
  }
  checkString(errors, `${path}.command`, value.command, { required: false });

  const hasSupportedSource = Boolean(
    value.env != null ||
    value.file != null ||
    (allowLiteral && value.literal != null) ||
    value.command != null
  );

  if (!hasSupportedSource) {
    const supported = allowLiteral ? 'env, file, literal, or command' : 'env, file, or command';
    addError(errors, path, `must include at least one of: ${supported}`);
  }
}

function validateOptionalBlocks(errors, warnings, path, value) {
  if (checkOptionalObject(errors, `${path}.model_policy`, value.model_policy)) {
    validateModelPolicy(errors, `${path}.model_policy`, value.model_policy);
  }

  if (checkOptionalObject(errors, `${path}.intent`, value.intent)) {
    validateIntent(errors, `${path}.intent`, value.intent);
  }

  if (checkOptionalObject(errors, `${path}.output`, value.output)) {
    validateOutput(errors, `${path}.output`, value.output);
  }

  if (checkOptionalObject(errors, `${path}.budgets`, value.budgets)) {
    validateBudgets(errors, `${path}.budgets`, value.budgets);
  }

  if (checkOptionalObject(errors, `${path}.delivery`, value.delivery)) {
    checkEnum(errors, `${path}.delivery.mode`, value.delivery.mode, ['announce', 'announce-always', 'none']);
    checkToken(errors, `${path}.delivery.channel`, value.delivery.channel, { required: false });
    checkToken(errors, `${path}.delivery.to`, value.delivery.to, { required: false });
    if (
      value.delivery.mode &&
      ['announce', 'announce-always'].includes(value.delivery.mode) &&
      (value.delivery.to == null || value.delivery.to === '')
    ) {
      addError(errors, `${path}.delivery.to`, 'is required when delivery.mode is "announce" or "announce-always"');
    }
  }

  if (checkOptionalObject(errors, `${path}.reliability`, value.reliability)) {
    checkEnum(errors, `${path}.reliability.guarantee`, value.reliability.guarantee, ['at-most-once', 'at-least-once']);
    checkEnum(errors, `${path}.reliability.overlap_policy`, value.reliability.overlap_policy, ['skip', 'allow', 'queue']);
    checkInteger(errors, `${path}.reliability.max_retries`, value.reliability.max_retries, 0);
  }

  if (checkOptionalObject(errors, `${path}.runtime`, value.runtime)) {
    checkInteger(errors, `${path}.runtime.timeout_ms`, value.runtime.timeout_ms, 1);
  }

  if (checkOptionalObject(errors, `${path}.approval`, value.approval)) {
    checkBoolean(errors, `${path}.approval.required`, value.approval.required);
    checkEnum(errors, `${path}.approval.policy`, value.approval.policy, ['manual', 'auto-approve', 'auto-reject']);
    checkEnum(errors, `${path}.approval.risk_level`, value.approval.risk_level, ['low', 'medium', 'high']);
    checkToken(errors, `${path}.approval.approver_scope`, value.approval.approver_scope, { required: false });
    checkEnum(errors, `${path}.approval.auto`, value.approval.auto, ['approve', 'reject']);
    checkInteger(errors, `${path}.approval.timeout_s`, value.approval.timeout_s, 1);
    if (value.approval.policy && value.approval.required != null) {
      warnings.push({
        path: `${path}.approval`,
        message: 'approval.policy takes precedence over approval.required for backend compilation'
      });
    }
  }

  if (checkOptionalObject(errors, `${path}.context`, value.context)) {
    checkEnum(errors, `${path}.context.retrieval`, value.context.retrieval, ['none', 'recent', 'hybrid']);
    checkInteger(errors, `${path}.context.limit`, value.context.limit, 1);
    if (value.budgets?.max_context_items != null && value.context.limit != null && value.budgets.max_context_items !== value.context.limit) {
      warnings.push({
        path: `${path}.context.limit`,
        message: 'context.limit takes precedence over budgets.max_context_items when both are set'
      });
    }
  }

  if (checkOptionalObject(errors, `${path}.session`, value.session)) {
    checkToken(errors, `${path}.session.preferred_key`, value.session.preferred_key, { required: false });
  }

  if (checkOptionalObject(errors, `${path}.identity`, value.identity)) {
    validateIdentity(errors, `${path}.identity`, value.identity);
  }

  if (checkOptionalObject(errors, `${path}.contract`, value.contract)) {
    validateContract(errors, `${path}.contract`, value.contract);
  }

  if (checkOptionalObject(errors, `${path}.authorization_proof`, value.authorization_proof)) {
    validateAuthorizationProofRef(errors, `${path}.authorization_proof`, value.authorization_proof);
  }
  if (checkOptionalObject(errors, `${path}.authorization`, value.authorization)) {
    validateAuthorizationRef(errors, `${path}.authorization`, value.authorization);
  }
  if (checkOptionalObject(errors, `${path}.evidence`, value.evidence)) {
    validateEvidenceRef(errors, `${path}.evidence`, value.evidence);
  }

  if (value.auth_profile != null) {
    checkString(errors, `${path}.auth_profile`, value.auth_profile);
  }

  checkBoolean(errors, `${path}.delete_after_run`, value.delete_after_run);
}

function validateVerify(errors, path, value) {
  if (!isObject(value)) {
    addError(errors, path, 'must be an object');
    return;
  }
  if (value.shell == null || typeof value.shell !== 'string' || value.shell.trim() === '') {
    addError(errors, `${path}.shell`, 'is required and must be a non-empty string');
  } else if (hasUnsupportedControlChars(value.shell)) {
    addError(errors, `${path}.shell`, 'contains unsupported control characters');
  }
  if (value.timeout_seconds != null) {
    if (!Number.isInteger(value.timeout_seconds) || value.timeout_seconds < 1) {
      addError(errors, `${path}.timeout_seconds`, 'must be an integer >= 1');
    }
  }
  checkEnum(errors, `${path}.on_failure`, value.on_failure, ['error', 'warn']);
}

function validateOnFailure(errors, warnings, path, task) {
  if (task.on_failure == null) return;
  if (!isObject(task.on_failure)) {
    addError(errors, path, 'must be an object');
    return;
  }

  const handler = task.on_failure;
  checkUnknownKeys(warnings, path, handler, KNOWN_ON_FAILURE_KEYS);
  checkIdentifier(errors, `${path}.id`, handler.id, { required: false });
  checkString(errors, `${path}.name`, handler.name, { required: false });
  checkBoolean(errors, `${path}.enabled`, handler.enabled);
  checkInteger(errors, `${path}.delay_s`, handler.delay_s, 0);
  validateTriggerCondition(errors, `${path}.condition`, handler.condition);

  if (handler.target != null) {
    validateTargetLike(errors, `${path}.target`, handler.target);
  }

  const inferredSessionTarget = handler.target?.session_target || (handler.shell ? 'shell' : 'isolated');
  validateExecutionSurface(errors, path, handler, inferredSessionTarget);
  validateOptionalBlocks(errors, warnings, path, handler);
}

function compareTrustLevels(a, b) {
  const indexA = TRUST_LEVELS.indexOf(a);
  const indexB = TRUST_LEVELS.indexOf(b);
  if (indexA === -1 || indexB === -1) return null;
  if (indexA < indexB) return -1;
  if (indexA > indexB) return 1;
  return 0;
}

function hasV2IdentityShape(identity) {
  return isObject(identity) && (
    identity.ref != null ||
    identity.scope != null ||
    identity.subject != null ||
    identity.auth != null ||
    identity.trust != null ||
    identity.presentation != null
  );
}

function resolveTrustSatisfiability(identityProfilesById, workflowIdentity, taskIdentity, workflowContract, taskContract) {
  const profileRef = taskIdentity?.ref ?? workflowIdentity?.ref ?? null;
  const profile = profileRef ? identityProfilesById.get(profileRef) ?? null : null;
  const profileTrust = profile?.trust || {};
  const workflowTrust = hasV2IdentityShape(workflowIdentity) ? workflowIdentity.trust || {} : {};
  const taskTrust = hasV2IdentityShape(taskIdentity) ? taskIdentity.trust || {} : {};
  const profileConstraints = profileTrust.constraints || {};
  const workflowConstraints = workflowTrust.constraints || {};
  const taskConstraints = taskTrust.constraints || {};
  const maxAutonomy =
    taskConstraints.max_autonomy ??
    workflowConstraints.max_autonomy ??
    profileConstraints.max_autonomy ??
    null;
  const requiredTrustLevel =
    taskContract?.required_trust_level ??
    workflowContract?.required_trust_level ??
    null;
  return { maxAutonomy, requiredTrustLevel };
}

export function validateManifest(manifest) {
  const errors = [];
  const warnings = [];

  if (!isObject(manifest)) {
    return { ok: false, errors: [{ path: '$', message: 'manifest must be an object' }], warnings };
  }

  if (!SUPPORTED_VERSIONS.includes(manifest.version)) {
    addError(errors, '$.version', `must be one of: ${SUPPORTED_VERSIONS.join(', ')}`);
  }

  checkUnknownKeys(warnings, '$', manifest, KNOWN_MANIFEST_KEYS);

  // Validate v0.2 profile arrays
  if (manifest.identity_profiles != null) {
    if (!Array.isArray(manifest.identity_profiles)) {
      addError(errors, '$.identity_profiles', 'must be an array');
    } else {
      const profileIds = new Set();
      for (const [i, profile] of manifest.identity_profiles.entries()) {
        const pp = `$.identity_profiles[${i}]`;
        if (!isObject(profile)) { addError(errors, pp, 'must be an object'); continue; }
        checkIdentifier(errors, `${pp}.id`, profile.id);
        checkString(errors, `${pp}.provider`, profile.provider);
        if (profile.id) {
          if (profileIds.has(profile.id)) addError(errors, `${pp}.id`, 'must be unique');
          profileIds.add(profile.id);
        }
        if (checkOptionalObject(errors, `${pp}.subject`, profile.subject)) {
          validateSubject(errors, `${pp}.subject`, profile.subject);
        }
        if (checkOptionalObject(errors, `${pp}.auth`, profile.auth)) {
          validateAuth(errors, `${pp}.auth`, profile.auth);
        }
        if (checkOptionalObject(errors, `${pp}.trust`, profile.trust)) {
          validateTrust(errors, `${pp}.trust`, profile.trust);
        }
        if (checkOptionalObject(errors, `${pp}.presentation`, profile.presentation)) {
          validatePresentation(errors, `${pp}.presentation`, profile.presentation);
        }
      }
    }
  }

  if (manifest.authorization_proof_profiles != null) {
    if (!Array.isArray(manifest.authorization_proof_profiles)) {
      addError(errors, '$.authorization_proof_profiles', 'must be an array');
    } else {
      const proofIds = new Set();
      for (const [i, profile] of manifest.authorization_proof_profiles.entries()) {
        const pp = `$.authorization_proof_profiles[${i}]`;
        if (!isObject(profile)) { addError(errors, pp, 'must be an object'); continue; }
        checkIdentifier(errors, `${pp}.id`, profile.id);
        checkEnum(errors, `${pp}.method`, profile.method, ['jwt', 'detached-signature', 'certificate', 'none']);
        if (profile.id) {
          if (proofIds.has(profile.id)) addError(errors, `${pp}.id`, 'must be unique');
          proofIds.add(profile.id);
        }
        checkString(errors, `${pp}.issuer`, profile.issuer, { required: false });
        checkString(errors, `${pp}.audience`, profile.audience, { required: false });
        checkString(errors, `${pp}.jwks_uri`, profile.jwks_uri, { required: false });
        checkString(errors, `${pp}.public_key`, profile.public_key, { required: false });
        if (checkOptionalObject(errors, `${pp}.proof`, profile.proof)) {
          if (checkOptionalObject(errors, `${pp}.proof.value_from`, profile.proof.value_from)) {
            validateValueFrom(errors, `${pp}.proof.value_from`, profile.proof.value_from);
          }
        }
        if (profile.claims != null && !isObject(profile.claims)) {
          addError(errors, `${pp}.claims`, 'must be an object');
        }
        if (checkOptionalObject(errors, `${pp}.verify`, profile.verify)) {
          checkBoolean(errors, `${pp}.verify.required`, profile.verify.required);
        }
      }
    }
  }

  if (manifest.authorization_profiles != null) {
    if (!Array.isArray(manifest.authorization_profiles)) {
      addError(errors, '$.authorization_profiles', 'must be an array');
    } else {
      const authzIds = new Set();
      for (const [i, profile] of manifest.authorization_profiles.entries()) {
        const pp = `$.authorization_profiles[${i}]`;
        if (!isObject(profile)) { addError(errors, pp, 'must be an object'); continue; }
        checkIdentifier(errors, `${pp}.id`, profile.id);
        checkString(errors, `${pp}.provider`, profile.provider);
        if (profile.id) {
          if (authzIds.has(profile.id)) addError(errors, `${pp}.id`, 'must be unique');
          authzIds.add(profile.id);
        }
        if (profile.provider_config != null && !isObject(profile.provider_config)) {
          addError(errors, `${pp}.provider_config`, 'must be an object');
        }
        checkEnum(errors, `${pp}.on_error`, profile.on_error, ['deny', 'warn']);
        if (checkOptionalObject(errors, `${pp}.request`, profile.request)) {
          validateAuthorizationRequest(errors, `${pp}.request`, profile.request);
        }
        if (checkOptionalObject(errors, `${pp}.decision`, profile.decision)) {
          validateAuthorizationDecision(errors, `${pp}.decision`, profile.decision);
        }
      }
    }
  }

  if (manifest.evidence_profiles != null) {
    if (!Array.isArray(manifest.evidence_profiles)) {
      addError(errors, '$.evidence_profiles', 'must be an array');
    } else {
      const evidIds = new Set();
      for (const [i, profile] of manifest.evidence_profiles.entries()) {
        const pp = `$.evidence_profiles[${i}]`;
        if (!isObject(profile)) { addError(errors, pp, 'must be an object'); continue; }
        checkIdentifier(errors, `${pp}.id`, profile.id);
        checkString(errors, `${pp}.provider`, profile.provider);
        if (profile.id) {
          if (evidIds.has(profile.id)) addError(errors, `${pp}.id`, 'must be unique');
          evidIds.add(profile.id);
        }
        if (profile.provider_config != null && !isObject(profile.provider_config)) {
          addError(errors, `${pp}.provider_config`, 'must be an object');
        }
        if (checkOptionalObject(errors, `${pp}.payload`, profile.payload)) {
          if (profile.payload.bind != null && !Array.isArray(profile.payload.bind)) {
            addError(errors, `${pp}.payload.bind`, 'must be an array');
          }
          if (profile.payload.context != null && !isObject(profile.payload.context)) {
            addError(errors, `${pp}.payload.context`, 'must be an object');
          }
          checkEnum(errors, `${pp}.payload.format`, profile.payload.format, ['canonical-json', 'json']);
        }
        if (checkOptionalObject(errors, `${pp}.verify`, profile.verify)) {
          checkBoolean(errors, `${pp}.verify.required`, profile.verify.required);
        }
      }
    }
  }

  if (!Array.isArray(manifest.workflows) || manifest.workflows.length === 0) {
    addError(errors, '$.workflows', 'must be a non-empty array');
  } else {
    const workflowIds = new Set();
    for (const [workflowIndex, workflow] of manifest.workflows.entries()) {
      const workflowPath = `$.workflows[${workflowIndex}]`;
      if (!isObject(workflow)) {
        addError(errors, workflowPath, 'must be an object');
        continue;
      }
      checkUnknownKeys(warnings, workflowPath, workflow, KNOWN_WORKFLOW_KEYS);
      checkIdentifier(errors, `${workflowPath}.id`, workflow.id);
      checkString(errors, `${workflowPath}.name`, workflow.name);
      if (checkOptionalObject(errors, `${workflowPath}.model_policy`, workflow.model_policy)) {
        validateModelPolicy(errors, `${workflowPath}.model_policy`, workflow.model_policy);
      }
      if (checkOptionalObject(errors, `${workflowPath}.identity`, workflow.identity)) {
        validateIdentity(errors, `${workflowPath}.identity`, workflow.identity);
      }
      if (checkOptionalObject(errors, `${workflowPath}.contract`, workflow.contract)) {
        validateContract(errors, `${workflowPath}.contract`, workflow.contract);
      }
      if (checkOptionalObject(errors, `${workflowPath}.authorization_proof`, workflow.authorization_proof)) {
        validateAuthorizationProofRef(errors, `${workflowPath}.authorization_proof`, workflow.authorization_proof);
      }
      if (checkOptionalObject(errors, `${workflowPath}.authorization`, workflow.authorization)) {
        validateAuthorizationRef(errors, `${workflowPath}.authorization`, workflow.authorization);
      }
      if (checkOptionalObject(errors, `${workflowPath}.evidence`, workflow.evidence)) {
        validateEvidenceRef(errors, `${workflowPath}.evidence`, workflow.evidence);
      }
      validateChildCredentialPolicy(errors, `${workflowPath}.child_credential_policy`, workflow.child_credential_policy);
      if (checkOptionalObject(errors, `${workflowPath}.verify`, workflow.verify)) {
        validateVerify(errors, `${workflowPath}.verify`, workflow.verify);
      }
      if (workflow.id) {
        if (workflowIds.has(workflow.id)) addError(errors, `${workflowPath}.id`, 'must be unique');
        workflowIds.add(workflow.id);
      }
      if (!Array.isArray(workflow.tasks) || workflow.tasks.length === 0) {
        addError(errors, `${workflowPath}.tasks`, 'must be a non-empty array');
        continue;
      }

      const taskIds = new Set();
      for (const [taskIndex, task] of workflow.tasks.entries()) {
        const taskPath = `${workflowPath}.tasks[${taskIndex}]`;
        if (!isObject(task)) {
          addError(errors, taskPath, 'must be an object');
          continue;
        }

        checkUnknownKeys(warnings, taskPath, task, KNOWN_TASK_KEYS);
        checkIdentifier(errors, `${taskPath}.id`, task.id);
        checkString(errors, `${taskPath}.name`, task.name);
        checkBoolean(errors, `${taskPath}.enabled`, task.enabled);
        if (task.id) {
          if (taskIds.has(task.id)) addError(errors, `${taskPath}.id`, 'must be unique within the workflow');
          taskIds.add(task.id);
        }

        if (!isObject(task.target)) {
          addError(errors, `${taskPath}.target`, 'must be an object');
        } else {
          validateTargetLike(errors, `${taskPath}.target`, task.target);
        }

        validateExecutionSurface(errors, taskPath, task, task.target?.session_target);

        const scheduleTypeError = task.schedule != null && !isObject(task.schedule);
        const triggerTypeError = task.trigger != null && !isObject(task.trigger);
        if (scheduleTypeError) {
          addError(errors, `${taskPath}.schedule`, 'must be an object');
        }
        if (triggerTypeError) {
          addError(errors, `${taskPath}.trigger`, 'must be an object');
        }
        const hasSchedule = isObject(task.schedule);
        const hasTrigger = isObject(task.trigger);
        if (!scheduleTypeError && !triggerTypeError && hasSchedule === hasTrigger) {
          addError(errors, taskPath, 'must define exactly one of schedule or trigger');
        }

        if (hasSchedule) {
          checkString(errors, `${taskPath}.schedule.cron`, task.schedule.cron);
          checkString(errors, `${taskPath}.schedule.tz`, task.schedule.tz, { required: false });
        }

        if (hasTrigger) {
          checkString(errors, `${taskPath}.trigger.parent`, task.trigger.parent);
          if (task.trigger.on == null) {
            addError(errors, `${taskPath}.trigger.on`, 'is required');
          } else {
            checkEnum(errors, `${taskPath}.trigger.on`, task.trigger.on, ['success', 'failure', 'complete']);
          }
          checkInteger(errors, `${taskPath}.trigger.delay_s`, task.trigger.delay_s, 0);
          validateTriggerCondition(errors, `${taskPath}.trigger.condition`, task.trigger.condition);
        }

        validateOptionalBlocks(errors, warnings, taskPath, task);
        validateChildCredentialPolicy(errors, `${taskPath}.child_credential_policy`, task.child_credential_policy);
        if (checkOptionalObject(errors, `${taskPath}.verify`, task.verify)) {
          validateVerify(errors, `${taskPath}.verify`, task.verify);
        }
        if (task.target?.session_target === 'shell' && (task.intent?.mode === 'plan' || task.intent?.read_only)) {
          warnings.push({
            path: `${taskPath}.intent`,
            message: 'shell targets do not get a first-class planning boundary in every backend; intent may be advisory only'
          });
        }
        validateOnFailure(errors, warnings, `${taskPath}.on_failure`, task);
      }

      const validTaskIds = new Set(workflow.tasks.filter(isObject).map(task => task.id).filter(Boolean));
      const effectiveTaskIds = new Set();
      for (const [taskIndex, task] of workflow.tasks.entries()) {
        if (!isObject(task)) continue;
        if (task.id) {
          if (effectiveTaskIds.has(task.id)) {
            addError(errors, `${workflowPath}.tasks[${taskIndex}].id`, 'must be unique after shorthand expansion');
          }
          effectiveTaskIds.add(task.id);
        }
        if (task.on_failure) {
          const handlerId = onFailureTaskId(task);
          if (handlerId) {
            if (effectiveTaskIds.has(handlerId)) {
              addError(errors, `${workflowPath}.tasks[${taskIndex}].on_failure.id`, 'must be unique after shorthand expansion');
            }
            effectiveTaskIds.add(handlerId);
          }
        }
      }

      for (const [taskIndex, task] of workflow.tasks.entries()) {
        if (!isObject(task)) continue;
        if (isObject(task.trigger)) {
          if (task.trigger.parent === task.id) {
            addError(errors, `${workflowPath}.tasks[${taskIndex}].trigger.parent`, 'must not reference its own task id');
          } else if (task.trigger.parent && !validTaskIds.has(task.trigger.parent)) {
            addError(errors, `${workflowPath}.tasks[${taskIndex}].trigger.parent`, 'must reference another task id in the same workflow');
          }
        }
        if (task.approval?.required && !task.trigger) {
          warnings.push({
            path: `${workflowPath}.tasks[${taskIndex}].approval.required`,
            message: 'approval_required is most useful on triggered tasks; root scheduled tasks usually should not block on approval'
          });
        }
      }
    }
  }

  // Cross-reference validation: verify ref targets exist in profile arrays
  const identityProfileIds = new Set((manifest.identity_profiles || []).filter(p => p.id).map(p => p.id));
  const identityProfilesById = new Map((manifest.identity_profiles || []).filter(p => p.id).map(p => [p.id, p]));
  const proofProfileIds = new Set((manifest.authorization_proof_profiles || []).filter(p => p.id).map(p => p.id));
  const authzProfileIds = new Set((manifest.authorization_profiles || []).filter(p => p.id).map(p => p.id));
  const evidProfileIds = new Set((manifest.evidence_profiles || []).filter(p => p.id).map(p => p.id));
  const trustSatisfiabilityErrors = new Set();

  function checkRef(refPath, ref, profileSet, profileType) {
    if (ref != null && typeof ref === 'string' && !profileSet.has(ref)) {
      addError(errors, refPath, `references unknown ${profileType} profile "${ref}"`);
    }
  }

  if (Array.isArray(manifest.workflows)) {
    for (const [wi, wf] of manifest.workflows.entries()) {
      if (!isObject(wf)) continue;
      const wp = `$.workflows[${wi}]`;
      if (wf.identity?.ref) checkRef(`${wp}.identity.ref`, wf.identity.ref, identityProfileIds, 'identity');
      if (wf.authorization_proof?.ref) checkRef(`${wp}.authorization_proof.ref`, wf.authorization_proof.ref, proofProfileIds, 'authorization_proof');
      if (wf.authorization?.ref) checkRef(`${wp}.authorization.ref`, wf.authorization.ref, authzProfileIds, 'authorization');
      if (wf.evidence?.ref) checkRef(`${wp}.evidence.ref`, wf.evidence.ref, evidProfileIds, 'evidence');
      for (const [ti, task] of (wf.tasks || []).entries()) {
        if (!isObject(task)) continue;
        const tp = `${wp}.tasks[${ti}]`;
        if (task.identity?.ref) checkRef(`${tp}.identity.ref`, task.identity.ref, identityProfileIds, 'identity');
        if (task.authorization_proof?.ref) checkRef(`${tp}.authorization_proof.ref`, task.authorization_proof.ref, proofProfileIds, 'authorization_proof');
        if (task.authorization?.ref) checkRef(`${tp}.authorization.ref`, task.authorization.ref, authzProfileIds, 'authorization');
        if (task.evidence?.ref) checkRef(`${tp}.evidence.ref`, task.evidence.ref, evidProfileIds, 'evidence');
        if (isObject(task.on_failure)) {
          if (task.on_failure.identity?.ref) {
            checkRef(`${tp}.on_failure.identity.ref`, task.on_failure.identity.ref, identityProfileIds, 'identity');
          }
          if (task.on_failure.authorization_proof?.ref) {
            checkRef(
              `${tp}.on_failure.authorization_proof.ref`,
              task.on_failure.authorization_proof.ref,
              proofProfileIds,
              'authorization_proof'
            );
          }
          if (task.on_failure.authorization?.ref) {
            checkRef(`${tp}.on_failure.authorization.ref`, task.on_failure.authorization.ref, authzProfileIds, 'authorization');
          }
          if (task.on_failure.evidence?.ref) {
            checkRef(`${tp}.on_failure.evidence.ref`, task.on_failure.evidence.ref, evidProfileIds, 'evidence');
          }
        }

        const taskTrust = resolveTrustSatisfiability(
          identityProfilesById,
          wf.identity || null,
          task.identity || null,
          wf.contract || null,
          task.contract || null
        );
        if (taskTrust.requiredTrustLevel && taskTrust.maxAutonomy) {
          const cmp = compareTrustLevels(taskTrust.requiredTrustLevel, taskTrust.maxAutonomy);
          if (cmp != null && cmp > 0) {
            const errorPath = task.contract?.required_trust_level != null
              ? `${tp}.contract.required_trust_level`
              : `${wp}.contract.required_trust_level`;
            const message = `must not exceed resolved identity max_autonomy "${taskTrust.maxAutonomy}"`;
            const errorKey = `${errorPath}:${message}`;
            if (!trustSatisfiabilityErrors.has(errorKey)) {
              addError(errors, errorPath, message);
              trustSatisfiabilityErrors.add(errorKey);
            }
          }
        }

        if (isObject(task.on_failure)) {
          const handlerTrust = resolveTrustSatisfiability(
            identityProfilesById,
            wf.identity || null,
            task.on_failure.identity || null,
            wf.contract || null,
            task.on_failure.contract || null
          );
          if (handlerTrust.requiredTrustLevel && handlerTrust.maxAutonomy) {
            const cmp = compareTrustLevels(handlerTrust.requiredTrustLevel, handlerTrust.maxAutonomy);
            if (cmp != null && cmp > 0) {
              const errorPath = task.on_failure.contract?.required_trust_level != null
                ? `${tp}.on_failure.contract.required_trust_level`
                : `${wp}.contract.required_trust_level`;
              const message = `must not exceed resolved identity max_autonomy "${handlerTrust.maxAutonomy}"`;
              const errorKey = `${errorPath}:${message}`;
              if (!trustSatisfiabilityErrors.has(errorKey)) {
                addError(errors, errorPath, message);
                trustSatisfiabilityErrors.add(errorKey);
              }
            }
          }
        }
      }
    }
  }

  return { ok: errors.length === 0, errors, warnings };
}
