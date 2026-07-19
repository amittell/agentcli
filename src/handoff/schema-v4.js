export const HANDOFF_V4_SCHEMA = 'openclaw.scheduler.handoff-artifact';
export const HANDOFF_V4_ARTIFACT_SCHEMA_VERSION = 1;
export const HANDOFF_V4_VERSION = 4;
export const HANDOFF_V4_SCHEDULER_SCHEMA_MIN = 29;
export const HANDOFF_V4_CANONICALIZATION = 'json-sort-v1';
export const HANDOFF_V4_CANONICALIZATION_VERSION = 1;
export const HANDOFF_V4_EXECUTION_BINDING_VERSION = 2;
export const HANDOFF_V4_SCHEDULER_JOB_BINDING_VERSION = 1;

const JSON_SCHEMA_DIALECT = 'https://json-schema.org/draft/2020-12/schema';
const SHA256_PATTERN = '^sha256:[0-9a-f]{64}$';

const nullableString = Object.freeze({ type: ['string', 'null'] });
const nullableInteger = Object.freeze({ type: ['integer', 'null'] });
const nullableNumber = Object.freeze({ type: ['number', 'null'] });
const digest = Object.freeze({ type: 'string', pattern: SHA256_PATTERN });
const nullableDigest = Object.freeze({ type: ['string', 'null'], pattern: SHA256_PATTERN });

function strictObject(properties, required = Object.keys(properties)) {
  return {
    type: 'object',
    required,
    properties,
    additionalProperties: false,
  };
}

const presentationMedium = {
  type: 'string',
  enum: ['none', 'env', 'temp-file', 'stdin', 'gateway-env-header'],
};

const presentationBindingSchema = strictObject({
  name: nullableString,
  medium: presentationMedium,
  env_key: nullableString,
  file_name: nullableString,
  source_hash: nullableDigest,
  required: { type: 'boolean' },
  redact: { type: 'boolean' },
  format: { type: 'string', minLength: 1 },
});

export const HANDOFF_V4_JSON_SCHEMA = Object.freeze({
  $schema: JSON_SCHEMA_DIALECT,
  title: 'openclaw-scheduler handoff v4 artifact',
  description: 'Immutable, canonical execution contract consumed by openclaw-scheduler.',
  ...strictObject({
    schema: { const: HANDOFF_V4_SCHEMA },
    artifact_schema_version: { const: HANDOFF_V4_ARTIFACT_SCHEMA_VERSION },
    handoff_version: { const: HANDOFF_V4_VERSION },
    scheduler_schema_min: { const: HANDOFF_V4_SCHEDULER_SCHEMA_MIN },
    canonicalization: strictObject({
      name: { const: HANDOFF_V4_CANONICALIZATION },
      version: { const: HANDOFF_V4_CANONICALIZATION_VERSION },
      digest: { const: 'sha256' },
      undefined: { const: 'null' },
    }),
    execution_binding_version: { const: HANDOFF_V4_EXECUTION_BINDING_VERSION },
    scheduler_job_binding: strictObject({
      version: { const: HANDOFF_V4_SCHEDULER_JOB_BINDING_VERSION },
      digest,
    }),
    manifest: strictObject({
      version: { type: 'string', minLength: 1 },
      digest,
      workflow_id: { type: 'string', minLength: 1 },
      task_id: { type: 'string', minLength: 1 },
    }),
    compiled: strictObject({
      target: { const: 'openclaw-scheduler' },
      job_id: { type: 'string', minLength: 1 },
      effective_task_hash: digest,
      source: strictObject({
        workflow_id: { type: 'string', minLength: 1 },
        task_id: { type: 'string', minLength: 1 },
      }),
    }),
    lifecycle: strictObject({
      enabled: { type: 'boolean' },
      delete_after_run: { type: 'boolean' },
      target: strictObject({
        session_target: { type: 'string', enum: ['main', 'isolated', 'shell'] },
        agent_id: nullableString,
        payload_kind: { type: 'string', enum: ['systemEvent', 'agentTurn', 'shellCommand'] },
      }),
    }),
    command: strictObject({
      kind: { type: 'string', enum: ['shell', 'prompt', 'system'] },
      program: nullableString,
      args_count: { type: 'integer', minimum: 0 },
      args_sha256: { type: 'array', items: digest },
      argv_sha256: nullableDigest,
      cwd: nullableString,
      stdin_sha256: nullableDigest,
      prompt_sha256: nullableDigest,
      input_sha256: nullableDigest,
      payload_message_sha256: digest,
      env: strictObject({
        declared_env_sha256: nullableDigest,
        effective_env_keys: {
          type: 'array',
          items: { type: 'string', minLength: 1 },
          uniqueItems: true,
        },
        effective_env_value_sha256: {
          type: 'object',
          propertyNames: { type: 'string', minLength: 1 },
          additionalProperties: digest,
        },
      }),
    }),
    runtime: strictObject({
      timeout_ms: { type: 'integer', minimum: 1 },
      instance_id: strictObject({
        kind: { const: 'deferred' },
        source: { const: 'run.id' },
      }),
    }),
    approval: strictObject({
      required: { type: 'boolean' },
      timeout_s: nullableInteger,
      auto: { type: ['string', 'null'], enum: ['approve', 'reject', null] },
      risk_level: { type: ['string', 'null'], enum: ['low', 'medium', 'high', null] },
      approver_scope: nullableString,
    }),
    identity: strictObject({
      ref: nullableString,
      provider: nullableString,
      scope: nullableString,
      subject_kind: nullableString,
      subject_principal: nullableString,
      subject_hash: nullableDigest,
      auth_hash: nullableDigest,
      trust_level: nullableString,
      delegation_mode: nullableString,
      presentation: strictObject({
        mode: nullableString,
        handoff: presentationMedium,
        bindings: { type: 'array', items: presentationBindingSchema },
        default_redaction: { type: ['boolean', 'null'] },
        cleanup: { type: 'string', enum: ['always', 'on-success', 'never'] },
      }),
    }),
    contract: strictObject({
      required_trust_level: nullableString,
      trust_enforcement: nullableString,
      sandbox: { type: ['string', 'null'], enum: ['none', 'permissive', 'strict', null] },
      allowed_paths_sha256: nullableDigest,
      network: { type: ['string', 'null'], enum: ['unrestricted', 'restricted', 'none', null] },
      max_cost_usd: nullableNumber,
      audit: { type: ['string', 'null'], enum: ['none', 'on-failure', 'always', null] },
      postcondition: strictObject({
        output_format: { type: ['string', 'null'], enum: ['json', 'ndjson', 'text', null] },
        verify_shell_sha256: nullableDigest,
        verify_timeout_s: nullableInteger,
        verify_on_failure: { type: ['string', 'null'], enum: ['error', 'warn', null] },
      }),
    }),
    authorization_proof: strictObject({
      ref: nullableString,
      method: nullableString,
      issuer: nullableString,
      audience: nullableString,
      claims_hash: nullableDigest,
      proof_source_hash: nullableDigest,
      verification_context_hash: nullableDigest,
      artifact_binding_required: { type: 'boolean' },
      replay_protection_required: { type: 'boolean' },
      revocation_check_required: { type: 'boolean' },
    }, [
      'ref',
      'method',
      'issuer',
      'audience',
      'claims_hash',
      'proof_source_hash',
      'artifact_binding_required',
      'replay_protection_required',
      'revocation_check_required',
    ]),
    authorization: strictObject({
      ref: nullableString,
      provider: nullableString,
      policy_digest: nullableDigest,
      on_error: nullableString,
      request_hash: nullableDigest,
      decision_hash: nullableDigest,
    }),
    evidence: strictObject({
      ref: nullableString,
      provider: nullableString,
      methods: { type: 'array', items: { type: 'string', minLength: 1 }, uniqueItems: true },
      payload_bind: { type: 'array', items: { type: 'string', minLength: 1 }, uniqueItems: true },
      payload_hash: nullableDigest,
      provider_config_hash: nullableDigest,
      verify_required: { type: 'boolean' },
      retention: nullableString,
      signed_or_provider_verified_required: { type: 'boolean' },
    }, [
      'ref',
      'provider',
      'methods',
      'payload_bind',
      'verify_required',
      'retention',
      'signed_or_provider_verified_required',
    ]),
    verification: strictObject({
      shell_sha256: nullableDigest,
      timeout_s: nullableInteger,
      on_failure: { type: ['string', 'null'], enum: ['error', 'warn', null] },
    }),
    output: strictObject({
      format: { type: ['string', 'null'], enum: ['json', 'ndjson', 'text', null] },
      store_limit_bytes: nullableInteger,
      excerpt_limit_bytes: nullableInteger,
      summary_limit_bytes: nullableInteger,
      offload_threshold_bytes: nullableInteger,
    }),
    child_credential_policy: {
      type: ['string', 'null'],
      enum: ['none', 'inherit', 'downscope', 'independent', null],
    },
    intent: strictObject({
      mode: { type: 'string', enum: ['execute', 'plan'] },
      read_only: { type: 'boolean' },
    }),
    delegation: strictObject({
      mode: nullableString,
      source_binding: { const: 'source_run_id' },
      max_depth: { type: 'integer', minimum: 1 },
      target_scope: nullableString,
      allowed_delegators: {
        type: 'array',
        items: { type: 'string', minLength: 1 },
        uniqueItems: true,
      },
      allowed_delegators_hash: digest,
      require_grant_per_hop: { type: 'boolean' },
    }),
  }),
});

function jsonType(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (Number.isInteger(value)) return 'integer';
  if (typeof value === 'number') return 'number';
  return typeof value;
}

function matchesType(value, expected) {
  if (expected === 'number') return typeof value === 'number' && Number.isFinite(value);
  if (expected === 'integer') return Number.isInteger(value);
  if (expected === 'object') return value !== null && typeof value === 'object' && !Array.isArray(value);
  if (expected === 'array') return Array.isArray(value);
  if (expected === 'null') return value === null;
  return typeof value === expected;
}

function validateNode(value, schema, path, errors) {
  const expectedTypes = schema.type == null
    ? []
    : Array.isArray(schema.type)
      ? schema.type
      : [schema.type];
  if (expectedTypes.length > 0 && !expectedTypes.some(type => matchesType(value, type))) {
    errors.push(`${path} must be ${expectedTypes.join(' or ')}, received ${jsonType(value)}`);
    return;
  }
  if (Object.hasOwn(schema, 'const') && !Object.is(value, schema.const)) {
    errors.push(`${path} must equal ${JSON.stringify(schema.const)}`);
  }
  if (schema.enum && !schema.enum.some(candidate => Object.is(candidate, value))) {
    errors.push(`${path} must be one of ${schema.enum.map(candidate => JSON.stringify(candidate)).join(', ')}`);
  }
  if (typeof value === 'string') {
    if (schema.minLength != null && value.length < schema.minLength) {
      errors.push(`${path} must contain at least ${schema.minLength} character(s)`);
    }
    if (schema.pattern && !new RegExp(schema.pattern, 'u').test(value)) {
      errors.push(`${path} must match ${schema.pattern}`);
    }
  }
  if (typeof value === 'number' && schema.minimum != null && value < schema.minimum) {
    errors.push(`${path} must be at least ${schema.minimum}`);
  }
  if (Array.isArray(value)) {
    if (schema.minItems != null && value.length < schema.minItems) {
      errors.push(`${path} must contain at least ${schema.minItems} item(s)`);
    }
    if (schema.uniqueItems === true) {
      const unique = new Set(value.map(item => JSON.stringify(item)));
      if (unique.size !== value.length) errors.push(`${path} must contain unique items`);
    }
    if (schema.items) {
      value.forEach((item, index) => validateNode(item, schema.items, `${path}[${index}]`, errors));
    }
  }
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const properties = schema.properties ?? {};
    for (const required of schema.required ?? []) {
      if (!Object.hasOwn(value, required)) errors.push(`${path}.${required} is required`);
    }
    for (const [key, child] of Object.entries(value)) {
      if (Object.hasOwn(properties, key)) {
        validateNode(child, properties[key], `${path}.${key}`, errors);
      } else if (schema.additionalProperties === false) {
        errors.push(`${path}.${key} is not allowed`);
      } else if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
        validateNode(child, schema.additionalProperties, `${path}.${key}`, errors);
      }
    }
    if (schema.propertyNames) {
      for (const key of Object.keys(value)) {
        validateNode(key, schema.propertyNames, `${path} property name`, errors);
      }
    }
  }
}

export function validateHandoffV4Structure(payload) {
  const errors = [];
  validateNode(payload, HANDOFF_V4_JSON_SCHEMA, 'artifact', errors);
  return errors;
}
