/**
 * Evidence payload builder.
 *
 * Builds canonical evidence payloads for attestation and provides
 * serialization utilities for deterministic signing.
 */

import {
  canonicalDigest,
  canonicalStringify,
  hashNullableString,
  hashString,
} from '../canonical.js';

export const EVIDENCE_PAYLOAD_SCHEMA = 'agentcli.evidence.payload';
export const EVIDENCE_PAYLOAD_VERSION = 1;
const SENSITIVE_FIELD = /(?:^|_)(?:access_token|refresh_token|id_token|token|secret|password|private_key|credentials?|cookie|client_assertion|api_key|authorization_header)(?:_|$)/i;
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;

function redactSensitiveEvidence(value, key = '') {
  if (SENSITIVE_FIELD.test(key)) {
    return {
      redacted: true,
      value_hash: value == null ? null : canonicalDigest(value),
    };
  }
  if (Array.isArray(value)) {
    return value.map(item => redactSensitiveEvidence(item));
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([entryKey, entryValue]) => [
        entryKey,
        redactSensitiveEvidence(entryValue, entryKey),
      ])
    );
  }
  return value;
}

function withoutRawCommandInputs(command = {}) {
  const {
    env,
    stdin,
    env_hash: providedEnvHash,
    stdin_hash: providedStdinHash,
    args,
    args_hashes: providedArgsHashes,
    ...safeCommand
  } = command;

  return {
    ...safeCommand,
    args_hashes: providedArgsHashes ?? (
      Array.isArray(args) ? args.map(value => hashString(value)) : null
    ),
    args_count: safeCommand.args_count ?? (Array.isArray(args) ? args.length : null),
    env_hash: providedEnvHash ?? (env == null ? null : canonicalDigest(env)),
    stdin_hash: providedStdinHash ?? hashNullableString(stdin),
  };
}

function withoutRawOutputs(value = {}) {
  const {
    stdout,
    stderr,
    structured,
    stdout_hash: providedStdoutHash,
    stderr_hash: providedStderrHash,
    structured_hash: providedStructuredHash,
    ...safeValue
  } = value;
  return {
    ...safeValue,
    stdout_hash: providedStdoutHash ?? hashNullableString(stdout),
    stderr_hash: providedStderrHash ?? hashNullableString(stderr),
    structured_hash: providedStructuredHash ?? (
      structured == null ? null : canonicalDigest(structured)
    ),
  };
}

function requiredString(value, field) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(`${field} must be a non-empty string`);
  }
  return value;
}

/**
 * Build the complete payload used by versioned execution evidence.
 *
 * Raw command environment values and stdin are never retained. Their hashes
 * bind the signed evidence to the exact inputs without turning the audit log
 * into a secret store.
 */
export function buildCompleteEvidencePayload({
  executionId,
  timestamp,
  source,
  manifest,
  manifestDigest,
  effectiveTask,
  effectiveTaskHash,
  handoffArtifactDigest = null,
  sourceRunId = null,
  sourceRunHandoffArtifactDigest = null,
  declaredIdentity = null,
  resolvedIdentity = null,
  authorizationProof = null,
  authorization = null,
  actorContext = null,
  contract = null,
  command,
  result,
  verify = null,
  complianceContext = {},
} = {}) {
  requiredString(executionId, 'executionId');
  requiredString(timestamp, 'timestamp');
  if (!source || typeof source !== 'object' || Array.isArray(source)) {
    throw new TypeError('source must be an object');
  }
  if (!command || typeof command !== 'object' || Array.isArray(command)) {
    throw new TypeError('command must be an object');
  }
  if (!result || typeof result !== 'object' || Array.isArray(result)) {
    throw new TypeError('result must be an object');
  }

  const computedManifestDigest = manifest == null ? null : canonicalDigest(manifest);
  const computedTaskHash = effectiveTask == null ? null : canonicalDigest(effectiveTask);
  if (manifestDigest && computedManifestDigest && manifestDigest !== computedManifestDigest) {
    throw new TypeError('manifestDigest does not match the provided manifest');
  }
  if (effectiveTaskHash && computedTaskHash && effectiveTaskHash !== computedTaskHash) {
    throw new TypeError('effectiveTaskHash does not match the provided effectiveTask');
  }
  const resolvedManifestDigest = manifestDigest ?? computedManifestDigest;
  const resolvedTaskHash = effectiveTaskHash ?? computedTaskHash;
  if (!resolvedManifestDigest) {
    throw new TypeError('manifest or manifestDigest is required');
  }
  if (!resolvedTaskHash) {
    throw new TypeError('effectiveTask or effectiveTaskHash is required');
  }

  return {
    schema: EVIDENCE_PAYLOAD_SCHEMA,
    version: EVIDENCE_PAYLOAD_VERSION,
    execution_id: executionId,
    timestamp,
    source,
    bindings: {
      manifest_digest: resolvedManifestDigest,
      effective_task_hash: resolvedTaskHash,
      ...(handoffArtifactDigest != null
        ? {
            handoff_artifact_digest: handoffArtifactDigest,
            source_run_id: sourceRunId,
            source_run_handoff_artifact_digest: sourceRunHandoffArtifactDigest,
          }
        : {}),
    },
    declared_identity: redactSensitiveEvidence(declaredIdentity),
    resolved_identity: redactSensitiveEvidence(resolvedIdentity),
    authorization_proof: redactSensitiveEvidence(authorizationProof),
    authorization: redactSensitiveEvidence(authorization),
    actor_context: redactSensitiveEvidence(actorContext),
    contract,
    command: withoutRawCommandInputs(command),
    result: withoutRawOutputs(result),
    verify: verify == null ? null : withoutRawOutputs(verify),
    compliance_context: complianceContext,
  };
}

export function validateCompleteEvidencePayload(payload) {
  const errors = [];
  const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { valid: false, errors: ['payload must be an object'] };
  }
  if (payload.schema !== EVIDENCE_PAYLOAD_SCHEMA) {
    errors.push(`schema must be "${EVIDENCE_PAYLOAD_SCHEMA}"`);
  }
  if (payload.version !== EVIDENCE_PAYLOAD_VERSION) {
    errors.push(`version must be ${EVIDENCE_PAYLOAD_VERSION}`);
  }
  for (const field of ['execution_id', 'timestamp']) {
    if (typeof payload[field] !== 'string' || payload[field].length === 0) {
      errors.push(`${field} must be a non-empty string`);
    }
  }
  if (!payload.source || typeof payload.source !== 'object' || Array.isArray(payload.source)) {
    errors.push('source must be an object');
  } else if (
    typeof payload.source.workflow_id !== 'string' ||
    typeof payload.source.task_id !== 'string' ||
    !payload.source.workflow_id ||
    !payload.source.task_id
  ) {
    errors.push('source must contain non-empty workflow_id and task_id');
  }
  if (
    !payload.bindings ||
    typeof payload.bindings.manifest_digest !== 'string' ||
    typeof payload.bindings.effective_task_hash !== 'string'
  ) {
    errors.push('bindings must contain manifest_digest and effective_task_hash');
  } else {
    for (const field of ['manifest_digest', 'effective_task_hash']) {
      if (!/^sha256:[a-f0-9]{64}$/.test(payload.bindings[field])) {
        errors.push(`bindings.${field} must be a SHA-256 digest`);
      }
    }
    for (const field of ['handoff_artifact_digest', 'source_run_handoff_artifact_digest']) {
      const value = payload.bindings[field];
      if (value != null && !/^sha256:[a-f0-9]{64}$/.test(value)) {
        errors.push(`bindings.${field} must be null or a SHA-256 digest`);
      }
    }
    if (payload.bindings.source_run_id != null
      && (typeof payload.bindings.source_run_id !== 'string'
        || payload.bindings.source_run_id.length === 0)) {
      errors.push('bindings.source_run_id must be null or a non-empty string');
    }
    if ((payload.bindings.source_run_id == null)
      !== (payload.bindings.source_run_handoff_artifact_digest == null)) {
      errors.push('source run id and source run artifact digest must be declared together');
    }
  }
  if (!payload.command || typeof payload.command !== 'object' || Array.isArray(payload.command)) {
    errors.push('command must be an object');
  } else {
    if (typeof payload.command.program !== 'string' || !payload.command.program) {
      errors.push('command.program must be a non-empty string');
    }
    if (!Array.isArray(payload.command.args_hashes)) {
      errors.push('command.args_hashes must be an array');
    }
    if (!Number.isInteger(payload.command.args_count) || payload.command.args_count < 0) {
      errors.push('command.args_count must be a non-negative integer');
    }
    if (!hasOwn(payload.command, 'env_hash')) {
      errors.push('command.env_hash is required');
    } else if (!/^sha256:[a-f0-9]{64}$/.test(payload.command.env_hash)) {
      errors.push('command.env_hash must be a SHA-256 digest');
    }
    if (!hasOwn(payload.command, 'stdin_hash')) {
      errors.push('command.stdin_hash is required');
    } else if (
      payload.command.stdin_hash !== null &&
      !/^sha256:[a-f0-9]{64}$/.test(payload.command.stdin_hash)
    ) {
      errors.push('command.stdin_hash must be null or a SHA-256 digest');
    }
  }
  if (!payload.result || typeof payload.result !== 'object' || Array.isArray(payload.result)) {
    errors.push('result must be an object');
  } else {
    for (const field of ['exit_code', 'timed_out', 'duration_ms', 'output_hash']) {
      if (!hasOwn(payload.result, field)) errors.push(`result.${field} is required`);
    }
    if (
      typeof payload.result.output_hash !== 'string' ||
      !/^sha256:[a-f0-9]{64}$/.test(payload.result.output_hash)
    ) {
      errors.push('result.output_hash must be a SHA-256 digest');
    }
  }
  if (!hasOwn(payload, 'verify')) {
    errors.push('verify field is required');
  }
  if (!hasOwn(payload, 'authorization_proof')) {
    errors.push('authorization_proof field is required');
  }
  if (!hasOwn(payload, 'authorization')) {
    errors.push('authorization field is required');
  }
  if (!hasOwn(payload, 'declared_identity')) {
    errors.push('declared_identity field is required');
  }
  if (!hasOwn(payload, 'resolved_identity')) {
    errors.push('resolved_identity field is required');
  }
  for (const field of ['actor_context', 'contract', 'compliance_context']) {
    if (!hasOwn(payload, field)) errors.push(`${field} field is required`);
  }
  return { valid: errors.length === 0, errors };
}

/**
 * Confirm that a verified signed payload belongs to its surrounding audit
 * record. This prevents transplanting a valid evidence envelope onto a
 * different execution record.
 */
export function validateEvidenceRecordBinding(payload, record) {
  const errors = [];
  const equalCanonical = (left, right) => canonicalStringify(left) === canonicalStringify(right);
  if (!payload || typeof payload !== 'object' || !record || typeof record !== 'object') {
    return { valid: false, errors: ['payload and audit record must be objects'] };
  }
  if (payload.execution_id !== record.execution_id) {
    errors.push('execution_id does not match the audit record');
  }
  if (payload.timestamp !== record.timestamp) {
    errors.push('timestamp does not match the audit record');
  }
  if (
    payload.source?.workflow_id !== record.source?.workflow_id ||
    payload.source?.task_id !== record.source?.task_id
  ) {
    errors.push('source does not match the audit record');
  }
  if (payload.bindings?.manifest_digest !== record.manifest_digest) {
    errors.push('manifest digest does not match the audit record');
  }
  if (payload.bindings?.effective_task_hash !== record.effective_task_hash) {
    errors.push('effective task hash does not match the audit record');
  }
  const payloadArtifactDigest = payload.bindings?.handoff_artifact_digest ?? null;
  const recordArtifactDigest = record.handoff_artifact_digest ?? null;
  const v4BindingRequired = [
    record.handoff_version,
    record.handoff?.version,
    record.handoff?.handoff_version,
  ].some(value => Number(value) === 4)
    || payloadArtifactDigest != null
    || recordArtifactDigest != null;
  if (v4BindingRequired) {
    if (!SHA256_PATTERN.test(recordArtifactDigest)) {
      errors.push('audit record handoff artifact digest must be a lowercase SHA-256 digest');
    }
    if (!SHA256_PATTERN.test(payloadArtifactDigest)) {
      errors.push('signed evidence handoff artifact digest must be a lowercase SHA-256 digest');
    }
  }
  if ((payload.bindings?.handoff_artifact_digest ?? null)
    !== (record.handoff_artifact_digest ?? null)) {
    errors.push('handoff artifact digest does not match the audit record');
  }
  const sourceRunMarker = record.source_run_required === true
    || record.child_run === true
    || record.is_child_run === true
    || record.parent_id != null
    || record.parent_run_id != null;
  const sourceRunFieldsPresent = payload.bindings?.source_run_id != null
    || payload.bindings?.source_run_handoff_artifact_digest != null
    || record.source_run_id != null
    || record.source_run_handoff_artifact_digest != null;
  const sourceRunRequired = sourceRunFieldsPresent || (v4BindingRequired && sourceRunMarker);
  if (sourceRunRequired) {
    if (typeof record.source_run_id !== 'string' || record.source_run_id.length === 0) {
      errors.push('audit record source run id must be a non-empty string');
    }
    if (typeof payload.bindings?.source_run_id !== 'string'
      || payload.bindings.source_run_id.length === 0) {
      errors.push('signed evidence source run id must be a non-empty string');
    }
    if (!SHA256_PATTERN.test(record.source_run_handoff_artifact_digest)) {
      errors.push('audit record source run artifact digest must be a lowercase SHA-256 digest');
    }
    if (!SHA256_PATTERN.test(payload.bindings?.source_run_handoff_artifact_digest)) {
      errors.push('signed evidence source run artifact digest must be a lowercase SHA-256 digest');
    }
  }
  if ((payload.bindings?.source_run_id ?? null) !== (record.source_run_id ?? null)) {
    errors.push('source run id does not match the audit record');
  }
  if ((payload.bindings?.source_run_handoff_artifact_digest ?? null)
    !== (record.source_run_handoff_artifact_digest ?? null)) {
    errors.push('source run artifact digest does not match the audit record');
  }
  const recordOutputHash = record.result?.output_hash ?? record.hashes?.result ?? null;
  if (payload.result?.output_hash !== recordOutputHash) {
    errors.push('result output hash does not match the audit record');
  }
  if (v4BindingRequired) {
    const payloadResult = payload.result;
    const recordResult = record.result;
    if (!payloadResult || typeof payloadResult !== 'object' || Array.isArray(payloadResult)) {
      errors.push('signed evidence result must be an object');
    }
    if (!recordResult || typeof recordResult !== 'object' || Array.isArray(recordResult)) {
      errors.push('audit record result must be an object');
    }
    if (!Object.hasOwn(payloadResult ?? {}, 'status')
      || typeof payloadResult?.status !== 'string'
      || payloadResult.status.length === 0) {
      errors.push('signed evidence result.status must be a non-empty string');
    }
    if (!Object.hasOwn(recordResult ?? {}, 'status')
      || typeof recordResult?.status !== 'string'
      || recordResult.status.length === 0) {
      errors.push('audit record result.status must be a non-empty string');
    }
    if ((payloadResult?.status ?? null) !== (recordResult?.status ?? null)) {
      errors.push('result.status does not match the signed evidence');
    }
    for (const [label, result] of [
      ['signed evidence', payloadResult],
      ['audit record', recordResult],
    ]) {
      if (!Object.hasOwn(result ?? {}, 'structured_hash')) {
        errors.push(`${label} result.structured_hash is required`);
      } else if (result.structured_hash !== null && !SHA256_PATTERN.test(result.structured_hash)) {
        errors.push(`${label} result.structured_hash must be null or a lowercase SHA-256 digest`);
      }
    }
    if ((payloadResult?.structured_hash ?? null) !== (recordResult?.structured_hash ?? null)) {
      errors.push('result.structured_hash does not match the signed evidence');
    }
  }

  const signedFieldMappings = [
    ['declared_identity', 'declared_identity'],
    ['resolved_identity', 'resolved_identity'],
    ['authorization_proof', 'authorization_proof'],
    ['authorization', 'authorization'],
    ['actor_context', 'actor_context'],
    ['contract', 'contract'],
  ];
  for (const [payloadField, recordField] of signedFieldMappings) {
    if (!equalCanonical(
      payload[payloadField],
      redactSensitiveEvidence(record[recordField] ?? null)
    )) {
      errors.push(`${recordField} does not match the signed evidence`);
    }
  }

  const expectedVerify = record.verify == null ? null : withoutRawOutputs(record.verify);
  if (!equalCanonical(payload.verify, expectedVerify)) {
    errors.push('verify result does not match the signed evidence');
  }

  for (const field of [
    'program', 'cwd', 'args_count', 'args_hashes', 'env_keys', 'env_hashes',
    'stdin_present', 'stdin_hash',
  ]) {
    const signedValue = field === 'stdin_present' && payload.command?.[field] === undefined
      ? payload.command?.stdin_hash != null
      : payload.command?.[field] ?? null;
    if (!equalCanonical(signedValue, record.command?.[field] ?? null)) {
      errors.push(`command.${field} does not match the signed evidence`);
    }
  }

  for (const field of [
    'exit_code', 'signal', 'timed_out', 'duration_ms', 'stdout_bytes',
    'stderr_bytes', 'output_hash',
  ]) {
    if (!equalCanonical(payload.result?.[field] ?? null, record.result?.[field] ?? null)) {
      errors.push(`result.${field} does not match the signed evidence`);
    }
  }
  return { valid: errors.length === 0, errors };
}

/**
 * Build a structured evidence payload from execution context.
 *
 * Only sections listed in bindTargets are included. Sections whose
 * value is null or undefined are also excluded.
 *
 * @param {object} params
 * @param {string} params.executionId         - Unique execution identifier.
 * @param {string} params.timestamp           - ISO 8601 timestamp.
 * @param {string} params.source              - Source identifier.
 * @param {object} params.declaredIdentity    - Declared identity block (provider, subject, trust_level).
 * @param {object} params.resolvedIdentity    - Resolved identity session description.
 * @param {object} params.authorizationProof  - Verification summary (method, issuer, verified, manifest_digest).
 * @param {object} params.authorization       - Phase 4.5 authorization decision.
 * @param {object} params.actorContext        - Canonical actor context (org, delegation, verification metadata).
 * @param {object} params.contract            - The contract block.
 * @param {object} params.command             - Command block (program, args, cwd).
 * @param {object} params.result              - Execution result block.
 * @param {object} params.complianceContext   - Compliance context fields.
 * @param {string[]} params.bindTargets       - Array of section keys to bind into the payload.
 * @returns {object} The structured evidence payload.
 */
export function buildEvidencePayload({
  executionId,
  timestamp,
  source,
  declaredIdentity,
  resolvedIdentity,
  authorizationProof,
  authorization,
  actorContext,
  contract,
  command,
  result,
  complianceContext,
  bindTargets = [],
} = {}) {
  const sectionMap = {
    execution_id: executionId,
    declared_identity: declaredIdentity,
    resolved_identity: resolvedIdentity,
    authorization_proof: authorizationProof,
    actor_context: actorContext,
    contract: contract,
    command: command,
    result: result,
    authorization: authorization,
    compliance_context: complianceContext,
  };

  const payload = {};

  // Always include timestamp and source when present, as they are envelope metadata
  if (timestamp !== null && timestamp !== undefined) {
    payload.timestamp = timestamp;
  }
  if (source !== null && source !== undefined) {
    payload.source = source;
  }

  for (const key of bindTargets) {
    const value = sectionMap[key];
    if (value === null || value === undefined) continue;
    payload[key] = value;
  }

  return payload;
}

/**
 * Serialize a payload object to a string.
 *
 * @param {object} payload  - The payload object to serialize.
 * @param {string} format   - Serialization format: 'canonical-json' or 'json'.
 * @returns {string} The serialized payload string.
 */
export function serializePayload(payload, format = 'canonical-json') {
  if (format === 'canonical-json') {
    return canonicalStringify(payload);
  }
  return JSON.stringify(payload);
}

/**
 * Collect compliance context fields from the execution context.
 *
 * For each enabled field in contextConfig, pulls the value from ctx.compliance_context
 * if available, or sets it to null as the spec requires for missing values.
 *
 * @param {object} ctx           - Execution context (should contain compliance_context).
 * @param {object} contextConfig - Evidence profile's payload.context configuration.
 * @returns {object} Object with enabled compliance context fields.
 */
export function collectComplianceContext(ctx = {}, contextConfig = {}) {
  const complianceSource = ctx.compliance_context || {};
  const result = {};

  const knownFields = ['model_version', 'policy_version', 'tool_versions', 'data_provenance'];

  for (const field of knownFields) {
    if (contextConfig[field]) {
      result[field] = complianceSource[field] !== undefined ? complianceSource[field] : null;
    }
  }

  return result;
}
