/**
 * Evidence payload builder.
 *
 * Builds canonical evidence payloads for attestation and provides
 * serialization utilities for deterministic signing.
 */

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
    return JSON.stringify(sortKeysDeep(payload));
  }
  return JSON.stringify(payload);
}

/**
 * Recursively sort all object keys in a value.
 * Arrays preserve element order; objects get alphabetically sorted keys.
 *
 * @param {*} value - The value to sort.
 * @returns {*} A new value with all object keys sorted.
 */
function sortKeysDeep(value) {
  if (value === null || value === undefined) {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map(item => sortKeysDeep(item));
  }

  if (typeof value === 'object') {
    const sorted = {};
    const keys = Object.keys(value).sort();
    for (const key of keys) {
      sorted[key] = sortKeysDeep(value[key]);
    }
    return sorted;
  }

  return value;
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
