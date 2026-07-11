export const ERROR_TYPES = Object.freeze([
  'validation_error',
  'unknown_command',
  'invalid_argument',
  'parse_error',
  'internal_error',
]);

export const ERROR_CODES = Object.freeze([
  ...ERROR_TYPES,
  'approval_required',
  'approval_auto_rejected',
  'approval_signature_invalid',
  'approval_scope_mismatch',
  'approval_lock_timeout',
  'approval_log_invalid',
  'policy_forbids_approval',
  'authorization_proof_failed',
  'authorization_proof_invalid',
  'unknown_verifier',
  'authorization_denied',
  'authorization_escalation_required',
  'authorization_error',
  'unknown_authorization_provider',
  'identity_resolution_failed',
  'identity_profile_invalid',
  'identity_delegation_invalid',
  'unknown_identity_provider',
  'identity_provider_error',
  'resolution_failed',
  'token_not_found',
  'token_file_empty',
  'token_file_not_found',
  'token_request_failed',
  'presentation_format_unsupported',
  'presentation_binding_invalid',
  'presentation_source_forbidden',
  'presentation_binding_missing',
  'presentation_target_unsupported',
  'presentation_target_invalid',
  'presentation_stdin_conflict',
  'evidence_failed',
  'verify_failed',
  'sandbox_unavailable',
  'sandbox_enforcement_unavailable',
  'sandbox_path_escape',
  'sandbox_path_invalid',
  'contract_violation',
  'trust_level_insufficient',
  'unsupported_capability',
  'capability_mismatch',
  'scheduler_error',
  'delegation_error',
  'no_runtime',
]);

const KNOWN_CODES = new Set(ERROR_CODES);

export class AgentcliError extends Error {
  constructor(message, { code = 'internal_error', errorType, cause, ...extra } = {}) {
    super(message, cause ? { cause } : undefined);
    this.name = 'AgentcliError';
    this.code = KNOWN_CODES.has(code) ? code : 'internal_error';
    this.error_type = errorType || errorTypeForCode(this.code);
    Object.assign(this, extra);
  }
}

export function errorTypeForCode(code) {
  if (ERROR_TYPES.includes(code)) return code;
  if (code === 'no_runtime' || code === 'unsupported_capability') return 'invalid_argument';
  if (code === 'approval_lock_timeout' || code === 'scheduler_error') return 'internal_error';
  if (KNOWN_CODES.has(code)) return 'validation_error';
  return 'internal_error';
}

export function makeError(message, code = 'internal_error', extra = {}) {
  return new AgentcliError(message, { code, ...extra });
}

export function normalizeError(error) {
  const source = error instanceof Error ? error : new Error(String(error));
  const requestedCode = typeof source.code === 'string' ? source.code : 'internal_error';
  const code = KNOWN_CODES.has(requestedCode) ? requestedCode : 'internal_error';
  return {
    message: source.message || 'Internal error',
    code,
    error_type: source.error_type || errorTypeForCode(code),
    ...(source.validation ? { validation: source.validation } : {}),
    ...(source.cleanup_warnings ? { cleanup_warnings: source.cleanup_warnings } : {}),
  };
}
