/**
 * Versioned field lists for openclaw-scheduler job specs.
 *
 * These live in a standalone module so both the compiler and the apply
 * layer can import them without creating a circular dependency chain.
 */

export const SCHEDULER_FIELDS_V1 = [
  'id', 'name', 'enabled',
  'schedule_cron', 'schedule_tz',
  'session_target', 'agent_id',
  'payload_kind', 'payload_message', 'payload_model', 'payload_thinking',
  'execution_intent', 'execution_read_only',
  'run_timeout_ms', 'overlap_policy', 'max_retries',
  'max_queued_dispatches', 'max_pending_approvals', 'max_trigger_fanout',
  'delivery_mode', 'delivery_channel', 'delivery_to', 'delivery_opt_out_reason', 'delivery_guarantee',
  'origin',
  'parent_id', 'trigger_on', 'trigger_delay_s', 'trigger_condition',
  'approval_required', 'approval_timeout_s', 'approval_auto',
  'context_retrieval', 'context_retrieval_limit',
  'output_store_limit_bytes', 'output_excerpt_limit_bytes', 'output_summary_limit_bytes', 'output_offload_threshold_bytes',
  'preferred_session_key',
  'delete_after_run',
];

export const SCHEDULER_FIELDS_V02 = [
  'identity_principal', 'identity_run_as', 'identity_attestation',
  'identity_ref', 'identity_subject_kind', 'identity_subject_principal',
  'identity_trust_level', 'identity_delegation_mode', 'identity',
  'authorization_proof_ref', 'authorization_proof',
  'authorization_ref', 'authorization',
  'evidence_ref', 'evidence',
  'contract_required_trust_level', 'contract_trust_enforcement',
  'contract_sandbox', 'contract_allowed_paths', 'contract_network',
  'contract_max_cost_usd', 'contract_audit',
  'child_credential_policy',
];

export const SCHEDULER_FIELD_VERSIONS = {
  '1': SCHEDULER_FIELDS_V1,
  '2': [...SCHEDULER_FIELDS_V1, ...SCHEDULER_FIELDS_V02],
};
