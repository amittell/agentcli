export const MANIFEST_VERSION = '0.2';

const nullableString = { type: 'string', nullable: true };
const nullableToken = { type: 'string', nullable: true, format: 'token', note: 'restricted to /^[A-Za-z0-9@:_./-]+$/' };
const nullableBoolean = { type: 'boolean', nullable: true };

const targetField = {
  type: 'object',
  required: ['session_target'],
  fields: {
    session_target: { type: 'string', enum: ['main', 'isolated', 'shell'] },
    agent_id: nullableToken,
    payload_kind: { type: 'string', enum: ['systemEvent', 'agentTurn', 'shellCommand'], nullable: true }
  }
};

const modelPolicyField = {
  type: 'object',
  nullable: true,
  fields: {
    provider: nullableToken,
    model: nullableToken,
    thinking: nullableToken
  }
};

const intentField = {
  type: 'object',
  nullable: true,
  fields: {
    mode: { type: 'string', enum: ['execute', 'plan'], nullable: true },
    read_only: nullableBoolean
  }
};

const outputField = {
  type: 'object',
  nullable: true,
  fields: {
    preview_bytes: { type: 'integer', min: 64, nullable: true },
    offload: { type: 'string', enum: ['auto', 'always', 'never'], nullable: true },
    retrieve: { type: 'string', enum: ['inline', 'on-demand'], nullable: true },
    format: { type: 'string', enum: ['json', 'ndjson', 'text'], nullable: true, note: 'Expected output format from the wrapped tool. When json or ndjson, exec parses stdout and includes structured result.' }
  }
};

const budgetsField = {
  type: 'object',
  nullable: true,
  fields: {
    max_iterations: { type: 'integer', min: 1, nullable: true },
    max_fanout: { type: 'integer', min: 1, nullable: true },
    max_context_items: { type: 'integer', min: 1, nullable: true },
    max_pending_approvals: { type: 'integer', min: 1, nullable: true },
    max_queued_dispatches: { type: 'integer', min: 1, nullable: true }
  }
};

const deliveryField = {
  type: 'object',
  nullable: true,
  fields: {
    mode: { type: 'string', enum: ['announce', 'announce-always', 'none'], nullable: true },
    channel: nullableToken,
    to: nullableToken
  }
};

const reliabilityField = {
  type: 'object',
  nullable: true,
  fields: {
    guarantee: { type: 'string', enum: ['at-most-once', 'at-least-once'], nullable: true },
    max_retries: { type: 'integer', min: 0, nullable: true },
    overlap_policy: { type: 'string', enum: ['skip', 'allow', 'queue'], nullable: true }
  }
};

const runtimeField = {
  type: 'object',
  nullable: true,
  fields: {
    timeout_ms: { type: 'integer', min: 1, nullable: true }
  }
};

const approvalField = {
  type: 'object',
  nullable: true,
  fields: {
    required: nullableBoolean,
    policy: { type: 'string', enum: ['manual', 'auto-approve', 'auto-reject'], nullable: true },
    risk_level: { type: 'string', enum: ['low', 'medium', 'high'], nullable: true },
    approver_scope: nullableToken,
    timeout_s: { type: 'integer', min: 1, nullable: true },
    auto: { type: 'string', enum: ['approve', 'reject'], nullable: true }
  }
};

const contextField = {
  type: 'object',
  nullable: true,
  fields: {
    retrieval: { type: 'string', enum: ['none', 'recent', 'hybrid'], nullable: true },
    limit: { type: 'integer', min: 1, nullable: true }
  }
};

const sessionField = {
  type: 'object',
  nullable: true,
  fields: {
    preferred_key: nullableToken
  }
};

const childCredentialPolicyField = {
  type: 'string',
  enum: ['none', 'inherit', 'downscope', 'independent'],
  nullable: true,
};

const identityField = {
  type: 'object',
  nullable: true,
  fields: {
    principal: nullableToken,
    run_as: nullableToken,
    attestation: nullableString
  }
};

const contractField = {
  type: 'object',
  nullable: true,
  fields: {
    sandbox: { type: 'string', enum: ['none', 'permissive', 'strict'], nullable: true },
    allowed_paths: { type: 'array', nullable: true, items: { type: 'string' } },
    network: { type: 'string', enum: ['unrestricted', 'restricted', 'none'], nullable: true },
    max_cost_usd: { type: 'number', min: 0, nullable: true },
    audit: { type: 'string', enum: ['none', 'on-failure', 'always'], nullable: true }
  }
};

const shellField = {
  type: 'object',
  nullable: true,
  required: ['program'],
  fields: {
    program: { type: 'string', format: 'token', note: 'restricted to /^[A-Za-z0-9@:_./-]+$/' },
    args: {
      type: 'array',
      nullable: true,
      items: { type: 'string' }
    },
    env: {
      type: 'object',
      nullable: true,
      values: { type: 'string' }
    },
    cwd: nullableString,
    stdin: nullableString
  }
};

const verifyField = {
  type: 'object',
  nullable: true,
  required: ['shell'],
  fields: {
    shell: { type: 'string', note: 'Shell command to run for post-completion verification' },
    timeout_seconds: { type: 'integer', min: 1, nullable: true, note: 'Max time for verify command (default: 30)' },
    on_failure: { type: 'string', enum: ['error', 'warn'], nullable: true, note: 'Behavior when verify fails (default: error)' }
  }
};

const onFailureField = {
  type: 'object',
  nullable: true,
  fields: {
    id: nullableString,
    name: nullableString,
    enabled: nullableBoolean,
    prompt: nullableString,
    command: { type: 'string', removed: true, note: 'use shell.program and shell.args' },
    shell: shellField,
    delay_s: { type: 'integer', min: 0, nullable: true },
    condition: nullableString,
    runtime: runtimeField,
    model_policy: modelPolicyField,
    intent: intentField,
    output: outputField,
    budgets: budgetsField,
    delivery: deliveryField,
    reliability: reliabilityField,
    approval: approvalField,
    context: contextField,
    session: sessionField,
    identity: identityField,
    contract: contractField,
    target: {
      type: 'object',
      nullable: true,
      required: ['session_target'],
      fields: targetField.fields
    },
    delete_after_run: nullableBoolean
  }
};

export const MANIFEST_SCHEMA = {
  manifest: {
    type: 'object',
    required: ['version', 'workflows'],
    fields: {
      version: { type: 'string', const: MANIFEST_VERSION },
      workflows: { type: 'array', minItems: 1 }
    }
  },
  workflow: {
    type: 'object',
    required: ['id', 'name', 'tasks'],
    fields: {
      id: { type: 'string' },
      name: { type: 'string' },
      model_policy: modelPolicyField,
      identity: identityField,
      contract: contractField,
      tasks: { type: 'array', minItems: 1 }
    }
  },
  task: {
    type: 'object',
    required: ['id', 'name', 'target'],
    note: 'Exactly one of schedule or trigger must be present.',
    fields: {
      id: { type: 'string' },
      name: { type: 'string' },
      enabled: nullableBoolean,
      prompt: nullableString,
      command: { type: 'string', removed: true, note: 'use shell.program and shell.args' },
      shell: shellField,
      target: targetField,
      model_policy: modelPolicyField,
      intent: intentField,
      output: outputField,
      budgets: budgetsField,
      schedule: {
        type: 'object',
        nullable: true,
        required: ['cron'],
        fields: {
          cron: { type: 'string' },
          tz: nullableString
        }
      },
      trigger: {
        type: 'object',
        nullable: true,
        required: ['parent', 'on'],
        fields: {
          parent: { type: 'string' },
          on: { type: 'string', enum: ['success', 'failure', 'complete'] },
          delay_s: { type: 'integer', min: 0, nullable: true },
          condition: nullableString
        }
      },
      delivery: deliveryField,
      reliability: reliabilityField,
      runtime: runtimeField,
      approval: approvalField,
      context: contextField,
      session: sessionField,
      identity: identityField,
      contract: contractField,
      on_failure: onFailureField,
      delete_after_run: nullableBoolean
    }
  },
  schedulerJob: {
    type: 'object',
    fields: {
      id: { type: 'string', note: 'sha256(workflowId:taskId) truncated to 32 hex chars' },
      source: {
        type: 'object',
        fields: {
          workflow_id: { type: 'string' },
          task_id: { type: 'string' }
        }
      },
      name: { type: 'string' },
      enabled: { type: 'integer', note: '1 or 0' },
      schedule_cron: nullableString,
      schedule_tz: nullableString,
      session_target: { type: 'string' },
      agent_id: { type: 'string' },
      payload_kind: { type: 'string' },
      payload_message: { type: 'string' },
      payload_model: nullableString,
      payload_thinking: nullableString,
      execution_intent: nullableString,
      execution_read_only: { type: 'integer', nullable: true, note: '1 or 0' },
      run_timeout_ms: { type: 'integer', nullable: true },
      overlap_policy: nullableString,
      max_retries: { type: 'integer', nullable: true },
      max_queued_dispatches: { type: 'integer', nullable: true },
      max_pending_approvals: { type: 'integer', nullable: true },
      max_trigger_fanout: { type: 'integer', nullable: true },
      delivery_mode: nullableString,
      delivery_channel: nullableString,
      delivery_to: nullableString,
      delivery_opt_out_reason: nullableString,
      delivery_guarantee: nullableString,
      origin: nullableString,
      parent_id: nullableString,
      trigger_on: nullableString,
      trigger_delay_s: { type: 'integer', nullable: true },
      trigger_condition: nullableString,
      approval_required: { type: 'integer', nullable: true, note: '1 or 0' },
      approval_timeout_s: { type: 'integer', nullable: true },
      approval_auto: nullableString,
      context_retrieval: nullableString,
      context_retrieval_limit: { type: 'integer', nullable: true },
      output_store_limit_bytes: { type: 'integer', nullable: true },
      output_excerpt_limit_bytes: { type: 'integer', nullable: true },
      output_summary_limit_bytes: { type: 'integer', nullable: true },
      output_offload_threshold_bytes: { type: 'integer', nullable: true },
      preferred_session_key: nullableString,
      identity_principal: nullableToken,
      identity_run_as: nullableToken,
      identity_attestation: nullableString,
      contract_sandbox: nullableString,
      contract_allowed_paths: nullableString,
      contract_network: nullableString,
      contract_max_cost_usd: { type: 'number', nullable: true },
      contract_audit: nullableString,
      delete_after_run: { type: 'integer', nullable: true, note: '1 or 0' }
    }
  },
  standalonePlan: {
    type: 'object',
    fields: {
      target: { type: 'string', const: 'standalone' },
      version: { type: 'string', const: '0.2' },
      capabilities: {
        type: 'object',
        fields: {
          authoring: { type: 'boolean' },
          planning: { type: 'boolean' },
          runtime_execution: { type: 'boolean' },
          rpc: { type: 'boolean' },
          model_policy: { type: 'boolean' },
          execution_intent: { type: 'boolean' },
          output_hints: { type: 'boolean' },
          budgets: { type: 'boolean' }
        }
      },
      workflows: {
        type: 'array',
        minItems: 1,
        items: {
          type: 'object',
          fields: {
            id: { type: 'string' },
            name: { type: 'string' },
            tasks: { type: 'array', note: 'normalizedTaskPlan objects with id, source, invocation, execution, intent, output, budgets, delivery, reliability, runtime, approval, context, session, identity, contract, delete_after_run, parent_compiled_id' },
            edges: { type: 'array', note: 'trigger edges with from, to, on, condition, delay_s fields' }
          }
        }
      },
      explain: { type: 'array', nullable: true, note: 'present when includeExplain is true' }
    }
  },
  rpcRequest: {
    type: 'object',
    required: ['jsonrpc', 'method'],
    fields: {
      jsonrpc: { type: 'string', const: '2.0' },
      id: { type: ['string', 'number'], nullable: true, note: 'JSON-RPC 2.0 allows string or integer IDs' },
      method: { type: 'string' },
      params: { type: 'object', nullable: true }
    }
  },
  rpcResponse: {
    type: 'object',
    required: ['jsonrpc'],
    fields: {
      jsonrpc: { type: 'string', const: '2.0' },
      id: { type: ['string', 'number'], nullable: true, note: 'JSON-RPC 2.0 allows string or integer IDs' },
      result: { type: 'object', nullable: true },
      error: { type: 'object', nullable: true }
    }
  }
};

// -- v0.2 schema field definitions --

/**
 * v0.1 identity field (flat principal/run_as/attestation).
 */
export const identityFieldV1 = identityField;

/**
 * Value-from reference: a field that can resolve its value from env, file, or literal.
 */
export const valueFromField = {
  type: 'object',
  nullable: true,
  fields: {
    env: nullableString,
    file: nullableString,
    literal: nullableString,
    command: nullableString,
  },
};

/**
 * Delegation policy sub-field for auth blocks.
 */
export const delegationPolicyField = {
  type: 'object',
  nullable: true,
  fields: {
    max_depth: { type: 'integer', min: 1, nullable: true },
    allowed_delegators: { type: 'array', nullable: true, items: { type: 'string' } },
    require_grant_per_hop: nullableBoolean,
  },
};

/**
 * Subject sub-field for v0.2 identity.
 */
export const subjectField = {
  type: 'object',
  nullable: true,
  fields: {
    kind: { type: 'string', enum: ['agent', 'service', 'workload', 'user', 'composite', 'delegated-agent', 'unknown'], nullable: true },
    principal: nullableString,
    display_name: nullableString,
    run_as: nullableToken,
    issuer: nullableString,
    delegation_mode: { type: 'string', enum: ['none', 'on-behalf-of', 'impersonation'], nullable: true },
    attributes: { type: 'object', nullable: true },
  },
};

/**
 * Auth sub-field for v0.2 identity.
 */
export const authField = {
  type: 'object',
  nullable: true,
  fields: {
    mode: { type: 'string', enum: ['none', 'service', 'delegated', 'on-behalf-of', 'impersonation', 'exchange'], nullable: true },
    scopes: { type: 'array', nullable: true, items: { type: 'string' } },
    audience: nullableString,
    resource: nullableString,
    cache: { type: 'string', enum: ['none', 'memory', 'state'], nullable: true },
    refresh: { type: 'string', enum: ['never', 'manual', 'auto'], nullable: true },
    required: nullableBoolean,
    delegation_policy: delegationPolicyField,
    provider_config: { type: 'object', nullable: true },
    inputs: { type: 'object', nullable: true },
  },
};

/**
 * Trust sub-field for v0.2 identity.
 */
export const trustField = {
  type: 'object',
  nullable: true,
  fields: {
    level: { type: 'string', enum: ['untrusted', 'restricted', 'supervised', 'autonomous'], nullable: true },
    constraints: {
      type: 'object',
      nullable: true,
      fields: {
        escalation: { type: 'string', enum: ['fail', 'human-approval', 'log-and-proceed'], nullable: true },
        max_autonomy: { type: 'string', enum: ['untrusted', 'restricted', 'supervised', 'autonomous'], nullable: true },
        escalation_timeout: nullableString,
        require_justification: nullableBoolean,
      },
    },
  },
};

/**
 * Presentation sub-field for v0.2 identity.
 */
export const presentationField = {
  type: 'object',
  nullable: true,
  fields: {
    bindings: { type: 'array', nullable: true, items: { type: 'object' } },
    handoff: { type: 'string', enum: ['none', 'downscope', 'transaction-token'], nullable: true },
    cleanup: { type: 'string', enum: ['always', 'on-success', 'on-failure', 'never'], nullable: true },
    default_redaction: nullableBoolean,
  },
};

/**
 * v0.2 identity field (ref + subject + auth + trust + presentation).
 */
export const identityFieldV2 = {
  type: 'object',
  nullable: true,
  fields: {
    ref: nullableString,
    scope: nullableString,
    subject: subjectField,
    auth: authField,
    trust: trustField,
    presentation: presentationField,
  },
};

/**
 * Identity profile definition for v0.2 manifest identity_profiles array.
 */
export const identityProfileField = {
  type: 'object',
  required: ['id', 'provider'],
  fields: {
    id: { type: 'string' },
    provider: { type: 'string' },
    subject: subjectField,
    auth: authField,
    trust: trustField,
    presentation: presentationField,
    provider_config: { type: 'object', nullable: true },
  },
};

/**
 * Authorization proof ref sub-field for v0.2 tasks.
 */
export const authorizationProofRefField = {
  type: 'object',
  nullable: true,
  required: ['ref'],
  fields: {
    ref: nullableString,
    claims: { type: 'object', nullable: true },
    verify: {
      type: 'object',
      nullable: true,
      fields: {
        required: nullableBoolean,
      },
    },
  },
};

/**
 * Authorization proof profile definition for v0.2 manifest authorization_proof_profiles array.
 */
export const authorizationProofProfileField = {
  type: 'object',
  required: ['id', 'method'],
  fields: {
    id: { type: 'string' },
    method: { type: 'string', enum: ['none', 'jwt', 'detached-signature', 'certificate'] },
    issuer: nullableString,
    audience: nullableString,
    jwks_uri: nullableString,
    public_key: nullableString,
    allowed_signers: nullableString,
    principal: nullableString,
    namespace: nullableString,
    ca_certificate: nullableString,
    ca_certificate_from: valueFromField,
    proof: {
      type: 'object',
      nullable: true,
      fields: {
        value_from: valueFromField,
      },
    },
    claims: { type: 'object', nullable: true },
    verify: {
      type: 'object',
      nullable: true,
      fields: {
        required: nullableBoolean,
      },
    },
  },
};

/**
 * Authorization ref sub-field for v0.2 tasks.
 */
export const authorizationRefField = {
  type: 'object',
  nullable: true,
  required: ['ref'],
  fields: {
    ref: nullableString,
    provider_config: { type: 'object', nullable: true },
    on_error: { type: 'string', enum: ['deny', 'warn'], nullable: true },
    request: { type: 'object', nullable: true },
    decision: { type: 'object', nullable: true },
  },
};

/**
 * Authorization profile definition for v0.2 manifest authorization_profiles array.
 */
export const authorizationProfileField = {
  type: 'object',
  required: ['id', 'provider'],
  fields: {
    id: { type: 'string' },
    provider: { type: 'string' },
    provider_config: { type: 'object', nullable: true },
    on_error: { type: 'string', enum: ['deny', 'warn'], nullable: true },
    request: {
      type: 'object',
      nullable: true,
      fields: {
        include: { type: 'array', nullable: true, items: { type: 'string' } },
      },
    },
    decision: {
      type: 'object',
      nullable: true,
      fields: {
        allow_values: { type: 'array', nullable: true, items: { type: 'string' } },
        deny_values: { type: 'array', nullable: true, items: { type: 'string' } },
        escalate_values: { type: 'array', nullable: true, items: { type: 'string' } },
      },
    },
  },
};

/**
 * Evidence ref sub-field for v0.2 tasks.
 */
export const evidenceRefField = {
  type: 'object',
  nullable: true,
  fields: {
    ref: nullableString,
    payload: {
      type: 'object',
      nullable: true,
      fields: {
        bind: { type: 'array', nullable: true, items: { type: 'string' } },
        context: { type: 'object', nullable: true },
        format: { type: 'string', enum: ['canonical-json', 'json'], nullable: true },
      },
    },
    verify: {
      type: 'object',
      nullable: true,
      fields: {
        required: nullableBoolean,
      },
    },
  },
};

/**
 * Evidence profile definition for v0.2 manifest evidence_profiles array.
 */
export const evidenceProfileField = {
  type: 'object',
  required: ['id', 'provider'],
  fields: {
    id: { type: 'string' },
    provider: { type: 'string' },
    methods: { type: 'array', nullable: true, items: { type: 'string' } },
    provider_config: { type: 'object', nullable: true },
    payload: {
      type: 'object',
      nullable: true,
      fields: {
        bind: { type: 'array', nullable: true, items: { type: 'string' } },
        context: { type: 'object', nullable: true },
        format: { type: 'string', enum: ['canonical-json', 'json'], nullable: true },
      },
    },
    verify: {
      type: 'object',
      nullable: true,
      fields: {
        required: nullableBoolean,
      },
    },
  },
};

Object.assign(contractField.fields, {
  required_trust_level: nullableString,
  trust_enforcement: { type: 'string', enum: ['none', 'advisory', 'strict'], nullable: true }
});

Object.assign(onFailureField.fields, {
  identity: identityFieldV2,
  contract: contractField,
  authorization_proof: authorizationProofRefField,
  authorization: authorizationRefField,
  evidence: evidenceRefField
});

MANIFEST_SCHEMA.manifest = {
  type: 'object',
  required: ['version', 'workflows'],
  fields: {
    version: { type: 'string', const: MANIFEST_VERSION },
    identity_profiles: { type: 'array', nullable: true, items: identityProfileField },
    authorization_proof_profiles: { type: 'array', nullable: true, items: authorizationProofProfileField },
    authorization_profiles: { type: 'array', nullable: true, items: authorizationProfileField },
    evidence_profiles: { type: 'array', nullable: true, items: evidenceProfileField },
    workflows: { type: 'array', minItems: 1, items: { type: 'object' } }
  }
};

MANIFEST_SCHEMA.workflow = {
  type: 'object',
  required: ['id', 'name', 'tasks'],
  fields: {
    id: { type: 'string' },
    name: { type: 'string' },
    model_policy: modelPolicyField,
    identity: identityFieldV2,
    contract: contractField,
    authorization_proof: authorizationProofRefField,
    authorization: authorizationRefField,
    evidence: evidenceRefField,
    child_credential_policy: childCredentialPolicyField,
    verify: verifyField,
    tasks: { type: 'array', minItems: 1, items: { type: 'object' } }
  }
};

MANIFEST_SCHEMA.manifest.fields.workflows.items = MANIFEST_SCHEMA.workflow;

MANIFEST_SCHEMA.task = {
  type: 'object',
  required: ['id', 'name', 'target'],
  note: 'Exactly one of schedule or trigger must be present.',
  fields: {
    id: { type: 'string' },
    name: { type: 'string' },
    enabled: nullableBoolean,
    prompt: nullableString,
    command: { type: 'string', removed: true, note: 'use shell.program and shell.args' },
    shell: shellField,
    target: targetField,
    model_policy: modelPolicyField,
    intent: intentField,
    output: outputField,
    budgets: budgetsField,
    schedule: {
      type: 'object',
      nullable: true,
      required: ['cron'],
      fields: {
        cron: { type: 'string' },
        tz: nullableString
      }
    },
    trigger: {
      type: 'object',
      nullable: true,
      required: ['parent', 'on'],
      fields: {
        parent: { type: 'string' },
        on: { type: 'string', enum: ['success', 'failure', 'complete'] },
        delay_s: { type: 'integer', min: 0, nullable: true },
        condition: nullableString
      }
    },
    delivery: deliveryField,
    reliability: reliabilityField,
    runtime: runtimeField,
    approval: approvalField,
    context: contextField,
    session: sessionField,
    identity: identityFieldV2,
    contract: contractField,
    authorization_proof: authorizationProofRefField,
    authorization: authorizationRefField,
    evidence: evidenceRefField,
    child_credential_policy: childCredentialPolicyField,
    verify: verifyField,
    on_failure: onFailureField,
    auth_profile: { type: 'string', nullable: true, note: 'Auth profile ID for scheduler dispatch (e.g. \'anthropic:me.com\'). Scheduler-target only — ignored by other backends.' },
    delete_after_run: nullableBoolean
  }
};

MANIFEST_SCHEMA.workflow.fields.tasks.items = MANIFEST_SCHEMA.task;

Object.assign(MANIFEST_SCHEMA.standalonePlan.fields.capabilities.fields, {
  identity: { type: 'boolean' },
  contracts: { type: 'boolean' },
  identity_declaration: { type: 'boolean' },
  evidence_generation: { type: 'boolean' },
  trust_evaluation: { type: 'boolean' },
  delegation_validation: { type: 'boolean' }
});

Object.assign(MANIFEST_SCHEMA.schedulerJob.fields, {
  identity_ref: nullableString,
  identity_subject_kind: nullableString,
  identity_subject_principal: nullableString,
  identity_trust_level: nullableString,
  identity_delegation_mode: nullableString,
  identity: { type: 'object', nullable: true },
  authorization_proof_ref: nullableString,
  authorization_proof: { type: 'object', nullable: true },
  authorization_ref: nullableString,
  authorization: { type: 'object', nullable: true },
  evidence_ref: nullableString,
  evidence: { type: 'object', nullable: true },
  contract_required_trust_level: nullableString,
  contract_trust_enforcement: nullableString,
  child_credential_policy: childCredentialPolicyField,
  authorization_proof_verification: { type: 'object', nullable: true },
  verify_shell: nullableString,
  verify_timeout_s: { type: 'integer', nullable: true, min: 1 },
  verify_on_failure: nullableString,
  auth_profile: { type: 'string', nullable: true, note: 'Auth profile ID for scheduler dispatch (e.g. \'anthropic:me.com\'). Scheduler-target only — ignored by other backends.' },
});

const JSON_SCHEMA_DIALECT = 'https://json-schema.org/draft/2020-12/schema';
const IDENTIFIER_PATTERN = '^[A-Za-z0-9][A-Za-z0-9._-]*$';
const TOKEN_PATTERN = '^[A-Za-z0-9@:_./-]+$';
const ENV_NAME_PATTERN = '^[A-Za-z_][A-Za-z0-9_]*$';

function objectSchema(properties, { required = [], additionalProperties = false, ...extra } = {}) {
  return {
    type: 'object',
    properties,
    additionalProperties,
    ...(required.length > 0 ? { required } : {}),
    ...extra,
  };
}

function nullableSchema(schema) {
  return { anyOf: [schema, { type: 'null' }] };
}

const nullableStringSchema = nullableSchema({ type: 'string' });
const nullableTokenSchema = nullableSchema({ type: 'string', pattern: TOKEN_PATTERN });
const nullableBooleanSchema = nullableSchema({ type: 'boolean' });

const jsonSchemaDefs = {
  valueFrom: objectSchema({
    env: nullableStringSchema,
    file: nullableStringSchema,
    literal: nullableStringSchema,
    command: nullableStringSchema,
  }, {
    anyOf: [
      { required: ['env'] },
      { required: ['file'] },
      { required: ['literal'] },
      { required: ['command'] },
    ],
  }),
  proofValueFrom: objectSchema({
    env: nullableStringSchema,
    file: nullableStringSchema,
    command: nullableStringSchema,
  }, {
    anyOf: [
      { required: ['env'] },
      { required: ['file'] },
      { required: ['command'] },
    ],
  }),
  target: objectSchema({
    session_target: { type: 'string', enum: ['main', 'isolated', 'shell'] },
    agent_id: nullableTokenSchema,
    payload_kind: nullableSchema({ type: 'string', enum: ['systemEvent', 'agentTurn', 'shellCommand'] }),
  }, { required: ['session_target'] }),
  shell: objectSchema({
    program: { type: 'string', pattern: TOKEN_PATTERN },
    args: nullableSchema({ type: 'array', items: { type: 'string' } }),
    env: nullableSchema({
      type: 'object',
      propertyNames: { pattern: ENV_NAME_PATTERN },
      additionalProperties: { type: 'string' },
    }),
    cwd: nullableStringSchema,
    stdin: nullableStringSchema,
  }, { required: ['program'] }),
  modelPolicy: objectSchema({
    provider: nullableTokenSchema,
    model: nullableTokenSchema,
    thinking: nullableTokenSchema,
  }),
  intent: objectSchema({
    mode: nullableSchema({ type: 'string', enum: ['execute', 'plan'] }),
    read_only: nullableBooleanSchema,
  }),
  output: objectSchema({
    preview_bytes: nullableSchema({ type: 'integer', minimum: 64 }),
    offload: nullableSchema({ type: 'string', enum: ['auto', 'always', 'never'] }),
    retrieve: nullableSchema({ type: 'string', enum: ['inline', 'on-demand'] }),
    format: nullableSchema({ type: 'string', enum: ['json', 'ndjson', 'text'] }),
  }),
  budgets: objectSchema({
    max_iterations: nullableSchema({ type: 'integer', minimum: 1 }),
    max_fanout: nullableSchema({ type: 'integer', minimum: 1 }),
    max_context_items: nullableSchema({ type: 'integer', minimum: 1 }),
    max_pending_approvals: nullableSchema({ type: 'integer', minimum: 1 }),
    max_queued_dispatches: nullableSchema({ type: 'integer', minimum: 1 }),
  }),
  schedule: objectSchema({
    cron: { type: 'string', minLength: 1 },
    tz: nullableStringSchema,
  }, { required: ['cron'] }),
  trigger: objectSchema({
    parent: { type: 'string', minLength: 1 },
    on: { type: 'string', enum: ['success', 'failure', 'complete'] },
    delay_s: nullableSchema({ type: 'integer', minimum: 0 }),
    condition: nullableStringSchema,
  }, { required: ['parent', 'on'] }),
  delivery: objectSchema({
    mode: nullableSchema({ type: 'string', enum: ['announce', 'announce-always', 'none'] }),
    channel: nullableTokenSchema,
    to: nullableTokenSchema,
  }),
  reliability: objectSchema({
    guarantee: nullableSchema({ type: 'string', enum: ['at-most-once', 'at-least-once'] }),
    max_retries: nullableSchema({ type: 'integer', minimum: 0 }),
    overlap_policy: nullableSchema({ type: 'string', enum: ['skip', 'allow', 'queue'] }),
  }),
  runtime: objectSchema({
    timeout_ms: nullableSchema({ type: 'integer', minimum: 1 }),
  }),
  approval: objectSchema({
    required: nullableBooleanSchema,
    policy: nullableSchema({ type: 'string', enum: ['manual', 'auto-approve', 'auto-reject'] }),
    risk_level: nullableSchema({ type: 'string', enum: ['low', 'medium', 'high'] }),
    approver_scope: nullableTokenSchema,
    timeout_s: nullableSchema({ type: 'integer', minimum: 1 }),
    auto: nullableSchema({ type: 'string', enum: ['approve', 'reject'] }),
  }),
  context: objectSchema({
    retrieval: nullableSchema({ type: 'string', enum: ['none', 'recent', 'hybrid'] }),
    limit: nullableSchema({ type: 'integer', minimum: 1 }),
  }),
  session: objectSchema({ preferred_key: nullableTokenSchema }),
  delegationPolicy: objectSchema({
    max_depth: nullableSchema({ type: 'integer', minimum: 1 }),
    allowed_delegators: nullableSchema({ type: 'array', items: { type: 'string' } }),
    require_grant_per_hop: nullableBooleanSchema,
  }),
  subject: objectSchema({
    kind: nullableSchema({ type: 'string', enum: ['agent', 'service', 'workload', 'user', 'composite', 'delegated-agent', 'unknown'] }),
    principal: nullableStringSchema,
    display_name: nullableStringSchema,
    run_as: nullableTokenSchema,
    issuer: nullableStringSchema,
    delegation_mode: nullableSchema({ type: 'string', enum: ['none', 'on-behalf-of', 'impersonation'] }),
    attributes: nullableSchema({ type: 'object', additionalProperties: true }),
  }),
  auth: objectSchema({
    mode: nullableSchema({ type: 'string', enum: ['none', 'service', 'delegated', 'on-behalf-of', 'impersonation', 'exchange'] }),
    scopes: nullableSchema({ type: 'array', items: { type: 'string' } }),
    audience: nullableStringSchema,
    resource: nullableStringSchema,
    cache: nullableSchema({ type: 'string', enum: ['none', 'memory', 'state'] }),
    refresh: nullableSchema({ type: 'string', enum: ['never', 'manual', 'auto'] }),
    required: nullableBooleanSchema,
    delegation_policy: nullableSchema({ $ref: '#/$defs/delegationPolicy' }),
    provider_config: nullableSchema({ type: 'object', additionalProperties: true }),
    inputs: nullableSchema({ type: 'object', additionalProperties: true }),
  }),
  trust: objectSchema({
    level: nullableSchema({ type: 'string', enum: ['untrusted', 'restricted', 'supervised', 'autonomous'] }),
    constraints: nullableSchema(objectSchema({
      escalation: nullableSchema({ type: 'string', enum: ['fail', 'human-approval', 'log-and-proceed'] }),
      max_autonomy: nullableSchema({ type: 'string', enum: ['untrusted', 'restricted', 'supervised', 'autonomous'] }),
      escalation_timeout: nullableStringSchema,
      require_justification: nullableBooleanSchema,
    })),
  }),
  presentationTarget: objectSchema({
    kind: nullableSchema({ type: 'string', enum: ['env', 'file', 'stdin', 'none'] }),
    name: nullableStringSchema,
    prefix: nullableSchema({
      type: 'string',
      minLength: 1,
      maxLength: 80,
      pattern: '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$',
    }),
    expose_as: nullableSchema({ type: 'string', pattern: ENV_NAME_PATTERN }),
  }),
  presentationBinding: objectSchema({
    source: { type: 'string', minLength: 1 },
    target: nullableSchema({ $ref: '#/$defs/presentationTarget' }),
    required: nullableBooleanSchema,
    redact: nullableBooleanSchema,
    format: nullableSchema({ type: 'string', enum: ['raw', 'json', 'base64'] }),
  }, { required: ['source'] }),
  presentation: objectSchema({
    bindings: nullableSchema({ type: 'array', items: { $ref: '#/$defs/presentationBinding' } }),
    handoff: nullableSchema({ type: 'string', enum: ['none', 'downscope', 'transaction-token'] }),
    cleanup: nullableSchema({ type: 'string', enum: ['always', 'on-success', 'on-failure', 'never'] }),
    default_redaction: nullableBooleanSchema,
  }),
  identityV1: objectSchema({
    principal: nullableTokenSchema,
    run_as: nullableTokenSchema,
    attestation: nullableStringSchema,
  }),
  identityV2: objectSchema({
    ref: nullableStringSchema,
    scope: nullableStringSchema,
    subject: nullableSchema({ $ref: '#/$defs/subject' }),
    auth: nullableSchema({ $ref: '#/$defs/auth' }),
    trust: nullableSchema({ $ref: '#/$defs/trust' }),
    presentation: nullableSchema({ $ref: '#/$defs/presentation' }),
  }),
  identity: {
    anyOf: [
      { $ref: '#/$defs/identityV1' },
      { $ref: '#/$defs/identityV2' },
    ],
  },
  contract: objectSchema({
    sandbox: nullableSchema({ type: 'string', enum: ['none', 'permissive', 'strict'] }),
    allowed_paths: nullableSchema({ type: 'array', items: { type: 'string' } }),
    network: nullableSchema({ type: 'string', enum: ['unrestricted', 'restricted', 'none'] }),
    max_cost_usd: nullableSchema({ type: 'number', minimum: 0 }),
    audit: nullableSchema({ type: 'string', enum: ['none', 'on-failure', 'always'] }),
    required_trust_level: nullableSchema({ type: 'string', enum: ['untrusted', 'restricted', 'supervised', 'autonomous'] }),
    trust_enforcement: nullableSchema({ type: 'string', enum: ['none', 'advisory', 'strict'] }),
  }),
  authorizationProofRef: objectSchema({
    ref: { type: 'string', minLength: 1 },
    claims: nullableSchema({ type: 'object', additionalProperties: true }),
    verify: nullableSchema(objectSchema({ required: nullableBooleanSchema })),
  }, { required: ['ref'] }),
  authorizationRequest: objectSchema({
    include: nullableSchema({ type: 'array', items: { type: 'string' } }),
  }),
  authorizationDecision: objectSchema({
    allow_values: nullableSchema({ type: 'array', items: { type: 'string' } }),
    deny_values: nullableSchema({ type: 'array', items: { type: 'string' } }),
    escalate_values: nullableSchema({ type: 'array', items: { type: 'string' } }),
  }),
  authorizationRef: objectSchema({
    ref: { type: 'string', minLength: 1 },
    provider_config: nullableSchema({ type: 'object', additionalProperties: true }),
    on_error: nullableSchema({ type: 'string', enum: ['deny', 'warn'] }),
    request: nullableSchema({ $ref: '#/$defs/authorizationRequest' }),
    decision: nullableSchema({ $ref: '#/$defs/authorizationDecision' }),
  }, { required: ['ref'] }),
  evidencePayload: objectSchema({
    bind: nullableSchema({ type: 'array', items: { type: 'string' } }),
    context: nullableSchema({ type: 'object', additionalProperties: true }),
    format: nullableSchema({ type: 'string', enum: ['canonical-json', 'json'] }),
  }),
  evidenceRef: objectSchema({
    ref: nullableStringSchema,
    payload: nullableSchema({ $ref: '#/$defs/evidencePayload' }),
    verify: nullableSchema(objectSchema({ required: nullableBooleanSchema })),
  }),
  verify: objectSchema({
    shell: { type: 'string', minLength: 1 },
    timeout_seconds: nullableSchema({ type: 'integer', minimum: 1 }),
    on_failure: nullableSchema({ type: 'string', enum: ['error', 'warn'] }),
  }, { required: ['shell'] }),
  identityProfile: objectSchema({
    id: { type: 'string', pattern: IDENTIFIER_PATTERN },
    provider: { type: 'string', minLength: 1 },
    subject: nullableSchema({ $ref: '#/$defs/subject' }),
    auth: nullableSchema({ $ref: '#/$defs/auth' }),
    trust: nullableSchema({ $ref: '#/$defs/trust' }),
    presentation: nullableSchema({ $ref: '#/$defs/presentation' }),
    provider_config: nullableSchema({ type: 'object', additionalProperties: true }),
  }, { required: ['id', 'provider'] }),
  authorizationProofProfile: objectSchema({
    id: { type: 'string', pattern: IDENTIFIER_PATTERN },
    method: { type: 'string', enum: ['none', 'jwt', 'detached-signature', 'certificate'] },
    issuer: nullableStringSchema,
    audience: nullableStringSchema,
    jwks_uri: nullableStringSchema,
    public_key: nullableStringSchema,
    allowed_signers: nullableStringSchema,
    principal: nullableStringSchema,
    namespace: nullableStringSchema,
    ca_certificate: nullableStringSchema,
    ca_certificate_from: nullableSchema({ $ref: '#/$defs/valueFrom' }),
    proof: nullableSchema(objectSchema({
      value_from: nullableSchema({ $ref: '#/$defs/proofValueFrom' }),
    })),
    claims: nullableSchema({ type: 'object', additionalProperties: true }),
    verify: nullableSchema(objectSchema({ required: nullableBooleanSchema })),
  }, { required: ['id', 'method'] }),
  authorizationProfile: objectSchema({
    id: { type: 'string', pattern: IDENTIFIER_PATTERN },
    provider: { type: 'string', minLength: 1 },
    provider_config: nullableSchema({ type: 'object', additionalProperties: true }),
    on_error: nullableSchema({ type: 'string', enum: ['deny', 'warn'] }),
    request: nullableSchema({ $ref: '#/$defs/authorizationRequest' }),
    decision: nullableSchema({ $ref: '#/$defs/authorizationDecision' }),
  }, { required: ['id', 'provider'] }),
  evidenceProfile: objectSchema({
    id: { type: 'string', pattern: IDENTIFIER_PATTERN },
    provider: { type: 'string', minLength: 1 },
    methods: nullableSchema({ type: 'array', items: { type: 'string' } }),
    provider_config: nullableSchema({ type: 'object', additionalProperties: true }),
    payload: nullableSchema({ $ref: '#/$defs/evidencePayload' }),
    verify: nullableSchema(objectSchema({ required: nullableBooleanSchema })),
  }, { required: ['id', 'provider'] }),
};

const commonExecutionProperties = {
  id: { type: 'string', pattern: IDENTIFIER_PATTERN },
  name: { type: 'string', minLength: 1 },
  enabled: nullableBooleanSchema,
  prompt: nullableStringSchema,
  shell: nullableSchema({ $ref: '#/$defs/shell' }),
  target: { $ref: '#/$defs/target' },
  model_policy: nullableSchema({ $ref: '#/$defs/modelPolicy' }),
  intent: nullableSchema({ $ref: '#/$defs/intent' }),
  output: nullableSchema({ $ref: '#/$defs/output' }),
  budgets: nullableSchema({ $ref: '#/$defs/budgets' }),
  delivery: nullableSchema({ $ref: '#/$defs/delivery' }),
  reliability: nullableSchema({ $ref: '#/$defs/reliability' }),
  runtime: nullableSchema({ $ref: '#/$defs/runtime' }),
  approval: nullableSchema({ $ref: '#/$defs/approval' }),
  context: nullableSchema({ $ref: '#/$defs/context' }),
  session: nullableSchema({ $ref: '#/$defs/session' }),
  identity: nullableSchema({ $ref: '#/$defs/identity' }),
  contract: nullableSchema({ $ref: '#/$defs/contract' }),
  authorization_proof: nullableSchema({ $ref: '#/$defs/authorizationProofRef' }),
  authorization: nullableSchema({ $ref: '#/$defs/authorizationRef' }),
  evidence: nullableSchema({ $ref: '#/$defs/evidenceRef' }),
  child_credential_policy: nullableSchema({ type: 'string', enum: ['none', 'inherit', 'downscope', 'independent'] }),
  auth_profile: nullableStringSchema,
  delete_after_run: nullableBooleanSchema,
};

const {
  child_credential_policy: _childCredentialPolicy,
  auth_profile: _authProfile,
  ...onFailureCommonProperties
} = commonExecutionProperties;

jsonSchemaDefs.onFailure = objectSchema({
  ...onFailureCommonProperties,
  delay_s: nullableSchema({ type: 'integer', minimum: 0 }),
  condition: nullableStringSchema,
}, {
  allOf: [{
    if: { required: ['shell'] },
    then: {
      properties: {
        shell: { $ref: '#/$defs/shell' },
        prompt: { type: 'null' },
      },
    },
    else: {
      required: ['prompt'],
      properties: {
        prompt: { type: 'string', minLength: 1 },
        shell: { type: 'null' },
      },
    },
  }],
});

jsonSchemaDefs.task = objectSchema({
  ...commonExecutionProperties,
  schedule: nullableSchema({ $ref: '#/$defs/schedule' }),
  trigger: nullableSchema({ $ref: '#/$defs/trigger' }),
  verify: nullableSchema({ $ref: '#/$defs/verify' }),
  on_failure: nullableSchema({ $ref: '#/$defs/onFailure' }),
}, {
  required: ['id', 'name', 'target'],
  oneOf: [
    {
      required: ['schedule'],
      properties: {
        schedule: { $ref: '#/$defs/schedule' },
        trigger: { type: 'null' },
      },
    },
    {
      required: ['trigger'],
      properties: {
        trigger: { $ref: '#/$defs/trigger' },
        schedule: { type: 'null' },
      },
    },
  ],
  allOf: [{
    if: {
      properties: {
        target: {
          properties: { session_target: { const: 'shell' } },
          required: ['session_target'],
        },
      },
      required: ['target'],
    },
    then: {
      required: ['shell'],
      properties: {
        shell: { $ref: '#/$defs/shell' },
        prompt: { type: 'null' },
      },
    },
    else: {
      required: ['prompt'],
      properties: {
        prompt: { type: 'string', minLength: 1 },
        shell: { type: 'null' },
      },
    },
  }],
});

jsonSchemaDefs.workflow = objectSchema({
  id: { type: 'string', pattern: IDENTIFIER_PATTERN },
  name: { type: 'string', minLength: 1 },
  model_policy: nullableSchema({ $ref: '#/$defs/modelPolicy' }),
  identity: nullableSchema({ $ref: '#/$defs/identity' }),
  contract: nullableSchema({ $ref: '#/$defs/contract' }),
  authorization_proof: nullableSchema({ $ref: '#/$defs/authorizationProofRef' }),
  authorization: nullableSchema({ $ref: '#/$defs/authorizationRef' }),
  evidence: nullableSchema({ $ref: '#/$defs/evidenceRef' }),
  child_credential_policy: nullableSchema({ type: 'string', enum: ['none', 'inherit', 'downscope', 'independent'] }),
  verify: nullableSchema({ $ref: '#/$defs/verify' }),
  tasks: { type: 'array', minItems: 1, items: { $ref: '#/$defs/task' } },
}, { required: ['id', 'name', 'tasks'] });

export const MANIFEST_JSON_SCHEMA = {
  $schema: JSON_SCHEMA_DIALECT,
  $id: 'https://github.com/amittell/agentcli/schema/manifest-0.2.json',
  title: 'agentcli workflow manifest',
  description: 'Draft 2020-12 schema for agentcli v0.1 and v0.2 manifests.',
  ...objectSchema({
    version: { type: 'string', enum: ['0.1', MANIFEST_VERSION] },
    identity_profiles: nullableSchema({ type: 'array', items: { $ref: '#/$defs/identityProfile' } }),
    authorization_proof_profiles: nullableSchema({ type: 'array', items: { $ref: '#/$defs/authorizationProofProfile' } }),
    authorization_profiles: nullableSchema({ type: 'array', items: { $ref: '#/$defs/authorizationProfile' } }),
    evidence_profiles: nullableSchema({ type: 'array', items: { $ref: '#/$defs/evidenceProfile' } }),
    workflows: { type: 'array', minItems: 1, items: { $ref: '#/$defs/workflow' } },
  }, { required: ['version', 'workflows'] }),
  $defs: jsonSchemaDefs,
};

function legacyDescriptorToJsonSchema(descriptor) {
  if (!descriptor || typeof descriptor !== 'object') return {};
  if (descriptor.removed) return false;

  const result = {};
  if (descriptor.type !== undefined) {
    const types = Array.isArray(descriptor.type) ? [...descriptor.type] : [descriptor.type];
    if (descriptor.nullable && !types.includes('null')) types.push('null');
    result.type = types.length === 1 ? types[0] : types;
  }
  if (descriptor.const !== undefined) result.const = descriptor.const;
  if (descriptor.enum) result.enum = [...descriptor.enum];
  if (descriptor.required) result.required = [...descriptor.required];
  if (descriptor.min !== undefined) result.minimum = descriptor.min;
  if (descriptor.minItems !== undefined) result.minItems = descriptor.minItems;
  if (descriptor.note) result.description = descriptor.note;
  if (descriptor.format === 'token') result.pattern = TOKEN_PATTERN;
  if (descriptor.fields) {
    result.properties = Object.fromEntries(
      Object.entries(descriptor.fields).map(([name, value]) => [name, legacyDescriptorToJsonSchema(value)])
    );
    result.additionalProperties = false;
  }
  if (descriptor.items) result.items = legacyDescriptorToJsonSchema(descriptor.items);
  if (descriptor.values) result.additionalProperties = legacyDescriptorToJsonSchema(descriptor.values);
  return result;
}

function fragmentSchema(definitionName, title) {
  return {
    $schema: JSON_SCHEMA_DIALECT,
    title,
    $ref: `#/$defs/${definitionName}`,
    $defs: jsonSchemaDefs,
  };
}

export const JSON_SCHEMAS = Object.freeze({
  manifest: MANIFEST_JSON_SCHEMA,
  workflow: fragmentSchema('workflow', 'agentcli workflow'),
  task: fragmentSchema('task', 'agentcli task'),
  schedulerJob: {
    $schema: JSON_SCHEMA_DIALECT,
    title: 'openclaw-scheduler compiled job',
    ...legacyDescriptorToJsonSchema(MANIFEST_SCHEMA.schedulerJob),
  },
  standalonePlan: {
    $schema: JSON_SCHEMA_DIALECT,
    title: 'agentcli standalone compiled plan',
    ...legacyDescriptorToJsonSchema(MANIFEST_SCHEMA.standalonePlan),
  },
  rpcRequest: {
    $schema: JSON_SCHEMA_DIALECT,
    title: 'agentcli JSON-RPC request',
    ...legacyDescriptorToJsonSchema(MANIFEST_SCHEMA.rpcRequest),
  },
  rpcResponse: {
    $schema: JSON_SCHEMA_DIALECT,
    title: 'agentcli JSON-RPC response',
    ...legacyDescriptorToJsonSchema(MANIFEST_SCHEMA.rpcResponse),
    oneOf: [{ required: ['result'] }, { required: ['error'] }],
  },
});
