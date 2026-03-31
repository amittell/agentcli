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
});
