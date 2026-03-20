export const MANIFEST_VERSION = '0.1';

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
    retrieve: { type: 'string', enum: ['inline', 'on-demand'], nullable: true }
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
      delivery_guarantee: nullableString,
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
            tasks: { type: 'array', note: 'normalizedTaskPlan objects with id, source, invocation, execution, intent, output, budgets, delivery, reliability, runtime, approval, context, session, delete_after_run, parent_compiled_id' },
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
