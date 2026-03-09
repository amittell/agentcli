export const MANIFEST_VERSION = '0.1';

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
      model_policy: {
        type: 'object',
        nullable: true,
        fields: {
          provider: { type: 'string', nullable: true },
          model: { type: 'string', nullable: true },
          thinking: { type: 'string', nullable: true }
        }
      },
      tasks: { type: 'array', minItems: 1 }
    }
  },
  task: {
    type: 'object',
    required: ['id', 'name', 'target'],
    fields: {
      id: { type: 'string' },
      name: { type: 'string' },
      enabled: { type: 'boolean', nullable: true },
      prompt: { type: 'string', nullable: true },
      command: { type: 'string', nullable: true },
      target: {
        type: 'object',
        required: ['session_target'],
        fields: {
          session_target: { type: 'string', enum: ['main', 'isolated', 'shell'] },
          agent_id: { type: 'string', nullable: true },
          payload_kind: { type: 'string', enum: ['systemEvent', 'agentTurn', 'shellCommand'], nullable: true }
        }
      },
      model_policy: {
        type: 'object',
        nullable: true,
        fields: {
          provider: { type: 'string', nullable: true },
          model: { type: 'string', nullable: true },
          thinking: { type: 'string', nullable: true }
        }
      },
      intent: {
        type: 'object',
        nullable: true,
        fields: {
          mode: { type: 'string', enum: ['execute', 'plan'], nullable: true },
          read_only: { type: 'boolean', nullable: true }
        }
      },
      output: {
        type: 'object',
        nullable: true,
        fields: {
          preview_bytes: { type: 'integer', min: 64, nullable: true },
          offload: { type: 'string', enum: ['auto', 'always', 'never'], nullable: true },
          retrieve: { type: 'string', enum: ['inline', 'on-demand'], nullable: true }
        }
      },
      budgets: {
        type: 'object',
        nullable: true,
        fields: {
          max_iterations: { type: 'integer', min: 1, nullable: true },
          max_fanout: { type: 'integer', min: 1, nullable: true },
          max_context_items: { type: 'integer', min: 1, nullable: true },
          max_pending_approvals: { type: 'integer', min: 1, nullable: true },
          max_queued_dispatches: { type: 'integer', min: 1, nullable: true }
        }
      },
      schedule: {
        type: 'object',
        nullable: true,
        fields: {
          cron: { type: 'string' },
          tz: { type: 'string', nullable: true }
        }
      },
      trigger: {
        type: 'object',
        nullable: true,
        fields: {
          parent: { type: 'string' },
          on: { type: 'string', enum: ['success', 'failure', 'complete'] },
          delay_s: { type: 'integer', min: 0, nullable: true },
          condition: { type: 'string', nullable: true }
        }
      },
      delivery: {
        type: 'object',
        nullable: true,
        fields: {
          mode: { type: 'string', enum: ['announce', 'announce-always', 'none'] },
          channel: { type: 'string', nullable: true },
          to: { type: 'string', nullable: true }
        }
      },
      reliability: {
        type: 'object',
        nullable: true,
        fields: {
          guarantee: { type: 'string', enum: ['at-most-once', 'at-least-once'], nullable: true },
          max_retries: { type: 'integer', min: 0, nullable: true },
          overlap_policy: { type: 'string', enum: ['skip', 'allow', 'queue'], nullable: true }
        }
      },
      runtime: {
        type: 'object',
        nullable: true,
        fields: {
          timeout_ms: { type: 'integer', min: 1, nullable: true }
        }
      },
      approval: {
        type: 'object',
        nullable: true,
        fields: {
          required: { type: 'boolean', nullable: true },
          policy: { type: 'string', enum: ['manual', 'auto-approve', 'auto-reject'], nullable: true },
          risk_level: { type: 'string', enum: ['low', 'medium', 'high'], nullable: true },
          approver_scope: { type: 'string', nullable: true },
          timeout_s: { type: 'integer', min: 1, nullable: true },
          auto: { type: 'string', enum: ['approve', 'reject'], nullable: true }
        }
      },
      context: {
        type: 'object',
        nullable: true,
        fields: {
          retrieval: { type: 'string', enum: ['none', 'recent', 'hybrid'], nullable: true },
          limit: { type: 'integer', min: 1, nullable: true }
        }
      },
      session: {
        type: 'object',
        nullable: true,
        fields: {
          preferred_key: { type: 'string', nullable: true }
        }
      },
      on_failure: {
        type: 'object',
        nullable: true,
        fields: {
          id: { type: 'string', nullable: true },
          name: { type: 'string', nullable: true },
          enabled: { type: 'boolean', nullable: true },
          prompt: { type: 'string', nullable: true },
          command: { type: 'string', nullable: true },
          delay_s: { type: 'integer', min: 0, nullable: true },
          condition: { type: 'string', nullable: true },
          runtime: {
            type: 'object',
            nullable: true,
            fields: {
              timeout_ms: { type: 'integer', min: 1, nullable: true }
            }
          },
          model_policy: {
            type: 'object',
            nullable: true,
            fields: {
              provider: { type: 'string', nullable: true },
              model: { type: 'string', nullable: true },
              thinking: { type: 'string', nullable: true }
            }
          },
          intent: {
            type: 'object',
            nullable: true,
            fields: {
              mode: { type: 'string', enum: ['execute', 'plan'], nullable: true },
              read_only: { type: 'boolean', nullable: true }
            }
          },
          output: {
            type: 'object',
            nullable: true,
            fields: {
              preview_bytes: { type: 'integer', min: 64, nullable: true },
              offload: { type: 'string', enum: ['auto', 'always', 'never'], nullable: true },
              retrieve: { type: 'string', enum: ['inline', 'on-demand'], nullable: true }
            }
          },
          budgets: {
            type: 'object',
            nullable: true,
            fields: {
              max_iterations: { type: 'integer', min: 1, nullable: true },
              max_fanout: { type: 'integer', min: 1, nullable: true },
              max_context_items: { type: 'integer', min: 1, nullable: true },
              max_pending_approvals: { type: 'integer', min: 1, nullable: true },
              max_queued_dispatches: { type: 'integer', min: 1, nullable: true }
            }
          },
          target: {
            type: 'object',
            nullable: true,
            fields: {
              session_target: { type: 'string', enum: ['main', 'isolated', 'shell'], nullable: true },
              agent_id: { type: 'string', nullable: true },
              payload_kind: { type: 'string', enum: ['systemEvent', 'agentTurn', 'shellCommand'], nullable: true }
            }
          }
        }
      },
      delete_after_run: { type: 'boolean', nullable: true }
    }
  },
  schedulerJob: {
    type: 'object',
    fields: {
      id: { type: 'string' },
      name: { type: 'string' },
      enabled: { type: 'boolean', nullable: true },
      session_target: { type: 'string' },
      payload_kind: { type: 'string' },
      payload_message: { type: 'string' },
      run_timeout_ms: { type: 'integer', nullable: true },
      payload_model: { type: 'string', nullable: true },
      payload_thinking: { type: 'string', nullable: true },
      execution_intent: { type: 'string', nullable: true },
      execution_read_only: { type: 'boolean', nullable: true },
      max_queued_dispatches: { type: 'integer', nullable: true },
      max_pending_approvals: { type: 'integer', nullable: true },
      max_trigger_fanout: { type: 'integer', nullable: true },
      output_store_limit_bytes: { type: 'integer', nullable: true },
      output_excerpt_limit_bytes: { type: 'integer', nullable: true },
      output_summary_limit_bytes: { type: 'integer', nullable: true },
      output_offload_threshold_bytes: { type: 'integer', nullable: true },
      schedule_cron: { type: 'string', nullable: true },
      schedule_tz: { type: 'string', nullable: true },
      parent_id: { type: 'string', nullable: true },
      trigger_on: { type: 'string', nullable: true },
      trigger_condition: { type: 'string', nullable: true }
    }
  },
  standalonePlan: {
    type: 'object',
    fields: {
      target: { type: 'string', const: 'standalone' },
      version: { type: 'string' },
      workflows: { type: 'array', minItems: 1 }
    }
  },
  rpcRequest: {
    type: 'object',
    required: ['jsonrpc', 'method'],
    fields: {
      jsonrpc: { type: 'string', const: '2.0' },
      id: { type: 'string', nullable: true },
      method: { type: 'string' },
      params: { type: 'object', nullable: true }
    }
  },
  rpcResponse: {
    type: 'object',
    required: ['jsonrpc'],
    fields: {
      jsonrpc: { type: 'string', const: '2.0' },
      id: { type: 'string', nullable: true },
      result: { type: 'object', nullable: true },
      error: { type: 'object', nullable: true }
    }
  }
};
