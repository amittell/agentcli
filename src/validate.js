import { MANIFEST_VERSION } from './schema.js';
import { onFailureTaskId } from './shorthand.js';

const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const TOKEN_RE = /^[A-Za-z0-9@:_./-]+$/;
const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

function isObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

function addError(errors, path, message) {
  errors.push({ path, message });
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
    if (!value.slice('regex:'.length)) {
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
    if (!value.slice('contains:'.length)) {
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

function validateOptionalBlocks(errors, warnings, path, value) {
  if (isObject(value.model_policy)) {
    validateModelPolicy(errors, `${path}.model_policy`, value.model_policy);
  }

  if (isObject(value.intent)) {
    validateIntent(errors, `${path}.intent`, value.intent);
  }

  if (isObject(value.output)) {
    validateOutput(errors, `${path}.output`, value.output);
  }

  if (isObject(value.budgets)) {
    validateBudgets(errors, `${path}.budgets`, value.budgets);
  }

  if (isObject(value.delivery)) {
    checkEnum(errors, `${path}.delivery.mode`, value.delivery.mode, ['announce', 'announce-always', 'none']);
    checkToken(errors, `${path}.delivery.channel`, value.delivery.channel, { required: false });
    checkToken(errors, `${path}.delivery.to`, value.delivery.to, { required: false });
  }

  if (isObject(value.reliability)) {
    checkEnum(errors, `${path}.reliability.guarantee`, value.reliability.guarantee, ['at-most-once', 'at-least-once']);
    checkEnum(errors, `${path}.reliability.overlap_policy`, value.reliability.overlap_policy, ['skip', 'allow', 'queue']);
    checkInteger(errors, `${path}.reliability.max_retries`, value.reliability.max_retries, 0);
  }

  if (isObject(value.runtime)) {
    checkInteger(errors, `${path}.runtime.timeout_ms`, value.runtime.timeout_ms, 1);
  }

  if (isObject(value.approval)) {
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

  if (isObject(value.context)) {
    checkEnum(errors, `${path}.context.retrieval`, value.context.retrieval, ['none', 'recent', 'hybrid']);
    checkInteger(errors, `${path}.context.limit`, value.context.limit, 1);
    if (value.budgets?.max_context_items != null && value.context.limit != null && value.budgets.max_context_items !== value.context.limit) {
      warnings.push({
        path: `${path}.context.limit`,
        message: 'context.limit takes precedence over budgets.max_context_items when both are set'
      });
    }
  }

  if (isObject(value.session)) {
    checkToken(errors, `${path}.session.preferred_key`, value.session.preferred_key, { required: false });
  }

  checkBoolean(errors, `${path}.delete_after_run`, value.delete_after_run);
}

function validateOnFailure(errors, warnings, path, task) {
  if (task.on_failure == null) return;
  if (!isObject(task.on_failure)) {
    addError(errors, path, 'must be an object');
    return;
  }

  const handler = task.on_failure;
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

export function validateManifest(manifest) {
  const errors = [];
  const warnings = [];

  if (!isObject(manifest)) {
    return { ok: false, errors: [{ path: '$', message: 'manifest must be an object' }], warnings };
  }

  if (manifest.version !== MANIFEST_VERSION) {
    addError(errors, '$.version', `must equal ${MANIFEST_VERSION}`);
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
      checkIdentifier(errors, `${workflowPath}.id`, workflow.id);
      checkString(errors, `${workflowPath}.name`, workflow.name);
      if (isObject(workflow.model_policy)) {
        validateModelPolicy(errors, `${workflowPath}.model_policy`, workflow.model_policy);
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

        const hasSchedule = isObject(task.schedule);
        const hasTrigger = isObject(task.trigger);
        if (hasSchedule === hasTrigger) {
          addError(errors, taskPath, 'must define exactly one of schedule or trigger');
        }

        if (hasSchedule) {
          checkString(errors, `${taskPath}.schedule.cron`, task.schedule.cron);
          checkString(errors, `${taskPath}.schedule.tz`, task.schedule.tz, { required: false });
        }

        if (hasTrigger) {
          checkString(errors, `${taskPath}.trigger.parent`, task.trigger.parent);
          checkEnum(errors, `${taskPath}.trigger.on`, task.trigger.on, ['success', 'failure', 'complete']);
          checkInteger(errors, `${taskPath}.trigger.delay_s`, task.trigger.delay_s, 0);
          validateTriggerCondition(errors, `${taskPath}.trigger.condition`, task.trigger.condition);
        }

        validateOptionalBlocks(errors, warnings, taskPath, task);
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
          if (task.trigger.parent && !validTaskIds.has(task.trigger.parent)) {
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

  return { ok: errors.length === 0, errors, warnings };
}
