import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { validateManifest } from './validate.js';
import { expandManifestShorthands } from './shorthand.js';
import { normalizeShellExecution } from './shell.js';
import { resolveIdentity, resolveContract } from './compiler/shared.js';
import { generateExecutionId, writeAuditRecord } from './audit.js';
import { getAgentcliPaths } from './home.js';
import { buildAttestationPayload, commandHash } from './attestation.js';
import { resolveProvider } from './signing/index.js';

// Ensure the ssh provider is registered on import
import './signing/ssh.js';

function preflightContractChecks(contract, shell) {
  const violations = [];
  const warnings = [];

  if (contract.allowed_paths && shell.cwd) {
    const allowed = contract.allowed_paths.some(p =>
      shell.cwd === p || shell.cwd.startsWith(p.endsWith('/') ? p : `${p}/`)
    );
    if (!allowed) {
      violations.push({
        field: 'contract.allowed_paths',
        message: `shell.cwd "${shell.cwd}" is not under any allowed path`
      });
    }
  }

  if (contract.sandbox === 'strict') {
    warnings.push('contract.sandbox is "strict" but OS-level sandboxing is not yet enforced by agentcli exec');
  }
  if (contract.sandbox === 'permissive') {
    warnings.push('contract.sandbox is "permissive"; execution proceeds with advisory logging');
  }
  if (contract.network === 'none') {
    warnings.push('contract.network is "none" but network blocking is not yet enforced by agentcli exec');
  }
  if (contract.network === 'restricted') {
    warnings.push('contract.network is "restricted"; execution proceeds with advisory logging');
  }

  return { violations, warnings };
}

function resolvePrincipal(identity) {
  if (identity.principal) return identity.principal;
  const user = process.env.USER || process.env.USERNAME || 'unknown';
  const host = process.env.HOSTNAME || process.env.HOST || 'localhost';
  return `${user}@${host}`;
}

export function executeTask(manifest, {
  workflowId,
  taskId,
  dryRun = false,
  timeoutMs,
  signer,
  signingKey: explicitSigningKey,
  cwd = process.cwd(),
  env = process.env,
} = {}) {
  if (!taskId) {
    throw Object.assign(
      new Error('taskId is required'),
      { code: 'invalid_argument' }
    );
  }

  const validation = validateManifest(manifest);
  if (!validation.ok) {
    throw Object.assign(
      new Error('Manifest validation failed'),
      { code: 'validation_error', validation }
    );
  }

  const expanded = expandManifestShorthands(manifest);

  let workflow;
  if (workflowId) {
    workflow = expanded.workflows.find(w => w.id === workflowId);
    if (!workflow) {
      throw Object.assign(
        new Error(`Workflow not found: ${workflowId}`),
        { code: 'invalid_argument' }
      );
    }
  } else if (expanded.workflows.length === 1) {
    workflow = expanded.workflows[0];
  } else {
    throw Object.assign(
      new Error(`Multiple workflows found; specify --workflow. Available: ${expanded.workflows.map(w => w.id).join(', ')}`),
      { code: 'invalid_argument' }
    );
  }

  const task = workflow.tasks.find(t => t.id === taskId);
  if (!task) {
    throw Object.assign(
      new Error(`Task not found: ${taskId} in workflow ${workflow.id}. Available: ${workflow.tasks.map(t => t.id).join(', ')}`),
      { code: 'invalid_argument' }
    );
  }

  if (task.target?.session_target !== 'shell') {
    throw Object.assign(
      new Error(
        `exec only supports shell-target tasks. Task "${taskId}" has session_target "${task.target?.session_target}". ` +
        'Prompt-based tasks require an agent runtime.'
      ),
      { code: 'invalid_argument' }
    );
  }

  if (!task.shell) {
    throw Object.assign(
      new Error(`Task "${taskId}" is a shell target but has no shell block`),
      { code: 'validation_error' }
    );
  }

  const identity = resolveIdentity(workflow, task);
  const contract = resolveContract(workflow, task);
  const auditPolicy = contract.audit ?? 'always';
  const shell = normalizeShellExecution(task.shell);
  const effectiveTimeout = timeoutMs ?? task.runtime?.timeout_ms ?? null;
  const { violations, warnings } = preflightContractChecks(contract, shell);

  if (violations.length > 0) {
    throw Object.assign(
      new Error(`Contract violation: ${violations.map(v => v.message).join('; ')}`),
      { code: 'contract_violation', violations, warnings }
    );
  }

  const timestamp = new Date().toISOString();
  const executionId = generateExecutionId(workflow.id, task.id, timestamp);
  const principal = resolvePrincipal(identity);

  const commandMeta = {
    program: shell.program,
    args: shell.args,
    cwd: shell.cwd || cwd,
    env_keys: Object.keys(shell.env),
    stdin_present: shell.stdin != null,
  };

  const cmdHash = commandHash(shell);

  // Resolve signing provider
  const provider = resolveProvider({ signer, env });
  const providerConfig = provider.resolve({ env, signingKey: explicitSigningKey });

  function buildAndSign() {
    if (!providerConfig) {
      return {
        attestation: null,
        attestation_note: `no credentials found for signing provider "${provider.name}"`,
      };
    }

    const payload = buildAttestationPayload({
      executionId,
      timestamp,
      source: { workflow_id: workflow.id, task_id: task.id },
      commandHash: cmdHash,
      principal,
    });

    const sigResult = provider.sign(payload, providerConfig);
    if (!sigResult.signed) {
      return { attestation: null, attestation_note: sigResult.reason };
    }

    return { attestation: sigResult.attestation, attestation_note: null };
  }

  if (dryRun) {
    const { attestation, attestation_note } = buildAndSign();

    const record = {
      execution_id: executionId,
      timestamp,
      source: { workflow_id: workflow.id, task_id: task.id },
      identity: {
        principal: identity.principal,
        run_as: identity.run_as,
        attestation_present: identity.attestation != null,
      },
      principal_used: principal,
      contract,
      command: commandMeta,
      command_hash: cmdHash,
      signer: provider.name,
      attestation,
      attestation_note,
      warnings,
      dry_run: true,
      result: { status: 'dry_run' },
    };

    if (auditPolicy === 'always') {
      const paths = getAgentcliPaths({ env });
      writeAuditRecord(record, { auditPath: paths.audit });
    }

    return {
      ok: true,
      dry_run: true,
      execution_id: executionId,
      source: record.source,
      identity,
      principal_used: principal,
      contract,
      command: commandMeta,
      command_hash: cmdHash,
      signer: provider.name,
      attestation: attestation ? { method: attestation.method, key_fingerprint: attestation.key_fingerprint } : null,
      attestation_note,
      warnings,
    };
  }

  const spawnEnv = Object.keys(shell.env).length > 0
    ? { ...process.env, ...shell.env }
    : process.env;

  const spawnOpts = {
    cwd: shell.cwd || cwd,
    env: spawnEnv,
    encoding: 'utf8',
    maxBuffer: 10 * 1024 * 1024,
  };

  if (effectiveTimeout) {
    spawnOpts.timeout = effectiveTimeout;
  }

  if (shell.stdin != null) {
    spawnOpts.input = shell.stdin;
  }

  const startMs = Date.now();
  const proc = spawnSync(shell.program, shell.args, spawnOpts);
  const durationMs = Date.now() - startMs;

  const stdout = proc.stdout || '';
  const stderr = proc.stderr || '';
  const exitCode = proc.status;
  const signal = proc.signal || null;
  const timedOut = Boolean(proc.error && proc.error.code === 'ETIMEDOUT') || signal === 'SIGTERM';

  const outputHash = createHash('sha256')
    .update(stdout)
    .update(stderr)
    .digest('hex');

  const outputFormat = task.output?.format ?? null;
  let structured = null;
  let structuredParseError = null;

  if (outputFormat === 'json' && stdout.trim()) {
    try {
      structured = JSON.parse(stdout);
    } catch (e) {
      structuredParseError = `output.format is "json" but stdout is not valid JSON: ${e.message}`;
    }
  } else if (outputFormat === 'ndjson' && stdout.trim()) {
    try {
      structured = stdout.trim().split('\n').map(line => JSON.parse(line));
    } catch (e) {
      structuredParseError = `output.format is "ndjson" but stdout contains invalid JSON lines: ${e.message}`;
    }
  }

  if (structuredParseError) {
    warnings.push(structuredParseError);
  }

  const result = {
    exit_code: exitCode,
    signal,
    timed_out: timedOut,
    duration_ms: durationMs,
    stdout,
    stderr,
    stdout_bytes: Buffer.byteLength(stdout, 'utf8'),
    stderr_bytes: Buffer.byteLength(stderr, 'utf8'),
    output_hash: `sha256:${outputHash}`,
    structured,
  };

  const { attestation, attestation_note } = buildAndSign();

  const auditResult = {
    exit_code: exitCode,
    signal,
    timed_out: timedOut,
    duration_ms: durationMs,
    stdout_bytes: result.stdout_bytes,
    stderr_bytes: result.stderr_bytes,
    output_hash: result.output_hash,
    structured_present: structured != null,
  };

  const shouldAudit =
    auditPolicy === 'always' ||
    (auditPolicy === 'on-failure' && exitCode !== 0);

  if (shouldAudit) {
    const record = {
      execution_id: executionId,
      timestamp,
      source: { workflow_id: workflow.id, task_id: task.id },
      identity: {
        principal: identity.principal,
        run_as: identity.run_as,
        attestation_present: identity.attestation != null,
      },
      principal_used: principal,
      contract,
      command: commandMeta,
      command_hash: cmdHash,
      signer: provider.name,
      attestation,
      attestation_note,
      warnings,
      dry_run: false,
      result: auditResult,
    };
    const paths = getAgentcliPaths({ env });
    writeAuditRecord(record, { auditPath: paths.audit });
  }

  return {
    ok: exitCode === 0,
    execution_id: executionId,
    source: { workflow_id: workflow.id, task_id: task.id },
    identity,
    principal_used: principal,
    contract,
    result,
    signer: provider.name,
    attestation: attestation ? { method: attestation.method, key_fingerprint: attestation.key_fingerprint } : null,
    attestation_note,
    warnings,
    audited: shouldAudit,
  };
}
