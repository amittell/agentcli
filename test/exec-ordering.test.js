import test from 'node:test';
import assert from 'node:assert/strict';
import {
  existsSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  evaluateTaskAuthorization,
  executeTask,
  inspectTaskIdentity,
  verifyTaskAuthorizationProof,
} from '../src/exec.js';
import { grantApproval } from '../src/approvals.js';
import { getAgentcliPaths } from '../src/home.js';
import { registerProvider as registerIdentityProvider } from '../src/identity/index.js';
import { registerAuthorizationProvider } from '../src/authorization/index.js';

function isolatedEnvironment(prefix) {
  const root = mkdtempSync(join(tmpdir(), prefix));
  return {
    root,
    env: { ...process.env, AGENTCLI_HOME: join(root, 'home'), AGENTCLI_SIGNER: 'none' },
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

function proofCommandManifest(marker, approval = { policy: 'manual', risk_level: 'high' }) {
  return {
    version: '0.2',
    authorization_proof_profiles: [{
      id: 'command-proof',
      method: 'none',
      proof: {
        value_from: {
          command: `printf ran > ${JSON.stringify(marker)}`,
        },
      },
      verify: { required: false },
    }],
    workflows: [{
      id: 'ops',
      name: 'Ops',
      tasks: [{
        id: 'dangerous',
        name: 'Dangerous',
        target: { session_target: 'shell' },
        shell: { program: 'printf', args: ['ok'] },
        schedule: { cron: '0 * * * *' },
        approval,
        authorization_proof: { ref: 'command-proof' },
        contract: { sandbox: 'permissive', network: 'unrestricted', audit: 'always' },
      }],
    }],
  };
}

test('manual approval is enforced before proof value_from.command', async () => {
  const { root, env, cleanup } = isolatedEnvironment('agentcli-order-proof-');
  const marker = join(root, 'proof-ran');
  try {
    const manifest = proofCommandManifest(marker);
    await assert.rejects(
      executeTask(manifest, { taskId: 'dangerous', env, signer: 'none' }),
      error => error.code === 'approval_required'
    );
    assert.equal(existsSync(marker), false);
  } finally {
    cleanup();
  }
});

test('dry-run does not resolve proof commands, sign, or write audit records', async () => {
  const { root, env, cleanup } = isolatedEnvironment('agentcli-order-dry-');
  const marker = join(root, 'proof-ran');
  try {
    const manifest = proofCommandManifest(marker);
    const result = await executeTask(manifest, {
      taskId: 'dangerous',
      dryRun: true,
      env,
      signer: 'none',
    });
    assert.equal(result.ok, true);
    assert.equal(result.dry_run, true);
    assert.equal(result.phases.authorization_proof, 'skipped');
    assert.equal(result.phases.audit, 'skipped');
    assert.equal(existsSync(marker), false);
    assert.equal(existsSync(getAgentcliPaths({ env }).audit), false);
  } finally {
    cleanup();
  }
});

test('manual approval is enforced before identity provider resolution', async () => {
  const { root, env, cleanup } = isolatedEnvironment('agentcli-order-identity-');
  const marker = join(root, 'resolved');
  const providerName = `ordering-provider-${process.pid}-${Date.now()}`;
  registerIdentityProvider({
    name: providerName,
    capabilities: {
      auth_modes: ['service'], credential_types: [], presentation_kinds: ['none'],
      handoff_modes: ['none'], refreshable: false, delegation: false,
      trust_levels: ['supervised'], approval_mechanisms: [],
    },
    validateProfile: () => ({ valid: true }),
    resolveSession: () => {
      writeFileSync(marker, 'resolved');
      return {
        provider: providerName,
        subject: { principal: 'test', issuer: null, run_as: null },
        trust: { declared_level: 'supervised', effective_level: 'supervised' },
        delegation_validation: { valid: true },
        credentials: {},
        provider_assertions: {},
      };
    },
    describeSession: session => ({ provider: session.provider, subject: session.subject }),
    materialize: () => ({ materialized: false, env_vars: {}, cleanup_required: false }),
    cleanup: () => ({ cleaned: true, warnings: [] }),
  });

  const manifest = {
    version: '0.2',
    identity_profiles: [{ id: 'identity', provider: providerName }],
    workflows: [{
      id: 'ops', name: 'Ops', tasks: [{
        id: 'task', name: 'Task', target: { session_target: 'shell' },
        shell: { program: 'printf', args: ['ok'] },
        schedule: { cron: '0 * * * *' },
        approval: { policy: 'manual', risk_level: 'high' },
        identity: { ref: 'identity' },
        contract: { sandbox: 'permissive', network: 'unrestricted', audit: 'none' },
      }],
    }],
  };

  try {
    await assert.rejects(
      executeTask(manifest, { taskId: 'task', env, signer: 'none' }),
      error => error.code === 'approval_required'
    );
    assert.equal(existsSync(marker), false);
  } finally {
    cleanup();
  }
});

test('materialized credentials are cleaned when post-execution verify fails', async () => {
  const { root, env, cleanup } = isolatedEnvironment('agentcli-order-cleanup-');
  const credentialFile = join(root, 'credential');
  const providerName = `cleanup-provider-${process.pid}-${Date.now()}`;
  registerIdentityProvider({
    name: providerName,
    capabilities: {
      auth_modes: ['service'], credential_types: ['token'], presentation_kinds: ['file'],
      handoff_modes: ['none'], refreshable: false, delegation: false,
      trust_levels: ['supervised'], approval_mechanisms: [],
    },
    validateProfile: () => ({ valid: true }),
    resolveSession: () => ({
      provider: providerName,
      subject: { principal: 'test', issuer: null, run_as: null },
      trust: { declared_level: 'supervised', effective_level: 'supervised' },
      delegation_validation: { valid: true },
      credentials: { token: { value: 'secret' } },
      provider_assertions: {},
    }),
    describeSession: session => ({ provider: session.provider, subject: session.subject }),
    materialize: session => {
      writeFileSync(credentialFile, session.credentials.token.value, { mode: 0o600 });
      return { materialized: true, env_vars: {}, temp_files: [credentialFile], cleanup_required: true };
    },
    cleanup: materialization => {
      for (const file of materialization.temp_files || []) rmSync(file, { force: true });
      return { cleaned: true, warnings: [] };
    },
  });

  const manifest = {
    version: '0.2',
    identity_profiles: [{ id: 'identity', provider: providerName }],
    workflows: [{
      id: 'ops', name: 'Ops', tasks: [{
        id: 'task', name: 'Task', target: { session_target: 'shell' },
        shell: { program: 'printf', args: ['ok'] },
        schedule: { cron: '0 * * * *' },
        approval: { policy: 'manual', risk_level: 'high' },
        identity: { ref: 'identity' },
        verify: { shell: 'exit 1', on_failure: 'error' },
        contract: { sandbox: 'permissive', network: 'unrestricted', audit: 'none' },
      }],
    }],
  };

  try {
    grantApproval({ manifest, taskId: 'task', approver: 'alice', signer: 'none', env });
    await assert.rejects(
      executeTask(manifest, { taskId: 'task', env, signer: 'none' }),
      error => error.code === 'verify_failed'
    );
    assert.equal(existsSync(credentialFile), false);
  } finally {
    cleanup();
  }
});

test('source credentials are not inherited by child processes unless explicitly declared', async () => {
  const { env, cleanup } = isolatedEnvironment('agentcli-child-env-');
  env.MASTER_API_TOKEN = 'source-secret';
  env.NEUTRAL_SOURCE_VALUE = 'neutral-secret';
  try {
    const manifest = {
      version: '0.2',
      workflows: [{
        id: 'ops', name: 'Ops', tasks: [{
          id: 'task', name: 'Task', target: { session_target: 'shell' },
          shell: {
            program: process.execPath,
            args: ['-e', `process.stdout.write(JSON.stringify({
              named: process.env.MASTER_API_TOKEN || 'missing',
              neutral: process.env.NEUTRAL_SOURCE_VALUE || 'missing',
              declared: process.env.DECLARED_INPUT || 'missing',
            }))`],
            env: { DECLARED_INPUT: 'allowed' },
          },
          schedule: { cron: '0 * * * *' },
          contract: { sandbox: 'permissive', network: 'unrestricted', audit: 'none' },
        }],
      }],
    };
    const result = await executeTask(manifest, { taskId: 'task', env, signer: 'none' });
    assert.deepEqual(JSON.parse(result.result.stdout), {
      named: 'missing',
      neutral: 'missing',
      declared: 'allowed',
    });
  } finally {
    cleanup();
  }
});

test('explicit identity inspection resolves and cleans identity without executing the task', async () => {
  const { root, env, cleanup } = isolatedEnvironment('agentcli-inspect-identity-');
  const resolvedMarker = join(root, 'resolved');
  const materializedMarker = join(root, 'materialized');
  const taskMarker = join(root, 'task-ran');
  const providerName = `inspection-provider-${process.pid}-${Date.now()}`;
  registerIdentityProvider({
    name: providerName,
    capabilities: {
      auth_modes: ['service'], credential_types: [], presentation_kinds: ['none'],
      handoff_modes: ['none'], refreshable: false, delegation: false,
      trust_levels: ['supervised'], approval_mechanisms: [],
    },
    validateProfile: () => ({ valid: true }),
    resolveSession: () => {
      writeFileSync(resolvedMarker, 'resolved');
      return {
        provider: providerName,
        subject: { principal: 'agent://tests/inspection', issuer: null, run_as: null },
        trust: { declared_level: 'supervised', effective_level: 'supervised' },
        delegation_validation: { valid: true, depth: 0 },
        credentials: {},
        provider_assertions: {},
      };
    },
    describeSession: session => ({ provider: session.provider, subject: session.subject }),
    materialize: () => {
      writeFileSync(materializedMarker, 'materialized');
      return { materialized: false, env_vars: {}, cleanup_required: false };
    },
    cleanup: () => ({ cleaned: true, warnings: [] }),
  });
  const manifest = {
    version: '0.2',
    identity_profiles: [{ id: 'identity', provider: providerName }],
    workflows: [{
      id: 'ops', name: 'Ops', tasks: [{
        id: 'task', name: 'Task', target: { session_target: 'shell' },
        shell: { program: 'sh', args: ['-c', `touch ${JSON.stringify(taskMarker)}`] },
        schedule: { cron: '0 * * * *' },
        identity: { ref: 'identity' },
        contract: { sandbox: 'permissive', network: 'unrestricted', audit: 'always' },
      }],
    }],
  };

  try {
    const result = await inspectTaskIdentity(manifest, { taskId: 'task', env });
    assert.equal(result.ok, true);
    assert.equal(result.principal_used, 'agent://tests/inspection');
    assert.equal(existsSync(resolvedMarker), true);
    assert.equal(existsSync(materializedMarker), false);
    assert.equal(existsSync(taskMarker), false);
    assert.equal(existsSync(getAgentcliPaths({ env }).audit), false);
  } finally {
    cleanup();
  }
});

test('explicit authorization evaluation returns deny without executing or auditing the task', async () => {
  const { root, env, cleanup } = isolatedEnvironment('agentcli-evaluate-auth-');
  const taskMarker = join(root, 'task-ran');
  const providerName = `authorization-inspection-${process.pid}-${Date.now()}`;
  registerAuthorizationProvider({
    name: providerName,
    capabilities: { decision_kinds: ['permit', 'deny'], escalation: false },
    validateProfile: () => ({ valid: true }),
    authorize: () => ({ decision: 'deny', reason: 'policy denied the action' }),
    describeDecision: decision => ({
      decision: decision.decision,
      reason: decision.reason ?? null,
    }),
  });
  const manifest = {
    version: '0.2',
    authorization_profiles: [{ id: 'policy', provider: providerName }],
    workflows: [{
      id: 'ops', name: 'Ops', tasks: [{
        id: 'task', name: 'Task', target: { session_target: 'shell' },
        shell: { program: 'sh', args: ['-c', `touch ${JSON.stringify(taskMarker)}`] },
        schedule: { cron: '0 * * * *' },
        authorization: { ref: 'policy' },
        contract: { sandbox: 'permissive', network: 'unrestricted', audit: 'always' },
      }],
    }],
  };

  try {
    const result = await evaluateTaskAuthorization(manifest, { taskId: 'task', env });
    assert.equal(result.ok, true);
    assert.equal(result.authorization.decision, 'deny');
    assert.equal(existsSync(taskMarker), false);
    assert.equal(existsSync(getAgentcliPaths({ env }).audit), false);
  } finally {
    cleanup();
  }
});

test('explicit proof verification resolves proof input without executing or auditing the task', async () => {
  const { root, env, cleanup } = isolatedEnvironment('agentcli-inspect-proof-');
  const proofMarker = join(root, 'proof-ran');
  const taskMarker = join(root, 'task-ran');
  const manifest = {
    version: '0.2',
    authorization_proof_profiles: [{
      id: 'proof',
      method: 'none',
      proof: {
        value_from: {
          command: `touch ${JSON.stringify(proofMarker)} && printf proof-value`,
        },
      },
      verify: { required: false },
    }],
    workflows: [{
      id: 'ops', name: 'Ops', tasks: [{
        id: 'task', name: 'Task', target: { session_target: 'shell' },
        shell: { program: 'sh', args: ['-c', `touch ${JSON.stringify(taskMarker)}`] },
        schedule: { cron: '0 * * * *' },
        authorization_proof: { ref: 'proof' },
        contract: { sandbox: 'permissive', network: 'unrestricted', audit: 'always' },
      }],
    }],
  };

  try {
    const result = await verifyTaskAuthorizationProof(manifest, { taskId: 'task', env });
    assert.equal(result.ok, true);
    assert.equal(result.authorization_proof.method, 'none');
    assert.equal(existsSync(proofMarker), true);
    assert.equal(existsSync(taskMarker), false);
    assert.equal(existsSync(getAgentcliPaths({ env }).audit), false);
  } finally {
    cleanup();
  }
});
