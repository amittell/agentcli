import test from 'node:test';
import assert from 'node:assert/strict';
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  buildEffectiveExecutionBinding,
  canonicalDigest,
  canonicalStringify,
  computeEffectiveTaskHash,
  convertManifestV1toV2,
  normalizeError,
  addToRegistry,
  ensureAgentcliHome,
  listRegistry,
  showRegistryEntry,
  validateManifest,
  writeAuditRecord,
  writeJsonOutput,
} from '../src/index.js';

function manifestWithSecrets() {
  return {
    version: '0.2',
    identity_profiles: [{
      id: 'operator',
      provider: 'env-bearer',
      auth: {
        provider_config: { client_secret: 'profile-secret' },
        inputs: { token: { literal: 'input-secret' } },
      },
    }],
    workflows: [{
      id: 'ops',
      name: 'Ops',
      tasks: [{
        id: 'deploy',
        name: 'Deploy',
        target: { session_target: 'shell' },
        shell: {
          program: 'printf',
          args: ['argument-secret'],
          env: { TOKEN: 'environment-secret' },
          stdin: 'stdin-secret',
        },
        schedule: { cron: '0 * * * *' },
        identity: { ref: 'operator' },
        approval: {
          policy: 'manual',
          risk_level: 'high',
          timeout_s: 120,
          approver_scope: 'domain:example.com',
        },
        contract: { sandbox: 'permissive', network: 'unrestricted', audit: 'always' },
      }],
    }],
  };
}

test('canonical serialization is deterministic for nested object key order', () => {
  const first = { z: 1, a: { y: [3, { b: 2, a: 1 }], x: true } };
  const second = { a: { x: true, y: [3, { a: 1, b: 2 }] }, z: 1 };
  assert.equal(canonicalStringify(first), canonicalStringify(second));
  assert.equal(canonicalDigest(first), canonicalDigest(second));
});

test('effective execution binding covers governed fields without exposing secrets', () => {
  const manifest = manifestWithSecrets();
  const workflow = manifest.workflows[0];
  const task = workflow.tasks[0];
  const binding = buildEffectiveExecutionBinding({ manifest, expanded: manifest, workflow, task });
  const serialized = canonicalStringify(binding);

  for (const secret of [
    'profile-secret',
    'input-secret',
    'argument-secret',
    'environment-secret',
    'stdin-secret',
  ]) {
    assert.equal(serialized.includes(secret), false, `binding leaked ${secret}`);
  }

  assert.equal(binding.approval.approver_scope, 'domain:example.com');
  assert.equal(binding.approval.timeout_s, 120);
  assert.match(binding.command.stdin_hash, /^sha256:/);
  assert.match(binding.command.env_hashes.TOKEN, /^sha256:/);
});

test('effective task hash changes for env, stdin, profile, contract, and verify changes', () => {
  const original = manifestWithSecrets();
  const hash = value => {
    const workflow = value.workflows[0];
    const task = workflow.tasks[0];
    return computeEffectiveTaskHash(buildEffectiveExecutionBinding({
      manifest: value,
      expanded: value,
      workflow,
      task,
    }));
  };
  const originalHash = hash(original);

  const mutations = [
    value => { value.workflows[0].tasks[0].shell.env.TOKEN = 'changed'; },
    value => { value.workflows[0].tasks[0].shell.stdin = 'changed'; },
    value => { value.identity_profiles[0].auth.provider_config.client_secret = 'changed'; },
    value => { value.workflows[0].tasks[0].contract.network = 'none'; },
    value => { value.workflows[0].tasks[0].verify = { shell: 'test -f output' }; },
  ];

  for (const mutate of mutations) {
    const changed = structuredClone(original);
    mutate(changed);
    assert.notEqual(hash(changed), originalHash);
  }
});

test('normalizeError exposes a closed error type and a separate detailed code', () => {
  const normalized = normalizeError(Object.assign(new Error('approval missing'), {
    code: 'approval_required',
  }));
  assert.equal(normalized.code, 'approval_required');
  assert.equal(normalized.error_type, 'validation_error');

  const unknown = normalizeError(Object.assign(new Error('library failure'), {
    code: 'ERR_SOMETHING_PRIVATE',
  }));
  assert.equal(unknown.code, 'internal_error');
  assert.equal(unknown.error_type, 'internal_error');
});

test('registry reports overwrites accurately and stores entries with private permissions', () => {
  const home = mkdtempSync(join(tmpdir(), 'agentcli-registry-'));
  const env = { ...process.env, AGENTCLI_HOME: home };
  const manifest = {
    version: '0.2',
    workflows: [{
      id: 'registry-test',
      name: 'Registry Test',
      tasks: [{
        id: 'run',
        name: 'Run',
        target: { session_target: 'shell' },
        shell: { program: 'true', args: [] },
        schedule: { cron: '0 * * * *' },
        output: { format: 'text' },
        contract: { sandbox: 'permissive', network: 'unrestricted', audit: 'always' },
      }],
    }],
  };

  try {
    const first = addToRegistry(manifest, { name: 'private-entry', env });
    const second = addToRegistry(manifest, { name: 'private-entry', env });
    assert.equal(first.overwritten, false);
    assert.equal(second.overwritten, true);
    if (process.platform !== 'win32') {
      assert.equal(statSync(first.path).mode & 0o777, 0o600);
      assert.equal(statSync(join(home, 'registry')).mode & 0o777, 0o700);
    }
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('audit append refuses symbolic-link destinations', { skip: process.platform === 'win32' }, () => {
  const root = mkdtempSync(join(tmpdir(), 'agentcli-audit-link-'));
  const target = join(root, 'outside.ndjson');
  const auditPath = join(root, 'audit.ndjson');
  try {
    writeFileSync(target, 'unchanged\n', 'utf8');
    symlinkSync(target, auditPath);
    assert.throws(
      () => writeAuditRecord({ execution_id: 'blocked' }, { auditPath }),
      error => error.code === 'ELOOP' || error.code === 'EACCES'
    );
    assert.equal(readFileSync(target, 'utf8'), 'unchanged\n');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('JSON output tightens permissions when overwriting an existing file', {
  skip: process.platform === 'win32',
}, () => {
  const root = mkdtempSync(join(tmpdir(), 'agentcli-output-mode-'));
  const outputPath = join(root, 'result.json');
  try {
    writeFileSync(outputPath, '{"old":true}\n', { mode: 0o644 });
    chmodSync(outputPath, 0o644);
    writeJsonOutput('result.json', { ok: true }, { cwd: root });
    assert.equal(statSync(outputPath).mode & 0o777, 0o600);
    assert.deepEqual(JSON.parse(readFileSync(outputPath, 'utf8')), { ok: true });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('registry refuses symbolic-link entries', { skip: process.platform === 'win32' }, () => {
  const home = mkdtempSync(join(tmpdir(), 'agentcli-registry-link-'));
  const env = { ...process.env, AGENTCLI_HOME: home };
  const manifest = {
    version: '0.2',
    workflows: [{
      id: 'registry-link', name: 'Registry Link', tasks: [{
        id: 'run', name: 'Run', target: { session_target: 'shell' },
        shell: { program: 'true', args: [] },
        schedule: { cron: '0 * * * *' },
      }],
    }],
  };
  try {
    addToRegistry(manifest, { name: 'safe', env });
    const target = join(home, 'outside.json');
    writeFileSync(target, '{"outside":true}\n', 'utf8');
    symlinkSync(target, join(home, 'registry', 'linked.json'));
    assert.throws(
      () => addToRegistry(manifest, { name: 'linked', env }),
      /symbolic-link/
    );
    assert.throws(() => showRegistryEntry('linked', { env }), /symbolic-link/);
    const linked = listRegistry({ env }).find(entry => entry.name === 'linked');
    assert.equal(linked.symlink_refused, true);
    assert.equal(readFileSync(target, 'utf8'), '{"outside":true}\n');
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('agentcli home stores state and scaffold files with private permissions', {
  skip: process.platform === 'win32',
}, () => {
  const home = mkdtempSync(join(tmpdir(), 'agentcli-private-home-'));
  const env = { ...process.env, AGENTCLI_HOME: home };
  try {
    const result = ensureAgentcliHome({ env });
    for (const directory of [
      result.paths.root,
      result.paths.manifests,
      result.paths.output,
      result.paths.state,
      result.paths.registry,
    ]) {
      assert.equal(statSync(directory).mode & 0o777, 0o700);
    }
    for (const file of [result.paths.readme, result.paths.sampleManifest]) {
      assert.equal(statSync(file).mode & 0o777, 0o600);
    }
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('v0.1 conversion produces unique valid profile ids for colliding principal slugs', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'convert-collisions',
      name: 'Convert Collisions',
      tasks: [
        {
          id: 'first', name: 'First', target: { session_target: 'shell' },
          shell: { program: 'true', args: [] },
          schedule: { cron: '0 * * * *' },
          identity: { principal: 'agent/a@b' },
        },
        {
          id: 'second', name: 'Second', target: { session_target: 'shell' },
          shell: { program: 'true', args: [] },
          schedule: { cron: '5 * * * *' },
          identity: { principal: 'agent/a/b' },
        },
      ],
    }],
  };
  const converted = convertManifestV1toV2(manifest);
  const ids = converted.identity_profiles.map(profile => profile.id);
  assert.equal(new Set(ids).size, 2);
  assert.equal(converted.version, '0.2');
});

test('complete manifest examples in the identity guide remain valid', () => {
  const guide = readFileSync(new URL('../docs/guide-identity.md', import.meta.url), 'utf8');
  const manifests = [...guide.matchAll(/```json\s*\n([\s\S]*?)```/g)]
    .map(match => match[1])
    .filter(block => /"version"\s*:/.test(block) && /"workflows"\s*:/.test(block))
    .map(block => JSON.parse(block));
  assert.ok(manifests.length >= 10);
  for (const manifest of manifests) {
    const validation = validateManifest(manifest);
    assert.equal(
      validation.ok,
      true,
      validation.errors.map(error => `${error.path}: ${error.message}`).join('; ')
    );
  }
});
