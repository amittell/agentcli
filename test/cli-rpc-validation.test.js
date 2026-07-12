import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  closeSync,
  constants as fsConstants,
  existsSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { runCli } from '../src/cli.js';
import { handleJsonRpcRequest } from '../src/jsonrpc.js';
import { writeJsonOutput } from '../src/io.js';
import { JSON_SCHEMAS, MANIFEST_JSON_SCHEMA, MANIFEST_SCHEMA } from '../src/schema.js';
import { validateManifest } from '../src/validate.js';

function validManifest(overrides = {}) {
  return {
    version: '0.2',
    workflows: [{
      id: 'workflow',
      name: 'Workflow',
      tasks: [{
        id: 'task',
        name: 'Task',
        prompt: 'Run the task.',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' },
      }],
    }],
    ...overrides,
  };
}

function governanceInspectionManifest(markerPath) {
  return {
    version: '0.2',
    identity_profiles: [{
      id: 'operator',
      provider: 'env-bearer',
      subject: { kind: 'service', principal: 'agent://test/operator' },
      auth: {
        required: true,
        provider_config: { token_env: 'INSPECTION_TOKEN' },
      },
      trust: { level: 'supervised' },
    }],
    authorization_profiles: [{ id: 'permit', provider: 'none' }],
    workflows: [{
      id: 'workflow',
      name: 'Workflow',
      identity: { ref: 'operator' },
      authorization: { ref: 'permit' },
      tasks: [{
        id: 'task',
        name: 'Task',
        shell: {
          program: process.execPath,
          args: ['-e', `require('node:fs').writeFileSync(${JSON.stringify(markerPath)}, 'executed')`],
        },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        contract: { audit: 'none' },
      }],
    }],
  };
}

test('v0.2 validation rejects unknown governed keys at every nested level', () => {
  const manifest = validManifest();
  manifest.workflows[0].tasks[0].approval = { polciy: 'manual' };
  manifest.workflows[0].tasks[0].contract = { sandbxo: 'strict' };
  manifest.workflows[0].tasks[0].identity = {
    subject: { pricipal: 'operator' },
  };

  const result = validateManifest(manifest);
  assert.equal(result.ok, false);
  assert.deepEqual(
    result.errors.filter(error => /unknown key/.test(error.message)).map(error => error.path).sort(),
    [
      '$.workflows[0].tasks[0].approval.polciy',
      '$.workflows[0].tasks[0].contract.sandbxo',
      '$.workflows[0].tasks[0].identity.subject.pricipal',
    ]
  );
});

test('v0.2 validation keeps deliberate provider and claims extension maps open', () => {
  const manifest = validManifest({
    identity_profiles: [{
      id: 'identity',
      provider: 'none',
      provider_config: { vendor_extension: { arbitrary: true } },
      subject: { attributes: { team: 'platform', nested: { allowed: true } } },
      auth: {
        provider_config: { vendor_option: 'value' },
        inputs: { credential: { value_from: { env: 'CREDENTIAL' } } },
      },
    }],
    authorization_proof_profiles: [{
      id: 'proof',
      method: 'none',
      claims: { custom_claim: { required: true } },
    }],
  });
  manifest.workflows[0].identity = { ref: 'identity' };
  manifest.workflows[0].authorization_proof = { ref: 'proof', claims: { runtime_claim: 1 } };

  const result = validateManifest(manifest);
  assert.equal(result.ok, true, JSON.stringify(result.errors));
});

test('file presentation targets validate prefix and expose_as in manifests and JSON Schema', () => {
  const manifest = validManifest({
    identity_profiles: [{
      id: 'identity',
      provider: 'env-bearer',
      auth: {
        required: true,
        provider_config: { token_env: 'PRESENTATION_TOKEN' },
      },
      presentation: {
        bindings: [{
          source: 'credentials.access_token.value',
          target: {
            kind: 'file',
            prefix: 'agentcli-credential',
            expose_as: 'AGENTCLI_CREDENTIAL_FILE',
          },
        }],
      },
    }],
  });
  manifest.workflows[0].identity = { ref: 'identity' };
  assert.equal(validateManifest(manifest).ok, true);

  const targetSchema = MANIFEST_JSON_SCHEMA.$defs.presentationTarget;
  assert.ok(targetSchema.properties.prefix);
  assert.ok(targetSchema.properties.expose_as);

  const invalidPrefix = structuredClone(manifest);
  invalidPrefix.identity_profiles[0].presentation.bindings[0].target.prefix = '../escape';
  assert.equal(validateManifest(invalidPrefix).ok, false);
  const invalidEnv = structuredClone(manifest);
  invalidEnv.identity_profiles[0].presentation.bindings[0].target.expose_as = 'not-valid';
  assert.equal(validateManifest(invalidEnv).ok, false);
});

test('profile provider existence and synchronous structural validation are enforced', () => {
  const unknown = validManifest({
    identity_profiles: [{ id: 'identity', provider: 'does-not-exist' }],
  });
  unknown.workflows[0].identity = { ref: 'identity' };
  const unknownResult = validateManifest(unknown);
  assert.equal(unknownResult.ok, false);
  assert.ok(unknownResult.errors.some(error => /unknown identity provider/.test(error.message)));

  const insecureOidc = validManifest({
    identity_profiles: [{
      id: 'identity',
      provider: 'oidc-client-credentials',
      auth: {
        provider_config: {
          token_endpoint: 'http://issuer.example/token',
          client_id: 'agentcli',
        },
        inputs: { client_secret: { value_from: { env: 'OIDC_CLIENT_SECRET' } } },
      },
    }],
  });
  insecureOidc.workflows[0].identity = { ref: 'identity' };
  const oidcResult = validateManifest(insecureOidc);
  assert.equal(oidcResult.ok, false);
  assert.ok(oidcResult.errors.some(error => /must use HTTPS/i.test(error.message)));
});

test('authorization proof values cannot be embedded as circular literals', () => {
  const manifest = validManifest({
    authorization_proof_profiles: [{
      id: 'proof',
      method: 'jwt',
      public_key: 'not-a-valid-key',
      proof: { value_from: { literal: 'signed-value' } },
    }],
  });
  manifest.workflows[0].authorization_proof = { ref: 'proof' };

  const result = validateManifest(manifest);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(error => (
    error.path.endsWith('.proof.value_from.literal') && /not supported/.test(error.message)
  )));
});

test('schema API exports Draft 2020-12 and retains the legacy descriptor API', async () => {
  assert.equal(MANIFEST_JSON_SCHEMA.$schema, 'https://json-schema.org/draft/2020-12/schema');
  assert.equal(MANIFEST_JSON_SCHEMA.type, 'object');
  assert.equal(MANIFEST_JSON_SCHEMA.additionalProperties, false);
  assert.ok(MANIFEST_JSON_SCHEMA.$defs.task);
  assert.equal(JSON_SCHEMAS.task.$schema, MANIFEST_JSON_SCHEMA.$schema);
  assert.equal(MANIFEST_SCHEMA.manifest.fields.version.const, '0.2');

  const standard = JSON.parse(await runCli(['schema', 'manifest']));
  assert.equal(standard.schema_format, 'json-schema-draft-2020-12');
  assert.equal(standard.schema.$schema, MANIFEST_JSON_SCHEMA.$schema);
  assert.equal(standard.schema.additionalProperties, false);

  const legacy = JSON.parse(await runCli(['schema', 'manifest', '--legacy']));
  assert.equal(legacy.schema_format, 'agentcli-legacy');
  assert.equal(legacy.schema.fields.version.const, '0.2');
});

test('strict CLI parsing distinguishes boolean flags from value flags', async () => {
  const version = JSON.parse(await runCli(['--json', 'version']));
  assert.equal(version.ok, true);

  const compile = JSON.parse(await runCli([
    'compile',
    '--explain',
    JSON.stringify(validManifest()),
  ]));
  assert.equal(compile.ok, true);
  assert.ok(Array.isArray(compile.output.explain));

  await assert.rejects(
    runCli(['version', '--unknown']),
    error => error.code === 'invalid_argument' && /Unknown flag/.test(error.message)
  );
  await assert.rejects(
    runCli(['version', '--json=false']),
    error => error.code === 'invalid_argument' && /does not accept a value/.test(error.message)
  );
  await assert.rejects(
    runCli(['compile', JSON.stringify(validManifest()), '--target']),
    error => error.code === 'invalid_argument' && /requires a value/.test(error.message)
  );
  await assert.rejects(
    runCli(['version', '--json', 'false']),
    error => error.code === 'invalid_argument' && /positional argument/.test(error.message)
  );
});

test('runCli preserves validation-result compatibility while process mode throws', async () => {
  const manifest = { version: '0.2', workflows: [] };
  const libraryResult = JSON.parse(await runCli(['validate', JSON.stringify(manifest)]));
  assert.equal(libraryResult.ok, false);

  await assert.rejects(
    runCli(['validate', JSON.stringify(manifest)], { throwOnValidationFailure: true }),
    error => (
      error.code === 'validation_error' &&
      error.validation?.ok === false &&
      Array.isArray(error.validation.errors)
    )
  );
});

test('binary validate exits nonzero and writes only a structured validation error to stderr', () => {
  const result = spawnSync(
    process.execPath,
    ['bin/agentcli.js', 'validate', '{"version":"0.2","workflows":[]}', '--json'],
    { cwd: process.cwd(), encoding: 'utf8' }
  );

  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  const error = JSON.parse(result.stderr);
  assert.equal(error.ok, false);
  assert.equal(error.error_type, 'validation_error');
  assert.equal(error.code, 'validation_error');
  assert.equal(error.validation.ok, false);
});

test('binary errors use stable categories and a separate detailed code', () => {
  const result = spawnSync(
    process.execPath,
    ['bin/agentcli.js', 'validate', 'missing-manifest.json'],
    { cwd: process.cwd(), encoding: 'utf8' }
  );

  assert.equal(result.status, 1);
  const error = JSON.parse(result.stderr);
  assert.equal(error.error_type, 'invalid_argument');
  assert.equal(error.code, 'invalid_argument');
  assert.match(error.error, /Input not found/);
});

test('JSON-RPC uses documented result envelopes and stable error data codes', async () => {
  const schema = await handleJsonRpcRequest({
    jsonrpc: '2.0',
    id: 'schema',
    method: 'agentcli.schema',
    params: { target: 'manifest' },
  });
  assert.equal(schema.result.ok, true);
  assert.equal(schema.result.schema_format, 'json-schema-draft-2020-12');

  const converted = await handleJsonRpcRequest({
    jsonrpc: '2.0',
    id: 'convert',
    method: 'agentcli.convert',
    params: { manifest: { ...validManifest(), version: '0.1' } },
  });
  assert.equal(converted.result.ok, true);
  assert.equal(converted.result.manifest.version, '0.2');

  const invalid = await handleJsonRpcRequest({
    jsonrpc: '2.0',
    id: 'compile',
    method: 'agentcli.compile',
    params: { manifest: { version: '0.2', workflows: [] } },
  });
  assert.equal(invalid.error.code, -32602);
  assert.equal(invalid.error.data.code, 'validation_error');
  assert.equal(invalid.error.data.error_type, 'validation_error');
  assert.equal(invalid.error.data.validation.ok, false);

  const unknown = await handleJsonRpcRequest({
    jsonrpc: '2.0',
    id: 'unknown',
    method: 'agentcli.notThere',
  });
  assert.equal(unknown.error.code, -32601);
  assert.equal(unknown.error.data.code, 'unknown_command');
});

test('JSON-RPC exposes read-only discovery and inspection methods', async (t) => {
  const home = mkdtempSync(join(tmpdir(), 'agentcli-rpc-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const defaults = { env: { ...process.env, AGENTCLI_HOME: home } };

  const targets = await handleJsonRpcRequest({
    jsonrpc: '2.0', id: 1, method: 'agentcli.targets',
  }, defaults);
  assert.equal(targets.result.ok, true);
  assert.ok(targets.result.targets.some(target => target.name === 'standalone'));

  const paths = await handleJsonRpcRequest({
    jsonrpc: '2.0', id: 2, method: 'agentcli.paths',
  }, defaults);
  assert.equal(paths.result.ok, true);
  assert.equal(paths.result.paths.root, home);

  const audit = await handleJsonRpcRequest({
    jsonrpc: '2.0', id: 3, method: 'agentcli.audit',
  }, defaults);
  assert.deepEqual(audit.result, { ok: true, count: 0, records: [], warnings: [] });

  const approvals = await handleJsonRpcRequest({
    jsonrpc: '2.0', id: 4, method: 'agentcli.approvals.list',
  }, defaults);
  assert.equal(approvals.result.ok, true);
  assert.equal(approvals.result.count, 0);
});

test('CLI and JSON-RPC governance inspection resolve state without executing the task', async (t) => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-governance-inspection-'));
  t.after(() => rmSync(workdir, { recursive: true, force: true }));
  const marker = join(workdir, 'task-executed');
  const manifest = governanceInspectionManifest(marker);
  const env = { ...process.env, INSPECTION_TOKEN: 'inspection-secret' };

  const cliIdentity = JSON.parse(await runCli([
    'identity', 'resolve', JSON.stringify(manifest), 'task',
  ], { cwd: workdir, env }));
  assert.equal(cliIdentity.principal_used, 'agent://test/operator');
  assert.equal(cliIdentity.resolved_identity.credentials.access_token.value, '[REDACTED]');

  const cliDelegation = JSON.parse(await runCli([
    'identity', 'validate-delegation', JSON.stringify(manifest), 'task',
  ], { cwd: workdir, env }));
  assert.equal(cliDelegation.delegation.valid, true);
  assert.equal(cliDelegation.delegation.depth, 1);

  const cliAuthorization = JSON.parse(await runCli([
    'authorization', 'evaluate', JSON.stringify(manifest), 'task',
  ], { cwd: workdir, env }));
  assert.equal(cliAuthorization.authorization.decision, 'permit');

  const cliWhoami = JSON.parse(await runCli([
    'whoami', JSON.stringify(manifest), 'task',
  ], { cwd: workdir, env }));
  assert.equal(cliWhoami.principal_used, 'agent://test/operator');

  const rpcDefaults = { cwd: workdir, env };
  const rpcIdentity = await handleJsonRpcRequest({
    jsonrpc: '2.0',
    id: 'identity',
    method: 'agentcli.identity.resolve',
    params: { manifest, taskId: 'task' },
  }, rpcDefaults);
  assert.equal(rpcIdentity.result.principal_used, 'agent://test/operator');
  assert.equal(rpcIdentity.result.resolved_identity.credentials.access_token.value, '[REDACTED]');

  const rpcDelegation = await handleJsonRpcRequest({
    jsonrpc: '2.0',
    id: 'delegation',
    method: 'agentcli.identity.validateDelegation',
    params: { manifest, taskId: 'task' },
  }, rpcDefaults);
  assert.equal(rpcDelegation.result.delegation.valid, true);

  const rpcAuthorization = await handleJsonRpcRequest({
    jsonrpc: '2.0',
    id: 'authorization',
    method: 'agentcli.authorization.evaluate',
    params: { manifest, taskId: 'task' },
  }, rpcDefaults);
  assert.equal(rpcAuthorization.result.authorization.decision, 'permit');
  assert.equal(existsSync(marker), false);
});

test('authorization-proof inspection resolves its command source without executing the task', async (t) => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-proof-inspection-'));
  t.after(() => rmSync(workdir, { recursive: true, force: true }));
  const proofMarker = join(workdir, 'proof-command-executed');
  const taskMarker = join(workdir, 'task-executed');
  const proofScript = join(workdir, 'proof-command.cjs');
  writeFileSync(
    proofScript,
    `require('node:fs').writeFileSync(${JSON.stringify(proofMarker)}, 'resolved'); process.stdout.write('proof-value');`,
    'utf8'
  );

  const manifest = {
    version: '0.2',
    authorization_proof_profiles: [{
      id: 'proof',
      method: 'none',
      proof: { value_from: { command: `${JSON.stringify(process.execPath)} ${JSON.stringify(proofScript)}` } },
    }],
    workflows: [{
      id: 'workflow',
      name: 'Workflow',
      authorization_proof: { ref: 'proof' },
      tasks: [{
        id: 'task',
        name: 'Task',
        shell: {
          program: process.execPath,
          args: ['-e', `require('node:fs').writeFileSync(${JSON.stringify(taskMarker)}, 'executed')`],
        },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        contract: { audit: 'none' },
      }],
    }],
  };

  const cli = JSON.parse(await runCli([
    'authorization-proof', 'verify', JSON.stringify(manifest), 'task',
  ], { cwd: workdir }));
  assert.equal(cli.authorization_proof.method, 'none');
  assert.equal(cli.authorization_proof.verified, false);
  assert.match(cli.effective_task_hash, /^sha256:/);
  assert.match(cli.manifest_digest, /^sha256:/);
  assert.equal(existsSync(proofMarker), true);
  assert.equal(existsSync(taskMarker), false);

  rmSync(proofMarker);
  const rpc = await handleJsonRpcRequest({
    jsonrpc: '2.0',
    id: 'proof',
    method: 'agentcli.authorizationProof.verify',
    params: { manifest, taskId: 'task' },
  }, { cwd: workdir, env: process.env });
  assert.equal(rpc.result.authorization_proof.method, 'none');
  assert.equal(rpc.result.authorization_proof.verified, false);
  assert.match(rpc.result.effective_task_hash, /^sha256:/);
  assert.match(rpc.result.manifest_digest, /^sha256:/);
  assert.equal(existsSync(proofMarker), true);
  assert.equal(existsSync(taskMarker), false);
});

test('audit inspection reports malformed line numbers without echoing raw content', async (t) => {
  const home = mkdtempSync(join(tmpdir(), 'agentcli-audit-malformed-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const state = join(home, 'state');
  mkdirSync(state, { recursive: true });
  writeFileSync(
    join(state, 'audit.ndjson'),
    '{"execution_id":"valid","timestamp":"now"}\nsecret malformed content\n',
    'utf8'
  );

  const output = JSON.parse(await runCli(['audit'], {
    env: { ...process.env, AGENTCLI_HOME: home },
  }));
  assert.equal(output.count, 1);
  assert.deepEqual(output.warnings, [{
    line_number: 2,
    message: 'malformed audit record skipped',
  }]);
  assert.equal(JSON.stringify(output).includes('secret malformed content'), false);
});

test('safe JSON output rejects parent symlinks that escape cwd', (t) => {
  if (process.platform === 'win32') {
    t.skip('symlink creation requires platform-specific privileges');
    return;
  }
  const base = mkdtempSync(join(tmpdir(), 'agentcli-output-base-'));
  const outside = mkdtempSync(join(tmpdir(), 'agentcli-output-outside-'));
  t.after(() => {
    rmSync(base, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  });

  symlinkSync(outside, join(base, 'escape'));
  assert.throws(
    () => writeJsonOutput('escape/result.json', { secret: false }, { cwd: base }),
    error => error.code === 'invalid_argument' && /symlink outside/.test(error.message)
  );
  assert.equal(existsSync(join(outside, 'result.json')), false);
});

test('safe JSON output creates mode-restricted files inside cwd', (t) => {
  const base = mkdtempSync(join(tmpdir(), 'agentcli-output-'));
  t.after(() => rmSync(base, { recursive: true, force: true }));

  const written = writeJsonOutput('nested/private/result.json', { ok: true }, { cwd: base });
  assert.equal(written, join(base, 'nested', 'private', 'result.json'));
  assert.deepEqual(JSON.parse(readFileSync(written, 'utf8')), { ok: true });
  if (process.platform !== 'win32') {
    assert.equal(statSync(join(base, 'nested')).mode & 0o777, 0o700);
    assert.equal(statSync(join(base, 'nested', 'private')).mode & 0o777, 0o700);
    assert.equal(statSync(written).mode & 0o777, 0o600);
  }
});

test('safe JSON output can atomically refuse overwrites without side effects', (t) => {
  const base = mkdtempSync(join(tmpdir(), 'agentcli-output-exclusive-'));
  t.after(() => rmSync(base, { recursive: true, force: true }));

  const existingPath = join(base, 'existing.json');
  writeFileSync(existingPath, 'sentinel\n', 'utf8');
  assert.throws(
    () => writeJsonOutput('existing.json', { replaced: true }, { cwd: base, overwrite: false }),
    error => error.code === 'EEXIST'
  );
  assert.equal(readFileSync(existingPath, 'utf8'), 'sentinel\n');

  const circular = {};
  circular.self = circular;
  assert.throws(
    () => writeJsonOutput('nested/circular.json', circular, { cwd: base, overwrite: false }),
    /circular/i
  );
  assert.equal(existsSync(join(base, 'nested')), false);

  assert.throws(
    () => writeJsonOutput('invalid.json', { ok: true }, { cwd: base, overwrite: 'no' }),
    error => error.code === 'invalid_argument' && /overwrite option/.test(error.message)
  );
});

test('safe JSON output refuses FIFO destinations without blocking', {
  skip: process.platform === 'win32',
}, (t) => {
  const base = mkdtempSync(join(tmpdir(), 'agentcli-output-fifo-'));
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const outputPath = join(base, 'result.json');
  const created = spawnSync('mkfifo', [outputPath], { encoding: 'utf8' });
  assert.equal(created.status, 0, created.stderr || created.error?.message);
  const reader = openSync(outputPath, fsConstants.O_RDONLY | fsConstants.O_NONBLOCK);
  try {
    assert.throws(
      () => writeJsonOutput('result.json', { ok: true }, { cwd: base }),
      error => error.code === 'invalid_argument' && /non-regular file/.test(error.message)
    );
  } finally {
    closeSync(reader);
  }
});
