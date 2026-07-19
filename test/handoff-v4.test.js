import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createSign } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyManifestToScheduler,
  requiredSchedulerFieldVersion,
  schedulerCreateSpec,
} from '../src/apply.js';
import { HANDOFF_V4_RUNTIME_CONTRACT } from '../src/capabilities.js';
import { compileManifestToScheduler } from '../src/compiler/openclaw-scheduler.js';
import {
  buildEffectiveExecutionBinding,
  computeEffectiveTaskHash,
} from '../src/compiler/shared.js';
import {
  assertValidSchedulerHandoffV4Job,
  HANDOFF_V4_EXECUTION_BINDING_VERSION,
  rebindSchedulerHandoffV4Job,
  validateSchedulerHandoffV4Artifact,
} from '../src/handoff/v4.js';
import { canonicalDigest, canonicalStringify } from '../src/canonical.js';
import { expandManifestShorthands } from '../src/shorthand.js';
import { jwtVerifier } from '../src/authorization-proof/jwt.js';
import {
  buildDetachedSignatureV4SigningContent,
  detachedSignatureKeyId,
  detachedSignatureVerifier,
} from '../src/authorization-proof/detached-signature.js';
import {
  buildCertificateV4SigningContent,
  certificateProofKeyId,
  certificateVerifier,
} from '../src/authorization-proof/certificate.js';
import { listInspectableEntities } from '../src/inspect.js';
import { registerProvider as registerIdentityProvider } from '../src/identity/index.js';

const V4_FEATURES = {
  root_approval_gate: true,
  approval_scope_enforcement: true,
  structured_output_format: true,
  runtime_execution: true,
  identity_declaration: true,
  runtime_identity_resolution: true,
  evidence_generation: true,
  audit_export: true,
  trust_evaluation: true,
  delegation_validation: true,
  credential_handoff: true,
  authorization_proof_verification: true,
  authorization_hook: true,
  handoff_v4_artifact: true,
  artifact_bound_proofs: true,
  signed_or_provider_verified_evidence: true,
  provider_session_cache: true,
  credential_presentation: true,
  source_run_bound_delegation: true,
  immutable_runtime_events: true,
};

const sharedConformanceFixture = JSON.parse(readFileSync(
  join(import.meta.dirname, '..', 'fixtures', 'handoff-v4', 'conformance.json'),
  'utf8',
));

function applyFixtureChanges(payload, changes) {
  const changed = structuredClone(payload);
  for (const change of changes) {
    let target = changed;
    for (const key of change.path.slice(0, -1)) target = target[key];
    const key = change.path.at(-1);
    if (change.op === 'delete') delete target[key];
    else target[key] = structuredClone(change.value);
  }
  return changed;
}

function manifest() {
  return {
    version: '0.2',
    workflows: [{
      id: 'v4-workflow',
      name: 'V4 workflow',
      tasks: [{
        id: 'root',
        name: 'V4 root',
        target: { session_target: 'shell' },
        shell: { program: 'printf', args: ['ok'] },
        schedule: { cron: '0 * * * *' },
        runtime: { timeout_ms: 120000 },
        output: { format: 'text' },
      }],
    }],
  };
}

function runner({
  handoffVersion = '4',
  schemaVersion = 29,
  handoffContract = HANDOFF_V4_RUNTIME_CONTRACT,
  features = V4_FEATURES,
} = {}) {
  const added = [];
  return {
    invocation: { label: 'mock-scheduler' },
    added,
    queryCapabilities() {
      return {
        scheduler_version: 'test',
        schema_version: schemaVersion,
        handoff_version: handoffVersion,
        handoff_contract: handoffContract,
        features,
      };
    },
    listJobs() { return []; },
    addJob(job) {
      added.push(job);
      return { ok: true, job };
    },
    updateJob() { throw new Error('unexpected update'); },
    deleteJob() { throw new Error('unexpected delete'); },
  };
}

function statefulRunner(initialJobs = [], {
  handoffVersion = '4',
  schemaVersion = 29,
  handoffContract = HANDOFF_V4_RUNTIME_CONTRACT,
  features = V4_FEATURES,
} = {}) {
  const jobs = new Map(initialJobs.map(job => [job.id, structuredClone(job)]));
  const history = [];
  return {
    invocation: { label: 'stateful-mock-scheduler' },
    history,
    queryCapabilities() {
      return {
        scheduler_version: 'test',
        schema_version: schemaVersion,
        handoff_version: handoffVersion,
        handoff_contract: handoffContract,
        features,
      };
    },
    listJobs() {
      return [...jobs.values()].map(job => structuredClone(job));
    },
    addJob(spec) {
      assert.equal(typeof spec.id, 'string');
      assert.equal(jobs.has(spec.id), false);
      const stored = structuredClone(spec);
      jobs.set(spec.id, stored);
      history.push({ action: 'add', id: spec.id, spec: structuredClone(spec) });
      return { ok: true, job: structuredClone(stored) };
    },
    updateJob(id, spec) {
      assert.equal(jobs.has(id), true);
      const stored = { ...jobs.get(id), ...structuredClone(spec), id };
      jobs.set(id, stored);
      history.push({ action: 'update', id, spec: structuredClone(spec) });
      return { ok: true, job: structuredClone(stored) };
    },
    deleteJob(id) {
      assert.equal(jobs.delete(id), true);
      history.push({ action: 'delete', id });
      return { ok: true };
    },
  };
}

function base64url(value) {
  return Buffer.from(value).toString('base64url');
}

function signJwtJson(payloadJson, privateKey) {
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'test-key' }));
  const body = base64url(payloadJson);
  const signingInput = `${header}.${body}`;
  const signer = createSign('RSA-SHA256');
  signer.update(signingInput);
  return `${signingInput}.${signer.sign(privateKey).toString('base64url')}`;
}

function signJwt(payload, privateKey) {
  return signJwtJson(JSON.stringify(payload), privateKey);
}

test('handoff v4 artifact is canonical, deterministic, and tamper evident', () => {
  const compiled = compileManifestToScheduler(manifest(), {
    schedulerHandoffVersion: '4',
    cwd: '/tmp',
    env: { PATH: '/usr/bin' },
  });
  const job = compiled.jobs[0];
  assert.equal(job.handoff_version, 4);
  assert.equal(requiredSchedulerFieldVersion(compiled.jobs), 4);

  const validation = validateSchedulerHandoffV4Artifact(job.handoff_artifact_payload, {
    expectedDigest: job.handoff_artifact_digest,
  });
  assert.equal(validation.ok, true, validation.errors.join('; '));
  assert.equal(job.effective_task_hash, job.handoff_artifact_payload.compiled.effective_task_hash);

  const reordered = JSON.parse(canonicalStringify(job.handoff_artifact_payload));
  assert.equal(
    validateSchedulerHandoffV4Artifact(reordered, {
      expectedDigest: job.handoff_artifact_digest,
    }).ok,
    true,
  );

  const tampered = structuredClone(job.handoff_artifact_payload);
  tampered.runtime.timeout_ms += 1;
  const tamperedValidation = validateSchedulerHandoffV4Artifact(tampered, {
    expectedDigest: job.handoff_artifact_digest,
  });
  assert.equal(tamperedValidation.ok, false);
  assert.match(tamperedValidation.errors.join('; '), /digest does not match/);

  const future = structuredClone(job.handoff_artifact_payload);
  future.scheduler_schema_min = 30;
  const futureValidation = validateSchedulerHandoffV4Artifact(future);
  assert.equal(futureValidation.ok, false);
  assert.match(futureValidation.errors.join('; '), /exactly 29/);
});

test('handoff v4 validation rejects missing identity fields and unknown properties', () => {
  const payload = compileManifestToScheduler(manifest(), {
    schedulerHandoffVersion: '4',
    cwd: '/tmp',
    env: { PATH: '/usr/bin' },
  }).jobs[0].handoff_artifact_payload;

  for (const path of [
    ['manifest', 'workflow_id'],
    ['manifest', 'task_id'],
    ['compiled', 'job_id'],
    ['command', 'kind'],
    ['runtime', 'timeout_ms'],
  ]) {
    const missing = structuredClone(payload);
    delete missing[path[0]][path[1]];
    const validation = validateSchedulerHandoffV4Artifact(missing);
    assert.equal(validation.ok, false, path.join('.'));
    assert.match(validation.errors.join('; '), new RegExp(`${path.join('\\.')} is required`));
  }

  const unknown = structuredClone(payload);
  unknown.command.secret = 'must-not-persist';
  const validation = validateSchedulerHandoffV4Artifact(unknown);
  assert.equal(validation.ok, false);
  assert.match(validation.errors.join('; '), /artifact\.command\.secret is not allowed/);

  for (const field of ['access_token', 'password', 'private_key']) {
    const credentialBearing = structuredClone(payload);
    credentialBearing.identity.presentation.bindings = [{
      name: 'credential',
      medium: 'env',
      env_key: 'CREDENTIAL',
      file_name: null,
      source_hash: null,
      required: true,
      redact: true,
      format: 'raw',
      [field]: 'must-not-persist',
    }];
    const credentialValidation = validateSchedulerHandoffV4Artifact(credentialBearing);
    assert.equal(credentialValidation.ok, false, field);
    assert.match(credentialValidation.errors.join('; '), new RegExp(`${field} is not allowed`));
  }
});

test('handoff v4 schema accepts every valid cleanup policy and rejects unknown proof methods', () => {
  const payload = compileManifestToScheduler(manifest(), {
    schedulerHandoffVersion: '4',
    cwd: '/tmp',
    env: { PATH: '/usr/bin' },
  }).jobs[0].handoff_artifact_payload;

  const cleanupOnFailure = structuredClone(payload);
  cleanupOnFailure.identity.presentation.cleanup = 'on-failure';
  const cleanupValidation = validateSchedulerHandoffV4Artifact(cleanupOnFailure);
  assert.equal(cleanupValidation.ok, true, cleanupValidation.errors.join('; '));

  const unknownProof = structuredClone(payload);
  unknownProof.authorization_proof.method = 'jtw';
  const proofValidation = validateSchedulerHandoffV4Artifact(unknownProof);
  assert.equal(proofValidation.ok, false);
  assert.match(proofValidation.errors.join('; '), /authorization_proof\.method/);

  assert.equal(payload.authorization_proof.verification_context_hash, null);
  const cryptographicProof = structuredClone(payload);
  cryptographicProof.authorization_proof.method = 'jwt';
  cryptographicProof.authorization_proof.verification_context_hash = `sha256:${'a'.repeat(64)}`;
  cryptographicProof.authorization_proof.artifact_binding_required = true;
  cryptographicProof.authorization_proof.replay_protection_required = true;
  cryptographicProof.authorization_proof.revocation_check_required = true;
  const cryptographicValidation = validateSchedulerHandoffV4Artifact(cryptographicProof);
  assert.equal(cryptographicValidation.ok, true, cryptographicValidation.errors.join('; '));

  for (const missingValue of ['delete', 'null']) {
    const missingContext = structuredClone(cryptographicProof);
    if (missingValue === 'delete') {
      delete missingContext.authorization_proof.verification_context_hash;
    } else {
      missingContext.authorization_proof.verification_context_hash = null;
    }
    const missingContextValidation = validateSchedulerHandoffV4Artifact(missingContext);
    assert.equal(missingContextValidation.ok, false, missingValue);
    assert.match(
      missingContextValidation.errors.join('; '),
      /authorization_proof\.verification_context_hash.*required/,
    );
  }
});

test('handoff v4 schema requires explicit nullable evidence hashes', () => {
  const payload = compileManifestToScheduler(manifest(), {
    schedulerHandoffVersion: '4',
    cwd: '/tmp',
    env: { PATH: '/usr/bin' },
  }).jobs[0].handoff_artifact_payload;

  assert.equal(payload.evidence.payload_hash, null);
  assert.equal(payload.evidence.provider_config_hash, null);
  for (const field of ['payload_hash', 'provider_config_hash']) {
    const missing = structuredClone(payload);
    delete missing.evidence[field];
    const validation = validateSchedulerHandoffV4Artifact(missing, {
      expectedDigest: canonicalDigest(missing),
    });
    assert.equal(validation.ok, false, field);
    assert.match(validation.errors.join('; '), new RegExp(`evidence\\.${field} is required`));
  }
});

test('shared handoff v4 conformance fixtures have exact digest parity and fail closed', () => {
  const fixture = sharedConformanceFixture;
  const [job] = compileManifestToScheduler(fixture.manifest, {
    schedulerHandoffVersion: '4',
    cwd: fixture.compile.cwd,
    env: fixture.compile.env,
  }).jobs;
  assert.equal(job.handoff_artifact_digest, fixture.expected.artifact_digest);
  assert.equal(job.handoff_artifact_payload.manifest.digest, fixture.expected.manifest_digest);
  assert.equal(job.effective_task_hash, fixture.expected.effective_task_hash);
  assert.equal(
    job.handoff_artifact_payload.scheduler_job_binding.digest,
    fixture.expected.scheduler_job_binding_digest,
  );
  assert.equal(validateSchedulerHandoffV4Artifact(job.handoff_artifact_payload, {
    expectedDigest: fixture.expected.artifact_digest,
  }).ok, true);

  for (const negative of fixture.negative_artifact_cases) {
    const validation = validateSchedulerHandoffV4Artifact(
      applyFixtureChanges(job.handoff_artifact_payload, negative.changes),
      negative.use_expected_digest
        ? { expectedDigest: fixture.expected.artifact_digest }
        : {},
    );
    assert.equal(validation.ok, false, negative.name);
    assert.match(validation.errors.join('; '), new RegExp(negative.expected_error), negative.name);
  }
});

test('handoff v4 maps declarative credential bindings to an exact runtime medium', () => {
  registerIdentityProvider({
    name: 'handoff-v4-test-identity',
    capabilities: {
      auth_modes: ['service'],
      credential_types: ['bearer'],
      presentation_kinds: ['env', 'file', 'stdin'],
      handoff_modes: ['none', 'transaction-token'],
      trust_levels: ['supervised'],
      approval_mechanisms: [],
      refreshable: false,
      delegation: false,
    },
    validateProfile() { return { valid: true }; },
    resolveSession() { return { ok: true, session: { credentials: { token: { value: 'test' } } } }; },
    describeSession() { return { provider: 'handoff-v4-test-identity' }; },
    materialize() { return { materialized: true, env_vars: {} }; },
    cleanup() { return { cleaned: true }; },
    prepareHandoff(session) { return { prepared: true, session }; },
  });

  const credentialManifest = target => ({
    version: '0.2',
    identity_profiles: [{
      id: 'v4-credential',
      provider: 'handoff-v4-test-identity',
      subject: { kind: 'service', principal: 'agent://v4-credential-test' },
      auth: { mode: 'service', required: true },
      trust: { level: 'supervised' },
      presentation: {
        handoff: 'transaction-token',
        cleanup: 'always',
        default_redaction: true,
        bindings: [{
          source: 'credentials.token.value',
          target,
          required: true,
          redact: true,
          format: 'raw',
        }],
      },
    }],
    workflows: [{
      id: 'credential-workflow',
      name: 'Credential workflow',
      tasks: [{
        id: 'credential-task',
        name: 'Credential task',
        target: { session_target: 'shell' },
        shell: { program: 'printf', args: ['ok'] },
        identity: { ref: 'v4-credential' },
        schedule: { cron: '0 * * * *' },
        runtime: { timeout_ms: 120000 },
      }],
    }],
  });

  const envJob = compileManifestToScheduler(
    credentialManifest({ kind: 'env', name: 'V4_RUNTIME_TOKEN' }),
    { schedulerHandoffVersion: '4', cwd: '/tmp', env: { PATH: '/usr/bin' } },
  ).jobs[0];
  assert.equal(envJob.handoff_artifact_payload.identity.presentation.mode, 'transaction-token');
  assert.equal(envJob.handoff_artifact_payload.identity.presentation.handoff, 'env');
  assert.equal(envJob.handoff_artifact_payload.identity.presentation.bindings[0].env_key, 'V4_RUNTIME_TOKEN');
  assert.match(
    envJob.handoff_artifact_payload.identity.presentation.bindings[0].source_hash,
    /^sha256:[0-9a-f]{64}$/,
  );

  const fileJob = compileManifestToScheduler(
    credentialManifest({ kind: 'file', name: 'token.txt', expose_as: 'V4_TOKEN_FILE' }),
    { schedulerHandoffVersion: '4', cwd: '/tmp', env: { PATH: '/usr/bin' } },
  ).jobs[0];
  assert.equal(fileJob.handoff_artifact_payload.identity.presentation.handoff, 'temp-file');
  assert.equal(fileJob.handoff_artifact_payload.identity.presentation.bindings[0].file_name, 'token.txt');
  assert.equal(fileJob.handoff_artifact_payload.identity.presentation.bindings[0].env_key, 'V4_TOKEN_FILE');

  const isolated = credentialManifest({ kind: 'env', name: 'V4_RUNTIME_TOKEN' });
  isolated.workflows[0].tasks[0] = {
    id: 'credential-task',
    name: 'Credential task',
    target: { session_target: 'isolated', agent_id: 'main' },
    prompt: 'Use the credential-bound runtime.',
    identity: { ref: 'v4-credential' },
    schedule: { cron: '0 * * * *' },
    runtime: { timeout_ms: 120000 },
  };
  const isolatedJob = compileManifestToScheduler(isolated, {
    schedulerHandoffVersion: '4', cwd: '/tmp', env: { PATH: '/usr/bin' },
  }).jobs[0];
  assert.equal(isolatedJob.handoff_artifact_payload.identity.presentation.handoff, 'gateway-env-header');
});

test('scheduler execution binding changes when execution controls change', () => {
  const first = manifest();
  const scheduledDifferently = manifest();
  scheduledDifferently.workflows[0].tasks[0].schedule.cron = '15 * * * *';
  const formattedDifferently = manifest();
  formattedDifferently.workflows[0].tasks[0].output.format = 'json';

  const compile = input => compileManifestToScheduler(input, {
    schedulerHandoffVersion: '4',
    cwd: '/tmp',
    env: { PATH: '/usr/bin' },
  }).jobs[0].handoff_artifact_payload.scheduler_job_binding.digest;

  assert.notEqual(compile(first), compile(scheduledDifferently));
  assert.notEqual(compile(first), compile(formattedDifferently));
});

test('handoff v4 effective task hashes use execution binding version 2', () => {
  const input = manifest();
  const expanded = expandManifestShorthands(input);
  const workflow = expanded.workflows[0];
  const task = workflow.tasks[0];
  const job = compileManifestToScheduler(input, {
    schedulerHandoffVersion: '4',
    cwd: '/tmp',
    env: { PATH: '/usr/bin' },
  }).jobs[0];
  const bindingOptions = {
    manifest: input,
    expanded,
    workflow,
    task,
    cwd: '/tmp',
    env: { PATH: '/usr/bin' },
    timeoutMs: job.run_timeout_ms,
    instanceId: null,
  };
  const v2Binding = buildEffectiveExecutionBinding({
    ...bindingOptions,
    bindingVersion: HANDOFF_V4_EXECUTION_BINDING_VERSION,
  });
  const v1Binding = buildEffectiveExecutionBinding({ ...bindingOptions, bindingVersion: 1 });

  assert.equal(v2Binding.binding_version, 2);
  assert.equal(job.handoff_artifact_payload.execution_binding_version, 2);
  assert.equal(job.effective_task_hash, computeEffectiveTaskHash(v2Binding));
  assert.notEqual(job.effective_task_hash, computeEffectiveTaskHash(v1Binding));
});

test('scheduler execution binding covers routing and resource controls', () => {
  const job = compileManifestToScheduler(manifest(), {
    schedulerHandoffVersion: '4',
    cwd: '/tmp',
    env: { PATH: '/usr/bin' },
  }).jobs[0];
  const originalBinding = job.handoff_artifact_payload.scheduler_job_binding.digest;

  for (const override of [
    { payload_scope: 'global' },
    { resource_pool: 'different-pool' },
    { job_class: 'pre_compaction_flush' },
    { payload_timeout_seconds: 321 },
    { payload_model_fallback: 'fallback-model' },
    { auth_profile_fallback: 'fallback-profile' },
    { shell_env_policy: 'inherit' },
  ]) {
    const rebound = rebindSchedulerHandoffV4Job(job, override);
    assert.notEqual(
      rebound.handoff_artifact_payload.scheduler_job_binding.digest,
      originalBinding,
      `${Object.keys(override)[0]} must affect scheduler_job_binding.digest`,
    );
  }
});

test('scheduler execution binding covers every watchdog execution control', () => {
  const job = compileManifestToScheduler(manifest(), {
    schedulerHandoffVersion: '4',
    cwd: '/tmp',
    env: { PATH: '/usr/bin' },
  }).jobs[0];
  const originalBinding = job.handoff_artifact_payload.scheduler_job_binding.digest;
  const explicitDefaults = rebindSchedulerHandoffV4Job(job, {
    job_type: 'standard',
    watchdog_target_label: null,
    watchdog_check_cmd: null,
    watchdog_timeout_min: null,
    watchdog_alert_channel: null,
    watchdog_alert_target: null,
    watchdog_self_destruct: true,
    watchdog_started_at: null,
  });

  assert.equal(
    explicitDefaults.handoff_artifact_payload.scheduler_job_binding.digest,
    originalBinding,
    'standard jobs must bind the documented watchdog defaults',
  );

  for (const override of [
    { job_type: 'watchdog' },
    { watchdog_target_label: 'gateway' },
    { watchdog_check_cmd: '/usr/bin/health-check --strict' },
    { watchdog_timeout_min: 15 },
    { watchdog_alert_channel: 'ops' },
    { watchdog_alert_target: 'on-call' },
    { watchdog_self_destruct: false },
    { watchdog_started_at: '2026-07-19T04:45:00.000Z' },
  ]) {
    const rebound = rebindSchedulerHandoffV4Job(job, override);
    assert.notEqual(
      rebound.handoff_artifact_payload.scheduler_job_binding.digest,
      originalBinding,
      `${Object.keys(override)[0]} must affect scheduler_job_binding.digest`,
    );
    assert.equal(
      canonicalStringify(rebound.handoff_artifact_payload).includes('/usr/bin/health-check --strict'),
      false,
      'watchdog check commands must be represented only by their digest',
    );
  }
});

test('handoff v4 scheduler rebinding replaces adoption metadata atomically', () => {
  const job = compileManifestToScheduler(manifest(), {
    schedulerHandoffVersion: '4',
    cwd: '/tmp',
    env: { PATH: '/usr/bin' },
  }).jobs[0];
  const originalDigest = job.handoff_artifact_digest;
  const originalBinding = job.handoff_artifact_payload.scheduler_job_binding.digest;
  const rebound = rebindSchedulerHandoffV4Job(job, { origin: 'legacy-origin' });

  assert.equal(rebound.origin, 'legacy-origin');
  assert.notEqual(rebound.handoff_artifact_digest, originalDigest);
  assert.notEqual(rebound.handoff_artifact_payload.scheduler_job_binding.digest, originalBinding);
  assert.equal(job.origin, 'system');
  assert.equal(job.handoff_artifact_digest, originalDigest);
  assert.equal(validateSchedulerHandoffV4Artifact(rebound.handoff_artifact_payload, {
    expectedDigest: rebound.handoff_artifact_digest,
  }).ok, true);
});

test('handoff v4 scheduler rebinding rejects a tampered original artifact', () => {
  const job = compileManifestToScheduler(manifest(), {
    schedulerHandoffVersion: '4',
    cwd: '/tmp',
    env: { PATH: '/usr/bin' },
  }).jobs[0];
  const tampered = structuredClone(job);
  tampered.handoff_artifact_payload.manifest.digest = `sha256:${'a'.repeat(64)}`;

  assert.throws(
    () => rebindSchedulerHandoffV4Job(tampered, { origin: 'legacy-origin' }),
    error => error.code === 'HANDOFF_ARTIFACT_INVALID'
      && /artifact digest does not match payload/.test(error.message),
  );

  const missingDigest = structuredClone(job);
  delete missingDigest.handoff_artifact_digest;
  assert.throws(
    () => rebindSchedulerHandoffV4Job(missingDigest, { origin: 'legacy-origin' }),
    error => error.code === 'HANDOFF_ARTIFACT_INVALID'
      && /valid original artifact digest/.test(error.message),
  );

  const changedJobProjection = structuredClone(job);
  changedJobProjection.payload_message = 'tampered outside the artifact';
  assert.throws(
    () => rebindSchedulerHandoffV4Job(changedJobProjection, { origin: 'legacy-origin' }),
    error => error.code === 'HANDOFF_ARTIFACT_INVALID'
      && /execution projection no longer matches/.test(error.message),
  );

  const changedJobId = structuredClone(job);
  changedJobId.id = 'different-job-id';
  assert.throws(
    () => rebindSchedulerHandoffV4Job(changedJobId, { origin: 'legacy-origin' }),
    error => error.code === 'HANDOFF_ARTIFACT_INVALID'
      && /compiled\.job_id does not match/.test(error.message),
  );

  const changedEffectiveTaskHash = structuredClone(job);
  changedEffectiveTaskHash.effective_task_hash = `sha256:${'0'.repeat(64)}`;
  assert.throws(
    () => rebindSchedulerHandoffV4Job(changedEffectiveTaskHash, { origin: 'legacy-origin' }),
    error => error.code === 'HANDOFF_ARTIFACT_INVALID'
      && /compiled\.effective_task_hash does not match/.test(error.message),
  );
});

test('handoff v4 scheduler rebinding rejects artifact-bound overrides', () => {
  const job = compileManifestToScheduler(manifest(), {
    schedulerHandoffVersion: '4',
    cwd: '/tmp',
    env: { PATH: '/usr/bin' },
  }).jobs[0];

  for (const [field, value] of [
    ['id', 'different-id'],
    ['handoff_version', 3],
    ['effective_task_hash', `sha256:${'0'.repeat(64)}`],
    ['handoff_artifact_payload', {}],
    ['handoff_artifact_digest', `sha256:${'1'.repeat(64)}`],
    ['enabled', 0],
    ['session_target', 'isolated'],
    ['payload_message', 'different payload'],
    ['run_timeout_ms', 1],
    ['approval_required', false],
    ['output_format', 'json'],
    ['identity', null],
    ['authorization_proof', null],
    ['authorization', null],
    ['evidence', null],
    ['contract_audit', 'never'],
    ['verify_shell', 'exit 0'],
    ['child_credential_policy', null],
    ['execution_intent', 'dry-run'],
  ]) {
    assert.throws(
      () => rebindSchedulerHandoffV4Job(job, { [field]: value }),
      error => error.code === 'HANDOFF_REBIND_OVERRIDE_INVALID'
        && error.fields.includes(field),
      field,
    );
  }
});

test('v4 builder rejects raw credential bindings', () => {
  const compiled = compileManifestToScheduler(manifest(), {
    schedulerHandoffVersion: '4',
    env: { PATH: '/usr/bin' },
  });
  const payload = structuredClone(compiled.jobs[0].handoff_artifact_payload);
  payload.identity.presentation.bindings = [{
    name: 'token',
    medium: 'env',
    value: 'must-not-persist',
  }];
  const result = validateSchedulerHandoffV4Artifact(payload);
  assert.equal(result.ok, false);
  assert.match(result.errors.join('; '), /raw credential material/);
});

test('scheduler projection emits artifact fields only for v4', () => {
  const v3Job = compileManifestToScheduler(manifest()).jobs[0];
  const v4Job = compileManifestToScheduler(manifest(), {
    schedulerHandoffVersion: '4',
    env: { PATH: '/usr/bin' },
  }).jobs[0];
  const v3 = schedulerCreateSpec(v3Job, { fieldVersion: '3' });
  const v4 = schedulerCreateSpec(v4Job, { fieldVersion: '4' });
  assert.equal('handoff_artifact_digest' in v3, false);
  assert.equal(typeof v4.handoff_artifact_digest, 'string');
  assert.equal(typeof v4.handoff_artifact_payload, 'string');
  assert.equal(JSON.parse(v4.handoff_artifact_payload).handoff_version, 4);
});

test('apply uses v4 only after every runtime gate is advertised', async () => {
  const v4Runner = runner();
  const v4 = await applyManifestToScheduler(manifest(), {
    runner: v4Runner,
    env: { PATH: '/usr/bin' },
  });
  assert.equal(v4.handoff.field_version, '4');
  assert.equal(v4Runner.added[0].handoff_version, 4);

  const missingGateRunner = runner({
    features: { ...V4_FEATURES, immutable_runtime_events: false },
  });
  const fallback = await applyManifestToScheduler(manifest(), {
    runner: missingGateRunner,
    env: { PATH: '/usr/bin' },
  });
  assert.equal(fallback.handoff.field_version, '3');
  assert.equal('handoff_version' in missingGateRunner.added[0], false);

  const omittedGateFeatures = { ...V4_FEATURES };
  delete omittedGateFeatures.immutable_runtime_events;
  const omittedGateRunner = runner({ features: omittedGateFeatures });
  const omittedGate = await applyManifestToScheduler(manifest(), {
    runner: omittedGateRunner,
    env: { PATH: '/usr/bin' },
  });
  assert.equal(omittedGate.handoff.field_version, '3');
  assert.equal('handoff_version' in omittedGateRunner.added[0], false);

  const missingProofVerificationRunner = runner({
    features: { ...V4_FEATURES, authorization_proof_verification: false },
  });
  const missingProofVerification = await applyManifestToScheduler(manifest(), {
    runner: missingProofVerificationRunner,
    env: { PATH: '/usr/bin' },
  });
  assert.equal(missingProofVerification.handoff.field_version, '3');
  assert.equal('handoff_version' in missingProofVerificationRunner.added[0], false);

  const oldRunner = runner({ handoffVersion: '3' });
  const oldRuntime = await applyManifestToScheduler(manifest(), {
    runner: oldRunner,
    env: { PATH: '/usr/bin' },
  });
  assert.equal(oldRuntime.handoff.field_version, '3');

  for (const [name, options] of [
    ['missing contract', { handoffContract: null }],
    ['old artifact schema', {
      handoffContract: { ...HANDOFF_V4_RUNTIME_CONTRACT, artifact_schema_version: 0 },
    }],
    ['future canonicalization', {
      handoffContract: { ...HANDOFF_V4_RUNTIME_CONTRACT, canonicalization_version: 2 },
    }],
    ['old scheduler schema', { schemaVersion: 28 }],
  ]) {
    const incompatibleRunner = runner(options);
    const result = await applyManifestToScheduler(manifest(), {
      runner: incompatibleRunner,
      env: { PATH: '/usr/bin' },
    });
    assert.equal(result.handoff.field_version, '3', name);
    assert.equal('handoff_version' in incompatibleRunner.added[0], false, name);
  }
});

test('v4 apply preserves direct-compile digests for an explicit environment', async () => {
  const scheduler = runner();
  const env = { PATH: '/v4-test/bin' };
  await applyManifestToScheduler(manifest(), {
    runner: scheduler,
    cwd: '/tmp',
    env,
  });
  const expected = compileManifestToScheduler(manifest(), {
    schedulerHandoffVersion: '4',
    cwd: '/tmp',
    env,
  }).jobs[0];
  assert.equal(scheduler.added[0].effective_task_hash, expected.effective_task_hash);
  assert.equal(scheduler.added[0].handoff_artifact_digest, expected.handoff_artifact_digest);
});

test('v4 apply add, update, clear-null, and adopt preserve complete immutable artifacts', async () => {
  const scheduler = statefulRunner();
  const created = await applyManifestToScheduler(manifest(), {
    runner: scheduler,
    cwd: '/tmp',
    env: { PATH: '/usr/bin' },
  });
  assert.equal(created.actions[0].action, 'created');
  const add = scheduler.history.at(-1);
  assert.equal(add.action, 'add');
  const originalPayload = JSON.parse(add.spec.handoff_artifact_payload);
  const originalDigest = add.spec.handoff_artifact_digest;
  assert.equal(validateSchedulerHandoffV4Artifact(originalPayload, {
    expectedDigest: originalDigest,
  }).ok, true);

  const clearedManifest = manifest();
  delete clearedManifest.workflows[0].tasks[0].output;
  const updated = await applyManifestToScheduler(clearedManifest, {
    runner: scheduler,
    cwd: '/tmp',
    env: { PATH: '/usr/bin' },
  });
  assert.equal(updated.actions[0].action, 'updated');
  const update = scheduler.history.at(-1);
  assert.equal(update.action, 'update');
  assert.equal(update.spec.output_format, null);
  assert.equal(update.spec.evidence_ref, null);
  assert.notEqual(update.spec.handoff_artifact_digest, originalDigest);
  const replacementPayload = JSON.parse(update.spec.handoff_artifact_payload);
  assert.equal(replacementPayload.output.format, null);
  assert.equal(validateSchedulerHandoffV4Artifact(replacementPayload, {
    expectedDigest: update.spec.handoff_artifact_digest,
  }).ok, true);
  assert.equal(validateSchedulerHandoffV4Artifact(originalPayload, {
    expectedDigest: originalDigest,
  }).ok, true);

  const legacyId = 'legacy-v3-row';
  const legacyRuntimeOverrides = {
    payload_scope: 'global',
    resource_pool: 'legacy-pool',
    job_class: 'pre_compaction_flush',
    payload_timeout_seconds: 321,
    payload_model_fallback: 'legacy-fallback-model',
    auth_profile_fallback: 'legacy-fallback-profile',
    shell_env_policy: 'inherit',
    job_type: 'watchdog',
    watchdog_target_label: 'legacy-target',
    watchdog_check_cmd: '/usr/bin/legacy-health-check',
    watchdog_timeout_min: 9,
    watchdog_alert_channel: 'ops',
    watchdog_alert_target: 'legacy-on-call',
    watchdog_self_destruct: false,
    watchdog_started_at: '2026-07-19T04:30:00.000Z',
  };
  const adopter = statefulRunner([{
    id: legacyId,
    name: manifest().workflows[0].tasks[0].name,
    origin: 'legacy-origin',
    ...legacyRuntimeOverrides,
  }]);
  const adopted = await applyManifestToScheduler(manifest(), {
    runner: adopter,
    adoptBy: 'name',
    cwd: '/tmp',
    env: { PATH: '/usr/bin' },
  });
  assert.equal(adopted.actions[0].action, 'adopted');
  assert.equal(adopted.actions[0].adopted_from_job_id, legacyId);
  assert.deepEqual(adopter.history.map(entry => entry.action), ['add', 'delete']);
  assert.equal(adopter.history[0].spec.origin, 'legacy-origin');
  for (const [field, value] of Object.entries(legacyRuntimeOverrides)) {
    assert.equal(adopter.history[0].spec[field], value, `${field} must survive v4 adoption`);
  }
  const adoptedPayload = JSON.parse(adopter.history[0].spec.handoff_artifact_payload);
  assert.equal(adoptedPayload.handoff_version, 4);
  const expectedAdopted = rebindSchedulerHandoffV4Job(
    compileManifestToScheduler(manifest(), {
      schedulerHandoffVersion: '4',
      cwd: '/tmp',
      env: { PATH: '/usr/bin' },
    }).jobs[0],
    { origin: 'legacy-origin', ...legacyRuntimeOverrides },
  );
  assert.equal(
    adoptedPayload.scheduler_job_binding.digest,
    expectedAdopted.handoff_artifact_payload.scheduler_job_binding.digest,
  );
  assert.equal(adopter.history[0].spec.handoff_artifact_digest, expectedAdopted.handoff_artifact_digest);
});

test('v4 updates preserve the stored origin and reject runtime-contract downgrades', async () => {
  const compiled = compileManifestToScheduler(manifest(), {
    schedulerHandoffVersion: '4',
    cwd: '/tmp',
    env: { PATH: '/usr/bin' },
  }).jobs[0];
  const preservedRuntimeOverrides = {
    origin: 'legacy-origin',
    payload_scope: 'global',
    resource_pool: 'preserved-pool',
    job_class: 'pre_compaction_flush',
    payload_timeout_seconds: 654,
    payload_model_fallback: 'preserved-fallback-model',
    auth_profile_fallback: 'preserved-fallback-profile',
    shell_env_policy: 'inherit',
    job_type: 'watchdog',
    watchdog_target_label: 'preserved-target',
    watchdog_check_cmd: '/usr/bin/preserved-health-check --strict',
    watchdog_timeout_min: 17,
    watchdog_alert_channel: 'ops',
    watchdog_alert_target: 'on-call',
    watchdog_self_destruct: false,
    watchdog_started_at: '2026-07-19T05:00:00.000Z',
  };
  const existing = rebindSchedulerHandoffV4Job(compiled, preservedRuntimeOverrides);
  const scheduler = statefulRunner([
    schedulerCreateSpec(existing, { originOverride: 'legacy-origin', fieldVersion: '4' }),
  ]);

  const result = await applyManifestToScheduler(manifest(), {
    runner: scheduler,
    cwd: '/tmp',
    env: { PATH: '/usr/bin' },
  });
  assert.equal(result.actions[0].action, 'updated');
  const update = scheduler.history.at(-1);
  assert.equal(update.action, 'update');
  const expected = rebindSchedulerHandoffV4Job(compiled, preservedRuntimeOverrides);
  for (const [field, value] of Object.entries(preservedRuntimeOverrides)) {
    if (field === 'origin') continue;
    assert.equal(update.spec[field], value, `${field} must survive the v4 update`);
  }
  assert.equal(update.spec.handoff_artifact_digest, expected.handoff_artifact_digest);
  assert.equal(
    JSON.parse(update.spec.handoff_artifact_payload).scheduler_job_binding.digest,
    expected.handoff_artifact_payload.scheduler_job_binding.digest,
  );

  const downgraded = statefulRunner([
    schedulerCreateSpec(existing, { originOverride: 'legacy-origin', fieldVersion: '4' }),
  ], {
    handoffVersion: '3',
    features: { ...V4_FEATURES, immutable_runtime_events: false },
  });
  await assert.rejects(
    applyManifestToScheduler(manifest(), {
      runner: downgraded,
      cwd: '/tmp',
      env: { PATH: '/usr/bin' },
    }),
    error => error.code === 'unsupported_capability'
      && /runtime capability downgrade/.test(error.message),
  );
  assert.deepEqual(downgraded.history, []);

  const legacyManifest = manifest();
  legacyManifest.workflows[0].id = 'legacy-v4-workflow';
  legacyManifest.workflows[0].tasks[0].id = 'legacy-v4-root';
  const legacyV4 = compileManifestToScheduler(legacyManifest, {
    schedulerHandoffVersion: '4',
    cwd: '/tmp',
    env: { PATH: '/usr/bin' },
  }).jobs[0];
  assert.notEqual(legacyV4.id, compiled.id);
  assert.equal(legacyV4.name, compiled.name);
  const downgradedAdopter = statefulRunner([
    schedulerCreateSpec(
      rebindSchedulerHandoffV4Job(legacyV4, { origin: 'legacy-origin' }),
      { fieldVersion: '4' },
    ),
  ], {
    handoffVersion: '3',
    features: { ...V4_FEATURES, immutable_runtime_events: false },
  });
  await assert.rejects(
    applyManifestToScheduler(manifest(), {
      runner: downgradedAdopter,
      adoptBy: 'name',
      cwd: '/tmp',
      env: { PATH: '/usr/bin' },
    }),
    error => error.code === 'unsupported_capability'
      && /runtime capability downgrade/.test(error.message),
  );
  assert.deepEqual(downgradedAdopter.history, []);

  const multiJobManifest = manifest();
  multiJobManifest.workflows[0].tasks = [
    {
      ...structuredClone(multiJobManifest.workflows[0].tasks[0]),
      id: 'new-before-conflict',
      name: 'New before conflict',
    },
    {
      ...structuredClone(multiJobManifest.workflows[0].tasks[0]),
      id: 'existing-v4-conflict',
      name: 'Existing v4 conflict',
    },
  ];
  const existingConflict = compileManifestToScheduler(multiJobManifest, {
    schedulerHandoffVersion: '4',
    cwd: '/tmp',
    env: { PATH: '/usr/bin' },
  }).jobs[1];
  const partiallyApplicable = statefulRunner([
    schedulerCreateSpec(existingConflict, { fieldVersion: '4' }),
  ], {
    handoffVersion: '3',
    features: { ...V4_FEATURES, immutable_runtime_events: false },
  });
  await assert.rejects(
    applyManifestToScheduler(multiJobManifest, {
      runner: partiallyApplicable,
      cwd: '/tmp',
      env: { PATH: '/usr/bin' },
    }),
    error => error.code === 'unsupported_capability'
      && /runtime capability downgrade/.test(error.message),
  );
  assert.deepEqual(
    partiallyApplicable.history,
    [],
    'all downgrade conflicts must be detected before the first scheduler write',
  );
});

test('v4 apply rejects tampered stored jobs before preserving runtime overrides', async () => {
  const compiled = compileManifestToScheduler(manifest(), {
    schedulerHandoffVersion: '4',
    cwd: '/tmp',
    env: { PATH: '/usr/bin' },
  }).jobs[0];
  const validStored = schedulerCreateSpec(
    rebindSchedulerHandoffV4Job(compiled, {
      resource_pool: 'trusted-pool',
      watchdog_check_cmd: '/usr/bin/trusted-health-check',
    }),
    { fieldVersion: '4' },
  );
  assert.doesNotThrow(() => assertValidSchedulerHandoffV4Job(validStored));

  for (const { field, value, dryRun } of [
    { field: 'resource_pool', value: 'tampered-pool', dryRun: false },
    { field: 'watchdog_check_cmd', value: '/usr/bin/tampered-health-check', dryRun: true },
  ]) {
    const tampered = structuredClone(validStored);
    tampered[field] = value;
    const scheduler = statefulRunner([tampered]);
    await assert.rejects(
      applyManifestToScheduler(manifest(), {
        runner: scheduler,
        dryRun,
        cwd: '/tmp',
        env: { PATH: '/usr/bin' },
      }),
      error => error.code === 'HANDOFF_ARTIFACT_INVALID'
        && /execution projection no longer matches/.test(error.message),
      `${field} must be checked before the scheduler row is rebound`,
    );
    assert.deepEqual(scheduler.history, []);
  }
});

test('handoff v4 JWT requires artifact binding, replay claim, and revocation check', () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const artifactDigest = `sha256:${'a'.repeat(64)}`;
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: 'issuer',
    sub: 'subject',
    aud: 'scheduler',
    iat: now,
    exp: now + 300,
    jti: 'proof-1',
    manifest_digest: `sha256:${'b'.repeat(64)}`,
    handoff_artifact_digest: artifactDigest,
  };
  const token = signJwt(payload, privateKey);
  const profile = {
    issuer: 'issuer',
    audience: 'scheduler',
    public_key: publicKey.export({ type: 'spki', format: 'pem' }),
    proof: { value_from: { env: 'PROOF' } },
  };
  const claimed = new Set();
  const context = {
    requireSignature: true,
    requireManifestBinding: true,
    trustedKey: profile.public_key,
    manifestDigest: payload.manifest_digest,
    artifactDigest,
    handoffVersion: 4,
    now: new Date(now * 1000),
    runId: 'run-1',
    claimProofReplay({ proofId }) {
      if (claimed.has(proofId)) return { claimed: false, reason: 'replay' };
      claimed.add(proofId);
      return { claimed: true };
    },
    checkProofRevocation() {
      return { revoked: false };
    },
  };

  const verified = jwtVerifier.verifyProof(token, profile, context);
  assert.equal(verified.verified, true, verified.reason);
  assert.equal(verified.artifact_bound, true);
  assert.equal(verified.replay_protected, true);
  assert.equal(verified.revocation_checked, true);
  assert.equal(verified.verified_at, new Date(now * 1000).toISOString());

  const replay = jwtVerifier.verifyProof(token, profile, context);
  assert.equal(replay.verified, false);
  assert.match(replay.reason, /replay/);

  const missingArtifact = signJwt({ ...payload, jti: 'proof-2', handoff_artifact_digest: undefined }, privateKey);
  const unbound = jwtVerifier.verifyProof(missingArtifact, profile, context);
  assert.equal(unbound.verified, false);
  assert.match(unbound.reason, /artifact digest claim/);

  const stringVersionUnbound = jwtVerifier.verifyProof(
    signJwt({ ...payload, jti: 'proof-string-version' }, privateKey),
    profile,
    {
      ...context,
      artifactDigest: undefined,
      handoffVersion: undefined,
      handoff_version: '4',
      claimProofReplay: () => ({ claimed: true }),
    },
  );
  assert.equal(stringVersionUnbound.verified, false);
  assert.match(stringVersionUnbound.reason, /trusted handoff artifact digest/);

  const expiredBeyondStringSkew = jwtVerifier.verifyProof(
    signJwt({
      ...payload,
      iat: now - 300,
      exp: now - 61,
      jti: 'proof-expired-string-skew',
    }, privateKey),
    profile,
    {
      ...context,
      clockSkewSeconds: '60',
      claimProofReplay: () => ({ claimed: true }),
    },
  );
  assert.equal(expiredBeyondStringSkew.verified, false);
  assert.match(expiredBeyondStringSkew.reason, /expired/);

  const invalidSkew = jwtVerifier.verifyProof(
    signJwt({ ...payload, jti: 'proof-invalid-skew' }, privateKey),
    profile,
    { ...context, clockSkewSeconds: 'not-a-number' },
  );
  assert.equal(invalidSkew.verified, false);
  assert.match(invalidSkew.reason, /clockSkewSeconds/);

  const invalidNow = jwtVerifier.verifyProof(
    signJwt({ ...payload, jti: 'proof-invalid-now' }, privateKey),
    profile,
    { ...context, now: new Date(Number.NaN) },
  );
  assert.equal(invalidNow.verified, false);
  assert.match(invalidNow.reason, /valid Date/);

  const outOfRangeNow = jwtVerifier.verifyProof(
    signJwt({ ...payload, jti: 'proof-out-of-range-now' }, privateKey),
    profile,
    { ...context, now: Number.MAX_VALUE },
  );
  assert.equal(outOfRangeNow.verified, false);
  assert.match(outOfRangeNow.reason, /valid Date/);

  const overflowingExpiry = jwtVerifier.verifyProof(
    signJwt({ ...payload, exp: Number.MAX_VALUE, jti: 'proof-overflowing-expiry' }, privateKey),
    profile,
    context,
  );
  assert.equal(overflowingExpiry.verified, false);
  assert.match(overflowingExpiry.reason, /supported Date range/);
  assert.equal(claimed.has('proof-overflowing-expiry'), false);

  const infiniteExpiryJson = JSON.stringify({
    ...payload,
    exp: '__INFINITE_EXPIRY__',
    jti: 'proof-infinite-expiry',
  }).replace('"__INFINITE_EXPIRY__"', '1e309');
  const infiniteExpiry = jwtVerifier.verifyProof(
    signJwtJson(infiniteExpiryJson, privateKey),
    profile,
    context,
  );
  assert.equal(infiniteExpiry.verified, false);
  assert.match(infiniteExpiry.reason, /finite number/);
  assert.equal(claimed.has('proof-infinite-expiry'), false);

  const outOfRangeExpiry = jwtVerifier.verifyProof(
    signJwt({ ...payload, exp: 8_640_000_000_001, jti: 'proof-out-of-range-expiry' }, privateKey),
    profile,
    context,
  );
  assert.equal(outOfRangeExpiry.verified, false);
  assert.match(outOfRangeExpiry.reason, /supported Date range/);
  assert.equal(claimed.has('proof-out-of-range-expiry'), false);

  const inverted = signJwt({
    ...payload,
    iat: now + 30,
    exp: now - 30,
    jti: 'proof-inverted',
  }, privateKey);
  const invertedResult = jwtVerifier.verifyProof(inverted, profile, {
    ...context,
    claimProofReplay: () => ({ claimed: true }),
  });
  assert.equal(invertedResult.verified, false);
  assert.match(invertedResult.reason, /exp claim must be greater than iat/);

  const mismatchedKeyId = jwtVerifier.verifyProof(
    signJwt({ ...payload, jti: 'proof-mismatched-key-id' }, privateKey),
    profile,
    {
      ...context,
      trustedKeyId: 'spki-sha256:unrelated',
      claimProofReplay: () => ({ claimed: true }),
    },
  );
  assert.equal(mismatchedKeyId.verified, false);
  assert.match(mismatchedKeyId.reason, /key ID does not match/);

  const indeterminateRevocation = signJwt({ ...payload, jti: 'proof-indeterminate' }, privateKey);
  let indeterminateReplayClaims = 0;
  const indeterminateResult = jwtVerifier.verifyProof(indeterminateRevocation, profile, {
    ...context,
    claimProofReplay: () => {
      indeterminateReplayClaims += 1;
      return { claimed: true };
    },
    checkProofRevocation: () => undefined,
  });
  assert.equal(indeterminateResult.verified, false);
  assert.match(indeterminateResult.reason, /did not explicitly confirm/);
  assert.equal(indeterminateReplayClaims, 0);
});

test('handoff v4 detached signatures cover nonce, validity, key, and artifact metadata', () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const compiled = compileManifestToScheduler(manifest(), {
    schedulerHandoffVersion: '4',
    env: { PATH: '/usr/bin' },
  }).jobs[0];
  const now = Date.now();
  const fields = {
    artifactDigest: compiled.handoff_artifact_digest,
    nonce: 'detached-proof-1',
    issuedAt: new Date(now - 1_000).toISOString(),
    expiresAt: new Date(now + 60_000).toISOString(),
    keyId: detachedSignatureKeyId(publicKey),
  };
  const signer = createSign('RSA-SHA256');
  signer.update(buildDetachedSignatureV4SigningContent(fields));
  const envelope = {
    signature: signer.sign(privateKey).toString('base64'),
    artifact_digest: fields.artifactDigest,
    nonce: fields.nonce,
    issued_at: fields.issuedAt,
    expires_at: fields.expiresAt,
    key_id: fields.keyId,
  };
  const claimed = new Set();
  const context = {
    artifactPayload: compiled.handoff_artifact_payload,
    artifactDigest: compiled.handoff_artifact_digest,
    handoffVersion: 4,
    now: new Date(now),
    runId: 'run-detached',
    claimProofReplay({ proofId }) {
      if (claimed.has(proofId)) return { claimed: false, reason: 'replay refused' };
      claimed.add(proofId);
      return { claimed: true };
    },
    checkProofRevocation: () => ({ revoked: false }),
  };
  const profile = {
    issuer: 'test-issuer',
    public_key: publicKey.export({ type: 'spki', format: 'pem' }),
    proof: { value_from: { env: 'PROOF' } },
  };

  const verified = detachedSignatureVerifier.verifyProof(envelope, profile, context);
  assert.equal(verified.verified, true, verified.signature_verification_reason);
  assert.equal(verified.artifact_bound, true);
  assert.equal(verified.replay_protected, true);
  assert.equal(verified.revocation_checked, true);
  assert.equal(verified.verified_at, new Date(now).toISOString());

  const invalidSkew = detachedSignatureVerifier.verifyProof(envelope, profile, {
    ...context,
    clockSkewSeconds: 'not-a-number',
  });
  assert.equal(invalidSkew.verified, false);
  assert.match(invalidSkew.signature_verification_reason, /clockSkewSeconds/);

  const invalidNow = detachedSignatureVerifier.verifyProof(envelope, profile, {
    ...context,
    now: new Date(Number.NaN),
  });
  assert.equal(invalidNow.verified, false);
  assert.match(invalidNow.signature_verification_reason, /valid Date/);

  const tampered = detachedSignatureVerifier.verifyProof({
    ...envelope,
    expires_at: new Date(now + 120_000).toISOString(),
  }, profile, {
    ...context,
    claimProofReplay: () => ({ claimed: true }),
  });
  assert.equal(tampered.verified, false);
  assert.match(tampered.signature_verification_reason, /signature verification failed/);

  const replay = detachedSignatureVerifier.verifyProof(envelope, profile, context);
  assert.equal(replay.verified, false);
  assert.match(replay.signature_verification_reason, /replay refused/);

  const wrongKeyFields = {
    ...fields,
    nonce: 'detached-proof-wrong-key',
    keyId: 'spki-sha256:unrelated',
  };
  const wrongKeySigner = createSign('RSA-SHA256');
  wrongKeySigner.update(buildDetachedSignatureV4SigningContent(wrongKeyFields));
  const wrongKey = detachedSignatureVerifier.verifyProof({
    signature: wrongKeySigner.sign(privateKey).toString('base64'),
    artifact_digest: wrongKeyFields.artifactDigest,
    nonce: wrongKeyFields.nonce,
    issued_at: wrongKeyFields.issuedAt,
    expires_at: wrongKeyFields.expiresAt,
    key_id: wrongKeyFields.keyId,
  }, profile, {
    ...context,
    claimProofReplay: () => ({ claimed: true }),
  });
  assert.equal(wrongKey.verified, false);
  assert.match(wrongKey.signature_verification_reason, /key_id does not match/);

  const mismatchedTrustedKeyFields = { ...fields, nonce: 'detached-proof-context-key-id' };
  const mismatchedTrustedKeySigner = createSign('RSA-SHA256');
  mismatchedTrustedKeySigner.update(buildDetachedSignatureV4SigningContent(mismatchedTrustedKeyFields));
  const mismatchedTrustedKey = detachedSignatureVerifier.verifyProof({
    signature: mismatchedTrustedKeySigner.sign(privateKey).toString('base64'),
    artifact_digest: mismatchedTrustedKeyFields.artifactDigest,
    nonce: mismatchedTrustedKeyFields.nonce,
    issued_at: mismatchedTrustedKeyFields.issuedAt,
    expires_at: mismatchedTrustedKeyFields.expiresAt,
    key_id: mismatchedTrustedKeyFields.keyId,
  }, profile, {
    ...context,
    trustedKeyId: 'spki-sha256:unrelated',
    claimProofReplay: () => ({ claimed: true }),
  });
  assert.equal(mismatchedTrustedKey.verified, false);
  assert.match(mismatchedTrustedKey.signature_verification_reason, /key ID does not match/);

  const uncheckedFields = { ...fields, nonce: 'detached-proof-unchecked' };
  const uncheckedSigner = createSign('RSA-SHA256');
  uncheckedSigner.update(buildDetachedSignatureV4SigningContent(uncheckedFields));
  let uncheckedReplayClaims = 0;
  const unchecked = detachedSignatureVerifier.verifyProof({
    signature: uncheckedSigner.sign(privateKey).toString('base64'),
    artifact_digest: uncheckedFields.artifactDigest,
    nonce: uncheckedFields.nonce,
    issued_at: uncheckedFields.issuedAt,
    expires_at: uncheckedFields.expiresAt,
    key_id: uncheckedFields.keyId,
  }, profile, {
    ...context,
    claimProofReplay: () => {
      uncheckedReplayClaims += 1;
      return { claimed: true };
    },
    checkProofRevocation: () => null,
  });
  assert.equal(unchecked.verified, false);
  assert.match(unchecked.signature_verification_reason, /did not explicitly confirm/);
  assert.equal(uncheckedReplayClaims, 0);

  const snakeCaseContext = detachedSignatureVerifier.verifyProof(envelope, profile, {
    handoff_version: 4,
    manifest: manifest(),
    trustedKey: profile.public_key,
  });
  assert.equal(snakeCaseContext.verified, false);
  assert.match(snakeCaseContext.signature_verification_reason, /artifact digest/);
});

test('handoff v4 certificate proof signs its replay and validity controls', t => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-v4-certificate-'));
  t.after(() => rmSync(workdir, { recursive: true, force: true }));
  const caKeyPath = join(workdir, 'ca-key.pem');
  const caCertPath = join(workdir, 'ca-cert.pem');
  const keyPath = join(workdir, 'leaf-key.pem');
  const csrPath = join(workdir, 'leaf.csr');
  const certPath = join(workdir, 'leaf-cert.pem');
  const extensionPath = join(workdir, 'leaf.ext');
  const commands = [
    ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', caKeyPath,
      '-out', caCertPath, '-days', '1', '-subj', '/CN=agentcli-v4-ca',
      '-addext', 'basicConstraints=critical,CA:TRUE',
      '-addext', 'keyUsage=critical,keyCertSign,cRLSign'],
    ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyPath,
      '-out', csrPath, '-subj', '/CN=agentcli-v4-leaf'],
  ];
  for (const args of commands) {
    const result = spawnSync('openssl', args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    assert.equal(result.status, 0, result.stderr);
  }
  writeFileSync(
    extensionPath,
    'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n',
  );
  const leaf = spawnSync('openssl', [
    'x509', '-req', '-in', csrPath, '-CA', caCertPath, '-CAkey', caKeyPath,
    '-CAcreateserial', '-out', certPath, '-days', '1', '-sha256', '-extfile', extensionPath,
  ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  assert.equal(leaf.status, 0, leaf.stderr);

  const compiled = compileManifestToScheduler(manifest(), {
    schedulerHandoffVersion: '4',
    env: { PATH: '/usr/bin' },
  }).jobs[0];
  const now = Date.now();
  const certificatePem = readFileSync(certPath, 'utf8');
  const fields = {
    artifactDigest: compiled.handoff_artifact_digest,
    nonce: 'certificate-proof-1',
    issuedAt: new Date(now - 1_000).toISOString(),
    expiresAt: new Date(now + 60_000).toISOString(),
    keyId: certificateProofKeyId(certificatePem),
  };
  const signer = createSign('SHA256');
  signer.update(buildCertificateV4SigningContent(fields));
  const envelope = {
    certificate: certificatePem,
    signature: signer.sign(readFileSync(keyPath, 'utf8')).toString('base64'),
    artifact_digest: fields.artifactDigest,
    nonce: fields.nonce,
    issued_at: fields.issuedAt,
    expires_at: fields.expiresAt,
    key_id: fields.keyId,
  };
  const profile = {
    ca_certificate: readFileSync(caCertPath, 'utf8'),
    proof: { value_from: { env: 'CERTIFICATE_PROOF' } },
    claims: { subject: 'agentcli-v4-leaf' },
  };
  const context = {
    artifactPayload: compiled.handoff_artifact_payload,
    artifactDigest: compiled.handoff_artifact_digest,
    handoffVersion: 4,
    now: new Date(now),
    runId: 'run-certificate',
    claimProofReplay: () => ({ claimed: true }),
    checkProofRevocation: () => ({ revoked: false }),
  };
  const verified = certificateVerifier.verifyProof(envelope, profile, context);
  assert.equal(verified.verified, true, verified.signature_verification_reason);
  assert.equal(verified.verified_at, new Date(now).toISOString());

  const invalidSkew = certificateVerifier.verifyProof(envelope, profile, {
    ...context,
    clockSkewSeconds: 'not-a-number',
  });
  assert.equal(invalidSkew.verified, false);
  assert.match(invalidSkew.reason, /clockSkewSeconds/);

  const invalidNow = certificateVerifier.verifyProof(envelope, profile, {
    ...context,
    now: new Date(Number.NaN),
  });
  assert.equal(invalidNow.verified, false);
  assert.match(invalidNow.reason, /valid Date/);

  const forged = certificateVerifier.verifyProof({
    ...envelope,
    nonce: 'certificate-proof-forged',
    signature: Buffer.from('forged-signature').toString('base64'),
  }, profile, {
    ...context,
    requireProofOfPossession: false,
  });
  assert.equal(forged.verified, false);
  assert.equal(forged.proof_of_possession_verified, false);
  assert.match(forged.signature_verification_reason, /signature verification failed/);

  const tampered = certificateVerifier.verifyProof({
    ...envelope,
    nonce: 'certificate-proof-tampered',
  }, profile, context);
  assert.equal(tampered.verified, false);
  assert.match(tampered.signature_verification_reason, /signature verification failed/);

  const revoked = certificateVerifier.verifyProof({
    ...envelope,
    nonce: 'certificate-proof-revoked',
    signature: (() => {
      const revokedSigner = createSign('SHA256');
      revokedSigner.update(buildCertificateV4SigningContent({
        ...fields,
        nonce: 'certificate-proof-revoked',
      }));
      return revokedSigner.sign(readFileSync(keyPath, 'utf8')).toString('base64');
    })(),
  }, profile, {
    ...context,
    checkProofRevocation: () => ({ revoked: true, reason: 'certificate revoked' }),
  });
  assert.equal(revoked.verified, false);
  assert.match(revoked.signature_verification_reason, /certificate revoked/);

  const wrongKeyFields = {
    ...fields,
    nonce: 'certificate-proof-wrong-key',
    keyId: 'x509-sha256:unrelated',
  };
  const wrongKeySigner = createSign('SHA256');
  wrongKeySigner.update(buildCertificateV4SigningContent(wrongKeyFields));
  const wrongKey = certificateVerifier.verifyProof({
    certificate: certificatePem,
    signature: wrongKeySigner.sign(readFileSync(keyPath, 'utf8')).toString('base64'),
    artifact_digest: wrongKeyFields.artifactDigest,
    nonce: wrongKeyFields.nonce,
    issued_at: wrongKeyFields.issuedAt,
    expires_at: wrongKeyFields.expiresAt,
    key_id: wrongKeyFields.keyId,
  }, profile, {
    ...context,
    claimProofReplay: () => ({ claimed: true }),
  });
  assert.equal(wrongKey.verified, false);
  assert.match(wrongKey.signature_verification_reason, /key_id does not match/);

  const uncheckedFields = { ...fields, nonce: 'certificate-proof-unchecked' };
  const uncheckedSigner = createSign('SHA256');
  uncheckedSigner.update(buildCertificateV4SigningContent(uncheckedFields));
  let uncheckedReplayClaims = 0;
  const unchecked = certificateVerifier.verifyProof({
    certificate: certificatePem,
    signature: uncheckedSigner.sign(readFileSync(keyPath, 'utf8')).toString('base64'),
    artifact_digest: uncheckedFields.artifactDigest,
    nonce: uncheckedFields.nonce,
    issued_at: uncheckedFields.issuedAt,
    expires_at: uncheckedFields.expiresAt,
    key_id: uncheckedFields.keyId,
  }, profile, {
    ...context,
    claimProofReplay: () => {
      uncheckedReplayClaims += 1;
      return { claimed: true };
    },
    checkProofRevocation: () => ({ ok: false, reason: 'revocation backend unavailable' }),
  });
  assert.equal(unchecked.verified, false);
  assert.match(unchecked.signature_verification_reason, /revocation backend unavailable/);
  assert.equal(uncheckedReplayClaims, 0);

  const snakeCaseContext = certificateVerifier.verifyProof(envelope, profile, {
    handoff_version: 4,
    manifest: manifest(),
  });
  assert.equal(snakeCaseContext.verified, false);
  assert.match(snakeCaseContext.reason, /artifact digest/);
});

test('inspect advertises every v4 immutable runtime entity', () => {
  const entities = listInspectableEntities();
  for (const entity of [
    'evidence',
    'artifacts',
    'events',
    'provider_sessions',
    'credential_presentations',
  ]) {
    assert.equal(entities.includes(entity), true, `missing inspect entity ${entity}`);
  }
});
