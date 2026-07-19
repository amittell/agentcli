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
import { compileManifestToScheduler } from '../src/compiler/openclaw-scheduler.js';
import {
  validateSchedulerHandoffV4Artifact,
} from '../src/handoff/v4.js';
import { canonicalStringify } from '../src/canonical.js';
import { jwtVerifier } from '../src/authorization-proof/jwt.js';
import {
  buildDetachedSignatureV4SigningContent,
  detachedSignatureVerifier,
} from '../src/authorization-proof/detached-signature.js';
import {
  buildCertificateV4SigningContent,
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

function runner({ handoffVersion = '4', features = V4_FEATURES } = {}) {
  const added = [];
  return {
    invocation: { label: 'mock-scheduler' },
    added,
    queryCapabilities() {
      return {
        scheduler_version: 'test',
        schema_version: 29,
        handoff_version: handoffVersion,
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

function statefulRunner(initialJobs = []) {
  const jobs = new Map(initialJobs.map(job => [job.id, structuredClone(job)]));
  const history = [];
  return {
    invocation: { label: 'stateful-mock-scheduler' },
    history,
    queryCapabilities() {
      return {
        scheduler_version: 'test',
        schema_version: 29,
        handoff_version: '4',
        features: V4_FEATURES,
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

function signJwt(payload, privateKey) {
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'test-key' }));
  const body = base64url(JSON.stringify(payload));
  const signingInput = `${header}.${body}`;
  const signer = createSign('RSA-SHA256');
  signer.update(signingInput);
  return `${signingInput}.${signer.sign(privateKey).toString('base64url')}`;
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

  const oldRunner = runner({ handoffVersion: '3' });
  const oldRuntime = await applyManifestToScheduler(manifest(), {
    runner: oldRunner,
    env: { PATH: '/usr/bin' },
  });
  assert.equal(oldRuntime.handoff.field_version, '3');
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
  const adopter = statefulRunner([{
    id: legacyId,
    name: manifest().workflows[0].tasks[0].name,
    origin: 'legacy-origin',
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
  assert.equal(JSON.parse(adopter.history[0].spec.handoff_artifact_payload).handoff_version, 4);
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

  const replay = jwtVerifier.verifyProof(token, profile, context);
  assert.equal(replay.verified, false);
  assert.match(replay.reason, /replay/);

  const missingArtifact = signJwt({ ...payload, jti: 'proof-2', handoff_artifact_digest: undefined }, privateKey);
  const unbound = jwtVerifier.verifyProof(missingArtifact, profile, context);
  assert.equal(unbound.verified, false);
  assert.match(unbound.reason, /artifact digest claim/);
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
    keyId: 'rsa-test-key',
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
    now,
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
  const fields = {
    artifactDigest: compiled.handoff_artifact_digest,
    nonce: 'certificate-proof-1',
    issuedAt: new Date(now - 1_000).toISOString(),
    expiresAt: new Date(now + 60_000).toISOString(),
    keyId: 'leaf-test-key',
  };
  const signer = createSign('SHA256');
  signer.update(buildCertificateV4SigningContent(fields));
  const envelope = {
    certificate: readFileSync(certPath, 'utf8'),
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
    now,
    runId: 'run-certificate',
    claimProofReplay: () => ({ claimed: true }),
    checkProofRevocation: () => ({ revoked: false }),
  };
  const verified = certificateVerifier.verifyProof(envelope, profile, context);
  assert.equal(verified.verified, true, verified.signature_verification_reason);
  assert.equal(verified.verified_at, new Date(now).toISOString());

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
