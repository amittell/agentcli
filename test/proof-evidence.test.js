import assert from 'node:assert/strict';
import {
  createSign,
  generateKeyPairSync,
} from 'node:crypto';
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

import { canonicalDigest, canonicalStringify, hashString } from '../src/canonical.js';
import { resolveCommandValue, resolveValueFrom } from '../src/command.js';
import {
  assertValidAuthorizationProofProfile,
  validateAuthorizationProofProfile,
  verifyAuthorizationProof,
} from '../src/authorization-proof/index.js';
import {
  resolveCertificateVerificationContext,
  certificateVerifier,
} from '../src/authorization-proof/certificate.js';
import { detachedSignatureVerifier } from '../src/authorization-proof/detached-signature.js';
import { jwtVerifier } from '../src/authorization-proof/jwt.js';
import {
  buildCompleteEvidencePayload,
  serializePayload,
  validateCompleteEvidencePayload,
  validateEvidenceRecordBinding,
} from '../src/evidence/payload.js';
import { sshEvidenceProvider } from '../src/evidence/ssh.js';
import { registerEvidenceProvider, verifyEvidenceEnvelope } from '../src/evidence/index.js';
import {
  generateExecutionId,
  readAuditLog,
  writeAuditRecord,
} from '../src/audit.js';
import { executeTask } from '../src/exec.js';
import { compileManifestToStandalone } from '../src/compiler/standalone.js';

function base64Url(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function signedJwt(payload, privateKey) {
  const header = base64Url({ alg: 'RS256', typ: 'JWT' });
  const body = base64Url(payload);
  const signingInput = `${header}.${body}`;
  const signer = createSign('RSA-SHA256');
  signer.update(signingInput);
  return `${signingInput}.${signer.sign(privateKey).toString('base64url')}`;
}

function unsignedJwt(payload) {
  return `${base64Url({ alg: 'none', typ: 'JWT' })}.${base64Url(payload)}.`;
}

function evidencePayload(overrides = {}) {
  return buildCompleteEvidencePayload({
    executionId: 'execution-1',
    timestamp: new Date().toISOString(),
    source: { workflow_id: 'workflow', task_id: 'task' },
    manifest: { version: '0.2', workflows: [] },
    effectiveTask: { binding_version: 1, command: { program: 'echo' } },
    declaredIdentity: { provider: 'none' },
    resolvedIdentity: {
      principal: 'agent://test',
      credentials: { access_token: 'secret-identity-token' },
    },
    authorizationProof: { method: 'jwt', verified: true },
    authorization: { decision: 'permit', provider_data: { api_key: 'secret-auth-key' } },
    actorContext: { principal: 'agent://test' },
    contract: { audit: 'always' },
    command: {
      program: 'echo',
      args: ['secret-argument'],
      cwd: '/tmp',
      env: { TOKEN: 'secret-environment' },
      stdin: 'secret-stdin',
    },
    result: {
      exit_code: 0,
      timed_out: false,
      duration_ms: 10,
      output_hash: hashString('secret-output'),
      stdout: 'secret-output',
      stderr: '',
      structured: { secret: true },
    },
    verify: {
      passed: true,
      stdout: 'verify-output',
      stderr: '',
    },
    complianceContext: { policy_version: 'policy-1' },
    ...overrides,
  });
}

test('resolveValueFrom disables command execution until explicitly allowed', () => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-value-from-'));
  const marker = join(workdir, 'marker');
  try {
    assert.throws(
      () => resolveValueFrom(
        { command: `printf blocked > "${marker}"; printf value` },
        { cwd: workdir }
      ),
      /disabled until the caller explicitly opts in/
    );
    assert.throws(() => readFileSync(marker, 'utf8'));

    const value = resolveValueFrom(
      { command: `printf allowed > "${marker}"; printf value` },
      { cwd: workdir, allowCommand: true }
    );
    assert.equal(value, 'value');
    assert.equal(readFileSync(marker, 'utf8'), 'allowed');
  } finally {
    rmSync(workdir, { recursive: true, force: true });
  }
});

test('resolveValueFrom rejects ambiguous sources and resolves relative files', () => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-value-file-'));
  try {
    writeFileSync(join(workdir, 'proof.txt'), 'proof-value\n');
    assert.equal(
      resolveValueFrom({ file: 'proof.txt' }, { cwd: workdir }),
      'proof-value'
    );
    assert.throws(
      () => resolveValueFrom({ env: 'TOKEN', literal: 'value' }, { env: { TOKEN: 'token' } }),
      /exactly one source/
    );
  } finally {
    rmSync(workdir, { recursive: true, force: true });
  }
});

test('value resolution separates lookup environment from command environment', () => {
  const env = { SECRET_PROOF: 'proof-from-full-environment' };
  const commandEnv = { AGENTCLI_MANIFEST_DIGEST: 'sha256:digest' };
  assert.equal(
    resolveValueFrom({ env: 'SECRET_PROOF' }, { env, commandEnv }),
    'proof-from-full-environment'
  );

  const runner = (_program, _args, options) => {
    assert.deepEqual(options.env, commandEnv);
    return { status: 0, stdout: 'command-proof', stderr: '' };
  };
  assert.equal(
    resolveValueFrom(
      { command: 'generate-proof' },
      { env, commandEnv, allowCommand: true, runner }
    ),
    'command-proof'
  );
  assert.equal(
    resolveCommandValue('generate-proof', { env, commandEnv, runner }),
    'command-proof'
  );
});

test('JWT claims-only parsing is never reported as verified', () => {
  const token = unsignedJwt({ sub: 'agent', exp: Math.floor(Date.now() / 1000) + 300 });
  const result = jwtVerifier.verifyProof(token, {}, { requireSignature: false });
  assert.equal(result.claims_validated, true);
  assert.equal(result.signature_verified, false);
  assert.equal(result.verified, false);
});

test('JWT verification succeeds only with a trusted signing key', async () => {
  const keys = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const manifest = { version: '0.2', workflows: [] };
  const token = signedJwt({
    sub: 'agent',
    manifest_digest: canonicalDigest(manifest),
    secret_claim: 'audit-secret-value',
  }, keys.privateKey);
  const profile = {
    method: 'jwt',
    public_key: keys.publicKey,
    proof: { value_from: { env: 'JWT' } },
    claims: { subject: 'agent', secret_claim: 'audit-secret-value' },
    verify: { required: true },
  };
  const result = await verifyAuthorizationProof(token, profile, { manifest });
  assert.equal(result.verified, true);
  assert.equal(result.signature_verified, true);
  assert.equal(result.manifest_bound, true);
  assert.equal(result.decoded_claims.secret_claim, undefined);
  assert.equal(JSON.stringify(jwtVerifier.describeVerification(result, {})).includes('audit-secret-value'), false);

  const changed = await verifyAuthorizationProof(token, profile, {
    manifest: { version: '0.2', workflows: [{ id: 'changed' }] },
  });
  assert.equal(changed.verified, false);
  assert.equal(changed.signature_verified, true);
  assert.equal(changed.manifest_bound, false);
});

test('authorization proof profile validation fails closed', () => {
  const unknown = validateAuthorizationProofProfile({ method: 'unknown' });
  assert.equal(unknown.valid, false);

  const missingProof = validateAuthorizationProofProfile({
    method: 'jwt',
    public_key: 'not-used-during-profile-validation',
  });
  assert.equal(missingProof.valid, false);
  assert.throws(
    () => assertValidAuthorizationProofProfile({ method: 'jwt' }),
    error => error.code === 'authorization_proof_invalid'
  );
});

test('authorization proof profiles reject private keys in public_key fields', () => {
  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  for (const verifier of [jwtVerifier, detachedSignatureVerifier]) {
    const profile = {
      id: 'proof',
      method: verifier.name,
      public_key: privateKey,
      proof: { value_from: { env: 'AUTHORIZATION_PROOF' } },
      verify: { required: true },
    };
    const validation = verifier.validateProfile(profile);
    assert.equal(validation.valid, false);
    assert.ok(validation.errors.some(error => (
      error.field === 'public_key' && /private|verification key|supported/i.test(error.message)
    )));

    const manifest = {
      version: '0.2',
      authorization_proof_profiles: [profile],
      workflows: [{
        id: 'proof-workflow',
        name: 'Proof Workflow',
        authorization_proof: { ref: 'proof' },
        tasks: [{
          id: 'proof-task',
          name: 'Proof Task',
          target: { session_target: 'shell' },
          shell: { program: 'true', args: [] },
          schedule: { cron: '0 * * * *' },
        }],
      }],
    };
    assert.throws(
      () => compileManifestToStandalone(manifest),
      error => !JSON.stringify(error).includes(privateKey) && error.validation?.ok === false
    );
  }
});

test('detached signatures verify canonical manifest content and reject changes', () => {
  const keys = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const manifest = { version: '0.2', metadata: { b: 2, a: 1 }, workflows: [] };
  const signer = createSign('RSA-SHA256');
  signer.update(canonicalStringify(manifest));
  const signature = signer.sign(keys.privateKey).toString('base64');
  const profile = {
    method: 'detached-signature',
    public_key: keys.publicKey,
    proof: { value_from: { env: 'SIGNATURE' } },
    verify: { required: true },
  };

  const verified = detachedSignatureVerifier.verifyProof(signature, profile, {
    manifest: { workflows: [], metadata: { a: 1, b: 2 }, version: '0.2' },
  });
  assert.equal(verified.verified, true);
  assert.match(verified.manifest_digest, /^sha256:/);

  const changed = detachedSignatureVerifier.verifyProof(signature, profile, {
    manifest: { ...manifest, metadata: { a: 1, b: 3 } },
  });
  assert.equal(changed.verified, false);
});

test('manifest-bound proof methods reject circular inline proof values', () => {
  for (const verifier of [jwtVerifier, detachedSignatureVerifier, certificateVerifier]) {
    const result = verifier.validateProfile({
      method: verifier.name,
      public_key: 'configured-trust',
      proof: { value_from: { literal: 'inline-proof' } },
      verify: { required: true },
    });
    assert.equal(result.valid, false);
    assert.ok(result.errors.some(error => error.field === 'proof.value_from.literal'));
  }
});

test('certificate context resolves a CA from safe value_from sources', () => {
  const context = resolveCertificateVerificationContext({
    ca_certificate_from: { env: 'CA_CERT' },
  }, {
    env: { CA_CERT: 'certificate-data' },
    manifest: { version: '0.2' },
  });
  assert.equal(context.caCert, 'certificate-data');
  assert.equal(context.caCertError, null);
  assert.match(context.manifestDigest, /^sha256:/);
});

test('certificate proof requires a trusted chain and manifest proof of possession', () => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-certificate-'));
  const caKeyPath = join(workdir, 'ca-key.pem');
  const caCertPath = join(workdir, 'ca-cert.pem');
  const keyPath = join(workdir, 'leaf-key.pem');
  const csrPath = join(workdir, 'leaf.csr');
  const certPath = join(workdir, 'leaf-cert.pem');
  const extensionPath = join(workdir, 'leaf.ext');
  try {
    const generatedCa = spawnSync('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', caKeyPath,
      '-out', caCertPath,
      '-subj', '/CN=agentcli-test-ca',
      '-addext', 'basicConstraints=critical,CA:TRUE',
      '-days', '1',
    ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    assert.equal(generatedCa.status, 0, generatedCa.stderr);

    const generatedCsr = spawnSync('openssl', [
      'req', '-new', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', keyPath,
      '-out', csrPath,
      '-subj', '/CN=agentcli-test',
    ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    assert.equal(generatedCsr.status, 0, generatedCsr.stderr);
    writeFileSync(
      extensionPath,
      'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
    );
    const generatedLeaf = spawnSync('openssl', [
      'x509', '-req',
      '-in', csrPath,
      '-CA', caCertPath,
      '-CAkey', caKeyPath,
      '-CAcreateserial',
      '-out', certPath,
      '-days', '1',
      '-sha256',
      '-extfile', extensionPath,
    ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    assert.equal(generatedLeaf.status, 0, generatedLeaf.stderr);

    const manifest = { version: '0.2', workflows: [] };
    const signer = createSign('SHA256');
    signer.update(canonicalStringify(manifest));
    const signature = signer.sign(readFileSync(keyPath, 'utf8')).toString('base64');
    const certificate = readFileSync(certPath, 'utf8');
    const profile = {
      method: 'certificate',
      ca_certificate: readFileSync(caCertPath, 'utf8'),
      proof: { value_from: { env: 'CERTIFICATE_PROOF' } },
      claims: { subject: 'agentcli-test' },
      verify: { required: true },
    };
    const proof = JSON.stringify({ certificate, signature });

    const verified = certificateVerifier.verifyProof(proof, profile, { manifest });
    assert.equal(verified.verified, true, verified.signature_verification_reason);
    assert.equal(verified.signature_verified, true);
    assert.equal(verified.proof_of_possession_verified, true);

    const partialSubject = certificateVerifier.verifyProof(proof, {
      ...profile,
      claims: { subject: 'agentcli' },
    }, { manifest });
    assert.equal(partialSubject.verified, false);
    assert.equal(partialSubject.claims_validated, false);

    const changed = certificateVerifier.verifyProof(proof, profile, {
      manifest: { version: '0.2', workflows: [{ id: 'changed' }] },
    });
    assert.equal(changed.verified, false);
    assert.equal(changed.proof_of_possession_verified, false);
  } finally {
    rmSync(workdir, { recursive: true, force: true });
  }
});

test('complete evidence binds all execution controls without retaining raw inputs', () => {
  const payload = evidencePayload();
  const validation = validateCompleteEvidencePayload(payload);
  assert.deepEqual(validation, { valid: true, errors: [] });
  assert.match(payload.bindings.manifest_digest, /^sha256:/);
  assert.match(payload.bindings.effective_task_hash, /^sha256:/);
  assert.equal(payload.command.args, undefined);
  assert.equal(payload.command.env, undefined);
  assert.equal(payload.command.stdin, undefined);
  assert.equal(payload.result.stdout, undefined);
  assert.equal(payload.result.structured, undefined);
  assert.equal(payload.verify.stdout, undefined);
  assert.match(payload.command.args_hashes[0], /^sha256:/);
  assert.match(payload.command.env_hash, /^sha256:/);
  assert.match(payload.command.stdin_hash, /^sha256:/);
  assert.match(payload.result.stdout_hash, /^sha256:/);
  assert.match(payload.verify.stdout_hash, /^sha256:/);

  const serialized = serializePayload(payload);
  for (const secret of [
    'secret-argument',
    'secret-environment',
    'secret-stdin',
    'secret-output',
    'verify-output',
    'secret-identity-token',
    'secret-auth-key',
  ]) {
    assert.equal(serialized.includes(secret), false);
  }
});

test('complete evidence rejects caller-supplied binding digest mismatches', () => {
  assert.throws(
    () => evidencePayload({ manifestDigest: 'sha256:not-the-manifest' }),
    /manifestDigest does not match/
  );
  assert.throws(
    () => evidencePayload({ effectiveTaskHash: 'sha256:not-the-task' }),
    /effectiveTaskHash does not match/
  );
});

test('verified evidence cannot be transplanted onto another audit record', () => {
  const payload = evidencePayload();
  const record = {
    execution_id: payload.execution_id,
    timestamp: payload.timestamp,
    source: payload.source,
    manifest_digest: payload.bindings.manifest_digest,
    effective_task_hash: payload.bindings.effective_task_hash,
    declared_identity: { provider: 'none' },
    resolved_identity: {
      principal: 'agent://test',
      credentials: { access_token: 'secret-identity-token' },
    },
    authorization_proof: { method: 'jwt', verified: true },
    authorization: { decision: 'permit', provider_data: { api_key: 'secret-auth-key' } },
    actor_context: { principal: 'agent://test' },
    contract: { audit: 'always' },
    command: Object.fromEntries([
      'program', 'cwd', 'args_count', 'args_hashes', 'env_keys', 'env_hashes',
      'stdin_present', 'stdin_hash',
    ].map(field => [
      field,
      field === 'stdin_present'
        ? payload.command.stdin_hash != null
        : payload.command[field] ?? null,
    ])),
    result: Object.fromEntries([
      'exit_code', 'signal', 'timed_out', 'duration_ms', 'stdout_bytes',
      'stderr_bytes', 'output_hash',
    ].map(field => [field, payload.result[field] ?? null])),
    verify: {
      passed: true,
      stdout: 'verify-output',
      stderr: '',
    },
  };
  assert.deepEqual(
    validateEvidenceRecordBinding(payload, record),
    { valid: true, errors: [] }
  );
  const transplanted = validateEvidenceRecordBinding(payload, {
    ...record,
    execution_id: 'different-execution',
  });
  assert.equal(transplanted.valid, false);
  assert.match(transplanted.errors[0], /execution_id/);

  const rewrittenIdentity = validateEvidenceRecordBinding(payload, {
    ...record,
    resolved_identity: { ...record.resolved_identity, principal: 'agent://attacker' },
  });
  assert.equal(rewrittenIdentity.valid, false);
  assert.ok(rewrittenIdentity.errors.some(error => /resolved_identity/.test(error)));
});

test('SSH evidence profiles reject non-canonical payload serialization', () => {
  const validation = sshEvidenceProvider.validateProfile({ payload: { format: 'json' } });
  assert.equal(validation.valid, false);
  assert.match(validation.errors[0], /canonical-json/);

  const manifest = {
    version: '0.2',
    evidence_profiles: [{
      id: 'ssh-evidence',
      provider: 'ssh',
      payload: { format: 'json' },
    }],
    workflows: [{
      id: 'evidence-workflow',
      name: 'Evidence Workflow',
      tasks: [{
        id: 'task',
        name: 'Task',
        shell: { program: 'true', args: [] },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        evidence: { ref: 'ssh-evidence' },
      }],
    }],
  };
  assert.throws(
    () => compileManifestToStandalone(manifest),
    error => error.validation?.ok === false && /canonical-json/.test(JSON.stringify(error.validation))
  );
});

test('SSH evidence persists a versioned envelope that can be independently verified', async () => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-evidence-'));
  const keyPath = join(workdir, 'evidence-key');
  const allowedSignersPath = join(workdir, 'allowed_signers');
  const untrustedKeyPath = join(workdir, 'untrusted-key');
  const untrustedSignersPath = join(workdir, 'untrusted_signers');
  try {
    const generated = spawnSync('ssh-keygen', [
      '-q', '-t', 'ed25519', '-N', '', '-f', keyPath,
    ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    assert.equal(generated.status, 0, generated.stderr);
    writeFileSync(
      allowedSignersPath,
      `agentcli ${readFileSync(`${keyPath}.pub`, 'utf8').trim()}\n`,
      { mode: 0o600 }
    );

    const payload = serializePayload(evidencePayload());
    const config = sshEvidenceProvider.resolve({
      key_path: keyPath,
      principal: 'agentcli',
    });
    const attested = sshEvidenceProvider.attest(payload, config);
    assert.equal(attested.attested, true, attested.reason);
    assert.equal(attested.envelope.schema, 'agentcli.evidence.envelope');
    assert.equal(attested.envelope.version, 1);
    assert.ok(attested.envelope.signature.includes('BEGIN SSH SIGNATURE'));

    const verified = await verifyEvidenceEnvelope(attested.envelope, {
      allowedSignersPath,
      principal: 'agentcli',
    });
    assert.equal(verified.verified, true, verified.reason);
    assert.equal(verified.payload.execution_id, 'execution-1');

    const missingTrust = await verifyEvidenceEnvelope(attested.envelope, {
      allowedSignersPath: join(workdir, 'missing_allowed_signers'),
      principal: 'agentcli',
    });
    assert.equal(missingTrust.verified, false);

    const generatedUntrusted = spawnSync('ssh-keygen', [
      '-q', '-t', 'ed25519', '-N', '', '-f', untrustedKeyPath,
    ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    assert.equal(generatedUntrusted.status, 0, generatedUntrusted.stderr);
    writeFileSync(
      untrustedSignersPath,
      `agentcli ${readFileSync(`${untrustedKeyPath}.pub`, 'utf8').trim()}\n`,
      { mode: 0o600 }
    );
    const untrusted = await verifyEvidenceEnvelope(attested.envelope, {
      allowedSignersPath: untrustedSignersPath,
      principal: 'agentcli',
    });
    assert.equal(untrusted.verified, false);

    const tampered = {
      ...attested.envelope,
      signed_payload: attested.envelope.signed_payload.replace('execution-1', 'execution-2'),
    };
    const rejected = await verifyEvidenceEnvelope(tampered, {
      allowedSignersPath,
      principal: 'agentcli',
    });
    assert.equal(rejected.verified, false);
    assert.match(rejected.reason, /digest mismatch/);

    const wrongFingerprint = await verifyEvidenceEnvelope({
      ...attested.envelope,
      key_fingerprint: 'SHA256:wrong',
    }, {
      allowedSignersPath,
      principal: 'agentcli',
    });
    assert.equal(wrongFingerprint.verified, false);
    assert.match(wrongFingerprint.reason, /signature|fingerprint/i);
  } finally {
    rmSync(workdir, { recursive: true, force: true });
  }
});

test('exec persists complete evidence that binds back to its audit record', async () => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-exec-evidence-'));
  const keyPath = join(workdir, 'evidence-key');
  const allowedSignersPath = join(workdir, 'allowed_signers');
  const agentcliHome = join(workdir, 'home');
  try {
    const generated = spawnSync('ssh-keygen', [
      '-q', '-t', 'ed25519', '-N', '', '-f', keyPath,
    ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    assert.equal(generated.status, 0, generated.stderr);
    writeFileSync(
      allowedSignersPath,
      `agentcli ${readFileSync(`${keyPath}.pub`, 'utf8').trim()}\n`,
      { mode: 0o600 }
    );

    const manifest = {
      version: '0.2',
      evidence_profiles: [{
        id: 'signed-evidence',
        provider: 'ssh',
        provider_config: {
          key_path: keyPath,
          principal: 'agentcli',
          allowed_signers_path: allowedSignersPath,
        },
        payload: { format: 'canonical-json' },
        verify: { required: true },
      }],
      workflows: [{
        id: 'evidence-workflow',
        name: 'Evidence Workflow',
        tasks: [{
          id: 'evidence-task',
          name: 'Evidence Task',
          shell: { program: 'printf', args: ['evidence-output'] },
          target: { session_target: 'shell' },
          schedule: { cron: '0 * * * *' },
          contract: { audit: 'always' },
          evidence: { ref: 'signed-evidence' },
        }],
      }],
    };
    const env = { ...process.env, AGENTCLI_HOME: agentcliHome };
    const result = await executeTask(manifest, {
      workflowId: 'evidence-workflow',
      taskId: 'evidence-task',
      env,
      cwd: workdir,
      signer: 'none',
    });
    assert.equal(result.ok, true);
    assert.equal(result.evidence.attested, true);
    assert.equal(result.evidence.verification.verified, true);
    assert.ok(result.evidence.envelope.signature);

    const auditPath = join(agentcliHome, 'state', 'audit.ndjson');
    const records = readAuditLog({ auditPath });
    assert.equal(records.length, 1);
    const payload = JSON.parse(records[0].evidence.envelope.signed_payload);
    assert.deepEqual(
      validateEvidenceRecordBinding(payload, records[0]),
      { valid: true, errors: [] }
    );
    const verified = await verifyEvidenceEnvelope(records[0].evidence.envelope, {
      allowedSignersPath,
      principal: 'agentcli',
    });
    assert.equal(verified.verified, true, verified.reason);

    const missingTrustManifest = structuredClone(manifest);
    missingTrustManifest.evidence_profiles[0].provider_config.allowed_signers_path =
      join(workdir, 'missing_allowed_signers');
    await assert.rejects(
      executeTask(missingTrustManifest, {
        workflowId: 'evidence-workflow',
        taskId: 'evidence-task',
        env,
        cwd: workdir,
        signer: 'none',
      }),
      error => error.code === 'evidence_failed' && /verification required but failed/i.test(error.message)
    );
  } finally {
    rmSync(workdir, { recursive: true, force: true });
  }
});

test('required evidence fails closed when a provider attests but cannot verify', async () => {
  const providerName = `test-evidence-unverified-${process.pid}-${Date.now()}`;
  const method = `${providerName}-signature`;
  registerEvidenceProvider({
    name: providerName,
    methods: [method],
    validateProfile: () => ({ valid: true }),
    resolve: () => ({}),
    attest: payload => ({
      attested: true,
      envelope: { method, signed_payload: payload },
    }),
    verify: () => ({ verified: false, reason: 'test verifier rejected the envelope' }),
    describe: () => ({ provider: providerName, attested: true }),
  });
  const home = mkdtempSync(join(tmpdir(), 'agentcli-unverified-evidence-'));
  const manifest = {
    version: '0.2',
    evidence_profiles: [{
      id: 'required-evidence',
      provider: providerName,
      verify: { required: true },
    }],
    workflows: [{
      id: 'evidence-workflow',
      name: 'Evidence Workflow',
      tasks: [{
        id: 'task',
        name: 'Task',
        shell: { program: 'true', args: [] },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        contract: { audit: 'always' },
        evidence: { ref: 'required-evidence' },
      }],
    }],
  };
  try {
    await assert.rejects(
      executeTask(manifest, {
        taskId: 'task',
        env: { ...process.env, AGENTCLI_HOME: home },
        signer: 'none',
      }),
      error => error.code === 'evidence_failed' && /test verifier rejected/.test(error.message)
    );
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('SSH evidence provider refuses to sign incomplete payloads', () => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-evidence-incomplete-'));
  const keyPath = join(workdir, 'evidence-key');
  try {
    const generated = spawnSync('ssh-keygen', [
      '-q', '-t', 'ed25519', '-N', '', '-f', keyPath,
    ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    assert.equal(generated.status, 0, generated.stderr);
    const result = sshEvidenceProvider.attest(
      JSON.stringify({ result: { exit_code: 0 } }),
      { keyPath, principal: 'agentcli' }
    );
    assert.equal(result.attested, false);
    assert.match(result.reason, /incomplete evidence payload/);
  } finally {
    rmSync(workdir, { recursive: true, force: true });
  }
});

test('audit log skips malformed and partial JSONL records with diagnostics', () => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-audit-'));
  const auditPath = join(workdir, 'state', 'audit.ndjson');
  try {
    writeAuditRecord({ execution_id: 'one' }, { auditPath });
    writeFileSync(
      auditPath,
      '{"execution_id":"one"}\nnot-json\n{"execution_id":"two"}\n{"partial":',
      { mode: 0o600 }
    );
    const malformed = [];
    const records = readAuditLog({
      auditPath,
      onMalformed: diagnostic => malformed.push(diagnostic),
    });
    assert.deepEqual(records.map(record => record.execution_id), ['one', 'two']);
    assert.deepEqual(malformed.map(item => item.lineNumber), [2, 4]);
    chmodSync(auditPath, 0o644);
    writeAuditRecord({ execution_id: 'three' }, { auditPath });
    assert.deepEqual(
      readAuditLog({ auditPath }).map(record => record.execution_id),
      ['one', 'two', 'three']
    );
    assert.equal(statSync(auditPath).mode & 0o777, 0o600);
  } finally {
    rmSync(workdir, { recursive: true, force: true });
  }
});

test('execution IDs remain unique for identical same-millisecond executions', () => {
  const ids = new Set();
  for (let index = 0; index < 1000; index += 1) {
    ids.add(generateExecutionId('workflow', 'task', 'same-timestamp'));
  }
  assert.equal(ids.size, 1000);
  for (const id of ids) assert.match(id, /^[a-f0-9]{32}$/);
});
