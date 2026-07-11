import test from 'node:test';
import assert from 'node:assert/strict';
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { createSign, generateKeyPairSync } from 'node:crypto';
import { createServer } from 'node:http';

import '../src/validate.js';
import { getProvider, listProviders } from '../src/identity/index.js';
import { validateSecureEndpoint } from '../src/identity/session.js';
import { verifyJwtSvid } from '../src/identity/spiffe-jwt-svid.js';

function envBearerProfile(overrides = {}) {
  return {
    provider: 'env-bearer',
    auth: {
      mode: 'service',
      required: true,
      provider_config: { token_env: 'TEST_BEARER_TOKEN' },
      ...(overrides.auth || {}),
    },
    trust: { level: 'supervised' },
    presentation: { handoff: 'none', ...(overrides.presentation || {}) },
    ...Object.fromEntries(Object.entries(overrides).filter(([key]) => !['auth', 'presentation'].includes(key))),
  };
}

function oidcProfile(tokenEndpoint) {
  return {
    provider: 'oidc-client-credentials',
    auth: {
      mode: 'service',
      provider_config: {
        token_endpoint: tokenEndpoint,
        client_id: 'client-id',
        client_secret: { value_from: { env: 'OIDC_CLIENT_SECRET' } },
      },
    },
    trust: { level: 'supervised' },
    presentation: { handoff: 'none' },
  };
}

function stripeProfile(apiBase) {
  return {
    provider: 'stripe-api-key',
    auth: {
      mode: 'service',
      provider_config: {
        key_strategy: 'dynamic',
        account_mode: 'test',
        master_key_source: { env: 'STRIPE_MASTER_KEY' },
        api_base: apiBase,
        allow_insecure_http: true,
      },
    },
    trust: { level: 'supervised' },
    presentation: { handoff: 'none' },
  };
}

function signedJwt(privateKey, payload, header = { alg: 'RS256', typ: 'JWT', kid: 'test-key' }) {
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signer = createSign('RSA-SHA256');
  signer.update(signingInput);
  return `${signingInput}.${signer.sign(privateKey).toString('base64url')}`;
}

test('every registered identity provider applies structural profile validation', async () => {
  for (const name of listProviders()) {
    const validation = await getProvider(name).validateProfile({
      auth: [],
      subject: [],
      trust: [],
      presentation: { bindings: 'not-an-array' },
    });
    assert.equal(validation.valid, false, `${name} accepted a structurally invalid profile`);
    assert.ok(validation.errors.length > 0);
  }
});

test('unsupported cache, refresh, delegation, and handoff declarations fail closed', async () => {
  const provider = getProvider('env-bearer');

  const cached = await provider.validateProfile(envBearerProfile({ auth: { cache: 'memory' } }));
  assert.equal(cached.valid, false);
  assert.match(cached.errors.join(' '), /cache/);

  const refreshed = await provider.validateProfile(envBearerProfile({ auth: { refresh: 'auto' } }));
  assert.equal(refreshed.valid, false);
  assert.match(refreshed.errors.join(' '), /refresh/);

  const delegated = await provider.validateProfile(envBearerProfile({
    auth: { delegation_policy: { max_depth: 1 } },
  }));
  assert.equal(delegated.valid, false);
  assert.match(delegated.errors.join(' '), /delegation/);

  const handedOff = await provider.validateProfile(envBearerProfile({
    presentation: { handoff: 'downscope' },
  }));
  assert.equal(handedOff.valid, false);
  assert.match(handedOff.errors.join(' '), /handoff/);

  const azure = getProvider('azure-managed-identity');
  const refreshableProfile = {
    provider: 'azure-managed-identity',
    auth: {
      mode: 'service',
      refresh: 'auto',
      provider_config: { resource: 'https://management.azure.com/' },
    },
    trust: { level: 'supervised' },
    presentation: { handoff: 'none' },
  };
  assert.equal((await azure.validateProfile(refreshableProfile)).valid, false);
  assert.equal((await azure.validateProfile(refreshableProfile, {
    structural: true,
  })).valid, true);
  assert.equal((await azure.validateProfile(refreshableProfile, {
    runtimeCapabilities: { credentialRefresh: true },
  })).valid, true);

  const stripe = getProvider('stripe-api-key');
  const portableHandoff = {
    ...stripeProfile('https://api.stripe.com'),
    presentation: { handoff: 'downscope' },
  };
  assert.equal((await stripe.validateProfile(portableHandoff)).valid, false);
  assert.equal((await stripe.validateProfile(portableHandoff, {
    structural: true,
  })).valid, true);
});

test('user-configurable HTTP endpoints are limited to loopback hosts', async () => {
  assert.deepEqual(validateSecureEndpoint('https://issuer.example/token'), []);
  assert.deepEqual(validateSecureEndpoint('http://127.25.3.9/token'), []);
  assert.deepEqual(validateSecureEndpoint('http://[::1]/token'), []);
  assert.notDeepEqual(validateSecureEndpoint('http://192.0.2.20/token'), []);

  const oidc = getProvider('oidc-client-credentials');
  assert.equal((await oidc.validateProfile(oidcProfile('http://127.0.0.1/token'))).valid, true);
  assert.equal((await oidc.validateProfile(
    oidcProfile('http://identity.example.test/token'),
    { allowInsecure: true }
  )).valid, false);

  const stripe = getProvider('stripe-api-key');
  assert.equal((await stripe.validateProfile(stripeProfile('http://localhost:8123'))).valid, true);
  assert.equal((await stripe.validateProfile(stripeProfile('http://192.0.2.30:8123'))).valid, false);
});

test('required presentation bindings fail and stdin bindings materialize exactly once', () => {
  const provider = getProvider('env-bearer');
  const session = provider.resolveSession(
    { profile: envBearerProfile() },
    { env: { TEST_BEARER_TOKEN: 'credential-sentinel' } }
  );

  assert.throws(
    () => provider.materialize(session, {
      bindings: [{
        source: 'credentials.missing.value',
        target: { kind: 'env', name: 'TOKEN' },
        required: true,
      }],
    }),
    error => error.code === 'presentation_binding_missing'
  );

  const materialized = provider.materialize(session, {
    bindings: [{
      source: 'credentials.access_token.value',
      target: { kind: 'stdin' },
      required: true,
    }],
  });
  assert.equal(materialized.stdin, 'credential-sentinel');
  assert.deepEqual(materialized.env_vars, {});
});

test('named credential files are private and cleanup is idempotent', () => {
  const provider = getProvider('env-bearer');
  const session = provider.resolveSession(
    { profile: envBearerProfile() },
    { env: { TEST_BEARER_TOKEN: 'file-credential-sentinel' } }
  );
  const materialized = provider.materialize(session, {
    bindings: [{
      source: 'credentials.access_token.value',
      target: { kind: 'file', name: 'access-token.txt', expose_as: 'ACCESS_TOKEN_FILE' },
      required: true,
    }],
  });

  const path = materialized.env_vars.ACCESS_TOKEN_FILE;
  assert.equal(readFileSync(path, 'utf8'), 'file-credential-sentinel');
  assert.equal(statSync(path).mode & 0o777, 0o600);
  assert.equal(statSync(dirname(path)).mode & 0o777, 0o700);

  assert.deepEqual(provider.cleanup(materialized).warnings ?? [], []);
  assert.equal(existsSync(path), false);
  assert.deepEqual(provider.cleanup(materialized).warnings ?? [], []);
  assert.throws(
    () => provider.materialize(session, {
      bindings: [{
        source: 'credentials.access_token.value',
        target: { kind: 'file', name: '../escape' },
        required: true,
      }],
    }),
    error => error.code === 'presentation_target_invalid'
  );
});

test('session descriptions redact credentials, source paths, and credential identifiers', () => {
  const provider = getProvider('env-bearer');
  const described = provider.describeSession({
    provider: 'env-bearer',
    credentials: {
      access_token: { kind: 'bearer', value: 'description-secret-value' },
    },
    child_credentials: {
      token: 'child-secret-value',
    },
    provider_assertions: {
      token_file: '/private/credential-source',
      token_endpoint: 'https://user:password@example.test/token?secret=value',
    },
    delegation_chain: [{
      principal: 'AKIA1234567890ABCDEF',
      grant: 'test',
      validated: true,
    }],
  });

  const json = JSON.stringify(described);
  assert.doesNotMatch(json, /description-secret-value|child-secret-value|credential-source|AKIA1234567890ABCDEF|password|secret=value/);
  assert.match(json, /\[REDACTED\]/);
});

test('provider resolution errors do not expose credential source locations', () => {
  const provider = getProvider('file-bearer');
  const sourcePath = '/private/nonexistent/credential-source';
  const profile = {
    provider: 'file-bearer',
    auth: {
      mode: 'service',
      required: true,
      provider_config: { token_file: sourcePath },
    },
    trust: { level: 'supervised' },
    presentation: { handoff: 'none' },
  };
  assert.throws(
    () => provider.resolveSession({ profile }, { env: {} }),
    error => error.code === 'token_file_not_found' && !error.message.includes(sourcePath)
  );
});

test('command credential sources receive only the explicit command environment', () => {
  const directory = mkdtempSync(join(tmpdir(), 'agentcli-command-env-'));
  const tokenPath = join(directory, 'token');
  writeFileSync(tokenPath, 'command-env-token', { mode: 0o600 });
  const provider = getProvider('file-bearer');
  const profile = {
    provider: 'file-bearer',
    auth: {
      mode: 'service',
      required: true,
      inputs: {
        token_file: {
          value_from: { command: 'printf %s "$PRIVATE_TOKEN_PATH"' },
        },
      },
    },
    trust: { level: 'supervised' },
    presentation: { handoff: 'none' },
  };

  try {
    assert.throws(
      () => provider.resolveSession({ profile }, {
        env: { PRIVATE_TOKEN_PATH: tokenPath },
        commandEnv: {},
      }),
      error => error.code === 'token_file_not_found'
    );
    const session = provider.resolveSession({ profile }, {
      env: { PRIVATE_TOKEN_PATH: tokenPath },
      commandEnv: { PRIVATE_TOKEN_PATH: tokenPath },
    });
    assert.equal(session.credentials.access_token.value, 'command-env-token');
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('delegation policy enforces allowed delegators and validated grants', () => {
  const provider = getProvider('aws-sts-assume-role');
  const result = provider.validateDelegation([
    { principal: 'agent://not-allowed', grant: 'assume-role', validated: true },
  ], {
    max_depth: 1,
    allowed_delegators: ['agent://allowed'],
    require_grant_per_hop: true,
  });
  assert.equal(result.valid, false);
  assert.match(result.errors.join(' '), /not allowed/);
});

test('dynamic provider cleanup is idempotent after successful revocation', async () => {
  let deleteCount = 0;
  const server = createServer((request, response) => {
    if (request.method === 'DELETE') deleteCount += 1;
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end('{}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const apiBase = `http://127.0.0.1:${address.port}`;
  const provider = getProvider('stripe-api-key');
  const session = {
    provider: 'stripe-api-key',
    credentials: {
      api_key: { kind: 'bearer', value: 'rk_test_child_credential', scope: 'payments' },
    },
    provider_assertions: {
      key_strategy: 'dynamic',
      account_mode: 'test',
      scope: 'payments',
      stripe_key_id: 'rk_test_cleanup_id',
      api_base: apiBase,
    },
  };
  const materialization = provider.materialize(session, {});
  const context = {
    env: { STRIPE_MASTER: 'sk_test_master_key_for_cleanup' },
    commandEnv: {},
    provider_config: {
      master_key_source: { env: 'STRIPE_MASTER' },
      api_base: apiBase,
    },
  };

  try {
    assert.deepEqual(await provider.cleanup(materialization, context), { cleaned: true });
    assert.deepEqual(await provider.cleanup(materialization, context), { cleaned: true });
    assert.equal(deleteCount, 1);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('SPIFFE provider accepts only trusted, audience-bound, file-mounted JWT-SVIDs', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'agentcli-spiffe-test-'));
  const svidPath = join(directory, 'svid.jwt');
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const now = Math.floor(Date.now() / 1000);
  const token = signedJwt(privateKey, {
    sub: 'spiffe://example.test/workload/api',
    iss: 'spiffe://example.test',
    aud: ['agentcli', 'other-audience'],
    iat: now - 5,
    exp: now + 300,
  });
  writeFileSync(svidPath, token, { mode: 0o600 });
  chmodSync(svidPath, 0o600);

  const profile = {
    provider: 'spiffe-jwt-svid',
    subject: { kind: 'workload' },
    auth: {
      mode: 'service',
      required: true,
      audience: 'agentcli',
      provider_config: { svid_file: svidPath, public_key_pem: publicKey },
    },
    trust: { level: 'supervised' },
    presentation: { handoff: 'none' },
  };
  const provider = getProvider('spiffe-jwt-svid');

  try {
    assert.equal((await provider.validateProfile(profile)).valid, true);
    const session = provider.resolveSession({ profile });
    assert.equal(session.provider_assertions.signature_verified, true);
    assert.equal(session.subject.principal, 'spiffe://example.test/workload/api');
    assert.equal(provider.describeSession(session).credentials.jwt_svid.value, '[REDACTED]');

    assert.throws(
      () => verifyJwtSvid(token, profile.auth.provider_config, 'wrong-audience'),
      error => error.code === 'spiffe_audience_mismatch'
    );
    const tokenSegments = token.split('.');
    tokenSegments[2] = `${tokenSegments[2][0] === 'A' ? 'B' : 'A'}${tokenSegments[2].slice(1)}`;
    const tampered = tokenSegments.join('.');
    assert.throws(
      () => verifyJwtSvid(tampered, profile.auth.provider_config, 'agentcli'),
      error => error.code === 'spiffe_signature_invalid'
    );
    const expiredToken = signedJwt(privateKey, {
      sub: 'spiffe://example.test/workload/api',
      aud: 'agentcli',
      iat: now - 600,
      exp: now - 500,
    });
    assert.throws(
      () => verifyJwtSvid(expiredToken, profile.auth.provider_config, 'agentcli'),
      error => error.code === 'spiffe_svid_expired'
    );

    const socketProfile = structuredClone(profile);
    socketProfile.auth.provider_config.workload_api_socket = 'unix:///run/spire/sockets/agent.sock';
    assert.equal((await provider.validateProfile(socketProfile)).valid, false);

    const untrustedProfile = structuredClone(profile);
    delete untrustedProfile.auth.provider_config.public_key_pem;
    assert.equal((await provider.validateProfile(untrustedProfile)).valid, false);

    const malformedTrustProfile = structuredClone(profile);
    malformedTrustProfile.auth.provider_config.public_key_pem = 'not-a-public-key';
    assert.equal((await provider.validateProfile(malformedTrustProfile)).valid, false);

    const optionalProfile = structuredClone(profile);
    optionalProfile.auth.required = false;
    delete optionalProfile.auth.audience;
    delete optionalProfile.auth.provider_config.public_key_pem;
    assert.deepEqual(provider.resolveSession({ profile: optionalProfile }).credentials, {});
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
