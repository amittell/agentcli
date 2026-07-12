# Testing Stripe Identity Step-Up

This guide walks through a local end-to-end test of the Stripe Identity step-up example using:

- the manifest: [`../examples/stripe-identity-step-up.json`](../examples/stripe-identity-step-up.json)
- the OPA policy: [`../examples/stripe-identity-step-up.rego`](../examples/stripe-identity-step-up.rego)

The generated local manifest replaces the remote API commands with harmless `printf` calls, so the guide can exercise live proof verification, OPA authorization, identity materialization, and audit output without contacting a backend API. Do not add `--dry-run` to those checks: dry-run is intentionally static and skips proof, provider, authorization, evidence, and audit side effects.

## Prerequisites

- Node 22+
- this repository checked out locally
- either:
  - `opa` installed locally, or
  - Docker available for running OPA

## 1. Validate the example manifest

```bash
node bin/agentcli.js validate examples/stripe-identity-step-up.json --json
```

You should see:

```json
{
  "ok": true,
  "errors": [],
  "warnings": []
}
```

## 2. Start OPA with the example policy

If you have the `opa` CLI:

```bash
opa run --server --addr 127.0.0.1:8181 examples/stripe-identity-step-up.rego
```

If you prefer Docker:

```bash
docker run --rm \
  -p 8181:8181 \
  -v "$PWD/examples:/policy" \
  openpolicyagent/opa:latest \
  run --server --addr :8181 /policy/stripe-identity-step-up.rego
```

The example manifest points at:

```text
http://127.0.0.1:8181/v1/data/agentcli/authz/allow
```

## 3. Create a local test manifest with a generated public key

The checked-in example uses an illustrative remote `jwks_uri`. For local testing, generate an RSA key pair and write a temporary manifest that embeds the public key directly.

```bash
node --input-type=module <<'EOF'
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
writeFileSync('/tmp/agentcli-step-up-private.pem', privateKey.export({ type: 'pkcs8', format: 'pem' }));

const manifest = JSON.parse(readFileSync('examples/stripe-identity-step-up.json', 'utf8'));
delete manifest.authorization_proof_profiles[0].jwks_uri;
manifest.authorization_proof_profiles[0].public_key = publicKey.export({ type: 'spki', format: 'pem' });
manifest.workflows[0].contract.sandbox = 'none';
for (const task of manifest.workflows[0].tasks) {
  task.shell = { program: 'printf', args: ['%s\\n', `local test: ${task.id}`] };
}

writeFileSync('/tmp/stripe-identity-step-up.local.json', JSON.stringify(manifest, null, 2));
EOF
```

Validate the generated manifest:

```bash
node bin/agentcli.js validate /tmp/stripe-identity-step-up.local.json --json
```

## 4. Export a dummy primary auth token

The manifest's identity profile still expects a runtime bearer token. The local commands only print fixed text, so use a synthetic local token that is never sent to a remote service.

```bash
export BOT_ACCESS_TOKEN="dummy-bot-token"
```

## 5. Generate a valid signed step-up JWT

This token matches both:

- the manifest proof check
- the OPA policy in `examples/stripe-identity-step-up.rego`

```bash
export ACTOR_STEP_UP_JWT="$(
  node --input-type=module <<'EOF'
import { createSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonicalDigest } from './src/canonical.js';

const privateKey = readFileSync('/tmp/agentcli-step-up-private.pem', 'utf8');
const manifest = JSON.parse(readFileSync('/tmp/stripe-identity-step-up.local.json', 'utf8'));
const header = Buffer.from(JSON.stringify({
  alg: 'RS256',
  typ: 'JWT',
  kid: 'local-step-up-test'
})).toString('base64url');

const payload = Buffer.from(JSON.stringify({
  iss: 'https://auth.example.com',
  aud: 'agentcli',
  sub: 'user_demo',
  org_id: 'org_demo',
  on_behalf_of_user_id: 'user_demo',
  delegation_grant_id: 'grant_demo',
  run_id: 'run_demo',
  agent_id: 'support-bot',
  verification_ref: 'vs_local_test',
  verification_level: 'document',
  verification_verified_at: '2026-04-07T12:00:00Z',
  step_up_policy: 'stripe_identity_sensitive_ops',
  manifest_digest: canonicalDigest(manifest),
  exp: Math.floor(Date.now() / 1000) + 3600
})).toString('base64url');

const signer = createSign('RSA-SHA256');
signer.update(`${header}.${payload}`);
process.stdout.write(`${header}.${payload}.${signer.sign(privateKey).toString('base64url')}`);
EOF
)"
```

## 6. Run the harmless non-sensitive task

This task does not require step-up proof or OPA authorization.

```bash
node bin/agentcli.js exec /tmp/stripe-identity-step-up.local.json list-safe-state --signer none --json
```

What to look for:

- `"ok": true`
- no authorization proof requirement
- resolved identity from the `ops-bot` profile

## 7. Run the harmless sensitive task with valid step-up proof

```bash
node bin/agentcli.js exec /tmp/stripe-identity-step-up.local.json view-sensitive-customer --signer none --json
```

What to look for in the JSON output:

- `"ok": true`
- `authorization_proof.verified` is `true`
- `authorization_proof.signature_verified` is `true`
- `authorization.decision` is `permit`
- `actor_context.org_id` is `org_demo`
- `actor_context.verification.ref` is `vs_local_test`
- `step_up.step_up_policy` is `stripe_identity_sensitive_ops`

## 8. Negative test: missing step-up proof

Unset the JWT and rerun the sensitive task:

```bash
unset ACTOR_STEP_UP_JWT
node bin/agentcli.js exec /tmp/stripe-identity-step-up.local.json view-sensitive-customer --signer none --json
```

Expected result:

- command fails
- error indicates the authorization proof value was not available

## 9. Negative test: proof passes but OPA denies

Generate a JWT that still satisfies the manifest proof check but fails the OPA policy by using the wrong `org_id`.

```bash
export ACTOR_STEP_UP_JWT="$(
  node --input-type=module <<'EOF'
import { createSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonicalDigest } from './src/canonical.js';

const privateKey = readFileSync('/tmp/agentcli-step-up-private.pem', 'utf8');
const manifest = JSON.parse(readFileSync('/tmp/stripe-identity-step-up.local.json', 'utf8'));
const header = Buffer.from(JSON.stringify({
  alg: 'RS256',
  typ: 'JWT',
  kid: 'local-step-up-test'
})).toString('base64url');

const payload = Buffer.from(JSON.stringify({
  iss: 'https://auth.example.com',
  aud: 'agentcli',
  sub: 'user_demo',
  org_id: 'org_wrong',
  on_behalf_of_user_id: 'user_demo',
  delegation_grant_id: 'grant_demo',
  run_id: 'run_demo',
  agent_id: 'support-bot',
  verification_ref: 'vs_local_test',
  verification_level: 'document',
  verification_verified_at: '2026-04-07T12:00:00Z',
  step_up_policy: 'stripe_identity_sensitive_ops',
  manifest_digest: canonicalDigest(manifest),
  exp: Math.floor(Date.now() / 1000) + 3600
})).toString('base64url');

const signer = createSign('RSA-SHA256');
signer.update(`${header}.${payload}`);
process.stdout.write(`${header}.${payload}.${signer.sign(privateKey).toString('base64url')}`);
EOF
)"
```

Now rerun:

```bash
node bin/agentcli.js exec /tmp/stripe-identity-step-up.local.json view-sensitive-customer --signer none --json
```

Expected result:

- proof verification still succeeds
- OPA returns `deny`
- `agentcli` fails with `authorization_denied`

## 10. Inspect audit output

Because the example workflow uses `contract.audit: "always"`, successful live local runs and authorization failures are written to the audit log. Static dry-runs never write audit records.

```bash
node bin/agentcli.js audit --limit 5 --json
```

What to look for in each record:

- `actor_context`
- `authorization_proof`
- `step_up`
- `authorization`
- `trust`

For denied runs, look for:

- `authorization_error`

For proof failures, look for:

- `authorization_proof.verified: false`

## 11. Clean up local test artifacts

```bash
rm -f /tmp/agentcli-step-up-private.pem
rm -f /tmp/stripe-identity-step-up.local.json
unset BOT_ACCESS_TOKEN
unset ACTOR_STEP_UP_JWT
```

## Expected Testing Sequence

1. `validate` passes for the checked-in example.
2. `validate` passes for the generated local manifest.
3. The harmless local `list-safe-state` task succeeds without step-up.
4. The harmless local `view-sensitive-customer` task succeeds with a valid manifest-bound JWT and OPA allow.
5. The sensitive task fails when the JWT is missing.
6. The sensitive task fails with `authorization_denied` when OPA rejects the actor context.
