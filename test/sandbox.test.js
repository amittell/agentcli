import test from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  mkdirSync,
  realpathSync,
  rmSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  buildMacOSSandboxProfile,
  canonicalizeSandboxPath,
  prepareSandboxedShellCommand,
  resolveSandboxSupport,
} from '../src/sandbox.js';

const shell = { program: '/bin/echo', args: ['ok'], cwd: null };

test('sandbox support resolution performs no executable probe', () => {
  assert.equal(resolveSandboxSupport({ platform: 'linux', env: {} }), null);
  assert.deepEqual(resolveSandboxSupport({ platform: 'darwin', env: {} }), {
    kind: 'sandbox-exec',
    command: '/usr/bin/sandbox-exec',
  });
  assert.deepEqual(resolveSandboxSupport({
    platform: 'darwin',
    env: { AGENTCLI_SANDBOX_EXEC: '/custom/sandbox-exec' },
  }), {
    kind: 'sandbox-exec',
    command: '/usr/bin/sandbox-exec',
  });
  assert.equal(resolveSandboxSupport({
    platform: 'darwin',
    env: { AGENTCLI_SANDBOX: 'disabled' },
  }), null);
});

test('strict and network-restricted contracts fail closed without enforcement', () => {
  for (const contract of [
    { sandbox: 'strict', network: 'unrestricted' },
    { sandbox: 'none', network: 'none' },
    { sandbox: 'permissive', network: 'restricted' },
    { sandbox: 'permissive', network: 'unrestricted', allowed_paths: [tmpdir()] },
  ]) {
    assert.throws(
      () => prepareSandboxedShellCommand(shell, contract, { platform: 'linux', env: {} }),
      error => error.code === 'sandbox_enforcement_unavailable'
    );
  }
});

test('allowed_paths creates a filesystem boundary even without sandbox strict', () => {
  const profile = buildMacOSSandboxProfile({
    contract: {
      sandbox: 'permissive',
      network: 'unrestricted',
      allowed_paths: [tmpdir()],
    },
    cwd: tmpdir(),
    shellCwd: tmpdir(),
  });
  assert.match(profile, /\(deny default\)/);
  assert.match(profile, /allow file-write/);
});

test('permissive isolation remains advisory only without a network restriction', () => {
  const result = prepareSandboxedShellCommand(shell, {
    sandbox: 'permissive',
    network: 'unrestricted',
  }, { platform: 'linux', env: {} });
  assert.equal(result.sandboxed, false);
  assert.equal(result.program, shell.program);
  assert.equal(result.warnings.length, 1);
});

test('darwin enforcement wraps the command without probing the runner', () => {
  const result = prepareSandboxedShellCommand(shell, {
    sandbox: 'strict',
    network: 'none',
  }, {
    platform: 'darwin',
    env: { AGENTCLI_SANDBOX_EXEC: '/custom/sandbox-exec' },
  });
  assert.equal(result.sandboxed, true);
  assert.equal(result.program, '/usr/bin/sandbox-exec');
  assert.deepEqual(result.args.slice(-2), ['/bin/echo', 'ok']);
  assert.doesNotMatch(result.profile, /allow network/);
});

test('sandbox paths resolve existing symlinks and anchor nonexistent descendants', () => {
  const root = mkdtempSync(join(tmpdir(), 'agentcli-sandbox-test-'));
  const requestedRoot = join(root, 'requested');
  const realRoot = join(root, 'real');
  mkdirSync(requestedRoot);
  mkdirSync(realRoot);
  const link = join(requestedRoot, 'link');
  symlinkSync(realRoot, link);
  const requested = join(link, 'future', 'output');
  const canonical = join(realpathSync(realRoot), 'future', 'output');

  try {
    assert.equal(canonicalizeSandboxPath(requested), canonical);
    const profile = buildMacOSSandboxProfile({
      contract: { sandbox: 'strict', network: 'none', allowed_paths: [requested] },
      cwd: requestedRoot,
      shellCwd: requested,
    });
    assert.match(profile, new RegExp(canonical.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    assert.doesNotMatch(profile, new RegExp(requested.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('sandbox rejects a working-directory symlink escape from allowed roots', () => {
  const root = mkdtempSync(join(tmpdir(), 'agentcli-sandbox-escape-'));
  const allowed = join(root, 'allowed');
  const outside = join(root, 'outside');
  mkdirSync(allowed);
  mkdirSync(outside);
  const link = join(allowed, 'link');
  symlinkSync(outside, link);
  try {
    assert.throws(
      () => buildMacOSSandboxProfile({
        contract: { sandbox: 'strict', network: 'none', allowed_paths: [allowed] },
        cwd: allowed,
        shellCwd: link,
      }),
      error => error.code === 'sandbox_path_escape'
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('dangling symlink sandbox roots are rejected rather than treated as missing', () => {
  const root = mkdtempSync(join(tmpdir(), 'agentcli-sandbox-dangling-'));
  const link = join(root, 'dangling');
  symlinkSync(join(root, 'missing-target'), link);
  try {
    assert.throws(
      () => canonicalizeSandboxPath(join(link, 'child')),
      error => error.code === 'sandbox_path_invalid'
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
