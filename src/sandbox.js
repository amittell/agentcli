import { spawnSync } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, resolve } from 'node:path';

function toAbsolutePath(value, cwd) {
  if (!value || typeof value !== 'string') return null;
  return isAbsolute(value) ? value : resolve(cwd, value);
}

function uniquePaths(paths) {
  return [...new Set(paths.filter(Boolean))];
}

function canonicalizePath(pathValue) {
  if (!pathValue) return [];
  const values = [pathValue];
  try {
    values.push(realpathSync(pathValue));
  } catch {
    // Ignore paths that do not exist yet; the non-canonical path is still useful.
  }
  return uniquePaths(values);
}

function escapeSandboxString(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function commandExists(command) {
  if (!command) return false;
  if (command.includes('/')) return true;
  const result = spawnSync('which', [command], {
    encoding: 'utf8',
    timeout: 5000,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  return result.status === 0;
}

export function resolveSandboxSupport({
  env = process.env,
  platform = process.platform,
} = {}) {
  const mode = String(env.AGENTCLI_SANDBOX || '').trim().toLowerCase();
  if (['off', '0', 'false', 'disabled', 'none'].includes(mode)) {
    return null;
  }

  if (platform === 'darwin') {
    const command = env.AGENTCLI_SANDBOX_EXEC || 'sandbox-exec';
    if (commandExists(command)) {
      return { kind: 'sandbox-exec', command };
    }
  }

  return null;
}

export function needsSandboxEnforcement(contract = {}) {
  return contract.sandbox === 'strict' || contract.network === 'restricted' || contract.network === 'none';
}

export function buildMacOSSandboxProfile({
  contract = {},
  cwd = process.cwd(),
  shellCwd,
} = {}) {
  const executionCwd = toAbsolutePath(shellCwd || cwd, cwd);
  const sandboxMode = contract.sandbox || 'none';

  if (sandboxMode !== 'strict') {
    const lines = ['(version 1)', '(allow default)'];
    if (contract.network === 'none') {
      lines.push('(deny network*)');
    } else if (contract.network === 'restricted') {
      lines.push('(deny network-inbound)');
    }
    return lines.join('\n');
  }

  const writeRoots = uniquePaths([
    ...canonicalizePath(executionCwd),
    ...canonicalizePath(tmpdir()),
    ...(contract.allowed_paths || []).flatMap(p => canonicalizePath(toAbsolutePath(p, cwd))),
  ]);

  const lines = [
    '(version 1)',
    '(deny default)',
    '(import "system.sb")',
    '(allow process*)',
    '(allow signal (target self))',
    '(allow file-read*)',
    '(allow file-read-metadata)',
    '(allow sysctl-read)',
  ];

  if (contract.network === 'unrestricted' || contract.network == null) {
    lines.push('(allow network*)');
  } else if (contract.network === 'restricted') {
    lines.push('(allow network-outbound)');
  }

  for (const root of writeRoots) {
    lines.push(`(allow file-write* (subpath "${escapeSandboxString(root)}"))`);
  }

  return lines.join('\n');
}

export function prepareSandboxedShellCommand(shell, contract, {
  cwd = process.cwd(),
  env = process.env,
  platform = process.platform,
} = {}) {
  const warnings = [];
  const support = resolveSandboxSupport({ env, platform });

  if (!needsSandboxEnforcement(contract)) {
    if (contract.sandbox === 'permissive') {
      warnings.push('contract.sandbox is "permissive"; execution proceeds without additional OS-level isolation');
    }
    return {
      program: shell.program,
      args: shell.args,
      warnings,
      sandboxed: false,
      profile: null,
      support: null,
    };
  }

  if (!support) {
    if (contract.sandbox === 'strict') {
      warnings.push('contract.sandbox is "strict" but no supported local sandbox runner is available; execution proceeds without OS-level sandbox enforcement');
    }
    if (contract.network === 'none') {
      warnings.push('contract.network is "none" but no supported local sandbox runner is available; execution proceeds without OS-level network enforcement');
    } else if (contract.network === 'restricted') {
      warnings.push('contract.network is "restricted" but no supported local sandbox runner is available; execution proceeds without OS-level inbound network enforcement');
    }
    return {
      program: shell.program,
      args: shell.args,
      warnings,
      sandboxed: false,
      profile: null,
      support: null,
    };
  }

  if (support.kind === 'sandbox-exec') {
    const profile = buildMacOSSandboxProfile({
      contract,
      cwd,
      shellCwd: shell.cwd,
    });
    return {
      program: support.command,
      args: ['-p', profile, shell.program, ...shell.args],
      warnings,
      sandboxed: true,
      profile,
      support,
    };
  }

  return {
    program: shell.program,
    args: shell.args,
    warnings,
    sandboxed: false,
    profile: null,
    support: null,
  };
}
