import { lstatSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, relative, resolve } from 'node:path';

function toAbsolutePath(value, cwd) {
  if (!value || typeof value !== 'string') return null;
  return resolve(isAbsolute(value) ? value : resolve(cwd, value));
}

function uniquePaths(paths) {
  return [...new Set(paths.filter(Boolean))];
}

function isPathWithin(candidate, root) {
  const relation = relative(root, candidate);
  return relation === '' || (!relation.startsWith('..') && !isAbsolute(relation));
}

/**
 * Resolve a requested sandbox path through its nearest existing ancestor.
 * Existing symlinks are resolved, dangling symlinks fail closed, and missing
 * descendants are appended only beneath the real ancestor path.
 */
export function canonicalizeSandboxPath(pathValue, { cwd = process.cwd() } = {}) {
  const absolute = toAbsolutePath(pathValue, cwd);
  if (!absolute) {
    throw Object.assign(new Error('Sandbox path must be a non-empty string'), {
      code: 'sandbox_path_invalid',
    });
  }

  const missing = [];
  let cursor = absolute;
  while (true) {
    try {
      lstatSync(cursor);
    } catch (error) {
      if (error?.code !== 'ENOENT' && error?.code !== 'ENOTDIR') {
        throw Object.assign(new Error('Sandbox path cannot be canonicalized safely'), {
          code: 'sandbox_path_invalid',
          cause: error,
        });
      }

      const parent = dirname(cursor);
      if (parent === cursor) {
        throw Object.assign(new Error('Sandbox path has no resolvable existing ancestor'), {
          code: 'sandbox_path_invalid',
        });
      }
      missing.push(basename(cursor));
      cursor = parent;
      continue;
    }

    try {
      const canonicalAncestor = realpathSync(cursor);
      return resolve(canonicalAncestor, ...missing.reverse());
    } catch (error) {
      // lstat succeeded, so an ENOENT here means a dangling symlink rather
      // than a merely nonexistent descendant. Never treat it as safe.
      throw Object.assign(new Error('Sandbox path resolves through an unsafe or dangling symlink'), {
        code: 'sandbox_path_invalid',
        cause: error,
      });
    }
  }
}

function escapeSandboxString(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

/**
 * Resolve configured sandbox support without spawning a probe process. The
 * eventual approved command spawn is the authoritative availability check.
 */
export function resolveSandboxSupport({
  env = process.env,
  platform = process.platform,
} = {}) {
  const mode = String(env.AGENTCLI_SANDBOX || '').trim().toLowerCase();
  if (['off', '0', 'false', 'disabled', 'none'].includes(mode)) return null;
  if (platform !== 'darwin') return null;
  return {
    kind: 'sandbox-exec',
    command: '/usr/bin/sandbox-exec',
  };
}

export function needsSandboxEnforcement(contract = {}) {
  return contract.sandbox === 'strict' ||
    contract.network === 'restricted' ||
    contract.network === 'none' ||
    (Array.isArray(contract.allowed_paths) && contract.allowed_paths.length > 0);
}

export function buildMacOSSandboxProfile({
  contract = {},
  cwd = process.cwd(),
  shellCwd,
} = {}) {
  const executionCwd = toAbsolutePath(shellCwd || cwd, cwd);
  const sandboxMode = contract.sandbox || 'none';
  const restrictFilesystem = sandboxMode === 'strict' ||
    (Array.isArray(contract.allowed_paths) && contract.allowed_paths.length > 0);

  if (!restrictFilesystem) {
    const lines = ['(version 1)', '(allow default)'];
    if (contract.network === 'none') {
      lines.push('(deny network*)');
    } else if (contract.network === 'restricted') {
      lines.push('(deny network-inbound)');
    }
    return lines.join('\n');
  }

  const canonicalExecutionCwd = canonicalizeSandboxPath(executionCwd, { cwd });
  const canonicalAllowedPaths = (contract.allowed_paths || [])
    .map(path => canonicalizeSandboxPath(path, { cwd }));
  if (canonicalAllowedPaths.length > 0 &&
      !canonicalAllowedPaths.some(root => isPathWithin(canonicalExecutionCwd, root))) {
    throw Object.assign(
      new Error('Execution working directory resolves outside contract.allowed_paths'),
      { code: 'sandbox_path_escape' }
    );
  }

  const writeRoots = uniquePaths([
    canonicalExecutionCwd,
    canonicalizeSandboxPath(tmpdir(), { cwd }),
    ...canonicalAllowedPaths,
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

export function prepareSandboxedShellCommand(shell, contract = {}, {
  cwd = process.cwd(),
  env = process.env,
  platform = process.platform,
} = {}) {
  const warnings = [];
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

  const support = resolveSandboxSupport({ env, platform });
  if (!support) {
    const constraints = [];
    if (contract.sandbox === 'strict') constraints.push('strict filesystem/process isolation');
    if (contract.network === 'none') constraints.push('network denial');
    if (contract.network === 'restricted') constraints.push('network restriction');
    throw Object.assign(
      new Error(`Required sandbox enforcement is unavailable: ${constraints.join(', ')}`),
      { code: 'sandbox_enforcement_unavailable', constraints }
    );
  }

  if (support.kind !== 'sandbox-exec') {
    throw Object.assign(new Error('Configured sandbox implementation is unsupported'), {
      code: 'sandbox_enforcement_unavailable',
    });
  }

  const profile = buildMacOSSandboxProfile({ contract, cwd, shellCwd: shell.cwd });
  return {
    program: support.command,
    args: ['-p', profile, shell.program, ...(shell.args || [])],
    warnings,
    sandboxed: true,
    profile,
    support,
  };
}
