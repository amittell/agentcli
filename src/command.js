import { spawnSync } from 'node:child_process';
import process from 'node:process';

export function shellCommandInvocation(command, platform = process.platform) {
  if (platform === 'win32') {
    return {
      program: 'cmd.exe',
      args: ['/d', '/s', '/c', command],
    };
  }
  return {
    program: 'sh',
    args: ['-c', command],
  };
}

export function resolveCommandValue(
  command,
  {
    cwd = process.cwd(),
    env = process.env,
    timeoutMs = 30000,
    runner = spawnSync,
    platform = process.platform,
  } = {}
) {
  try {
    const invocation = shellCommandInvocation(command, platform);
    const result = runner(invocation.program, invocation.args, {
      cwd,
      env,
      encoding: 'utf8',
      timeout: timeoutMs,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    if (result.status === 0 && result.stdout) {
      return result.stdout.trim();
    }
    return null;
  } catch {
    return null;
  }
}
